"""Parsers for USB evidence the operating system already keeps, for machines that never ran the agent.

  setupapi  Windows C:\\Windows\\INF\\setupapi.dev.log: each USB device's first install, with its time
  registry  a .reg export of HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB (and ...\\Enum\\USBSTOR): every
            device ever enumerated, with its name and driver, but no times
  linux     kernel log lines (journalctl -k -o short-iso, /var/log/syslog, kern.log): connects and
            disconnects with VID/PID, serial and whether the device was storage or a keyboard

Each parser returns ParsedEvent rows (UTC timestamps) plus any undated devices and warnings.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

STORAGE, INPUT, GENERIC = "USB Mass Storage Device", "USB Input Device", "USB Device"
SERVICE_TYPES = {
    "usbstor": STORAGE,
    "uaspstor": STORAGE,
    "hidusb": INPUT,
    "usbvideo": "USB Video Device",
    "usbprint": "USB Printing Support",
    "usbaudio": "USB Audio Device",
    "usbccgp": "USB Composite Device",
}
ROOT_HUBS = {("1D6B", "0001"), ("1D6B", "0002"), ("1D6B", "0003")}  # Linux Foundation virtual root hubs


@dataclass
class ParsedEvent:
    timestamp: datetime
    event_type: str  # connect | disconnect
    vendor_id: str
    product_id: str
    serial_number: str | None
    device_type: str | None
    machine_hostname: str | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class ParseResult:
    kind: str
    events: list[ParsedEvent] = field(default_factory=list)
    undated: list[dict] = field(default_factory=list)  # devices known to the machine with no recorded time
    warnings: list[str] = field(default_factory=list)


def real_serial(instance: str) -> str | None:
    """Windows makes up instance IDs like 6&2a3b4c&0&1 for devices without a serial number."""
    return None if "&" in instance else instance


def decode(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")  # regedit exports are UTF-16
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


def detect_kind(text: str) -> str | None:
    head = text[:20000]
    if "Windows Registry Editor" in head or re.search(r"^\[HKEY_LOCAL_MACHINE\\", head, re.M):
        return "registry"
    if ">>>  Section start" in head or re.search(r"^>>>\s+\[", head, re.M):
        return "setupapi"
    if re.search(r"kernel:.*usb [\d.-]+: ", head):
        return "linux"
    return None


# --- Windows setupapi.dev.log ---------------------------------------------------------------------

SETUP_HEADER = re.compile(r"^>>>\s+\[(?P<title>.*?) - (?P<instance>[^\]]+)\]\s*$")
SETUP_START = re.compile(r"^>>>\s+Section start (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
USB_INSTANCE = re.compile(r"^USB\\VID_(?P<vid>[0-9A-F]{4})&PID_(?P<pid>[0-9A-F]{4})\\(?P<inst>[^\\]+)$", re.I)
USBSTOR_INSTANCE = re.compile(r"^USBSTOR\\[^\\]+\\(?P<serial>[^\\&]+)(?:&\d+)?$", re.I)
HID_INSTANCE = re.compile(r"^HID\\VID_(?P<vid>[0-9A-F]{4})&PID_(?P<pid>[0-9A-F]{4})", re.I)


def parse_setupapi(text: str, tz: str) -> ParseResult:
    """Every USB device install section is the first time this machine saw that device."""
    zone = ZoneInfo(tz)
    result = ParseResult("setupapi")
    installs: list[tuple[datetime, str, str, str | None]] = []
    storage_serials: set[str] = set()
    hid_models: set[tuple[str, str]] = set()
    pending: str | None = None
    for line in text.splitlines():
        header = SETUP_HEADER.match(line)
        if header:
            pending = header["instance"].strip()
            continue
        start = SETUP_START.match(line)
        if start and pending:
            when = datetime.strptime(start["ts"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=zone).astimezone(timezone.utc)
            if m := USB_INSTANCE.match(pending):
                installs.append((when, m["vid"].upper(), m["pid"].upper(), real_serial(m["inst"])))
            elif m := USBSTOR_INSTANCE.match(pending):
                storage_serials.add(m["serial"].upper())
            elif m := HID_INSTANCE.match(pending):
                hid_models.add((m["vid"].upper(), m["pid"].upper()))
            pending = None

    seen = set()
    for when, vid, pid, serial in sorted(installs):
        if (vid, pid, serial) in seen:  # a reinstall of the same device is not a new first sighting
            continue
        seen.add((vid, pid, serial))
        is_storage = serial is not None and serial.upper() in storage_serials
        is_input = (vid, pid) in hid_models
        dtype = "USB Composite Device" if is_storage and is_input else STORAGE if is_storage else INPUT if is_input else GENERIC
        result.events.append(ParsedEvent(when, "connect", vid, pid, serial, dtype, detail={"evidence": "first install (setupapi.dev.log)"}))
    if not installs:
        result.warnings.append("No USB device install sections found in this setupapi log.")
    return result


# --- Windows registry export ----------------------------------------------------------------------

REG_KEY = re.compile(
    r"^\[HKEY_LOCAL_MACHINE\\SYSTEM\\(?:CurrentControlSet|ControlSet\d{3})\\Enum\\USB\\VID_(?P<vid>[0-9A-F]{4})&PID_(?P<pid>[0-9A-F]{4})\\(?P<inst>[^\\\]]+)\]$",
    re.I,
)
REG_ANY_KEY = re.compile(r"^\[.*\]$")
REG_VALUE = re.compile(r'^"(?P<name>[^"]+)"="(?P<value>(?:[^"\\]|\\.)*)"$')


def parse_registry(text: str) -> ParseResult:
    result = ParseResult("registry")
    current: dict | None = None
    for line in text.splitlines():
        line = line.strip()
        if key := REG_KEY.match(line):
            current = {
                "vendor_id": key["vid"].upper(),
                "product_id": key["pid"].upper(),
                "serial_number": real_serial(key["inst"]),
                "device_type": None,
                "service": None,
                "name": None,
            }
            result.undated.append(current)
        elif REG_ANY_KEY.match(line):
            current = None
        elif current is not None and (val := REG_VALUE.match(line)):
            name, value = val["name"].lower(), val["value"].replace("\\\\", "\\")
            if name == "service":
                current["service"] = value
                current["device_type"] = current["device_type"] or SERVICE_TYPES.get(value.lower())
            elif name in ("devicedesc", "friendlyname"):
                text_part = value.split(";")[-1]  # "@usb.inf,%usb.devicedesc%;USB Mass Storage Device"
                current["name"] = current["name"] or text_part
                if "storage" in text_part.lower():
                    current["device_type"] = STORAGE
                elif "input" in text_part.lower() or "keyboard" in text_part.lower():
                    current["device_type"] = current["device_type"] or INPUT
    if not result.undated:
        result.warnings.append("No HKLM\\SYSTEM\\...\\Enum\\USB keys found in this registry export.")
    return result


def enrich_from_registry(events: list[ParsedEvent], registry: ParseResult) -> None:
    """Fill in device types the timed source could not tell, from the registry's driver names."""
    by_identity = {(d["vendor_id"], d["product_id"], d["serial_number"]): d for d in registry.undated}
    for e in events:
        reg = by_identity.get((e.vendor_id, e.product_id, e.serial_number))
        if reg and reg["device_type"] and e.device_type in (None, GENERIC):
            e.device_type = reg["device_type"]
        if reg and reg["name"]:
            e.detail["registry_name"] = reg["name"]


# --- Linux kernel log -----------------------------------------------------------------------------

MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
ISO_LINE = re.compile(r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+kernel:\s+(?:\[\s*[\d.]+\]\s+)?(?P<msg>.*)$")
SYSLOG_LINE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+kernel:\s+(?:\[\s*[\d.]+\]\s+)?(?P<msg>.*)$")
NEW_DEVICE = re.compile(r"^usb (?P<port>[\d.-]+): New USB device found, idVendor=(?P<vid>[0-9a-fA-F]{4}), idProduct=(?P<pid>[0-9a-fA-F]{4})")
SERIAL = re.compile(r"^usb (?P<port>[\d.-]+): SerialNumber: (?P<serial>.+)$")
PRODUCT = re.compile(r"^usb (?P<port>[\d.-]+): Product: (?P<product>.+)$")
STORAGE_LINE = re.compile(r"^usb-storage (?P<port>[\d.-]+):[\d.]+: USB Mass Storage device detected")
HID_LINE = re.compile(r"^(?:hid-generic|usbhid|hid-\w+) [0-9A-Fa-f]{4}:(?P<vid>[0-9A-Fa-f]{4}):(?P<pid>[0-9A-Fa-f]{4})\.[0-9A-Fa-f]+: .*USB HID v[\d.]+ (?P<kind>\w+)")
DISCONNECT = re.compile(r"^usb (?P<port>[\d.-]+): USB disconnect, device number")


def _linux_time(m: re.Match, zone: ZoneInfo, year: int) -> datetime:
    if "iso" in m.groupdict() and m["iso"]:
        iso = m["iso"].replace("Z", "+00:00")
        iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", iso)
        when = datetime.fromisoformat(iso)
        return (when if when.tzinfo else when.replace(tzinfo=zone)).astimezone(timezone.utc)
    hh, mm, ss = (int(x) for x in m["time"].split(":"))
    return datetime(year, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=zone).astimezone(timezone.utc)


def parse_linux(text: str, tz: str, year: int) -> ParseResult:
    zone = ZoneInfo(tz)
    result = ParseResult("linux")
    at_port: dict[tuple[str, str], ParsedEvent] = {}  # (host, port) -> the device currently attached there
    connects: list[ParsedEvent] = []
    disconnects: list[tuple[datetime, str, str, ParsedEvent]] = []  # (time, host, port, the connect it closes)
    for line in text.splitlines():
        m = ISO_LINE.match(line) or SYSLOG_LINE.match(line)
        if not m:
            continue
        when, host, msg = _linux_time(m, zone, year), m["host"], m["msg"]
        if new := NEW_DEVICE.match(msg):
            vid, pid = new["vid"].upper(), new["pid"].upper()
            if (vid, pid) in ROOT_HUBS:
                continue
            e = ParsedEvent(when, "connect", vid, pid, None, GENERIC, host, {"evidence": "kernel log", "port": new["port"]})
            at_port[(host, new["port"])] = e
            connects.append(e)
        elif s := SERIAL.match(msg):
            if e := at_port.get((host, s["port"])):
                e.serial_number = s["serial"].strip()
        elif p := PRODUCT.match(msg):
            if e := at_port.get((host, p["port"])):
                e.detail["product"] = p["product"].strip()
        elif st := STORAGE_LINE.match(msg):
            if e := at_port.get((host, st["port"])):
                e.device_type = "USB Composite Device" if e.device_type == INPUT else STORAGE
        elif hid := HID_LINE.match(msg):
            vid, pid = hid["vid"].upper(), hid["pid"].upper()
            for e in reversed(connects):
                if e.machine_hostname == host and (e.vendor_id, e.product_id) == (vid, pid):
                    e.device_type = "USB Composite Device" if e.device_type == STORAGE else INPUT
                    e.detail["hid"] = hid["kind"]
                    break
        elif d := DISCONNECT.match(msg):
            if e := at_port.pop((host, d["port"]), None):
                disconnects.append((when, host, d["port"], e))
    # Built after the loop: a disconnect reuses everything its connect learned from later lines (serial, type).
    closes = [
        ParsedEvent(when, "disconnect", c.vendor_id, c.product_id, c.serial_number, c.device_type, host, {"evidence": "kernel log", "port": port})
        for when, host, port, c in disconnects
    ]
    result.events = sorted(connects + closes, key=lambda e: (e.timestamp, e.event_type != "connect"))
    if not connects:
        result.warnings.append("No 'New USB device found' kernel lines in this log.")
    return result
