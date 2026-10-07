"""OS-specific USB event sources. Each one puts RawEvents on a queue from its own thread
and returns the devices attached at start-up (so they are not reported as new connects)."""

import os
import queue
import re
import sys
import threading
import time

from agent.core import RawEvent

# ---------------------------------------------------------------- Linux (udev)


def _linux_ids(dev) -> tuple[str, str] | None:
    product = dev.properties.get("PRODUCT")  # kernel uevent: "46d/c52b/1201"
    if not product:
        return None
    vid, pid, _ = product.split("/")
    return vid.zfill(4).upper(), pid.zfill(4).upper()


def _linux_event(dev, action: str) -> RawEvent | None:
    ids = _linux_ids(dev)
    if ids is None:
        return None
    if dev.device_type == "usb_device":
        if dev.properties.get("TYPE", "").split("/")[0] == "9":
            return None  # hubs, including root hubs
        return RawEvent(
            action=action,
            kind="device",
            key=dev.sys_path,
            vendor_id=ids[0],
            product_id=ids[1],
            serial_number=dev.properties.get("ID_SERIAL_SHORT"),
            extra={"driver": dev.properties.get("DRIVER"), "sys_path": dev.sys_path},
        )
    if dev.device_type == "usb_interface" and action == "add":
        cls = dev.properties.get("INTERFACE", "").split("/")[0]  # "3/1/2" (decimal)
        return RawEvent(
            action=action,
            kind="interface",
            key=os.path.dirname(dev.sys_path),
            vendor_id=ids[0],
            product_id=ids[1],
            interface_class=int(cls) if cls.isdigit() else None,
        )
    return None


def start_linux(out: queue.Queue) -> list[RawEvent]:
    import pyudev

    ctx = pyudev.Context()
    existing = [e for d in ctx.list_devices(subsystem="usb", DEVTYPE="usb_device") if (e := _linux_event(d, "add"))]
    monitor = pyudev.Monitor.from_netlink(ctx)
    monitor.filter_by(subsystem="usb")

    def loop():
        for dev in iter(monitor.poll, None):  # blocks on the netlink socket: instant, no polling
            ev = _linux_event(dev, dev.action)
            if ev is not None and ev.action in ("add", "remove"):
                out.put(ev)

    threading.Thread(target=loop, daemon=True, name="udev").start()
    return existing


# ---------------------------------------------------------------- Windows (WMI)

# USB\VID_xxxx&PID_xxxx\<instance> is the device; ...&MI_nn\... is one of its interfaces.
DEVICE_RE = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})\\([^\\]+)$", re.I)
INTERFACE_RE = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})&MI_[0-9A-F]{2}\\", re.I)
CLASS_RE = re.compile(r"USB\\Class_([0-9A-F]{2})", re.I)


def _windows_event(entity, action: str) -> RawEvent | None:
    pnp_id = entity.DeviceID or ""
    if m := DEVICE_RE.match(pnp_id):
        instance = m.group(3)
        return RawEvent(
            action=action,
            kind="device",
            key=pnp_id,
            vendor_id=m.group(1).upper(),
            product_id=m.group(2).upper(),
            # Windows invents instance IDs containing '&' for devices without a real serial number.
            serial_number=None if "&" in instance else instance,
            device_type=entity.Description,
            extra={"pnp_device_id": pnp_id, "pnp_class": entity.PNPClass, "service": entity.Service},
        )
    if action == "add" and (m := INTERFACE_RE.match(pnp_id)):
        cls = next((c.group(1) for cid in (entity.CompatibleID or []) if (c := CLASS_RE.search(cid))), None)
        return RawEvent(
            action=action,
            kind="interface",
            key=pnp_id,
            vendor_id=m.group(1).upper(),
            product_id=m.group(2).upper(),
            interface_class=int(cls, 16) if cls else None,
        )
    return None


def start_windows(out: queue.Queue) -> list[RawEvent]:
    import pythoncom
    import wmi

    existing = [e for ent in wmi.WMI().Win32_PnPEntity() if (e := _windows_event(ent, "add")) and e.kind == "device"]

    def watch(notification: str, action: str):
        pythoncom.CoInitialize()  # each thread needs its own COM apartment
        watcher = wmi.WMI().Win32_PnPEntity.watch_for(notification, delay_secs=1)
        while True:
            try:
                ev = _windows_event(watcher(timeout_ms=1000), action)
            except wmi.x_wmi_timed_out:
                continue
            if ev is not None:
                out.put(ev)

    # WMI instance events: the OS pushes creations/deletions (checked by WMI every second).
    threading.Thread(target=watch, args=("creation", "add"), daemon=True, name="wmi-add").start()
    threading.Thread(target=watch, args=("deletion", "remove"), daemon=True, name="wmi-remove").start()
    return existing


# ---------------------------------------------------------------- fallback (libusb polling, e.g. macOS)


def start_polling(out: queue.Queue, interval: float = 2.0) -> list[RawEvent]:
    import usb.core

    from agent.descriptors import _backend, _serial

    def snapshot() -> dict[str, RawEvent]:
        devs = {}
        for d in usb.core.find(find_all=True, backend=_backend()):
            if d.bDeviceClass == 9:
                continue
            key = f"{d.bus}-{d.address}"
            devs[key] = RawEvent("add", "device", key, f"{d.idVendor:04X}", f"{d.idProduct:04X}", serial_number=_serial(d))
        return devs

    previous = snapshot()

    def loop():
        nonlocal previous
        while True:
            time.sleep(interval)
            current = snapshot()
            for k in current.keys() - previous.keys():
                out.put(current[k])
            for k in previous.keys() - current.keys():
                ev = previous[k]
                out.put(RawEvent("remove", "device", k, ev.vendor_id, ev.product_id, serial_number=ev.serial_number))
            previous = current

    threading.Thread(target=loop, daemon=True, name="usb-poll").start()
    return list(previous.values())


def start(out: queue.Queue) -> tuple[str, list[RawEvent]]:
    if sys.platform == "win32":
        return "windows-wmi-events", start_windows(out)
    if sys.platform.startswith("linux"):
        try:
            return "linux-udev", start_linux(out)
        except ImportError:
            pass
    return "libusb-polling", start_polling(out)
