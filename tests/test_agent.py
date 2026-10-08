import json
from types import SimpleNamespace

import requests

from agent import backends
from agent.core import EnumerationTracker, RawEvent, Sender, build_payload
from agent.descriptors import describe, device_type_for


def dev_event(key="1-1", vid="0781", pid="5581", t=0.0, **kw):
    return RawEvent("add", "device", key, vid, pid, t=t, **kw)


def iface_event(cls, key="1-1", vid="0781", pid="5581", t=0.0):
    return RawEvent("add", "interface", key, vid, pid, t=t, interface_class=cls)


def test_tracker_reports_interface_order_and_enumeration_time():
    tr = EnumerationTracker(settle_seconds=1.5)
    tr.device_added(dev_event(t=10.0))
    tr.interface_added(iface_event(8, t=10.05))
    tr.interface_added(iface_event(3, t=10.30))
    assert tr.due(11.0) == []  # still settling
    [(ev, enum)] = tr.due(11.6)
    assert ev.key == "1-1"
    assert enum == {"interface_order": [8, 3], "duration_ms": 300.0}


def test_tracker_matches_windows_interfaces_by_vid_pid_even_before_the_device():
    tr = EnumerationTracker()
    tr.interface_added(iface_event(3, key="USB\\VID_0781&PID_5581&MI_01\\x", t=4.9))
    tr.device_added(dev_event(key="USB\\VID_0781&PID_5581\\SER", t=5.0))
    tr.interface_added(iface_event(8, key="USB\\VID_0781&PID_5581&MI_00\\y", t=5.1))
    [(_, enum)] = tr.due(7.0)
    assert enum["interface_order"] == [3, 8]


def test_device_removed_while_settling_is_never_reported():
    tr = EnumerationTracker()
    tr.device_added(dev_event(t=0.0))
    assert tr.device_removed("1-1") is True
    assert tr.due(10.0) == []


def test_payload_carries_os_time_descriptor_and_enumeration():
    ev = dev_event(serial_number="ABC", device_type="USB Mass Storage Device", extra={"service": "USBSTOR"})
    p = build_payload("PC-1", ev, "connect", {"bcd_usb": "0210", "interfaces": []}, {"interface_order": [8], "duration_ms": 90})
    assert p["timestamp"] == ev.wall.isoformat()
    assert p["descriptor"] == {"service": "USBSTOR", "bcd_usb": "0210", "interfaces": []}
    assert p["enumeration"]["interface_order"] == [8]


class FakeSession:
    def __init__(self):
        self.up, self.sent, self.headers = False, [], None

    def post(self, url, json, headers, timeout):
        if not self.up:
            raise requests.ConnectionError("down")
        self.sent.append(json)
        self.headers = headers
        return SimpleNamespace(status_code=200, json=lambda: {"risk_score": 5, "risk_level": "low"}, text="")


def test_sender_spools_while_server_is_down_and_delivers_in_order_later(tmp_path):
    spool = tmp_path / "spool.jsonl"
    session = FakeSession()
    s = Sender("http://srv", "key1", spool, session=session)
    assert s.send({"n": 1}) == [] and s.send({"n": 2}) == []
    assert [json.loads(line)["n"] for line in spool.read_text().splitlines()] == [1, 2]

    # A restarted agent picks the spool back up.
    s2 = Sender("http://srv", "key1", spool, session=session)
    session.up = True
    assert len(s2.flush()) == 2
    assert [p["n"] for p in session.sent] == [1, 2]
    assert session.headers == {"X-API-Key": "key1"}
    assert not spool.exists()


def test_describe_reads_interfaces_and_endpoints_from_pyusb_objects():
    ep_in = SimpleNamespace(bEndpointAddress=0x81, bmAttributes=0x02, wMaxPacketSize=512)
    ep_out = SimpleNamespace(bEndpointAddress=0x02, bmAttributes=0x02, wMaxPacketSize=512)

    class Intf(list):
        pass

    storage = Intf([ep_in, ep_out])
    storage.__dict__.update(bAlternateSetting=0, bInterfaceNumber=0, bInterfaceClass=8, bInterfaceSubClass=6, bInterfaceProtocol=80)
    alt = Intf([])
    alt.__dict__.update(bAlternateSetting=1, bInterfaceNumber=0, bInterfaceClass=8, bInterfaceSubClass=6, bInterfaceProtocol=80)

    class Dev(list):
        pass

    dev = Dev([[storage, alt]])
    dev.__dict__.update(bcdUSB=0x0210, bDeviceClass=0, bDeviceSubClass=0, bDeviceProtocol=0, bMaxPacketSize0=64, bNumConfigurations=1)

    d = describe(dev)
    assert d["bcd_usb"] == "0210"
    assert len(d["interfaces"]) == 1  # alternate settings are skipped
    assert d["interfaces"][0]["endpoints"] == [
        {"address": "0x81", "direction": "in", "transfer_type": "bulk", "max_packet_size": 512},
        {"address": "0x02", "direction": "out", "transfer_type": "bulk", "max_packet_size": 512},
    ]


def test_device_type_names():
    assert device_type_for([8]) == "USB Mass Storage Device"
    assert device_type_for([8, 3]) == "USB Composite Device"
    assert device_type_for([2, 10]) == "USB Communications Device"


def udev(props, device_type, sys_path):
    return SimpleNamespace(properties=props, device_type=device_type, sys_path=sys_path)


def test_linux_udev_events_are_parsed_and_hubs_skipped():
    d = backends._linux_event(udev({"PRODUCT": "781/5581/100", "TYPE": "0/0/0", "ID_SERIAL_SHORT": "4C53"}, "usb_device", "/sys/x/1-1"), "add")
    assert (d.kind, d.vendor_id, d.product_id, d.serial_number, d.key) == ("device", "0781", "5581", "4C53", "/sys/x/1-1")
    i = backends._linux_event(udev({"PRODUCT": "781/5581/100", "INTERFACE": "8/6/80"}, "usb_interface", "/sys/x/1-1/1-1:1.0"), "add")
    assert (i.kind, i.interface_class, i.key) == ("interface", 8, "/sys/x/1-1")
    assert backends._linux_event(udev({"PRODUCT": "1d6b/2/600", "TYPE": "9/0/1"}, "usb_device", "/sys/usb1"), "add") is None


def test_windows_pnp_entities_are_parsed():
    ent = SimpleNamespace(DeviceID="USB\\VID_0781&PID_5581\\4C530001", Description="USB Mass Storage Device", PNPClass="USB", Service="USBSTOR", CompatibleID=None)
    d = backends._windows_event(ent, "add")
    assert (d.kind, d.serial_number, d.extra["service"]) == ("device", "4C530001", "USBSTOR")
    no_serial = SimpleNamespace(**{**ent.__dict__, "DeviceID": "USB\\VID_0781&PID_5581\\5&2A&0&1"})
    assert backends._windows_event(no_serial, "add").serial_number is None
    iface = SimpleNamespace(DeviceID="USB\\VID_0781&PID_5581&MI_01\\6&1", Description="", PNPClass="HIDClass", Service="HidUsb",
                            CompatibleID=["USB\\Class_03&SubClass_01&Prot_01", "USB\\Class_03"])
    i = backends._windows_event(iface, "add")
    assert (i.kind, i.interface_class) == ("interface", 3)
