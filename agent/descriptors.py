"""Read the real USB descriptor tree with pyusb (libusb).

Only cached descriptors are read (device + configuration descriptors), so no
driver has to be detached and no interface claimed. On Windows, libusb reads
them through the hub driver, which works for devices bound to any driver.
"""

USB_CLASS_NAMES = {
    1: "USB Audio Device",
    2: "USB Communications Device",
    3: "USB Input Device",
    7: "USB Printing Support",
    8: "USB Mass Storage Device",
    10: "USB Communications Device",
    11: "USB Smart Card Reader",
    14: "USB Video Device",
    224: "USB Wireless Controller",
    255: "USB Vendor-Specific Device",
}

TRANSFER_TYPES = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}


def device_type_for(interface_classes: list[int]) -> str | None:
    """A Windows-style device type name from the interface classes (used where the OS gives none)."""
    distinct = list(dict.fromkeys(interface_classes))
    if not distinct:
        return None
    if len(distinct) > 1 and not set(distinct) <= {2, 10}:
        return "USB Composite Device"
    return USB_CLASS_NAMES.get(distinct[0], f"USB Class {distinct[0]:02X} Device")


def describe(dev) -> dict:
    """Turn a pyusb Device into the descriptor dict the server fingerprints."""
    cfg = next(iter(dev))  # first configuration; iterating uses cached descriptors, no open needed
    interfaces = []
    for intf in cfg:
        if intf.bAlternateSetting != 0:
            continue
        interfaces.append(
            {
                "interface_number": intf.bInterfaceNumber,
                "interface_class": intf.bInterfaceClass,
                "interface_subclass": intf.bInterfaceSubClass,
                "interface_protocol": intf.bInterfaceProtocol,
                "endpoints": [
                    {
                        "address": f"0x{ep.bEndpointAddress:02X}",
                        "direction": "in" if ep.bEndpointAddress & 0x80 else "out",
                        "transfer_type": TRANSFER_TYPES[ep.bmAttributes & 0x3],
                        "max_packet_size": ep.wMaxPacketSize,
                    }
                    for ep in intf
                ],
            }
        )
    return {
        "bcd_usb": f"{dev.bcdUSB:04X}",
        "device_class": dev.bDeviceClass,
        "device_subclass": dev.bDeviceSubClass,
        "device_protocol": dev.bDeviceProtocol,
        "max_packet_size0": dev.bMaxPacketSize0,
        "num_configurations": dev.bNumConfigurations,
        "interfaces": interfaces,
    }


def _backend():
    try:
        import libusb_package  # bundles libusb binaries (needed on Windows)
        import usb.backend.libusb1

        return usb.backend.libusb1.get_backend(find_library=libusb_package.find_library)
    except ImportError:
        return None  # let pyusb find a system libusb


def _serial(dev) -> str | None:
    import usb.util

    try:
        return usb.util.get_string(dev, dev.iSerialNumber) if dev.iSerialNumber else None
    except Exception:  # reading strings needs the device open, which may be denied
        return None


def read_descriptor(vendor_id: str, product_id: str, serial: str | None = None) -> dict | None:
    """Descriptor tree for the attached device with this identity, or None if libusb is unavailable."""
    try:
        import usb.core
    except ImportError:
        return None
    try:
        devs = list(usb.core.find(find_all=True, idVendor=int(vendor_id, 16), idProduct=int(product_id, 16), backend=_backend()))
    except (usb.core.NoBackendError, ValueError):
        return None
    if len(devs) > 1 and serial:
        devs = [d for d in devs if _serial(d) == serial] or devs
    for dev in devs:
        try:
            return describe(dev)
        except Exception:
            continue
    return None
