"""Structural USB descriptor fingerprint.

The agent reports the raw descriptor tree (device class, USB version, every
interface and its endpoints). Identifier fields (VID, PID, serial) are left out
on purpose: they are firmware strings an attacker can set freely, whereas the
interface/endpoint layout follows from what the hardware actually does. Two
genuine units of the same model share a fingerprint; a BadUSB clone that copies
the identity but adds a keyboard interface does not.
"""

import hashlib
import json

DEVICE_FIELDS = ("bcd_usb", "device_class", "device_subclass", "device_protocol", "max_packet_size0", "num_configurations")
INTERFACE_FIELDS = ("interface_class", "interface_subclass", "interface_protocol")
ENDPOINT_FIELDS = ("direction", "transfer_type", "max_packet_size")


def structure(descriptor: dict | None) -> dict | None:
    """The identity-free part of a descriptor, or None if the agent sent no interface tree."""
    if not descriptor or not descriptor.get("interfaces"):
        return None
    return {
        **{f: descriptor.get(f) for f in DEVICE_FIELDS},
        "interfaces": [
            {
                **{f: i.get(f) for f in INTERFACE_FIELDS},
                "endpoints": [{f: e.get(f) for f in ENDPOINT_FIELDS} for e in i.get("endpoints", [])],
            }
            for i in descriptor["interfaces"]
        ],
    }


def fingerprint(descriptor: dict | None) -> str | None:
    s = structure(descriptor)
    if s is None:
        return None
    return hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()[:16]


def enrich(descriptor: dict | None) -> dict | None:
    """Add the fingerprint and the summary fields the rules compare (interface_classes, endpoint_count)."""
    if not descriptor:
        return descriptor
    out = dict(descriptor)
    fp = fingerprint(descriptor)
    if fp is not None:
        out["fingerprint"] = fp
        out["interface_classes"] = [i.get("interface_class") for i in descriptor["interfaces"]]
        out["endpoint_count"] = sum(len(i.get("endpoints", [])) for i in descriptor["interfaces"])
    return out
