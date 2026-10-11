"""Identifiers of programmable USB boards commonly used for keystroke-injection (BadUSB) attacks.

These boards are legitimate hobby hardware, so the rule only fires when one presents a keyboard
(HID) interface: a dev board typing into a machine is what a payload looks like. VID/PID are
firmware strings and trivially changed (Hak5 tools clone the real keyboard's IDs by default), so
this is one weak signal; the structural fingerprint and the behavioural model cover spoofed IDs.

Sources:
  Digispark 16D0:0753, HID 16C0:05DF  https://homepages.uni-regensburg.de/~erc24492/TINY85_Arduino/TINY85_Arduino.html
  Teensy 16C0:0482                    https://blog.didierstevens.com/2011/07/14/quickpost-blocking-and-detecting-a-teensy-dropper/
  Flipper Zero 0483:5740              https://appstream.debian.org/sid/main/metainfo/qflipper.html
  Arduino Leonardo / Micro 2341:8036, 2341:8037 (Arduino LLC USB IDs, ATmega32U4 boards with native USB HID)
"""

ATTACK_BOARDS: dict[tuple[str, str], str] = {
    ("16D0", "0753"): "Digispark (ATtiny85)",
    ("16C0", "05DF"): "Digispark HID (V-USB)",
    ("16C0", "0482"): "Teensy (keyboard/mouse/joystick)",
    ("0483", "5740"): "Flipper Zero",
    ("2341", "8036"): "Arduino Leonardo",
    ("2341", "8037"): "Arduino Micro",
}

HID_CLASS = 3


def match(vendor_id: str, product_id: str) -> str | None:
    return ATTACK_BOARDS.get((vendor_id.upper(), product_id.upper()))


def presents_keyboard(device_type: str | None, descriptor: dict | None) -> bool:
    classes = (descriptor or {}).get("interface_classes") or []
    return HID_CLASS in classes or "input" in (device_type or "").lower() or "keyboard" in (device_type or "").lower()
