"""Synthetic multi-machine dataset for development and demos.

    python -m server.seed_synthetic_data --reset

1. Six weeks of normal USB usage across five machines (rules only).
2. Trains the Isolation Forest on that baseline.
3. Replays planted attack scenarios through the live pipeline.
"""

import argparse
import random
from datetime import datetime, timedelta, timezone

from server.database import Base, SessionLocal, engine
from server.detection import ml_model
from server.schemas import EventIngest
from server.services.ingest import process_event

HID = {"pnp_class": "HIDClass", "service": "HidUsb", "interface_classes": [3], "endpoint_count": 2}
MASS = {"pnp_class": "USB", "service": "USBSTOR", "interface_classes": [8], "endpoint_count": 2}
VIDEO = {"pnp_class": "Camera", "service": "usbvideo", "interface_classes": [14, 14], "endpoint_count": 3}
PRINT = {"pnp_class": "USB", "service": "usbprint", "interface_classes": [7], "endpoint_count": 2}
MODEM = {"pnp_class": "USB", "service": "usbccgp", "interface_classes": [2, 10], "endpoint_count": 5}

INPUT, STORAGE = "USB Input Device", "USB Mass Storage Device"

# name -> (vid, pid, serial, type, descriptor)
D = {
    "mouse": ("046D", "C52B", "A1B2C3D4E5", INPUT, HID),
    "keyboard": ("413C", "2113", "KB7781002", INPUT, HID),
    "sandisk1": ("0781", "5581", "4C530001230516", STORAGE, MASS),
    "sandisk2": ("0781", "5581", "4C530001220516", STORAGE, MASS),
    "kingston": ("0951", "1666", "0019E06B8A0A1E91", STORAGE, MASS),
    "webcam": ("046D", "0825", "7F3E21A9", "USB Video Device", VIDEO),
    "yubikey": ("1050", "0407", "11223344", INPUT, HID),
    "printer": ("03F0", "0C17", "CN8BS2P0K5", "USB Printing Support", PRINT),
    "phone": ("04E8", "6860", "R58M30ABCDE", "SAMSUNG Mobile USB Modem", MODEM),
}

# device -> ([machines, mostly the first], sessions per workday, probability of a workday)
BASELINE = {
    "mouse": (["LAB-PC-01"], 1, 0.95),
    "keyboard": (["LAB-PC-02"], 1, 0.95),
    "sandisk1": (["LAB-PC-01", "LAB-PC-03"], 1, 0.3),
    "sandisk2": (["LAB-PC-03"], 1, 0.25),
    "kingston": (["ADMIN-LAPTOP", "LAB-PC-04"], 1, 0.35),
    "webcam": (["LAB-PC-03"], 1, 0.6),
    "yubikey": (["ADMIN-LAPTOP"], 3, 0.9),
    "printer": (["LAB-PC-04"], 1, 0.4),
    "phone": (["ADMIN-LAPTOP"], 1, 0.2),
}


def ev(machine, dev, kind, ts, serial="keep", dtype="keep", descriptor="keep", vid=None, pid=None):
    v, p, s, t, d = D[dev] if isinstance(dev, str) else dev
    return EventIngest(
        machine_hostname=machine,
        vendor_id=vid or v,
        product_id=pid or p,
        serial_number=s if serial == "keep" else serial,
        device_type=t if dtype == "keep" else dtype,
        event_type=kind,
        timestamp=ts,
        descriptor=d if descriptor == "keep" else descriptor,
    )


def baseline_events(rng: random.Random, today: datetime) -> list[EventIngest]:
    out = []
    for day in range(-42, -1):
        date = today + timedelta(days=day)
        if date.weekday() >= 5:
            continue
        for name, (machines, sessions, prob) in BASELINE.items():
            if rng.random() > prob:
                continue
            for _ in range(sessions):
                machine = machines[0] if rng.random() < 0.8 else rng.choice(machines)
                start = date.replace(hour=rng.randint(9, 16), minute=rng.randint(0, 59), second=rng.randint(0, 59))
                end = start + timedelta(minutes=rng.randint(10, 150))
                out += [ev(machine, name, "connect", start), ev(machine, name, "disconnect", end)]
    return sorted(out, key=lambda e: e.timestamp)


def attack_events(today: datetime) -> list[tuple[str, list[EventIngest]]]:
    y = today - timedelta(days=1)
    at = lambda h, m, s=0: y.replace(hour=h, minute=m, second=s)
    ghost = ("1D6B", "0104", "11223344", INPUT, HID)  # clone of the YubiKey's serial on different hardware

    burst = [ev("LAB-PC-01", "mouse", "connect", at(22, 40, 0) + timedelta(seconds=20 * i)) for i in range(9)]
    return [
        (
            "A. Type-switching device (BadUSB): a Kingston flash drive re-appears as a keyboard at 03:12 on a new machine",
            [
                ev("LAB-PC-02", "kingston", "connect", at(3, 12), dtype=INPUT, descriptor=HID),
                ev("LAB-PC-02", "kingston", "disconnect", at(3, 12, 40), dtype=INPUT, descriptor=HID),
            ],
        ),
        (
            "B. Serial cloning: unknown hardware presents the YubiKey's serial number",
            [ev("LAB-PC-01", ghost, "connect", at(14, 20)), ev("LAB-PC-01", ghost, "disconnect", at(14, 31))],
        ),
        (
            "C. Behavioural drift (no rule fires): the known mouse reconnects 9 times in 3 minutes at night",
            burst + [ev("LAB-PC-01", "mouse", "disconnect", at(22, 43, 30))],
        ),
        (
            "D. Flash drive of a known model with no serial number",
            [ev("LAB-PC-04", ("0781", "5581", None, STORAGE, MASS), "connect", at(16, 45))],
        ),
        (
            "E. Plain unknown device, otherwise consistent",
            [
                ev("ADMIN-LAPTOP", ("045E", "07A5", "ZZ99FF31", INPUT, HID), "connect", at(11, 30)),
                ev("ADMIN-LAPTOP", ("045E", "07A5", "ZZ99FF31", INPUT, HID), "disconnect", at(12, 5)),
            ],
        ),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="drop and recreate all tables first")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    if args.reset:
        Base.metadata.drop_all(bind=engine)
        ml_model.MODEL_PATH.unlink(missing_ok=True)
        ml_model._bundle = None
    Base.metadata.create_all(bind=engine)

    rng = random.Random(args.seed)
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    with SessionLocal() as db:
        base = baseline_events(rng, today)
        for e in base:
            process_event(db, e)
        print(f"baseline: {len(base)} events")

        print("ML:", ml_model.train(db))

        for title, events in attack_events(today):
            print(f"\n{title}")
            for e in events:
                out = process_event(db, e)
                if e.event_type == "connect":
                    names = [a.name for a in out.event.anomalies]
                    print(f"  {e.timestamp:%H:%M:%S} score={out.risk.score:>5} {out.risk.level:<8} incident={out.incident.id if out.incident else '-'} {names}")


if __name__ == "__main__":
    main()
