"""Behavioural features per connect event, computed from the device's own history."""

import math
from datetime import timedelta

from sqlalchemy.orm import Session

from server.models import Event
from server.timeutil import as_utc

# Identity questions (unknown device, new machine, ...) belong to the rule engine;
# the model only sees behaviour, so the two layers do not double count.
FEATURE_NAMES = [
    "gap_log",  # log(1 + seconds since the device's previous connection)
    "hour_of_day",
    "events_last_hour",
    "machines_seen",
]

FEATURE_LABELS = {
    "gap_log": "inter-event timing",
    "hour_of_day": "time of day",
    "events_last_hour": "connection frequency (last hour)",
    "machines_seen": "number of distinct machines",
}

# A device with no history has no meaningful gap; use a neutral half-day.
NEUTRAL_GAP_SECONDS = 12 * 3600.0


def features_from_history(history: list[tuple], current: tuple) -> list[float]:
    """history: [(timestamp, machine_id)] of strictly earlier events, oldest first.
    current: (timestamp, machine_id) of the event being scored."""
    ts, machine_id = as_utc(current[0]), current[1]
    prior = [(as_utc(t), m) for t, m in history]
    gap = max((ts - prior[-1][0]).total_seconds(), 0.0) if prior else NEUTRAL_GAP_SECONDS
    last_hour = sum(1 for t, _ in prior if ts - t <= timedelta(hours=1))
    machines = {m for _, m in prior} | {machine_id}
    return [math.log1p(gap), float(ts.hour), float(last_hour), float(len(machines))]


def extract_event_features(db: Session, event: Event) -> list[float]:
    rows = (
        db.query(Event.timestamp, Event.machine_id)
        .filter(
            Event.device_id == event.device_id,
            Event.event_type == "connect",
            Event.id != event.id,
            Event.timestamp <= event.timestamp,
        )
        .order_by(Event.timestamp)
        .all()
    )
    return features_from_history([(r[0], r[1]) for r in rows], (event.timestamp, event.machine_id))


def build_training_matrix(db: Session) -> list[list[float]]:
    """One row per historical connect event, using only data available at that moment."""
    by_device: dict[int, list[tuple]] = {}
    for dev_id, ts, mach in (
        db.query(Event.device_id, Event.timestamp, Event.machine_id)
        .filter(Event.event_type == "connect")
        .order_by(Event.timestamp)
        .all()
    ):
        by_device.setdefault(dev_id, []).append((ts, mach))

    rows: list[list[float]] = []
    for events in by_device.values():
        for i, cur in enumerate(events):
            rows.append(features_from_history(events[:i], cur))
    return rows
