"""Tamper-evident evidence log: every event is hash-chained to the one before it.

record_hash = SHA-256(prev_hash + canonical JSON of the event's evidence fields). Changing,
deleting or reordering any stored event breaks every hash after it, so verify() can say
whether the evidence is intact and where it was altered. The newest hash (the chain head)
summarises the whole log: noting it down (it is printed in every forensic report) means even
removing the newest events can be detected later by comparing heads.
"""

import hashlib
import json
import threading

from sqlalchemy.orm import Session

from server.models import Event
from server.timeutil import as_utc

GENESIS = "0" * 64  # prev_hash of the first event

# Chaining reads the current head and writes the next link; one writer at a time keeps the chain linear.
chain_lock = threading.Lock()


def record_hash(event: Event, prev_hash: str) -> str:
    evidence = {
        "id": event.id,
        "device_id": event.device_id,
        "machine_id": event.machine_id,
        "event_type": event.event_type,
        "timestamp": as_utc(event.timestamp).isoformat(),
        "raw_payload": event.raw_payload,
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def head(db: Session) -> str:
    last = db.query(Event.record_hash).filter(Event.record_hash.isnot(None)).order_by(Event.id.desc()).first()
    return last[0] if last else GENESIS


def link(db: Session, event: Event) -> None:
    """Chain a freshly flushed event onto the log (call under chain_lock)."""
    event.prev_hash = head(db)
    event.record_hash = record_hash(event, event.prev_hash)


def backfill(db: Session) -> int:
    """Chain events stored before the evidence log existed, oldest first."""
    pending = db.query(Event).filter(Event.record_hash.is_(None)).order_by(Event.id).all()
    if not pending:
        return 0
    with chain_lock:
        prev = head(db)
        for e in pending:
            e.prev_hash = prev
            e.record_hash = prev = record_hash(e, prev)
        db.commit()
    return len(pending)


def verify(db: Session) -> dict:
    prev = GENESIS
    checked = 0
    for e in db.query(Event).order_by(Event.id).yield_per(500):
        if e.record_hash is None:
            return _broken(checked, prev, e.id, "Event was never added to the evidence chain.")
        if e.prev_hash != prev:
            return _broken(checked, prev, e.id, "Chain link broken: an earlier event was deleted, inserted or reordered.")
        if record_hash(e, prev) != e.record_hash:
            return _broken(checked, prev, e.id, "Event contents were modified after they were recorded.")
        prev = e.record_hash
        checked += 1
    return {"intact": True, "events_checked": checked, "chain_head": prev, "first_broken_event_id": None, "problem": None}


def _broken(checked: int, head_hash: str, event_id: int, problem: str) -> dict:
    return {"intact": False, "events_checked": checked, "chain_head": head_hash, "first_broken_event_id": event_id, "problem": problem}
