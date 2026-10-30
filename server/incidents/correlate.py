"""Group related suspicious events into incidents, and incidents into cross-machine cases.

0. What opens an incident: risk at NIST SP 800-30 Rev. 1 level High or above (Table I-3: a severe
   or catastrophic adverse effect), either
   - from one event, or
   - aggregated over one device's findings within RISK_WINDOW (risk aggregation, Chapter 2, p. 13:
     several lower risks that materialise together can make a higher one), so Low and Moderate
     findings that are harmless alone still escalate together.
1. Per machine: an event joins an active incident on its machine that ended within WINDOW when
   either it involves a device already in the incident, or it is itself suspicious (two devices,
   one compromise). Ordinary low-risk events from other devices are never dragged in.
2. Across machines: incidents on different machines that involve the same device, or a
   device presenting the same serial number (a clone), within CASE_WINDOW share a case_id.
   A device that already has an active incident and then shows up on another machine opens
   an incident there too, even if that connection alone scores low: that is the spread.
"""

from datetime import timedelta

from sqlalchemy.orm import Session

from sqlalchemy import func

from server.models import Anomaly, Device, Event, Incident, IncidentEvent, RiskScore
from server.scoring import nist
from server.timeutil import as_utc

INCIDENT_RISK = float(nist.SCALE["high"][0])  # NIST "High": one event, or a device's findings in RISK_WINDOW
RISK_WINDOW = timedelta(hours=24)
WINDOW = timedelta(minutes=30)  # events within this gap of the last one join the incident
CASE_WINDOW = timedelta(hours=24)  # incidents on other machines this close in time join the case
ACTIVE = ("open", "investigating")  # resolved incidents stop collecting events


def related_device_ids(db: Session, device_id: int) -> set[int]:
    """The device itself plus any device presenting the same serial number."""
    device = db.get(Device, device_id)
    ids = {device_id}
    if device is not None and device.serial_number:
        ids |= {i for (i,) in db.query(Device.id).filter(Device.serial_number == device.serial_number).all()}
    return ids


def cross_machine_incidents(db: Session, event: Event, ts) -> list[Incident]:
    return [
        i
        for i in db.query(Incident)
        .filter(
            Incident.device_id.in_(related_device_ids(db, event.device_id)),
            Incident.machine_id != event.machine_id,
            Incident.status.in_(ACTIVE),
        )
        .order_by(Incident.start_time)
        .all()
        if as_utc(i.start_time) - CASE_WINDOW <= ts <= as_utc(i.end_time) + CASE_WINDOW
    ]


def link_case(incident: Incident, others: list[Incident]) -> None:
    case_id = min(o.case_id or o.id for o in others)
    hosts = sorted({o.machine.hostname for o in others})
    same_device = any(o.device_id == incident.device_id for o in others)
    incident.case_id = case_id
    incident.case_reason = (
        f"Same device also in incident(s) on {', '.join(hosts)} within {CASE_WINDOW.total_seconds() / 3600:.0f}h."
        if same_device
        else f"Device shares its serial number with a device in incident(s) on {', '.join(hosts)}."
    )
    for o in others:
        if o.case_id is None:
            o.case_id = case_id
            o.case_reason = o.case_reason or "First incident of a cross-machine case."


def _members(db: Session, incident_id: int) -> set[int]:
    rows = (
        db.query(Event.device_id)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .filter(IncidentEvent.incident_id == incident_id)
        .distinct()
        .all()
    )
    return {r[0] for r in rows}


def _find_incident(db: Session, event: Event, suspicious: bool) -> Incident | None:
    ts = as_utc(event.timestamp)
    candidates = (
        db.query(Incident)
        .filter(Incident.machine_id == event.machine_id, Incident.status.in_(ACTIVE))
        .order_by(Incident.end_time.desc())
        .all()
    )
    for inc in candidates:
        if ts - as_utc(inc.end_time) > WINDOW or ts < as_utc(inc.start_time) - WINDOW:
            continue
        if suspicious or event.device_id in _members(db, inc.id):
            return inc
    return None


def _include_preceding_connect(db: Session, incident: Incident, event: Event, ts) -> None:
    """A typing report or a disconnect (a large copy) that opens an incident is about the
    connection it followed: link that too."""
    connect = (
        db.query(Event)
        .filter(
            Event.device_id == event.device_id,
            Event.machine_id == event.machine_id,
            Event.event_type == "connect",
            Event.id != event.id,
        )
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .first()
    )
    # A disconnect closes its connection however long the device was attached; a typing report
    # only belongs to a connection it closely followed.
    if connect is not None and (event.event_type == "disconnect" or ts - as_utc(connect.timestamp) <= WINDOW):
        db.add(IncidentEvent(incident_id=incident.id, event_id=connect.id))
        incident.start_time = min(as_utc(incident.start_time), as_utc(connect.timestamp))


def accumulated_risk(db: Session, event: Event, ts) -> float:
    """Risk of every finding about this event's device in the RISK_WINDOW up to it, added up.
    Only findings count: a disconnect's inherited score is the same risk, not new risk."""
    own = db.query(func.count(Anomaly.id)).filter(Anomaly.event_id == event.id).scalar()
    if not own:
        return 0.0
    total = (
        db.query(func.coalesce(func.sum(Anomaly.weight), 0.0))
        .join(Event, Event.id == Anomaly.event_id)
        .filter(Event.device_id == event.device_id, Event.timestamp > ts - RISK_WINDOW, Event.timestamp <= ts)
        .scalar()
    )
    return float(total)


def is_suspicious(db: Session, event: Event, risk: RiskScore, ts) -> bool:
    return risk.score >= INCIDENT_RISK or accumulated_risk(db, event, ts) >= INCIDENT_RISK


def correlate(db: Session, event: Event, risk: RiskScore) -> Incident | None:
    ts = as_utc(event.timestamp)
    suspicious = is_suspicious(db, event, risk, ts)
    incident = _find_incident(db, event, suspicious)

    if incident is None:
        others = cross_machine_incidents(db, event, ts) if event.event_type == "connect" else []
        if not suspicious and not others:
            return None
        incident = Incident(
            device_id=event.device_id,
            machine_id=event.machine_id,
            start_time=ts,
            end_time=ts,
            max_score=risk.score,
        )
        db.add(incident)
        db.flush()
        if others:
            link_case(incident, others)
        if event.event_type in ("typing", "disconnect"):
            _include_preceding_connect(db, incident, event, ts)

    db.add(IncidentEvent(incident_id=incident.id, event_id=event.id))
    incident.start_time = min(as_utc(incident.start_time), ts)
    incident.end_time = max(as_utc(incident.end_time), ts)
    incident.max_score = max(incident.max_score, risk.score)
    return incident
