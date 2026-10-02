"""Group related suspicious events (same device, same machine, close in time) into incidents."""

from datetime import timedelta

from sqlalchemy.orm import Session

from server.models import Event, Incident, IncidentEvent, RiskScore
from server.timeutil import as_utc

INCIDENT_THRESHOLD = 40.0  # a connection scoring this high opens an incident
WINDOW = timedelta(minutes=30)  # events within this gap of the last one join the incident


def correlate(db: Session, event: Event, risk: RiskScore) -> Incident | None:
    ts = as_utc(event.timestamp)
    candidates = (
        db.query(Incident)
        .filter(Incident.device_id == event.device_id, Incident.machine_id == event.machine_id, Incident.status == "open")
        .order_by(Incident.end_time.desc())
        .all()
    )
    incident = next((i for i in candidates if ts - as_utc(i.end_time) <= WINDOW and ts >= as_utc(i.start_time) - WINDOW), None)

    if incident is None:
        if risk.score < INCIDENT_THRESHOLD:
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

    db.add(IncidentEvent(incident_id=incident.id, event_id=event.id))
    incident.start_time = min(as_utc(incident.start_time), ts)
    incident.end_time = max(as_utc(incident.end_time), ts)
    incident.max_score = max(incident.max_score, risk.score)
    return incident
