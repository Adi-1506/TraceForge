"""Attack graph and incident replay: which devices touched which machines, in time order.

GET /graph?days=7         every connection in the last N days of activity (the fleet view)
GET /graph?incident_id=3  every event in that incident's cross-machine case, for step-by-step replay
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from server.auth import current_user
from server.detection.mitre import techniques_for_all
from server.models import Device, Event, Incident, IncidentEvent
from server.schemas import GraphOut
from server.database import get_db
from server.scoring.trust import compute_trust
from server.services.queries import case_members
from server.timeutil import as_utc

router = APIRouter(prefix="/graph", tags=["graph"], dependencies=[Depends(current_user)])
MAX_EVENTS = 2000


@router.get("", response_model=GraphOut)
def graph(
    days: float = Query(default=7, gt=0, le=365),
    incident_id: int | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(Event).options(joinedload(Event.machine), joinedload(Event.device), joinedload(Event.anomalies), joinedload(Event.risk_score))
    title = None
    if incident_id is not None:
        incident = db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        members = case_members(db, incident) or [incident]
        ids = [m.id for m in members]
        q = q.join(IncidentEvent, IncidentEvent.event_id == Event.id).filter(IncidentEvent.incident_id.in_(ids))
        title = f"Case #{incident.case_id}" if incident.case_id else f"Incident #{incident.id}"
    else:
        latest = db.query(func.max(Event.timestamp)).scalar()
        if latest is not None:
            q = q.filter(Event.timestamp >= as_utc(latest) - timedelta(days=days))

    events = q.order_by(Event.timestamp, Event.id).limit(MAX_EVENTS).all()
    in_incident = dict(
        db.query(IncidentEvent.event_id, IncidentEvent.incident_id).filter(IncidentEvent.event_id.in_([e.id for e in events])).all()
    ) if events else {}

    machines: dict[int, dict] = {}
    devices: dict[int, dict] = {}
    frames = []
    for e in events:
        score = e.risk_score.score if e.risk_score else 0.0
        level = e.risk_score.level if e.risk_score else "low"
        m = machines.setdefault(e.machine_id, {"id": e.machine_id, "hostname": e.machine.hostname, "max_risk": 0.0})
        m["max_risk"] = max(m["max_risk"], score)
        if e.device_id not in devices:
            d: Device = e.device
            trust = compute_trust(db, d)
            devices[e.device_id] = {
                "id": d.id,
                "label": f"{d.vendor_id}:{d.product_id} {d.device_type or ''}".strip(),
                "serial_number": d.serial_number,
                "trust_level": trust.level,
                "max_risk": 0.0,
            }
        devices[e.device_id]["max_risk"] = max(devices[e.device_id]["max_risk"], score)
        names = [a.name for a in e.anomalies]
        frames.append(
            {
                "event_id": e.id,
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "device_id": e.device_id,
                "machine_id": e.machine_id,
                "risk_score": score,
                "risk_level": level,
                "findings": names,
                "mitre": [t["id"] for t in techniques_for_all(names)],
                "incident_id": in_incident.get(e.id),
            }
        )

    return GraphOut(
        title=title,
        start=frames[0]["timestamp"] if frames else None,
        end=frames[-1]["timestamp"] if frames else None,
        machines=sorted(machines.values(), key=lambda m: m["hostname"]),
        devices=sorted(devices.values(), key=lambda d: -d["max_risk"]),
        events=frames,
        truncated=len(events) == MAX_EVENTS,
    )
