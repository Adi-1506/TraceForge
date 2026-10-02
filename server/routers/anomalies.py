from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from server.database import get_db
from server.models import Anomaly, Event
from server.schemas import AnomalyOut

router = APIRouter(prefix="/anomalies", tags=["anomalies"])


@router.get("", response_model=list[AnomalyOut])
def list_anomalies(device_id: int | None = None, source: str | None = None, limit: int = 200, db: Session = Depends(get_db)):
    q = db.query(Anomaly).join(Event, Event.id == Anomaly.event_id)
    if device_id is not None:
        q = q.filter(Event.device_id == device_id)
    if source is not None:
        q = q.filter(Anomaly.source == source)
    return q.order_by(Event.timestamp.desc(), Anomaly.id.desc()).limit(limit).all()
