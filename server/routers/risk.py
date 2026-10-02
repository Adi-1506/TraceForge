from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from server.database import get_db
from server.models import Device, Event, RiskScore
from server.schemas import RiskOut

router = APIRouter(prefix="/risk-scores", tags=["risk"])


@router.get("/{device_id}", response_model=list[RiskOut])
def device_risk_history(device_id: int, db: Session = Depends(get_db)):
    if db.get(Device, device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return (
        db.query(RiskScore)
        .join(Event, Event.id == RiskScore.event_id)
        .filter(RiskScore.device_id == device_id)
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .all()
    )
