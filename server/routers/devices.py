from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from server.database import get_db
from server.models import Device
from server.schemas import DeviceDetailOut, DeviceOut, TimelineEntry
from server.services.queries import device_detail, device_events, device_summary, timeline_entries

router = APIRouter(prefix="/devices", tags=["devices"])


def _get(db: Session, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    summaries = [device_summary(db, d) for d in db.query(Device).all()]
    return sorted(summaries, key=lambda d: (d.risk_score or 0, d.last_seen or d.first_seen), reverse=True)


@router.get("/{device_id}", response_model=DeviceDetailOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    return device_detail(db, _get(db, device_id))


@router.get("/{device_id}/timeline", response_model=list[TimelineEntry])
def get_timeline(device_id: int, db: Session = Depends(get_db)):
    _get(db, device_id)
    return timeline_entries(device_events(db, device_id))
