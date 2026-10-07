from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from server.database import get_db
from server.schemas import EventIngest, IngestResult
from server.security import require_api_key
from server.services.ingest import process_event

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest", response_model=IngestResult, dependencies=[Depends(require_api_key)])
def ingest_event(payload: EventIngest, db: Session = Depends(get_db)):
    out = process_event(db, payload)
    return IngestResult(
        event=out.event,
        is_new_device=out.is_new_device,
        risk_score=out.risk.score,
        risk_level=out.risk.level,
        incident_id=out.incident.id if out.incident else None,
    )
