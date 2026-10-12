import base64
import binascii
from dataclasses import asdict
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from server import audit
from server.auth import actor, current_user, require_role
from server.config import settings
from server.database import get_db
from server.forensics import importer
from server.models import EvidenceImport, User
from server.schemas import UTCDatetime

router = APIRouter(prefix="/evidence", tags=["forensics"], dependencies=[Depends(current_user)])
MAX_BYTES = 50 * 1024 * 1024


class ImportIn(BaseModel):
    filename: str = Field(max_length=255)
    content_b64: str  # the file's exact bytes, base64-encoded (registry exports are UTF-16)
    kind: str = "auto"  # auto | setupapi | registry | linux
    machine_hostname: str | None = Field(default=None, max_length=255)  # required unless the log names it (Linux)
    timezone: str | None = None  # the seized machine's zone; setupapi and syslog times are local
    year: int = Field(default=2026, ge=2000, le=2100)  # syslog lines carry no year
    registry_b64: str | None = None  # optional registry export, to fill in device types
    dry_run: bool = False  # parse and preview only


class ImportRecordOut(BaseModel):
    id: int
    filename: str
    sha256: str
    kind: str
    machine_hostname: str | None
    imported_by: str
    imported_at: UTCDatetime
    events_imported: int

    model_config = {"from_attributes": True}


def _bytes(b64: str) -> bytes:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=422, detail="File content is not valid base64.")
    if len(raw) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File is larger than 50 MB.")
    return raw


@router.post("/import")
def import_evidence(body: ImportIn, db: Session = Depends(get_db), user: User | None = Depends(require_role("investigator"))):
    tz = body.timezone or settings.timezone
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise HTTPException(status_code=422, detail=f"Unknown timezone '{tz}'.")
    try:
        outcome = importer.run(
            db,
            _bytes(body.content_b64),
            body.filename,
            body.machine_hostname,
            kind=body.kind,
            tz=tz,
            year=body.year,
            dry_run=body.dry_run,
            imported_by=actor(user),
            registry_raw=_bytes(body.registry_b64) if body.registry_b64 else None,
        )
    except importer.ImportRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not body.dry_run:
        audit.record(
            db, actor(user), "evidence.import", "evidence_import", outcome.import_id,
            filename=body.filename, sha256=outcome.sha256, kind=outcome.kind, events=outcome.events_imported,
        )
        db.commit()
    return asdict(outcome)


@router.get("/imports", response_model=list[ImportRecordOut])
def list_imports(db: Session = Depends(get_db)):
    return db.query(EvidenceImport).order_by(EvidenceImport.id.desc()).all()
