from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from server.auth import require_role
from server.database import get_db
from server.models import AuditEntry
from server.schemas import AuditOut

router = APIRouter(prefix="/audit", tags=["audit"], dependencies=[Depends(require_role("admin"))])


@router.get("", response_model=list[AuditOut])
def list_audit(
    actor: str | None = None,
    action: str | None = None,
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(get_db),
):
    q = db.query(AuditEntry)
    if actor:
        q = q.filter(AuditEntry.actor == actor)
    if action:
        q = q.filter(AuditEntry.action == action)
    return q.order_by(AuditEntry.id.desc()).limit(limit).all()
