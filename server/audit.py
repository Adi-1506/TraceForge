"""Audit log: who did what, and when. An investigation tool has to account for its investigators."""

from sqlalchemy.orm import Session

from server.models import AuditEntry


def record(db: Session, actor: str, action: str, target_type: str | None = None, target_id: int | None = None, **detail) -> None:
    """Add an entry; it is committed with the caller's own change, so the two cannot disagree."""
    db.add(AuditEntry(actor=actor, action=action, target_type=target_type, target_id=target_id, detail=detail or None))
