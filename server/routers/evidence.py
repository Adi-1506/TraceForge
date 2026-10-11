from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from server import integrity
from server.database import get_db
from server.schemas import IntegrityOut

router = APIRouter(prefix="/integrity", tags=["evidence"])


@router.get("/verify", response_model=IntegrityOut)
def verify(db: Session = Depends(get_db)):
    """Recompute the evidence hash chain and report whether any stored event was altered."""
    return integrity.verify(db)
