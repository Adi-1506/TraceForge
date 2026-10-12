"""Shared-secret check for machine clients (agents, scripts) on endpoints that change state."""

import hashlib
import hmac

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from server.auth import current_user
from server.config import settings
from server.database import get_db
from server.models import User


def api_key_configured() -> bool:
    return bool(settings.api_key_hash or settings.api_key)


def api_key_valid(x_api_key: str | None) -> bool:
    if x_api_key is None:
        return False
    if settings.api_key_hash:  # only the key's SHA-256 is stored on the server
        return hmac.compare_digest(hashlib.sha256(x_api_key.encode()).hexdigest(), settings.api_key_hash.strip().lower())
    return hmac.compare_digest(x_api_key.encode(), settings.api_key.encode())


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """No-op when no key is configured (local development); otherwise X-API-Key must match."""
    if api_key_configured() and not api_key_valid(x_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")


def admin_or_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> str:
    """For admin actions a script may also run (retraining): a valid API key, or an admin login.
    Returns who did it, for the audit log."""
    if api_key_configured() and api_key_valid(x_api_key):
        return "api-key"
    if settings.auth_enabled:
        user: User | None = current_user(authorization, db)
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="This needs the admin role.")
        return user.username
    if api_key_configured():
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")
    return "anonymous"

