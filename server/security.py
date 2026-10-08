"""Shared-secret check for endpoints that change state (agent ingest, model retraining)."""

import hmac

from fastapi import Header, HTTPException

from server.config import settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """No-op when API_KEY is unset (local development); otherwise the X-API-Key header must match."""
    if not settings.api_key:
        return
    if x_api_key is None or not hmac.compare_digest(x_api_key.encode(), settings.api_key.encode()):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")
