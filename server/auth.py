"""Investigator logins, roles and sessions.

Off unless AUTH_ENABLED=true (local development), like the API key. When on:
  - every read needs a logged-in user,
  - changing incidents or device trust needs the investigator or admin role,
  - retraining, user management and the audit log need admin.
Agents never log in; they keep using the API key on /events/ingest.

Passwords are stored as salted PBKDF2-SHA256 hashes. Session tokens are random, sent as
"Authorization: Bearer <token>", and stored only as their SHA-256, so a leaked database
does not contain usable tokens.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from server.config import settings
from server.database import get_db
from server.models import User, UserSession
from server.timeutil import as_utc

ROLES = ("investigator", "admin")
PBKDF2_ITERATIONS = 600_000
SESSION_LIFETIME = timedelta(hours=12)
MIN_PASSWORD_LENGTH = 8


def hash_password(password: str, iterations: int | None = None) -> str:
    iterations = iterations or PBKDF2_ITERATIONS
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()
    return hmac.compare_digest(candidate, digest)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_user(db: Session, username: str, password: str, role: str = "investigator") -> User:
    if role not in ROLES:
        raise ValueError(f"Role must be one of {', '.join(ROLES)}.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if db.query(User).filter(User.username == username).first():
        raise ValueError(f"User '{username}' already exists.")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()
    return user


# A dummy hash so a login for an unknown user costs the same time as one with a wrong password.
_DUMMY_HASH = hash_password(secrets.token_hex(8))


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username, User.active.is_(True)).first()
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return None
    return user if verify_password(password, user.password_hash) else None


def start_session(db: Session, user: User) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + SESSION_LIFETIME
    db.add(UserSession(token_hash=token_digest(token), user_id=user.id, expires_at=expires))
    db.commit()
    return token, expires


def end_session(db: Session, token: str) -> None:
    db.query(UserSession).filter(UserSession.token_hash == token_digest(token)).delete()
    db.commit()


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return None


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User | None:
    """The logged-in user, or None when logins are switched off."""
    if not settings.auth_enabled:
        return None
    token = _bearer(authorization)
    session = db.query(UserSession).filter(UserSession.token_hash == token_digest(token)).first() if token else None
    if session is None or as_utc(session.expires_at) <= datetime.now(timezone.utc) or not session.user.active:
        raise HTTPException(status_code=401, detail="Log in to continue.", headers={"WWW-Authenticate": "Bearer"})
    return session.user


def require_role(*roles: str):
    """Dependency: the user must hold one of these roles (admin may do anything)."""

    def check(user: User | None = Depends(current_user)) -> User | None:
        if user is not None and user.role != "admin" and user.role not in roles:
            raise HTTPException(status_code=403, detail=f"This needs the {' or '.join(roles)} role.")
        return user

    return check


def actor(user: User | None) -> str:
    return user.username if user is not None else "anonymous"
