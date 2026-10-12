import hashlib

import pytest

from server import auth
from server.config import settings
from server.database import SessionLocal
from tests.conftest import make_event


@pytest.fixture()
def secured(client, monkeypatch):
    """Logins on, fast password hashing, one user of each role."""
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(auth, "PBKDF2_ITERATIONS", 1000)
    with SessionLocal() as db:
        auth.create_user(db, "admin", "admin-pass-1", "admin")
        auth.create_user(db, "ivy", "investigator-1", "investigator")
    return client


def login(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_logins_off_keeps_everything_open(client):
    assert client.get("/auth/config").json() == {"auth_enabled": False}
    assert client.get("/devices").status_code == 200
    assert client.get("/auth/me").json()["username"] == "anonymous"


def test_reads_need_a_login_when_enabled(secured):
    assert secured.get("/devices").status_code == 401
    assert secured.get("/stats").status_code == 401
    assert secured.get("/integrity/verify").status_code == 401
    headers = login(secured, "ivy", "investigator-1")
    assert secured.get("/devices", headers=headers).status_code == 200
    assert secured.get("/auth/me", headers=headers).json() == {"username": "ivy", "role": "investigator"}


def test_wrong_password_is_refused_and_audited(secured):
    r = secured.post("/auth/login", json={"username": "ivy", "password": "nope-nope"})
    assert r.status_code == 401 and r.json()["detail"] == "Wrong username or password."
    unknown = secured.post("/auth/login", json={"username": "ghost", "password": "nope-nope"})
    assert unknown.json()["detail"] == r.json()["detail"]  # does not reveal which usernames exist
    admin = login(secured, "admin", "admin-pass-1")
    actions = [(e["actor"], e["action"]) for e in secured.get("/audit", headers=admin).json()]
    assert ("ivy", "auth.login_failed") in actions and ("ghost", "auth.login_failed") in actions


def test_passwords_and_tokens_are_never_stored_in_clear(secured):
    from server.models import User, UserSession

    token = login(secured, "ivy", "investigator-1")["Authorization"][7:]
    with SessionLocal() as db:
        stored = db.query(User).filter(User.username == "ivy").one().password_hash
        assert stored.startswith("pbkdf2_sha256$") and "investigator-1" not in stored
        assert db.query(UserSession).one().token_hash == hashlib.sha256(token.encode()).hexdigest()


def test_roles_decide_who_may_change_what(secured):
    secured.post("/events/ingest", json=make_event())
    secured.post("/events/ingest", json=make_event(dtype="USB Input Device", ts="2026-09-02T03:00:00Z"))
    ivy, admin = login(secured, "ivy", "investigator-1"), login(secured, "admin", "admin-pass-1")

    assert secured.patch("/incidents/1", json={"status": "investigating"}).status_code == 401
    assert secured.patch("/incidents/1", json={"status": "investigating", "note": "on it"}, headers=ivy).status_code == 200
    assert secured.put("/devices/1/trust", json={"status": "blocklisted"}, headers=ivy).status_code == 200

    assert secured.get("/audit", headers=ivy).status_code == 403  # admin only
    assert secured.post("/auth/users", json={"username": "eve", "password": "long-enough"}, headers=ivy).status_code == 403
    assert secured.post("/ml/train", headers=ivy).status_code == 403

    entries = secured.get("/audit", headers=admin).json()
    update = next(e for e in entries if e["action"] == "incident.update")
    assert update["actor"] == "ivy" and update["detail"]["previous_status"] == "open" and update["detail"]["note"] == "on it"
    trust = next(e for e in entries if e["action"] == "device.trust")
    assert trust["actor"] == "ivy" and trust["detail"]["status"] == "blocklisted"


def test_admin_creates_users_and_logout_ends_the_session(secured):
    admin = login(secured, "admin", "admin-pass-1")
    assert secured.post("/auth/users", json={"username": "sam", "password": "short"}, headers=admin).status_code == 422
    r = secured.post("/auth/users", json={"username": "sam", "password": "long-enough", "role": "investigator"}, headers=admin)
    assert r.status_code == 201
    sam = login(secured, "sam", "long-enough")
    assert secured.post("/auth/logout", headers=sam).status_code == 204
    assert secured.get("/devices", headers=sam).status_code == 401


def test_expired_session_is_refused(secured):
    from datetime import datetime, timedelta, timezone

    from server.models import UserSession

    headers = login(secured, "ivy", "investigator-1")
    with SessionLocal() as db:
        db.query(UserSession).update({UserSession.expires_at: datetime.now(timezone.utc) - timedelta(minutes=1)})
        db.commit()
    assert secured.get("/devices", headers=headers).status_code == 401


def test_agents_use_the_api_key_and_it_may_be_stored_as_a_hash(client, monkeypatch):
    key = "agent-secret-123"
    monkeypatch.setattr(settings, "api_key_hash", hashlib.sha256(key.encode()).hexdigest())
    assert client.post("/events/ingest", json=make_event()).status_code == 401
    assert client.post("/events/ingest", json=make_event(), headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/events/ingest", json=make_event(), headers={"X-API-Key": key}).status_code == 200


def test_retraining_accepts_an_admin_login_or_the_api_key(secured, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "script-key")
    admin = login(secured, "admin", "admin-pass-1")
    # Not enough history to train either way, but both callers get past the access check (400, not 401/403).
    assert secured.post("/ml/train", headers=admin).status_code == 400
    assert secured.post("/ml/train", headers={"X-API-Key": "script-key"}).status_code == 400
    assert secured.post("/ml/train").status_code == 401


def test_cors_only_allows_the_configured_dashboard(client):
    allowed = client.options("/devices", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    evil = client.options("/devices", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in evil.headers
