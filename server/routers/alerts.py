import asyncio
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from server import alerts, audit
from server.auth import actor, current_user, require_role, user_for_token
from server.config import settings
from server.database import get_db
from server.models import User

router = APIRouter(prefix="/alerts", tags=["alerts"])
HEARTBEAT_SECONDS = 15


@router.get("/config", dependencies=[Depends(current_user)])
def config():
    return {"min_level": settings.alert_min_level, "channels": alerts.channels()}


@router.get("/recent", dependencies=[Depends(current_user)])
def recent(limit: int = Query(default=20, le=50)):
    return list(alerts.broker.recent)[:limit]


@router.get("/stream")
async def stream(request: Request, token: str | None = None, db: Session = Depends(get_db)):
    """Server-Sent Events. Browsers' EventSource cannot send headers, so the login token comes as ?token=."""
    user_for_token(db, token)  # 401 before streaming starts if logins are on and the token is bad
    db.close()  # the stream can stay open for hours; it does not need the database
    queue = alerts.broker.subscribe()

    async def events():
        try:
            yield ": connected\n\n"
            while not await request.is_disconnected():
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"event: usb\ndata: {json.dumps(item)}\n\n"
        finally:
            alerts.broker.unsubscribe(queue)

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/test")
def test_message(db: Session = Depends(get_db), user: User | None = Depends(require_role("admin"))):
    """Send a test message to every configured channel."""
    sent = alerts.send("TraceForge test alert: if you can read this, alerts reach this channel.")
    audit.record(db, actor(user), "alerts.test", channels=sent)
    db.commit()
    return {"configured": alerts.channels(), "delivered": sent}
