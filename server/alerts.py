"""Live alerts: a real-time feed for the dashboard, and messages to Slack/Discord/Teams webhooks or Telegram.

Every ingested event goes to the live feed (Server-Sent Events, GET /alerts/stream). An event at or
above ALERT_MIN_LEVEL is an alert; external messages are sent once per incident and again only when
it escalates, so one attack does not page anyone twenty times. Imported historical evidence appears
in the feed but never sends a message. Messages go out from a background worker: a slow webhook
can never hold up ingestion.
"""

import asyncio
import json
import logging
import threading
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from server.config import settings
from server.timeutil import as_utc, to_local

log = logging.getLogger("traceforge.alerts")
LEVELS = ["low", "medium", "high", "critical"]
RECENT = 50


class Broker:
    """Fan-out from the (threaded) ingestion pipeline to every connected dashboard."""

    def __init__(self):
        self._subscribers: set[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = set()
        self._lock = threading.Lock()
        self.recent: deque[dict] = deque(maxlen=RECENT)

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        with self._lock:
            self._subscribers.add((asyncio.get_running_loop(), queue))
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers = {s for s in self._subscribers if s[1] is not queue}

    def publish(self, item: dict) -> None:
        self.recent.appendleft(item)
        with self._lock:
            subscribers = list(self._subscribers)
        for loop, queue in subscribers:
            loop.call_soon_threadsafe(_offer, queue, item)


def _offer(queue: asyncio.Queue, item: dict) -> None:
    if not queue.full():  # a dashboard that stopped reading loses old items, not the server
        queue.put_nowait(item)


broker = Broker()
_sender = ThreadPoolExecutor(max_workers=1, thread_name_prefix="traceforge-alerts")
_alerted: dict[int, str] = {}  # incident id -> highest level already sent
_alerted_lock = threading.Lock()


def at_least(level: str, minimum: str) -> bool:
    return LEVELS.index(level) >= LEVELS.index(minimum)


def feed_item(outcome) -> dict:
    e, risk, incident = outcome.event, outcome.risk, outcome.incident
    d = e.device
    payload = e.raw_payload or {}
    return {
        "event_id": e.id,
        "timestamp": as_utc(e.timestamp).isoformat(),
        "event_type": e.event_type,
        "device_id": d.id,
        "device": f"{d.vendor_id}:{d.product_id} {d.device_type or ''}".strip(),
        "serial_number": d.serial_number,
        "machine": e.machine.hostname,
        "risk_score": risk.score,
        "risk_level": risk.level,
        "findings": [a.name for a in e.anomalies],
        "incident_id": incident.id if incident else None,
        "imported": bool(payload.get("source")),
        "alert": e.event_type == "connect" and at_least(risk.level, settings.alert_min_level),
    }


def message(item: dict) -> str:
    when = to_local(datetime.fromisoformat(item["timestamp"]))
    incident = f" · incident #{item['incident_id']}" if item["incident_id"] else ""
    findings = f"\nFindings: {', '.join(item['findings'])}" if item["findings"] else ""
    return (
        f"TraceForge {item['risk_level'].upper()} ({item['risk_score']:g}/100){incident}\n"
        f"{item['device']} connected to {item['machine']} at {when:%H:%M %d %b %Y}{findings}"
    )


def should_notify(item: dict) -> bool:
    """Once per incident, and again only if it escalates; never for imported history."""
    if not item["alert"] or item["imported"]:
        return False
    if item["incident_id"] is None:
        return True
    with _alerted_lock:
        previous = _alerted.get(item["incident_id"])
        if previous is not None and not LEVELS.index(item["risk_level"]) > LEVELS.index(previous):
            return False
        _alerted[item["incident_id"]] = item["risk_level"]
    return True


def _post_json(url: str, body: dict) -> None:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (URL comes from the server's own settings)
        resp.read()


def send(text: str) -> list[str]:
    """Deliver to every configured channel; returns the channels that worked."""
    sent = []
    if settings.alert_webhook_url:
        try:
            # "text" for Slack / Teams / Mattermost, "content" for Discord.
            _post_json(settings.alert_webhook_url, {"text": text, "content": text})
            sent.append("webhook")
        except Exception as exc:  # an alert channel being down must never break anything else
            log.warning("Alert webhook failed: %s", exc)
    if settings.telegram_bot_token and settings.telegram_chat_id:
        try:
            _post_json(f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage", {"chat_id": settings.telegram_chat_id, "text": text})
            sent.append("telegram")
        except Exception as exc:
            log.warning("Telegram alert failed: %s", exc)
    return sent


def channels() -> list[str]:
    out = []
    if settings.alert_webhook_url:
        out.append("webhook")
    if settings.telegram_bot_token and settings.telegram_chat_id:
        out.append("telegram")
    return out


def on_event(outcome) -> None:
    item = feed_item(outcome)
    broker.publish(item)
    if channels() and should_notify(item):
        _sender.submit(send, message(item))
