from tests.conftest import HID, MASS, make_event


def post(client, **kw):
    r = client.post("/events/ingest", json=make_event(**kw))
    assert r.status_code == 200, r.text
    return r.json()


SPOOF = dict(dtype="USB Input Device", descriptor=HID)


# --- 3.1 attack graph and incident replay ---------------------------------------------------------


def test_graph_shows_who_touched_what_in_time_order(client):
    post(client, ts="2026-09-01T10:00:00Z")
    post(client, machine="PC-2", vid="046D", pid="C52B", serial="A1B2C3", dtype="USB Input Device", descriptor=HID, ts="2026-09-01T11:00:00Z")
    g = client.get("/graph").json()
    assert [m["hostname"] for m in g["machines"]] == ["PC-1", "PC-2"]
    assert len(g["devices"]) == 2 and len(g["events"]) == 2
    assert [e["timestamp"] for e in g["events"]] == sorted(e["timestamp"] for e in g["events"])
    assert g["start"].startswith("2026-09-01T10:00") and g["title"] is None


def test_graph_window_counts_back_from_the_latest_activity(client):
    post(client, ts="2026-08-01T10:00:00Z")
    post(client, ts="2026-09-01T10:00:00Z")
    assert len(client.get("/graph", params={"days": 7}).json()["events"]) == 1
    assert len(client.get("/graph", params={"days": 60}).json()["events"]) == 2


def test_replay_covers_the_whole_cross_machine_case(client):
    post(client, descriptor=MASS)
    first = post(client, ts="2026-09-02T03:00:00Z", **SPOOF)
    post(client, machine="PC-2", ts="2026-09-02T03:08:00Z", **SPOOF)
    post(client, machine="PC-3", ts="2026-09-02T03:20:00Z", **SPOOF)
    post(client, machine="PC-9", vid="046D", pid="C52B", serial="UNRELATED", ts="2026-09-02T03:21:00Z")  # not in the case

    replay = client.get("/graph", params={"incident_id": first["incident_id"]}).json()
    assert replay["title"] == f"Case #{first['incident_id']}"
    assert [m["hostname"] for m in replay["machines"]] == ["PC-1", "PC-2", "PC-3"]
    steps = replay["events"]
    assert [s["machine_id"] for s in steps] == sorted(s["machine_id"] for s in steps)  # spreads PC-1 -> PC-2 -> PC-3
    assert all(s["incident_id"] is not None for s in steps)
    assert "T1200" in steps[0]["mitre"] and "device_type_mismatch" in steps[0]["findings"]


def test_replay_of_an_unknown_incident_is_404(client):
    assert client.get("/graph", params={"incident_id": 99}).status_code == 404


# --- 3.2 importing USB evidence from seized machines ----------------------------------------------

import base64  # noqa: E402
from pathlib import Path  # noqa: E402

from server.forensics import parsers  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return (FIXTURES / name).read_bytes()


def b64(name):
    return base64.b64encode(fixture(name)).decode()


def test_setupapi_gives_first_installs_with_local_time_and_device_types():
    r = parsers.parse_setupapi(parsers.decode(fixture("setupapi.dev.log")), "Asia/Kolkata")
    assert [(e.vendor_id, e.product_id, e.serial_number, e.device_type) for e in r.events] == [
        ("0951", "1666", "0019E06B8A0A1E91", "USB Mass Storage Device"),  # linked to its USBSTOR section by serial
        ("16D0", "0753", None, "USB Input Device"),  # Windows-made instance ID: no real serial; HID section by VID/PID
    ]
    assert r.events[0].timestamp.isoformat() == "2026-09-03T08:35:11+00:00"  # 14:05:11 IST
    assert len(r.events) == 2  # the reinstall on 09-10 is not a new first sighting; root hubs are skipped


def test_registry_export_in_utf16_lists_devices_with_names_but_no_times():
    raw = fixture("usb.reg")
    assert raw.startswith(b"\xff\xfe")
    r = parsers.parse_registry(parsers.decode(raw))
    assert not r.events
    by_vid = {d["vendor_id"]: d for d in r.undated}
    assert set(by_vid) == {"0951", "046D"}
    assert by_vid["0951"]["serial_number"] == "0019E06B8A0A1E91" and by_vid["0951"]["device_type"] == "USB Mass Storage Device"
    assert by_vid["046D"]["serial_number"] is None  # composite parent without a serial


def test_linux_kernel_log_pairs_connects_and_disconnects_and_spots_a_keyboard():
    r = parsers.parse_linux(parsers.decode(fixture("kern.log")), "Asia/Kolkata", 2026)
    assert [(e.event_type, e.device_type) for e in r.events] == [
        ("connect", "USB Mass Storage Device"),
        ("disconnect", "USB Mass Storage Device"),
        ("connect", "USB Composite Device"),  # the same drive came back also typing as a keyboard
    ]
    assert {e.serial_number for e in r.events} == {"4C530001230516"}
    assert {e.machine_hostname for e in r.events} == {"lab-ubuntu"}
    assert all(e.vendor_id != "1D6B" for e in r.events)  # the root hub is not a device


def test_linux_short_iso_lines_carry_their_own_offset():
    log = "2026-09-05T22:14:03+0530 box kernel: usb 2-1: New USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00\n"
    r = parsers.parse_linux(log, "UTC", 2026)
    assert r.events[0].timestamp.isoformat() == "2026-09-05T16:44:03+00:00"


def test_kind_is_detected_from_the_contents():
    assert parsers.detect_kind(parsers.decode(fixture("setupapi.dev.log"))) == "setupapi"
    assert parsers.detect_kind(parsers.decode(fixture("usb.reg"))) == "registry"
    assert parsers.detect_kind(parsers.decode(fixture("kern.log"))) == "linux"


def test_importing_a_seized_windows_log_runs_the_full_pipeline(client):
    body = {"filename": "setupapi.dev.log", "content_b64": b64("setupapi.dev.log"), "machine_hostname": "SEIZED-LAPTOP", "timezone": "Asia/Kolkata"}
    preview = client.post("/evidence/import", json={**body, "dry_run": True}).json()
    assert preview["events_found"] == 2 and preview["events_imported"] == 0 and len(preview["preview"]) == 2

    r = client.post("/evidence/import", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["kind"] == "setupapi" and out["events_imported"] == 2 and out["new_devices"] == 2
    assert out["incidents"], "the Digispark typing as a keyboard should open an incident"

    names = {a["name"] for a in client.get("/anomalies").json()}
    assert "programmable_hid_board" in names
    assert client.get("/integrity/verify").json()["intact"] is True  # imported events join the evidence chain
    timeline = client.get("/devices/1/timeline").json()
    assert timeline[0]["machine_hostname"] == "SEIZED-LAPTOP"

    imports = client.get("/evidence/imports").json()
    assert imports[0]["sha256"] == out["sha256"] and imports[0]["events_imported"] == 2


def test_the_same_file_cannot_be_imported_twice(client):
    body = {"filename": "setupapi.dev.log", "content_b64": b64("setupapi.dev.log"), "machine_hostname": "SEIZED-LAPTOP"}
    assert client.post("/evidence/import", json=body).status_code == 200
    again = client.post("/evidence/import", json=body)
    assert again.status_code == 400 and "already imported" in again.json()["detail"]


def test_linux_import_catches_the_drive_that_came_back_as_a_keyboard(client):
    r = client.post("/evidence/import", json={"filename": "kern.log", "content_b64": b64("kern.log"), "timezone": "Asia/Kolkata"}).json()
    assert r["kind"] == "linux" and r["events_imported"] == 3
    assert "device_type_mismatch" in {a["name"] for a in client.get("/anomalies").json()}
    assert [m["hostname"] for m in client.get("/graph", params={"days": 365}).json()["machines"]] == ["lab-ubuntu"]


def test_registry_enriches_a_log_and_events_the_agent_already_sent_are_skipped(client):
    # The live agent already reported the Kingston's connection at the same moment.
    client.post("/events/ingest", json=make_event(machine="SEIZED-LAPTOP", ts="2026-09-03T08:35:12Z", serial="0019E06B8A0A1E91"))
    r = client.post(
        "/evidence/import",
        json={
            "filename": "setupapi.dev.log",
            "content_b64": b64("setupapi.dev.log"),
            "registry_b64": b64("usb.reg"),
            "machine_hostname": "SEIZED-LAPTOP",
            "timezone": "Asia/Kolkata",
        },
    ).json()
    assert r["duplicates_skipped"] == 1 and r["events_imported"] == 1


def test_import_needs_a_machine_name_when_the_file_has_none_and_rejects_unknown_files(client):
    no_host = client.post("/evidence/import", json={"filename": "setupapi.dev.log", "content_b64": b64("setupapi.dev.log")})
    assert no_host.status_code == 400 and "hostname" in no_host.json()["detail"]
    junk = client.post("/evidence/import", json={"filename": "notes.txt", "content_b64": base64.b64encode(b"hello").decode(), "machine_hostname": "X"})
    assert junk.status_code == 400
    bad_tz = client.post("/evidence/import", json={"filename": "a", "content_b64": b64("kern.log"), "timezone": "Mars/Base"})
    assert bad_tz.status_code == 422


# --- 3.4 plain-English incident story -------------------------------------------------------------


def test_story_tells_a_badusb_spread_in_order_with_times_and_next_steps(client):
    post(client, descriptor=MASS)
    first = post(client, ts="2026-09-02T03:00:00Z", **SPOOF)
    post(client, machine="PC-2", ts="2026-09-02T03:08:00Z", **SPOOF)
    story = client.get(f"/incidents/{first['incident_id']}/story").json()

    assert story["headline"] == "Possible keystroke-injection (BadUSB) attack: PC-1, PC-2"
    text = " ".join(story["paragraphs"])
    assert "08:30 on 02 Sep 2026" in text  # 03:00 UTC in Asia/Kolkata
    assert "on record as a USB Mass Storage Device but now declared itself a USB Input Device" in text
    assert "8 minutes later the same device appeared on PC-2" in text
    assert "reached 2 machines" in text
    assert "T1200 Hardware Additions" in text and "T1091" in text
    assert any("compromised" in step for step in story["recommendations"])


def test_story_for_an_attack_board_names_the_board(client):
    out = post(client, vid="16D0", pid="0753", serial=None, dtype="USB Input Device", descriptor=HID)
    story = client.get(f"/incidents/{out['incident_id']}/story").json()
    assert "Digispark" in " ".join(story["paragraphs"])
    assert story["headline"].startswith("Possible keystroke-injection")


def test_story_includes_the_investigators_note_and_status(client):
    post(client, descriptor=MASS)
    first = post(client, ts="2026-09-02T03:00:00Z", **SPOOF)
    client.patch(f"/incidents/{first['incident_id']}", json={"status": "investigating", "note": "Drive found in the lab"})
    text = " ".join(client.get(f"/incidents/{first['incident_id']}/story").json()["paragraphs"])
    assert "investigating" in text and "Investigator note: Drive found in the lab" in text


def test_story_does_not_advise_blocklisting_a_device_that_already_is(client):
    post(client, descriptor=MASS)
    first = post(client, ts="2026-09-02T03:00:00Z", **SPOOF)
    client.put("/devices/1/trust", json={"status": "blocklisted"})
    steps = client.get(f"/incidents/{first['incident_id']}/story").json()["recommendations"]
    assert steps and not any(s.startswith("Blocklist") for s in steps)


# --- 3.5 live alerts ------------------------------------------------------------------------------

import pytest  # noqa: E402

from server import alerts  # noqa: E402
from server.config import settings  # noqa: E402


@pytest.fixture()
def channels(client, monkeypatch):
    """A webhook and Telegram configured, with delivery captured instead of sent."""
    alerts._alerted.clear()
    alerts.broker.recent.clear()
    monkeypatch.setattr(settings, "alert_webhook_url", "https://hooks.example/abc")
    monkeypatch.setattr(settings, "telegram_bot_token", "bot-token")
    monkeypatch.setattr(settings, "telegram_chat_id", "42")
    sent = []
    monkeypatch.setattr(alerts, "_post_json", lambda url, body: sent.append((url, body)))
    monkeypatch.setattr(alerts._sender, "submit", lambda fn, *a: fn(*a))  # deliver inline for the test
    return sent


def test_every_event_reaches_the_live_feed_and_serious_ones_are_alerts(client, channels):
    post(client)  # unknown device: medium, not an alert at the default "high"
    post(client, ts="2026-09-02T03:00:00Z", **SPOOF)  # BadUSB: critical
    recent = client.get("/alerts/recent").json()
    assert [r["alert"] for r in recent] == [True, False]  # newest first
    assert recent[0]["risk_level"] == "critical" and recent[0]["machine"] == "PC-1" and recent[0]["incident_id"]
    assert client.get("/alerts/config").json() == {"min_level": "high", "channels": ["webhook", "telegram"]}


def test_one_message_per_incident_on_every_channel_and_again_only_if_it_escalates(client, channels):
    post(client, descriptor=MASS)
    post(client, ts="2026-09-02T03:00:00Z", vid="0951", pid="1666", serial=None)  # missing serial: high
    first_batch = len(channels)
    assert first_batch == 2  # webhook + Telegram
    url, body = channels[0]
    assert url == "https://hooks.example/abc" and "TraceForge HIGH" in body["text"] and body["content"] == body["text"]
    assert channels[1][0] == "https://api.telegram.org/botbot-token/sendMessage" and channels[1][1]["chat_id"] == "42"

    post(client, ts="2026-09-02T03:01:00Z", vid="0951", pid="1666", serial=None)  # same incident, same level
    assert len(channels) == first_batch
    post(client, ts="2026-09-02T03:02:00Z", vid="0951", pid="1666", serial=None, **SPOOF)  # escalates to critical
    assert len(channels) == first_batch + 2 and "CRITICAL" in channels[-1][1]["text"]


def test_imported_history_is_in_the_feed_but_never_pages_anyone(client, channels):
    r = client.post("/evidence/import", json={"filename": "setupapi.dev.log", "content_b64": b64("setupapi.dev.log"), "machine_hostname": "SEIZED"})
    assert r.json()["incidents"]
    assert channels == []
    assert all(item["imported"] for item in client.get("/alerts/recent").json())


def test_a_failing_channel_does_not_break_ingestion(client, monkeypatch):
    alerts._alerted.clear()
    monkeypatch.setattr(settings, "alert_webhook_url", "https://hooks.example/down")

    def down(url, body):
        raise OSError("connection refused")

    monkeypatch.setattr(alerts, "_post_json", down)
    monkeypatch.setattr(alerts._sender, "submit", lambda fn, *a: fn(*a))
    post(client, descriptor=MASS)
    assert post(client, ts="2026-09-02T03:00:00Z", **SPOOF)["risk_level"] == "critical"


def test_admin_can_send_a_test_message(client, channels):
    r = client.post("/alerts/test").json()
    assert r == {"configured": ["webhook", "telegram"], "delivered": ["webhook", "telegram"]}


def test_live_stream_needs_a_valid_token_when_logins_are_on(client, monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    assert client.get("/alerts/stream", params={"token": "nope"}).status_code == 401


def test_live_stream_delivers_events_as_server_sent_events(client):
    import asyncio
    import json as _json

    from server.routers import alerts as alert_routes

    class FakeRequest:
        def __init__(self):
            self.calls = 0

        async def is_disconnected(self):
            self.calls += 1
            return self.calls > 2

    async def scenario():
        from server.database import SessionLocal

        response = await alert_routes.stream(FakeRequest(), token=None, db=SessionLocal())
        chunks = response.body_iterator
        first = await chunks.__anext__()
        alerts.broker.publish({"event_id": 7, "alert": True})
        second = await chunks.__anext__()
        return first, second

    first, second = asyncio.run(scenario())
    assert first.startswith(": connected")
    assert second.startswith("event: usb\ndata: ") and _json.loads(second.split("data: ", 1)[1])["event_id"] == 7


# --- 3.3 keystroke-injection (BadUSB typing speed) ------------------------------------------------

from agent.keystrokes import summarize  # noqa: E402


def human_typing():
    import random

    rng = random.Random(3)
    t, times = 2.0, []
    for _ in range(60):
        t += rng.uniform(0.08, 0.35)  # 80-350 ms, irregular
        times.append(t)
    return summarize(times, connected_at=0.0, watched_s=30)


def injected_typing():
    times = [1.2 + i * 0.008 for i in range(400)]  # 8 ms apart, perfectly regular, 1.2 s after plug-in
    return summarize(times, connected_at=0.0, watched_s=30)


def test_timing_summary_has_no_key_identities_and_tells_people_from_machines():
    human, machine = human_typing(), injected_typing()
    assert set(machine) == {"keys", "watched_s", "first_key_after_s", "duration_s", "rate_per_s", "median_gap_ms", "min_gap_ms", "gap_cv", "burst_fraction"}
    assert human["median_gap_ms"] > 80 and human["gap_cv"] > 0.2 and human["rate_per_s"] < 10
    assert machine["median_gap_ms"] == 8.0 and machine["gap_cv"] < 0.01 and machine["rate_per_s"] > 100
    assert machine["first_key_after_s"] == 1.2 and machine["burst_fraction"] == 1.0


def typing_event(typing, **kw):
    return {**make_event(dtype="USB Input Device", descriptor=HID, **kw), "event_type": "typing", "typing": typing}


def test_machine_speed_typing_is_flagged_and_joins_the_device_incident(client):
    connect = post(client, vid="046D", pid="C31C", serial="KB100", dtype="USB Input Device", descriptor=HID, ts="2026-09-02T03:00:00Z")
    r = client.post("/events/ingest", json=typing_event(injected_typing(), vid="046D", pid="C31C", serial="KB100", ts="2026-09-02T03:00:31Z"))
    assert r.status_code == 200
    out = r.json()
    assert out["risk_level"] in ("high", "critical") and out["incident_id"] is not None
    finding = next(a for a in client.get("/anomalies", params={"device_id": 1}).json() if a["name"] == "keystroke_injection")
    assert "400 keys" in finding["explanation"] and [t["id"] for t in finding["mitre"]] == ["T1200", "T1059"]
    story = client.get(f"/incidents/{out['incident_id']}/story").json()
    assert story["headline"].startswith("Keystroke-injection (BadUSB) attack")
    assert "this was a machine typing" in " ".join(story["paragraphs"])
    assert connect["incident_id"] is None  # the connection alone looked like an ordinary new keyboard


def test_a_person_typing_on_a_new_keyboard_is_not_flagged(client):
    post(client, vid="046D", pid="C31C", serial="KB100", dtype="USB Input Device", descriptor=HID)
    r = client.post("/events/ingest", json=typing_event(human_typing(), vid="046D", pid="C31C", serial="KB100", ts="2026-09-01T10:00:31Z")).json()
    assert r["risk_level"] == "low" and r["incident_id"] is None
    assert "keystroke_injection" not in {a["name"] for a in client.get("/anomalies").json()}


def test_agent_watches_only_devices_with_a_keyboard():
    from types import SimpleNamespace

    from agent.agent import has_keyboard

    boot_keyboard = {"interfaces": [{"interface_class": 3, "interface_protocol": 1}]}
    mouse = {"interfaces": [{"interface_class": 3, "interface_protocol": 2}]}
    stick = {"interfaces": [{"interface_class": 8, "interface_protocol": 80}]}
    dev = SimpleNamespace(device_type=None)
    assert has_keyboard(dev, boot_keyboard) and not has_keyboard(dev, mouse) and not has_keyboard(dev, stick)
    assert has_keyboard(SimpleNamespace(device_type="USB Input Device"), None)
