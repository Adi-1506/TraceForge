from server.config import settings
from server.detection import evaluate
from tests.conftest import make_event


def tree(*interfaces):
    """A descriptor in the shape the live agent sends."""
    return {
        "pnp_class": "USB",
        "service": "USBSTOR",
        "bcd_usb": "0210",
        "device_class": 0,
        "device_subclass": 0,
        "device_protocol": 0,
        "max_packet_size0": 64,
        "num_configurations": 1,
        "interfaces": [
            {"interface_class": c, "interface_subclass": 6, "interface_protocol": 80,
             "endpoints": [{"direction": "in", "transfer_type": t, "max_packet_size": 512}]}
            for c, t in interfaces
        ],
    }


STICK = tree((8, "bulk"))
STICK_WITH_KEYBOARD = tree((8, "bulk"), (3, "interrupt"))


def post(client, **kw):
    r = client.post("/events/ingest", json=make_event(**kw))
    assert r.status_code == 200, r.text
    return r.json()


def names(client, device_id):
    return {a["name"] for a in client.get("/anomalies", params={"device_id": device_id}).json()}


def test_server_fingerprints_descriptor_tree_and_derives_summary(client):
    out = post(client, descriptor=STICK)
    d = client.get(f"/devices/{out['event']['device_id']}").json()["descriptor_json"]
    assert len(d["fingerprint"]) == 16
    assert d["interface_classes"] == [8] and d["endpoint_count"] == 1


def test_fingerprint_ignores_identity_but_not_structure(client):
    a = post(client, serial="4C530001230516", descriptor=STICK)
    b = post(client, serial="4C530001220516", descriptor=STICK, ts="2026-09-01T11:00:00Z")
    fa = client.get(f"/devices/{a['event']['device_id']}").json()["descriptor_json"]["fingerprint"]
    fb = client.get(f"/devices/{b['event']['device_id']}").json()["descriptor_json"]["fingerprint"]
    assert fa == fb
    assert "descriptor_model_mismatch" not in names(client, b["event"]["device_id"])


def test_new_unit_with_structure_unlike_its_model_is_flagged(client):
    post(client, serial="4C530001230516", descriptor=STICK)
    out = post(client, serial="4C530001240516", descriptor=STICK_WITH_KEYBOARD, ts="2026-09-01T12:00:00Z")
    assert "descriptor_model_mismatch" in names(client, out["event"]["device_id"])
    assert out["risk_level"] == "high"


def test_known_device_changing_structure_is_flagged(client):
    post(client, descriptor=STICK)
    out = post(client, descriptor=STICK_WITH_KEYBOARD, ts="2026-09-02T10:00:00Z")
    assert "descriptor_mismatch" in names(client, out["event"]["device_id"])


def test_api_key_is_enforced_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "s3cret")
    body = make_event()
    assert client.post("/events/ingest", json=body).status_code == 401
    assert client.post("/events/ingest", json=body, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/events/ingest", json=body, headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.post("/ml/train").status_code == 401
    assert client.get("/devices").status_code == 200  # reads stay open for the dashboard


def test_suspicious_device_spreading_to_another_machine_joins_one_case(client):
    post(client, descriptor=STICK)
    first = post(client, dtype="USB Input Device", descriptor=STICK_WITH_KEYBOARD, ts="2026-09-02T03:00:00Z")
    assert first["incident_id"] is not None
    # Same device on another machine two hours later, looking normal again: alone it scores below the threshold.
    second = post(client, machine="PC-2", descriptor=STICK, ts="2026-09-02T05:00:00Z")
    assert second["risk_score"] < 40
    assert second["incident_id"] not in (None, first["incident_id"])

    detail = client.get(f"/incidents/{second['incident_id']}").json()
    assert detail["case_id"] == first["incident_id"]
    assert detail["case_machines"] == ["PC-1", "PC-2"]
    assert [r["id"] for r in detail["related"]] == [first["incident_id"]]
    assert "PC-1" in detail["case_reason"]


def test_serial_clone_on_another_machine_joins_the_case(client):
    post(client, vid="1050", pid="0407", serial="11223344", dtype="USB Input Device")
    post(client, vid="1050", pid="0407", serial="11223344", dtype="USB Mass Storage Device", ts="2026-09-02T03:00:00Z")
    clone = post(client, machine="PC-2", vid="1D6B", pid="0104", serial="11223344", ts="2026-09-02T04:00:00Z")
    detail = client.get(f"/incidents/{clone['incident_id']}").json()
    assert detail["case_machines"] == ["PC-1", "PC-2"]
    assert "serial number" in detail["case_reason"]


def test_incident_far_apart_in_time_is_not_linked(client):
    post(client, descriptor=STICK)
    post(client, dtype="USB Input Device", descriptor=STICK_WITH_KEYBOARD, ts="2026-09-02T03:00:00Z")
    later = post(client, machine="PC-2", descriptor=STICK, ts="2026-09-05T03:00:00Z")
    assert later["incident_id"] is None


def test_slow_enumeration_is_reported_as_unseen_behaviour(client):
    def connect(day, ms, order=(8,)):
        body = make_event(ts=f"2026-08-{day:02d}T10:00:00Z")
        body["enumeration"] = {"interface_order": list(order), "duration_ms": ms}
        r = client.post("/events/ingest", json=body)
        assert r.status_code == 200
        return r.json()

    for day in range(1, 31):
        connect(day, 100 + (day % 5) * 5)
    assert client.post("/ml/train").status_code == 200
    out = connect(31, 2500, order=(3, 8))
    ml = [a for a in client.get("/anomalies", params={"source": "ml"}).json() if a["event_id"] == out["event"]["id"]]
    unseen = next(a for a in ml if a["name"] == "unseen_behaviour")
    assert "enumeration" in unseen["explanation"] and "different order" in unseen["explanation"]


def test_evaluation_shows_full_model_beats_the_original_features():
    r = evaluate.run(n_devices=15, seed=3)
    assert r["overall"]["iforest-9+"]["recall"] > r["overall"]["baseline-4"]["recall"]
    assert r["false_positive_rate"]["iforest-9+"] < 0.1
    assert r["detection_rate"]["slow_enumeration"]["iforest-9+"] > 0.9
