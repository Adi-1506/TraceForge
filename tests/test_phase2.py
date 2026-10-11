from tests.conftest import HID, MASS, make_event

SERIAL_BOARD = {"pnp_class": "Ports", "service": "usbser", "interface_classes": [2, 10], "endpoint_count": 3}


def post(client, **kw):
    r = client.post("/events/ingest", json=make_event(**kw))
    assert r.status_code == 200, r.text
    return r.json()


def anomaly_names(client, device_id):
    return {a["name"] for a in client.get("/anomalies", params={"device_id": device_id}).json()}


# --- programmable boards -------------------------------------------------------------------------


def test_programmable_board_typing_as_a_keyboard_is_flagged(client):
    out = post(client, vid="16D0", pid="0753", serial=None, dtype="USB Input Device", descriptor=HID)
    assert "programmable_hid_board" in anomaly_names(client, out["event"]["device_id"])
    assert out["risk_level"] in ("high", "critical")


def test_programmable_board_used_as_a_serial_port_is_not_flagged(client):
    out = post(client, vid="2341", pid="8036", serial="7543932", dtype="USB Serial Device", descriptor=SERIAL_BOARD)
    assert "programmable_hid_board" not in anomaly_names(client, out["event"]["device_id"])


# --- same model, different serial (lookalike swap) ------------------------------------------------


def test_lookalike_on_the_same_machine_within_a_day_is_flagged(client):
    post(client, serial="4C530001230516")
    out = post(client, serial="4C530001230599", ts="2026-09-01T15:00:00Z")
    assert "same_model_new_serial" in anomaly_names(client, out["event"]["device_id"])


def test_second_unit_on_another_machine_or_days_later_is_not_flagged(client):
    post(client, serial="4C530001230516")
    other_machine = post(client, machine="PC-2", serial="4C530001230599", ts="2026-09-01T15:00:00Z")
    days_later = post(client, serial="4C530001230577", ts="2026-09-05T10:00:00Z")
    assert "same_model_new_serial" not in anomaly_names(client, other_machine["event"]["device_id"])
    assert "same_model_new_serial" not in anomaly_names(client, days_later["event"]["device_id"])


# --- MITRE ATT&CK ---------------------------------------------------------------------------------


def test_findings_carry_mitre_techniques(client):
    out = post(client)
    anomalies = client.get("/anomalies", params={"device_id": out["event"]["device_id"]}).json()
    unknown = next(a for a in anomalies if a["name"] == "unknown_device")
    assert [t["id"] for t in unknown["mitre"]] == ["T1200"]
    assert unknown["mitre"][0]["url"] == "https://attack.mitre.org/techniques/T1200/"


def test_incident_rolls_up_techniques_and_a_case_adds_lateral_movement(client):
    post(client, descriptor=MASS)
    first = post(client, dtype="USB Input Device", descriptor=HID, ts="2026-09-02T03:00:00Z")
    ids = [t["id"] for t in client.get(f"/incidents/{first['incident_id']}").json()["mitre"]]
    assert "T1200" in ids and "T1059" in ids  # a drive that types: keystroke injection

    hop = post(client, machine="PC-2", dtype="USB Input Device", descriptor=HID, ts="2026-09-02T03:10:00Z")
    ids = [t["id"] for t in client.get(f"/incidents/{hop['incident_id']}").json()["mitre"]]
    assert "T1091" in ids


# --- ML: One-Class SVM, attack-free training, scheduled retraining --------------------------------


def daily_history(client, days=40):
    for day in range(days):
        month, dom = (8, day + 1) if day < 31 else (9, day - 30)
        post(client, ts=f"2026-{month:02d}-{dom:02d}T{9 + day % 4:02d}:{(day * 7) % 60:02d}:00Z")


def test_one_class_svm_detects_and_explains_with_shap(client, monkeypatch):
    from server.config import settings

    monkeypatch.setattr(settings, "ml_algorithm", "ocsvm")
    daily_history(client)
    status = client.post("/ml/train").json()
    assert status["trained"] and status["algorithm"] == "ocsvm"

    flagged = [post(client, ts=f"2026-09-20T21:30:{i * 10:02d}Z") for i in range(6)]
    ml = [a for a in client.get("/anomalies", params={"source": "ml"}).json() if a["name"] == "behavioural_outlier"]
    assert flagged and ml, "the burst at 03:00 local time should be an outlier"
    assert ml[0]["detail"]["algorithm"] == "ocsvm"
    assert ml[0]["detail"]["drivers"], "SHAP drivers should be reported for the One-Class SVM too"


def test_switching_algorithm_ignores_the_model_trained_with_the_other(client, monkeypatch):
    from server.config import settings

    daily_history(client)
    assert client.post("/ml/train").json()["algorithm"] == "iforest"
    monkeypatch.setattr(settings, "ml_algorithm", "ocsvm")
    assert client.get("/ml/status").json()["trained"] is False


def test_connections_in_incidents_are_left_out_of_training(client):
    daily_history(client)
    post(client, dtype="USB Input Device", descriptor=HID, ts="2026-09-20T03:00:00Z")  # opens an incident
    status = client.post("/ml/train").json()
    assert status["excluded_rows"] == 1
    assert status["training_rows"] == 40
    assert status["trained_at"]


def test_scheduled_retraining_trains_once_there_is_enough_history(client):
    from server.scheduler import retrain_once

    post(client)
    assert retrain_once() is None  # not enough history: skipped, not an error
    daily_history(client)
    assert retrain_once()["trained"] is True
    assert client.get("/ml/status").json()["trained"] is True
