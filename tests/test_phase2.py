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
