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
