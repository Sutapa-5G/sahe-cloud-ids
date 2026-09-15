def test_create_and_get_event(client):
    r = client.post("/events", json={"attack_type": "DDoS", "severity": "HIGH"})
    assert r.status_code == 200
    event_id = r.json()["event_id"]

    r2 = client.get(f"/events/{event_id}")
    assert r2.status_code == 200
    assert r2.json()["attack_type"] == "DDoS"


def test_get_unknown_event_404(client):
    r = client.get("/events/does-not-exist")
    assert r.status_code == 404


def test_list_events_includes_created(client):
    r = client.post("/events", json={"attack_type": "PortScan", "severity": "LOW"})
    event_id = r.json()["event_id"]

    r2 = client.get("/events")
    assert r2.status_code == 200
    assert any(e["event_id"] == event_id for e in r2.json())
