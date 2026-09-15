"""
Verifies /events routes work correctly when a MongoDB-backed
EventRepository IS available (simulated here via mongomock, since no
real MongoDB is reachable in this environment). This is distinct from
backend/tests/test_events_routes.py, which tests the in-memory fallback
path (the actual current behavior when the app starts normally in this
sandbox, since MongoDB is unreachable).
"""
import pytest

from backend.app.database.repositories import EventRepository
from backend.tests.database.mongomock_async_wrapper import make_async_mongomock_db


@pytest.fixture
def client_with_mongo():
    from backend.app.main import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    with TestClient(app) as c:
        db = make_async_mongomock_db()
        app.state.event_repository = EventRepository(db)
        yield c


def test_create_event_uses_mongodb_backend(client_with_mongo):
    r = client_with_mongo.post("/events", json={"attack_type": "DDoS", "severity": "HIGH"})
    assert r.status_code == 200
    assert r.json()["storage_backend"] == "mongodb"


def test_get_event_from_mongodb(client_with_mongo):
    r = client_with_mongo.post("/events", json={"attack_type": "PortScan", "severity": "LOW"})
    event_id = r.json()["event_id"]

    r2 = client_with_mongo.get(f"/events/{event_id}")
    assert r2.status_code == 200
    assert r2.json()["attack_type"] == "PortScan"
    assert r2.json()["storage_backend"] == "mongodb"


def test_get_unknown_event_from_mongodb_404(client_with_mongo):
    r = client_with_mongo.get("/events/does-not-exist")
    assert r.status_code == 404


def test_list_events_from_mongodb(client_with_mongo):
    client_with_mongo.post("/events", json={"attack_type": "Bot", "severity": "MEDIUM"})
    client_with_mongo.post("/events", json={"attack_type": "DDoS", "severity": "CRITICAL"})

    r = client_with_mongo.get("/events")
    assert r.status_code == 200
    assert len(r.json()) == 2
    assert all(e["storage_backend"] == "mongodb" for e in r.json())
