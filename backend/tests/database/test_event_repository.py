"""
These tests exercise the EventRepository's actual query logic against
mongomock (a real, well-tested MongoDB simulator) - NOT against a real
MongoDB server, which is unavailable in this environment. This validates
the repository's query construction and data flow correctly, but does
NOT verify behavior specific to real MongoDB (e.g. actual index
performance, replica set behavior, real network failure modes). See
docs/methodology/mongodb.md for the full caveat.
"""
import pytest

from backend.app.database.repositories import EventRepository
from backend.app.database.models import EventDocument, CryptoMetadata, ModelInfo
from backend.tests.database.mongomock_async_wrapper import make_async_mongomock_db


@pytest.fixture
def db():
    return make_async_mongomock_db()


def _make_event(event_id: str, attack_type: str = "DDoS", severity: str = "HIGH") -> EventDocument:
    return EventDocument(
        event_id=event_id,
        attack_type=attack_type,
        severity=severity,
        crypto=CryptoMetadata(scheme="SAHE-ECDH-AES-GCM", key_management="ECDH_X25519"),
        payload_base64="Y2lwaGVydGV4dA==",
        nonce_base64="bm9uY2U=",
        model=ModelInfo(name="RandomForestClassifier", confidence=0.95),
    )


@pytest.mark.asyncio
async def test_insert_and_get_by_id(db):
    repo = EventRepository(db)
    event = _make_event("event-1")
    await repo.insert(event)

    fetched = await repo.get_by_id("event-1")
    assert fetched is not None
    assert fetched.attack_type == "DDoS"
    assert fetched.severity == "HIGH"


@pytest.mark.asyncio
async def test_get_by_id_not_found_returns_none(db):
    repo = EventRepository(db)
    result = await repo.get_by_id("does-not-exist")
    assert result is None


@pytest.mark.asyncio
async def test_list_all_returns_all_inserted(db):
    repo = EventRepository(db)
    await repo.insert(_make_event("event-1"))
    await repo.insert(_make_event("event-2"))
    await repo.insert(_make_event("event-3"))

    results = await repo.list_all()
    assert len(results) == 3
    ids = {r.event_id for r in results}
    assert ids == {"event-1", "event-2", "event-3"}


@pytest.mark.asyncio
async def test_list_all_respects_limit(db):
    repo = EventRepository(db)
    for i in range(10):
        await repo.insert(_make_event(f"event-{i}"))

    results = await repo.list_all(limit=3)
    assert len(results) == 3


@pytest.mark.asyncio
async def test_list_by_severity_filters_correctly(db):
    repo = EventRepository(db)
    await repo.insert(_make_event("event-1", severity="HIGH"))
    await repo.insert(_make_event("event-2", severity="LOW"))
    await repo.insert(_make_event("event-3", severity="HIGH"))

    results = await repo.list_by_severity("HIGH")
    assert len(results) == 2
    assert all(r.severity == "HIGH" for r in results)


@pytest.mark.asyncio
async def test_count_by_attack_type_aggregation(db):
    repo = EventRepository(db)
    await repo.insert(_make_event("event-1", attack_type="DDoS"))
    await repo.insert(_make_event("event-2", attack_type="DDoS"))
    await repo.insert(_make_event("event-3", attack_type="PortScan"))

    counts = await repo.count_by_attack_type()
    assert counts["DDoS"] == 2
    assert counts["PortScan"] == 1


@pytest.mark.asyncio
async def test_no_internal_mongo_id_leaks_into_returned_model(db):
    """
    Ensures the repository correctly strips MongoDB's internal _id field
    before constructing the Pydantic model - a real bug class if
    forgotten (EventDocument has no _id field, so this would raise a
    validation error if the strip logic were missing/broken).
    """
    repo = EventRepository(db)
    await repo.insert(_make_event("event-1"))
    fetched = await repo.get_by_id("event-1")
    assert not hasattr(fetched, "_id")
