import pytest

from backend.app.database.repositories import (
    BenchmarkResultRepository,
    FirewallActionRepository,
    AuditLogRepository,
)
from backend.app.database.models import (
    BenchmarkResultDocument,
    FirewallActionDocument,
    AuditLogDocument,
)
from backend.tests.database.mongomock_async_wrapper import make_async_mongomock_db


@pytest.fixture
def db():
    return make_async_mongomock_db()


# --- BenchmarkResultRepository ---

@pytest.mark.asyncio
async def test_benchmark_insert_many_and_get_by_algorithm(db):
    repo = BenchmarkResultRepository(db)
    docs = [
        BenchmarkResultDocument(algorithm="AES-256-GCM", payload_size_bytes=1024, total_operation_seconds_mean=0.0001, run_id="run-1"),
        BenchmarkResultDocument(algorithm="AES-256-GCM", payload_size_bytes=2048, total_operation_seconds_mean=0.0002, run_id="run-1"),
        BenchmarkResultDocument(algorithm="RSA-OAEP-Hybrid", payload_size_bytes=1024, total_operation_seconds_mean=0.0003, run_id="run-1"),
    ]
    await repo.insert_many(docs)

    aes_results = await repo.get_by_algorithm("AES-256-GCM")
    assert len(aes_results) == 2
    assert all(r.algorithm == "AES-256-GCM" for r in aes_results)
    # Should be sorted by payload_size_bytes ascending
    assert aes_results[0].payload_size_bytes < aes_results[1].payload_size_bytes


@pytest.mark.asyncio
async def test_benchmark_insert_many_empty_list_no_error(db):
    repo = BenchmarkResultRepository(db)
    await repo.insert_many([])  # should not raise
    results = await repo.get_all()
    assert results == []


@pytest.mark.asyncio
async def test_benchmark_get_all(db):
    repo = BenchmarkResultRepository(db)
    await repo.insert_many([
        BenchmarkResultDocument(algorithm="DES", payload_size_bytes=1024, total_operation_seconds_mean=0.01, run_id="run-1"),
        BenchmarkResultDocument(algorithm="AES-256-GCM", payload_size_bytes=1024, total_operation_seconds_mean=0.0001, run_id="run-1"),
    ])
    results = await repo.get_all()
    assert len(results) == 2


# --- FirewallActionRepository ---

@pytest.mark.asyncio
async def test_firewall_action_insert_and_list_by_ip(db):
    repo = FirewallActionRepository(db)
    await repo.insert(FirewallActionDocument(ip="10.0.0.1", action="block", mode="simulated", reason="DDoS"))
    await repo.insert(FirewallActionDocument(ip="10.0.0.1", action="unblock", mode="simulated", reason="resolved"))
    await repo.insert(FirewallActionDocument(ip="10.0.0.2", action="block", mode="simulated", reason="other"))

    actions = await repo.list_by_ip("10.0.0.1")
    assert len(actions) == 2
    assert actions[0].action == "block"
    assert actions[1].action == "unblock"


@pytest.mark.asyncio
async def test_firewall_action_list_recent_respects_limit(db):
    repo = FirewallActionRepository(db)
    for i in range(5):
        await repo.insert(FirewallActionDocument(ip=f"10.0.0.{i}", action="block", mode="simulated", reason="test"))
    recent = await repo.list_recent(limit=2)
    assert len(recent) == 2


# --- AuditLogRepository ---

@pytest.mark.asyncio
async def test_audit_log_insert_and_list_by_correlation_id(db):
    repo = AuditLogRepository(db)
    await repo.insert(AuditLogDocument(audit_id="a1", event_type="DETECTION", details={"x": 1}, correlation_id="corr-1"))
    await repo.insert(AuditLogDocument(audit_id="a2", event_type="SAHE_DECISION", details={"y": 2}, correlation_id="corr-1"))
    await repo.insert(AuditLogDocument(audit_id="a3", event_type="DETECTION", details={"z": 3}, correlation_id="corr-2"))

    events = await repo.list_by_correlation_id("corr-1")
    assert len(events) == 2
    assert {e.event_type for e in events} == {"DETECTION", "SAHE_DECISION"}


@pytest.mark.asyncio
async def test_audit_log_list_recent(db):
    repo = AuditLogRepository(db)
    for i in range(3):
        await repo.insert(AuditLogDocument(audit_id=f"a{i}", event_type="DETECTION", details={}))
    recent = await repo.list_recent(limit=10)
    assert len(recent) == 3


@pytest.mark.asyncio
async def test_audit_log_has_no_update_or_delete_methods():
    """
    Structural test confirming the append-only design requirement: the
    repository must not expose update/delete methods.
    """
    repo = AuditLogRepository(make_async_mongomock_db())
    assert not hasattr(repo, "update")
    assert not hasattr(repo, "delete")
    assert not hasattr(repo, "delete_one")
    assert not hasattr(repo, "update_one")
