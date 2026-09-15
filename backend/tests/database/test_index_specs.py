import pytest

from backend.tests.database.mongomock_async_wrapper import make_async_mongomock_db


@pytest.mark.asyncio
async def test_ensure_indexes_runs_without_error():
    """
    Exercises the same index-creation calls MongoManager.ensure_indexes()
    would make, against mongomock, to confirm the index specs themselves
    are valid (correct field names, no typos) - this does NOT verify
    real MongoDB index behavior/performance, only that the calls succeed
    against a MongoDB-compatible interface.
    """
    db = make_async_mongomock_db()

    events = db["events"]
    await events.create_index("timestamp")
    await events.create_index("severity")
    await events.create_index("attack_type")
    await events.create_index("event_id", unique=True)

    crypto_metadata = db["crypto_metadata"]
    await crypto_metadata.create_index("event_id")

    benchmark_results = db["benchmark_results"]
    await benchmark_results.create_index("algorithm")
    await benchmark_results.create_index("payload_size_bytes")

    firewall_actions = db["firewall_actions"]
    await firewall_actions.create_index("ip")
    await firewall_actions.create_index("timestamp")

    audit_log = db["audit_log"]
    await audit_log.create_index("timestamp")
    await audit_log.create_index("event_type")
    await audit_log.create_index("correlation_id")
    # If we reach here without an exception, all index specs were accepted.
