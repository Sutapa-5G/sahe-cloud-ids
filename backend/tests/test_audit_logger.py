import pytest

from backend.app.audit.audit_logger import (
    AuditLogger,
    InMemoryAuditSink,
    MongoAuditSink,
    AuditEventType,
)


def test_audit_logger_records_events():
    logger = AuditLogger(InMemoryAuditSink())
    logger.log_detection("DDoS", 0.9)
    logger.log_severity_assignment({"final_severity": "HIGH"})

    events = logger.sink.read_all()
    assert len(events) == 2
    assert events[0].event_type == AuditEventType.DETECTION
    assert events[1].event_type == AuditEventType.SEVERITY_ASSIGNMENT


def test_audit_event_has_id_and_timestamp():
    logger = AuditLogger(InMemoryAuditSink())
    event = logger.log_firewall_action("block", "10.0.0.1", "simulated")
    assert event.audit_id
    assert event.timestamp


def test_correlation_id_links_related_events():
    logger = AuditLogger(InMemoryAuditSink())
    correlation_id = "event-123"
    logger.log_sahe_decision({"method": "ECDH_X25519"}, correlation_id=correlation_id)
    logger.log_encryption("ECDH_X25519", False, correlation_id=correlation_id)

    events = logger.sink.read_all()
    assert all(e.correlation_id == correlation_id for e in events)


def test_mongo_audit_sink_not_implemented_yet():
    """
    Confirms MongoAuditSink honestly raises NotImplementedError rather
    than silently pretending to work — Phase 10 will implement this
    against a real MongoDB, which is not available in this environment.
    """
    sink = MongoAuditSink(collection=None)
    with pytest.raises(NotImplementedError):
        sink.write(None)
    with pytest.raises(NotImplementedError):
        sink.read_all()


def test_to_dict_serializable():
    logger = AuditLogger(InMemoryAuditSink())
    event = logger.log_auth_failure("invalid token")
    d = event.to_dict()
    assert d["event_type"] == "AUTH_FAILURE"
    assert d["details"]["reason"] == "invalid token"
