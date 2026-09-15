from backend.app.services.blocking_service import BlockingService
from backend.app.firewall.provider import SimulatedFirewallProvider
from backend.app.audit.audit_logger import AuditLogger, InMemoryAuditSink
from ml.severity.severity_engine import Severity


def _make_service():
    provider = SimulatedFirewallProvider()
    audit_logger = AuditLogger(InMemoryAuditSink())
    return BlockingService(provider, audit_logger), provider, audit_logger


def test_evaluate_low_severity_does_not_block():
    service, _, _ = _make_service()
    decision = service.evaluate(Severity.LOW, "10.0.0.1")
    assert decision.should_block is False
    assert "below the auto-block threshold" in decision.reason


def test_evaluate_medium_severity_does_not_block():
    service, _, _ = _make_service()
    decision = service.evaluate(Severity.MEDIUM, "10.0.0.1")
    assert decision.should_block is False


def test_evaluate_high_severity_with_ip_blocks():
    service, _, _ = _make_service()
    decision = service.evaluate(Severity.HIGH, "10.0.0.1")
    assert decision.should_block is True


def test_evaluate_critical_severity_with_ip_blocks():
    service, _, _ = _make_service()
    decision = service.evaluate(Severity.CRITICAL, "10.0.0.1")
    assert decision.should_block is True


def test_evaluate_high_severity_without_ip_does_not_block():
    service, _, _ = _make_service()
    decision = service.evaluate(Severity.HIGH, None)
    assert decision.should_block is False
    assert "no source_ip" in decision.reason


def test_enforce_actually_blocks_for_high_severity():
    service, provider, _ = _make_service()
    decision = service.enforce(Severity.HIGH, "10.0.0.5", "DDoS")
    assert decision.action_taken is True
    assert decision.action_success is True

    rules = provider.list_rules()
    assert any(r["ip"] == "10.0.0.5" for r in rules)


def test_enforce_does_not_block_for_low_severity():
    service, provider, _ = _make_service()
    decision = service.enforce(Severity.LOW, "10.0.0.5", "PortScan")
    assert decision.action_taken is False
    assert provider.list_rules() == []


def test_enforce_logs_skip_to_audit_trail_for_low_severity():
    service, _, audit_logger = _make_service()
    service.enforce(Severity.LOW, "10.0.0.5", "PortScan", correlation_id="event-1")
    events = audit_logger.sink.read_all()
    assert len(events) == 1
    assert events[0].details["action"] == "auto_block_skipped"
    assert events[0].correlation_id == "event-1"


def test_enforce_logs_block_to_audit_trail_for_high_severity():
    service, _, audit_logger = _make_service()
    service.enforce(Severity.CRITICAL, "10.0.0.5", "DDoS", correlation_id="event-2")
    events = audit_logger.sink.read_all()
    assert len(events) == 1
    assert events[0].details["action"] == "block"
    assert events[0].correlation_id == "event-2"


def test_enforce_without_ip_does_not_crash():
    service, provider, _ = _make_service()
    decision = service.enforce(Severity.CRITICAL, None, "DDoS")
    assert decision.action_taken is False
    assert provider.list_rules() == []
