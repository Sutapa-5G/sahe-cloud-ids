import pytest

from backend.app.services.alert_service import AlertService, AlertPayload
from backend.app.websocket.manager import ConnectionManager
from backend.app.audit.audit_logger import AuditLogger, InMemoryAuditSink


class FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def accept(self):
        pass

    async def send_text(self, text):
        self.sent.append(text)


@pytest.mark.asyncio
async def test_raise_alert_broadcasts_to_connected_clients():
    manager = ConnectionManager()
    audit_logger = AuditLogger(InMemoryAuditSink())
    service = AlertService(manager, audit_logger)

    ws = FakeWebSocket()
    await manager.connect(ws)

    alert = await service.raise_alert(attack_type="DDoS", confidence=0.95, severity="CRITICAL")

    assert len(ws.sent) == 1
    assert "DDoS" in ws.sent[0]
    assert "CRITICAL" in ws.sent[0]
    assert isinstance(alert, AlertPayload)
    assert alert.attack_type == "DDoS"


@pytest.mark.asyncio
async def test_raise_alert_logs_to_audit_trail():
    manager = ConnectionManager()
    audit_logger = AuditLogger(InMemoryAuditSink())
    service = AlertService(manager, audit_logger)

    alert = await service.raise_alert(attack_type="PortScan", confidence=0.7, severity="LOW")

    events = audit_logger.sink.read_all()
    assert len(events) == 2  # detection + severity_assignment
    assert all(e.correlation_id == alert.event_id for e in events)


@pytest.mark.asyncio
async def test_raise_alert_uses_supplied_event_id():
    manager = ConnectionManager()
    audit_logger = AuditLogger(InMemoryAuditSink())
    service = AlertService(manager, audit_logger)

    alert = await service.raise_alert(
        attack_type="DDoS", confidence=0.9, severity="HIGH", event_id="my-custom-id"
    )
    assert alert.event_id == "my-custom-id"

    events = audit_logger.sink.read_all()
    assert all(e.correlation_id == "my-custom-id" for e in events)


@pytest.mark.asyncio
async def test_raise_alert_generates_id_when_not_supplied():
    manager = ConnectionManager()
    audit_logger = AuditLogger(InMemoryAuditSink())
    service = AlertService(manager, audit_logger)

    alert1 = await service.raise_alert(attack_type="DDoS", confidence=0.9, severity="HIGH")
    alert2 = await service.raise_alert(attack_type="DDoS", confidence=0.9, severity="HIGH")

    assert alert1.event_id != alert2.event_id


@pytest.mark.asyncio
async def test_raise_alert_with_no_connected_clients_does_not_error():
    manager = ConnectionManager()
    audit_logger = AuditLogger(InMemoryAuditSink())
    service = AlertService(manager, audit_logger)

    # No clients connected — should not raise.
    alert = await service.raise_alert(attack_type="DDoS", confidence=0.9, severity="HIGH")
    assert alert is not None


@pytest.mark.asyncio
async def test_alert_payload_to_dict_shape():
    manager = ConnectionManager()
    audit_logger = AuditLogger(InMemoryAuditSink())
    service = AlertService(manager, audit_logger)

    alert = await service.raise_alert(attack_type="DDoS", confidence=0.9, severity="HIGH")
    d = alert.to_dict()
    assert d["type"] == "alert"
    assert d["attack_type"] == "DDoS"
    assert d["confidence"] == 0.9
    assert d["severity"] == "HIGH"
    assert "timestamp" in d
