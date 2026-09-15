"""
backend/app/services/alert_service.py

Phase 11: orchestrates what happens when a malicious detection occurs:
1. Broadcast a real-time alert to connected WebSocket clients.
2. Log the alert to the audit trail (with a correlation_id the caller
   reuses when it separately creates the persisted event record).

This is a SERVICE, not a route handler, so it can be tested directly
(no HTTP/WebSocket layer needed) and reused from multiple call sites
(the /detect route in this phase; a future live-traffic-capture path if
that nice-to-have is ever built).

Benign detections do NOT go through this service — only malicious ones
trigger alerts/broadcasts, matching the architecture diagram in
docs/architecture/overview.md (BENIGN -> normal logging, MALICIOUS ->
Alert Engine).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from backend.app.audit.audit_logger import AuditLogger
from backend.app.websocket.manager import ConnectionManager


@dataclass
class AlertPayload:
    """The shape broadcast to WebSocket clients. Deliberately does NOT
    include the raw feature vector or any encrypted payload — only the
    summary an operator's dashboard needs to display live."""
    event_id: str
    attack_type: str
    confidence: float
    severity: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "type": "alert",
            "event_id": self.event_id,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


class AlertService:
    def __init__(self, connection_manager: ConnectionManager, audit_logger: AuditLogger):
        self._connection_manager = connection_manager
        self._audit_logger = audit_logger

    async def raise_alert(
        self, attack_type: str, confidence: float, severity: str, event_id: str | None = None
    ) -> AlertPayload:
        """
        Broadcasts an alert and logs it to the audit trail. Does NOT
        create an event record itself — event persistence (in-memory or
        MongoDB, per Phase 10's fallback pattern) is the caller's
        responsibility, since the caller (the /detect route) already has
        the event-creation logic and this service shouldn't duplicate or
        fight over that decision. This keeps AlertService focused on one
        job: real-time notification.

        If `event_id` is not supplied, one is generated here — but
        callers that will ALSO create a persisted event record should
        pass a pre-generated event_id so the broadcast, the audit trail,
        and the stored event all share the same identifier.
        """
        resolved_event_id = event_id or str(uuid.uuid4())
        payload = AlertPayload(
            event_id=resolved_event_id,
            attack_type=attack_type,
            confidence=confidence,
            severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        await self._connection_manager.broadcast(payload.to_dict())
        self._audit_logger.log_detection(attack_type, confidence, correlation_id=resolved_event_id)
        self._audit_logger.log_severity_assignment({"final_severity": severity}, correlation_id=resolved_event_id)

        return payload
