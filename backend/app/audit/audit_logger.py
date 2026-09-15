"""
backend/app/audit/audit_logger.py

Security audit logging, per the Phase 0 review requirement: "Add
security audit logging to the architecture for: detection, severity
assignment, SAHE decision, encryption, storage, and firewall/block
actions."

This module defines the audit event shape and an abstract sink
interface. Two sink implementations are provided:

  - InMemoryAuditSink: for tests and this phase's structural validation
    (no MongoDB available in the assistant's sandbox).
  - MongoAuditSink: a thin wrapper the Phase 10 MongoDB integration will
    complete — defined now so the interface exists, but its actual
    database calls are NOT exercised here (no real MongoDB in this
    environment). This is flagged, not hidden.

Audit entries are append-only by design: this module exposes no
update/delete operation on any sink.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum


class AuditEventType(str, Enum):
    DETECTION = "DETECTION"
    SEVERITY_ASSIGNMENT = "SEVERITY_ASSIGNMENT"
    SAHE_DECISION = "SAHE_DECISION"
    ENCRYPTION = "ENCRYPTION"
    STORAGE = "STORAGE"
    FIREWALL_ACTION = "FIREWALL_ACTION"
    AUTH_FAILURE = "AUTH_FAILURE"


@dataclass
class AuditEvent:
    event_type: AuditEventType
    details: dict
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    correlation_id: str | None = None  # links related events (e.g. one detection -> one SAHE decision -> one storage event)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


class AuditSink(ABC):
    @abstractmethod
    def write(self, event: AuditEvent) -> None:
        ...

    @abstractmethod
    def read_all(self) -> list[AuditEvent]:
        """Read-only retrieval, for tests/inspection. A real deployment's
        MongoAuditSink would paginate; this base interface doesn't
        mandate that, since InMemoryAuditSink doesn't need it."""
        ...


class InMemoryAuditSink(AuditSink):
    """Used for tests and for this phase's structural validation, since
    no MongoDB is available in this environment."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self._events.append(event)

    def read_all(self) -> list[AuditEvent]:
        return list(self._events)


class MongoAuditSink(AuditSink):
    """
    Phase 10 will complete this. The interface is defined now so
    services can depend on `AuditSink` (the abstraction) rather than a
    concrete implementation, but the actual `motor`/`pymongo` calls are
    NOT implemented or tested here — there is no MongoDB instance in the
    assistant's sandbox to test against. Calling write()/read_all() on
    this class as currently written will raise NotImplementedError.
    """

    def __init__(self, collection):
        """`collection` is expected to be a pymongo/motor collection
        object, injected by Phase 10's database setup code — not
        constructed here."""
        self._collection = collection

    def write(self, event: AuditEvent) -> None:
        raise NotImplementedError(
            "MongoAuditSink.write() is not implemented yet — Phase 10 "
            "will wire this to a real MongoDB collection. No MongoDB "
            "instance is available in the current environment to "
            "implement/test this against."
        )

    def read_all(self) -> list[AuditEvent]:
        raise NotImplementedError(
            "MongoAuditSink.read_all() is not implemented yet — same "
            "reason as write()."
        )


class AuditLogger:
    """
    Thin convenience wrapper so calling code writes
    `audit_logger.log_detection(...)` instead of constructing
    AuditEvent(...) by hand everywhere.
    """

    def __init__(self, sink: AuditSink):
        self.sink = sink

    def _log(self, event_type: AuditEventType, details: dict, correlation_id: str | None = None) -> AuditEvent:
        event = AuditEvent(event_type=event_type, details=details, correlation_id=correlation_id)
        self.sink.write(event)
        return event

    def log_detection(self, attack_type: str, confidence: float, correlation_id: str | None = None) -> AuditEvent:
        return self._log(
            AuditEventType.DETECTION,
            {"attack_type": attack_type, "confidence": confidence},
            correlation_id,
        )

    def log_severity_assignment(self, decision_dict: dict, correlation_id: str | None = None) -> AuditEvent:
        return self._log(AuditEventType.SEVERITY_ASSIGNMENT, decision_dict, correlation_id)

    def log_sahe_decision(self, decision_dict: dict, correlation_id: str | None = None) -> AuditEvent:
        return self._log(AuditEventType.SAHE_DECISION, decision_dict, correlation_id)

    def log_encryption(self, key_establishment_method: str, has_signature: bool, correlation_id: str | None = None) -> AuditEvent:
        return self._log(
            AuditEventType.ENCRYPTION,
            {"key_establishment_method": key_establishment_method, "has_signature": has_signature},
            correlation_id,
        )

    def log_storage(self, event_id: str, collection: str, correlation_id: str | None = None) -> AuditEvent:
        return self._log(AuditEventType.STORAGE, {"event_id": event_id, "collection": collection}, correlation_id)

    def log_firewall_action(self, action: str, ip: str, mode: str, correlation_id: str | None = None) -> AuditEvent:
        return self._log(
            AuditEventType.FIREWALL_ACTION,
            {"action": action, "ip": ip, "mode": mode},
            correlation_id,
        )

    def log_auth_failure(self, reason: str, correlation_id: str | None = None) -> AuditEvent:
        return self._log(AuditEventType.AUTH_FAILURE, {"reason": reason}, correlation_id)
