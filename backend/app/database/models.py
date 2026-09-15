"""
backend/app/database/models.py

Pydantic models matching the MongoDB document schema from
docs/architecture/overview.md. Used both for validating data before
insert and for typing repository return values.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field


class CryptoMetadata(BaseModel):
    scheme: str
    key_management: str
    cipher: str = "AES-256-GCM"


class ModelInfo(BaseModel):
    name: str
    confidence: float


class EventDocument(BaseModel):
    event_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attack_type: str
    severity: str
    crypto: CryptoMetadata
    payload_base64: str  # ciphertext, base64-encoded for JSON/BSON-friendly storage
    nonce_base64: str
    auth_tag_included_in_payload: bool = True  # AES-GCM's tag is appended to ciphertext by this project's convention
    model: ModelInfo | None = None
    blocking_action: str | None = None


class BenchmarkResultDocument(BaseModel):
    algorithm: str
    payload_size_bytes: int
    total_operation_seconds_mean: float
    throughput_mb_per_second_mean: float | None = None
    run_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FirewallActionDocument(BaseModel):
    ip: str
    action: str  # "block" | "unblock"
    mode: str    # "simulated" | "iptables"
    reason: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditLogDocument(BaseModel):
    audit_id: str
    event_type: str
    details: dict
    correlation_id: str | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
