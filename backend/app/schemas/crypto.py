"""
backend/app/schemas/crypto.py

Request/response schemas for /encrypt, /decrypt, /crypto/policy.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class EncryptRequest(BaseModel):
    plaintext_base64: str = Field(..., description="Base64-encoded plaintext bytes to encrypt.")
    severity: str = Field(..., description="One of LOW, MEDIUM, HIGH, CRITICAL.")
    data_type: str = Field(..., description="One of LOG, ALERT, FILE, AUDIT.")


class EncryptResponse(BaseModel):
    envelope_id: str
    key_establishment_method: str
    requires_signature: bool
    ciphertext_base64: str
    nonce_base64: str
    # Only one of these two will be populated, matching key_establishment_method
    ecdh_sender_ephemeral_public_key_base64: str | None
    rsa_wrapped_key_base64: str | None
    signature_base64: str | None
    rationale: str


class DecryptRequest(BaseModel):
    envelope_id: str


class DecryptResponse(BaseModel):
    plaintext_base64: str


class PolicyPreviewRequest(BaseModel):
    payload_size_bytes: int
    severity: str
    data_type: str


class PolicyPreviewResponse(BaseModel):
    key_establishment_method: str
    requires_signature: bool
    signature_reason: str | None
    rationale: str
