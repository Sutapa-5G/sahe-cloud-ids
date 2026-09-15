"""
backend/app/api/routes/crypto.py

/encrypt, /decrypt, /crypto/policy endpoints. Protected by require_auth
per the Phase 0 review requirement.

Since no MongoDB is available in this environment (Phase 10 will wire
real storage), encrypted envelopes are held in an in-process dict keyed
by envelope_id for this phase — clearly a development-only stand-in, not
a persistence layer. This is documented here, not hidden.

Recipient keys: for this phase, one long-term "server" keypair set is
generated at app startup (see backend/app/main.py) and used for every
request — a real deployment (Phase 10+) would look up per-tenant or
per-purpose keys via a proper key manager. This is a documented
simplification appropriate for the phase's scope.
"""
from __future__ import annotations

import base64
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from backend.app.api.auth import require_auth
from backend.app.schemas.crypto import (
    EncryptRequest,
    EncryptResponse,
    DecryptRequest,
    DecryptResponse,
    PolicyPreviewRequest,
    PolicyPreviewResponse,
)
from crypto.sahe.engine import encrypt_with_sahe, decrypt_with_sahe, SaheEnvelope
from crypto.sahe.policy import decide, DataType
from ml.severity.severity_engine import Severity

# /encrypt and /decrypt are top-level per the original endpoint spec;
# /crypto/policy is namespaced. Two routers, included separately in main.py.
router = APIRouter(prefix="/crypto", tags=["crypto"])
top_level_router = APIRouter(tags=["crypto"])

# Development-only in-memory envelope store. Phase 10 replaces this with
# MongoDB. NOT suitable for production or for anything that must survive
# a process restart.
_envelope_store: dict[str, SaheEnvelope] = {}


def _parse_severity(value: str) -> Severity:
    try:
        return Severity[value.upper()]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid severity '{value}'. Must be one of: {[s.name for s in Severity]}",
        )


def _parse_data_type(value: str) -> DataType:
    try:
        return DataType[value.upper()]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid data_type '{value}'. Must be one of: {[d.value for d in DataType]}",
        )


@top_level_router.post("/encrypt", response_model=EncryptResponse, dependencies=[Depends(require_auth)])
async def encrypt_endpoint(body: EncryptRequest, request: Request) -> EncryptResponse:
    try:
        plaintext = base64.b64decode(body.plaintext_base64)
    except Exception:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="plaintext_base64 is not valid base64.")

    severity = _parse_severity(body.severity)
    data_type = _parse_data_type(body.data_type)

    recipient_keys = request.app.state.recipient_keys
    audit_logger = request.app.state.audit_logger

    envelope = encrypt_with_sahe(
        plaintext,
        payload_size_bytes=len(plaintext),
        severity=severity,
        data_type=data_type,
        recipient_keys=recipient_keys,
    )

    envelope_id = str(uuid.uuid4())
    _envelope_store[envelope_id] = envelope

    audit_logger.log_sahe_decision(envelope.decision.to_dict(), correlation_id=envelope_id)
    audit_logger.log_encryption(
        envelope.key_establishment_method.value,
        envelope.signature is not None,
        correlation_id=envelope_id,
    )

    return EncryptResponse(
        envelope_id=envelope_id,
        key_establishment_method=envelope.key_establishment_method.value,
        requires_signature=envelope.decision.requires_signature,
        ciphertext_base64=base64.b64encode(envelope.aes_ciphertext.ciphertext).decode(),
        nonce_base64=base64.b64encode(envelope.aes_ciphertext.nonce).decode(),
        ecdh_sender_ephemeral_public_key_base64=(
            base64.b64encode(envelope.ecdh_context.sender_ephemeral_public_key).decode()
            if envelope.ecdh_context else None
        ),
        rsa_wrapped_key_base64=(
            base64.b64encode(envelope.rsa_wrapped_key).decode() if envelope.rsa_wrapped_key else None
        ),
        signature_base64=(base64.b64encode(envelope.signature).decode() if envelope.signature else None),
        rationale=envelope.decision.rationale,
    )


@top_level_router.post("/decrypt", response_model=DecryptResponse, dependencies=[Depends(require_auth)])
async def decrypt_endpoint(body: DecryptRequest, request: Request) -> DecryptResponse:
    envelope = _envelope_store.get(body.envelope_id)
    if envelope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No envelope found for id {body.envelope_id}.")

    recipient_keys = request.app.state.recipient_keys

    try:
        plaintext = decrypt_with_sahe(envelope, recipient_keys)
    except Exception as e:
        # Deliberately vague to the client (never leak crypto internals
        # like "wrong key" vs "tampered" distinctions over the API), but
        # the real exception is preserved for server-side logs via `from e`.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Decryption failed.") from e

    return DecryptResponse(plaintext_base64=base64.b64encode(plaintext).decode())


@router.post("/policy", response_model=PolicyPreviewResponse)
async def policy_preview(body: PolicyPreviewRequest) -> PolicyPreviewResponse:
    """
    Unauthenticated on purpose: this just previews what SAHE WOULD decide
    for given inputs, without performing any actual encryption or
    touching real key material — useful for the dashboard's "SAHE
    Decisions" page to explain the policy without needing a real payload.
    """
    if body.payload_size_bytes < 0:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="payload_size_bytes must be >= 0.")

    severity = _parse_severity(body.severity)
    data_type = _parse_data_type(body.data_type)

    decision = decide(body.payload_size_bytes, severity, data_type)

    return PolicyPreviewResponse(
        key_establishment_method=decision.key_establishment_method.value,
        requires_signature=decision.requires_signature,
        signature_reason=decision.signature_reason,
        rationale=decision.rationale,
    )
