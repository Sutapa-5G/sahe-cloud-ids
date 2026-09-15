"""
crypto/sahe/engine.py

Executes a SaheDecision (crypto/sahe/policy.py) using the real crypto
primitives in crypto/algorithms/. This is where policy meets mechanism:
AES-256-GCM always encrypts the payload; the chosen key-establishment
method (ECDH/X25519 or RSA-OAEP) wraps/derives the AES key; a signature
is attached only if the policy decision requires one.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto.algorithms.aes_gcm import generate_aes_key, encrypt, decrypt, AesGcmCiphertext
from crypto.algorithms.ecdh_x25519 import (
    sender_establish_key,
    recipient_recover_key,
    EcdhEncryptionContext,
)
from crypto.algorithms.rsa_oaep_hybrid import wrap_key, unwrap_key
from crypto.algorithms.signatures import sign, verify
from crypto.sahe.policy import SaheDecision, KeyEstablishmentMethod, decide, DataType
from ml.severity.severity_engine import Severity


@dataclass
class RecipientKeys:
    """The recipient's long-term key material for both possible
    key-establishment paths, plus signing key if signatures may be
    required. A real deployment would source these from a proper key
    manager (see docs/methodology/crypto_design.md); this dataclass is
    the interface Phase 9's key_manager.py will need to satisfy."""
    x25519_private_key: X25519PrivateKey
    x25519_public_key: X25519PublicKey
    rsa_private_key: RSAPrivateKey
    rsa_public_key: RSAPublicKey
    ed25519_private_key: Ed25519PrivateKey | None = None
    ed25519_public_key: Ed25519PublicKey | None = None


@dataclass
class SaheEnvelope:
    """Everything needed to decrypt: the AES-GCM ciphertext plus whichever
    key-establishment context/wrapped-key was used, plus an optional
    signature. This is the shape that would be stored in MongoDB
    (Phase 10) alongside event metadata."""
    decision: SaheDecision
    aes_ciphertext: AesGcmCiphertext
    key_establishment_method: KeyEstablishmentMethod
    ecdh_context: EcdhEncryptionContext | None
    rsa_wrapped_key: bytes | None
    signature: bytes | None


def encrypt_with_sahe(
    plaintext: bytes,
    payload_size_bytes: int,
    severity: Severity,
    data_type: DataType,
    recipient_keys: RecipientKeys,
    associated_data: bytes | None = None,
) -> SaheEnvelope:
    """
    Runs the SAHE policy decision, then executes it: generates/derives an
    AES key via the chosen method, encrypts the payload, and signs if
    required.
    """
    decision = decide(payload_size_bytes, severity, data_type)

    ecdh_context = None
    rsa_wrapped_key = None

    if decision.key_establishment_method == KeyEstablishmentMethod.ECDH_X25519:
        aes_key, ecdh_context = sender_establish_key(recipient_keys.x25519_public_key)
    else:
        aes_key = generate_aes_key()
        rsa_wrapped_key = wrap_key(aes_key, recipient_keys.rsa_public_key)

    aes_ciphertext = encrypt(plaintext, aes_key, associated_data=associated_data)

    signature = None
    if decision.requires_signature:
        if recipient_keys.ed25519_private_key is None:
            raise ValueError(
                "SAHE policy requires a signature for this "
                "severity/data_type combination, but no Ed25519 signing "
                "key was provided in recipient_keys."
            )
        # Sign over the ciphertext + nonce, so the signature covers exactly
        # what will be stored/transmitted.
        message_to_sign = aes_ciphertext.ciphertext + aes_ciphertext.nonce
        signature = sign(message_to_sign, recipient_keys.ed25519_private_key)

    return SaheEnvelope(
        decision=decision,
        aes_ciphertext=aes_ciphertext,
        key_establishment_method=decision.key_establishment_method,
        ecdh_context=ecdh_context,
        rsa_wrapped_key=rsa_wrapped_key,
        signature=signature,
    )


def decrypt_with_sahe(envelope: SaheEnvelope, recipient_keys: RecipientKeys) -> bytes:
    """
    Reverses encrypt_with_sahe: recovers the AES key via the same method
    that was used, verifies the signature if present, and decrypts.
    """
    if envelope.signature is not None:
        if recipient_keys.ed25519_public_key is None:
            raise ValueError("Envelope has a signature but no Ed25519 public key was provided to verify it.")
        message_to_verify = envelope.aes_ciphertext.ciphertext + envelope.aes_ciphertext.nonce
        verify(message_to_verify, envelope.signature, recipient_keys.ed25519_public_key)

    if envelope.key_establishment_method == KeyEstablishmentMethod.ECDH_X25519:
        if envelope.ecdh_context is None:
            raise ValueError("Envelope specifies ECDH_X25519 but has no ecdh_context.")
        aes_key = recipient_recover_key(recipient_keys.x25519_private_key, envelope.ecdh_context)
    else:
        if envelope.rsa_wrapped_key is None:
            raise ValueError("Envelope specifies RSA_OAEP but has no rsa_wrapped_key.")
        aes_key = unwrap_key(envelope.rsa_wrapped_key, recipient_keys.rsa_private_key)

    return decrypt(envelope.aes_ciphertext, aes_key)
