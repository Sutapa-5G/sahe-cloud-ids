"""
crypto/algorithms/signatures.py

Ed25519 digital signatures. Per the Phase 0 correction, this is added
ONLY where a specific property is needed that AES-GCM's authentication
tag does not provide: non-repudiation to a third party (e.g. an auditor
who does not hold the shared AES key). AES-GCM's tag proves integrity
and authenticity to whoever holds the key; a signature proves origin
to anyone holding the public key, without needing the secret AES key
at all.

This module is deliberately NOT wired into the default encryption flow
for every message — SAHE (crypto/sahe/) decides, per severity/data-type
policy, whether a signature is warranted (currently: AUDIT + CRITICAL
only — see docs/methodology/crypto_design.md).
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption


class SignatureVerificationError(Exception):
    """Raised when signature verification fails. Never silently ignored."""


@dataclass
class Ed25519KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def generate_keypair() -> Ed25519KeyPair:
    private_key = Ed25519PrivateKey.generate()
    return Ed25519KeyPair(private_key=private_key, public_key=private_key.public_key())


def public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)


def private_key_from_bytes(data: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(data)


def sign(message: bytes, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(message)


def verify(message: bytes, signature: bytes, public_key: Ed25519PublicKey) -> None:
    """Raises SignatureVerificationError on failure. Returns None (no
    exception) on success — callers must not interpret a lack of return
    value as failure."""
    try:
        public_key.verify(signature, message)
    except InvalidSignature as e:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed: the message, signature, "
            "or public key do not match. This indicates tampering, wrong "
            "key, or a corrupted signature — never a normal outcome."
        ) from e
