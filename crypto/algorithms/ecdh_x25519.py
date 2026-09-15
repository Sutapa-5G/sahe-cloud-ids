"""
crypto/algorithms/ecdh_x25519.py

Standard ECDH key establishment using Curve25519 (X25519), followed by
HKDF to derive a symmetric AES-256 key from the shared secret.

This is a standard ECIES-like construction — NOT an invented "ECC
key-wrap" primitive (per the Phase 0 correction). ECC never encrypts
payload data directly; it only ever establishes a key for AES-256-GCM
(see aes_gcm.py) to use.

Flow:
    1. Recipient has a long-term (or ephemeral, caller's choice) X25519
       key pair.
    2. Sender generates an ephemeral X25519 key pair.
    3. Both sides compute ECDH(their_private, other's_public) -> shared_secret
    4. HKDF(shared_secret, salt, info) -> 256-bit AES key
    5. The sender's ephemeral public key is sent alongside the ciphertext
       so the recipient can recompute the same shared secret.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

HKDF_INFO_DEFAULT = b"sahe-v1-aes-key"
HKDF_OUTPUT_KEY_LENGTH = 32  # 256-bit AES key


@dataclass
class X25519KeyPair:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_bytes(self) -> bytes:
        """Raw private key bytes. Handle with the same care as any secret
        key material — never log or store alongside ciphertext."""
        return self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def generate_keypair() -> X25519KeyPair:
    private_key = X25519PrivateKey.generate()
    return X25519KeyPair(private_key=private_key, public_key=private_key.public_key())


def public_key_from_bytes(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def private_key_from_bytes(data: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(data)


def derive_shared_key(
    own_private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    salt: bytes | None = None,
    info: bytes = HKDF_INFO_DEFAULT,
) -> bytes:
    """
    Computes ECDH(own_private, peer_public) and derives a 256-bit AES key
    via HKDF-SHA256. `salt` should ideally be a fresh random value shared
    out-of-band or derived from context (e.g. a per-message nonce/ID);
    None is cryptographically acceptable for HKDF (it uses a zero-salt
    fallback internally) but a real, per-message salt is recommended and
    should be decided when this is wired into the SAHE engine.
    """
    shared_secret = own_private_key.exchange(peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_OUTPUT_KEY_LENGTH,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


@dataclass
class EcdhEncryptionContext:
    """
    Everything the RECIPIENT needs to re-derive the same AES key that the
    sender used. This is what gets stored/transmitted alongside the
    AES-GCM ciphertext for the ECC key-establishment path.
    """
    sender_ephemeral_public_key: bytes
    hkdf_salt: bytes | None
    hkdf_info: bytes


def sender_establish_key(
    recipient_public_key: X25519PublicKey,
    salt: bytes | None = None,
    info: bytes = HKDF_INFO_DEFAULT,
) -> tuple[bytes, EcdhEncryptionContext]:
    """
    Sender side: generates a fresh ephemeral key pair, computes the shared
    AES key, and returns (aes_key, context_to_send_to_recipient).
    """
    ephemeral = generate_keypair()
    aes_key = derive_shared_key(ephemeral.private_key, recipient_public_key, salt=salt, info=info)
    context = EcdhEncryptionContext(
        sender_ephemeral_public_key=ephemeral.public_bytes(),
        hkdf_salt=salt,
        hkdf_info=info,
    )
    return aes_key, context


def recipient_recover_key(
    recipient_private_key: X25519PrivateKey,
    context: EcdhEncryptionContext,
) -> bytes:
    """Recipient side: recomputes the same AES key from the sender's
    ephemeral public key and the recipient's own private key."""
    sender_public = public_key_from_bytes(context.sender_ephemeral_public_key)
    return derive_shared_key(
        recipient_private_key, sender_public, salt=context.hkdf_salt, info=context.hkdf_info
    )
