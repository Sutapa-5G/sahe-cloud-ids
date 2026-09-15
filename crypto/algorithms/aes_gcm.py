"""
crypto/algorithms/aes_gcm.py

AES-256-GCM authenticated encryption. Per the project's cryptographic
design rules, this is the ONLY mechanism that encrypts payload bytes
directly, anywhere in this system. ECC and RSA (see ecdh_x25519.py and
rsa_oaep_hybrid.py) are used only to establish/wrap the AES key.

GCM already provides authenticity (via its tag) alongside confidentiality
— no additional HMAC is stacked on top by default anywhere in this
module, per the Phase 0 correction.

Nonce discipline: a random 96-bit (12-byte) nonce is generated per
encryption call using a CSPRNG (os.urandom via the cryptography library's
internals). The SAME (key, nonce) pair must NEVER be reused — this
module generates a fresh random nonce every call specifically to make
that misuse difficult, but it is still the CALLER'S responsibility not
to reuse a (key, nonce) pair returned from elsewhere.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

AES_KEY_SIZE_BYTES = 32          # AES-256
AES_GCM_NONCE_SIZE_BYTES = 12    # 96 bits, the standard/recommended GCM nonce size
AES_GCM_TAG_SIZE_BYTES = 16      # 128-bit authentication tag (appended by AESGCM internally)


class DecryptionError(Exception):
    """Raised when authenticated decryption fails (tampered ciphertext,
    wrong key, or wrong nonce/AAD). Never silently returns garbage
    plaintext."""


@dataclass
class AesGcmCiphertext:
    ciphertext: bytes          # includes the appended 16-byte tag, per AESGCM's convention
    nonce: bytes
    associated_data: bytes | None


def generate_aes_key() -> bytes:
    """Generates a fresh random AES-256 key using a CSPRNG."""
    return AESGCM.generate_key(bit_length=256)


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes | None = None) -> AesGcmCiphertext:
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")

    nonce = os.urandom(AES_GCM_NONCE_SIZE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return AesGcmCiphertext(ciphertext=ciphertext, nonce=nonce, associated_data=associated_data)


def decrypt(ct: AesGcmCiphertext, key: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(ct.nonce, ct.ciphertext, ct.associated_data)
    except InvalidTag as e:
        raise DecryptionError(
            "AES-GCM authentication failed: ciphertext, nonce, key, or "
            "associated data do not match. This indicates tampering, "
            "corruption, or a programming error (wrong key/nonce/AAD) — "
            "never a normal outcome."
        ) from e
