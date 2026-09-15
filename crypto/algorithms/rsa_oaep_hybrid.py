"""
crypto/algorithms/rsa_oaep_hybrid.py

RSA-OAEP is used ONLY to wrap (encrypt) a randomly generated AES-256 key.
It never encrypts payload data directly — raw RSA has well-known
weaknesses for bulk data (message size limits tied to key size, no
semantic security without proper padding, extremely slow relative to
AES). OAEP padding is used, not raw/textbook RSA.

Flow:
    1. Generate a random AES-256 key (see aes_gcm.generate_aes_key()).
    2. Encrypt the actual payload with AES-256-GCM (aes_gcm.py).
    3. Wrap the AES key with RSA-OAEP using the recipient's RSA public key.
    4. Store/transmit: AES-GCM ciphertext + nonce + wrapped AES key.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_pem_public_key,
    load_pem_private_key,
)

RSA_KEY_SIZE_BITS = 3072  # ~128-bit security level, matches common modern guidance (2048 is a floor, 3072 is more future-proof)
RSA_PUBLIC_EXPONENT = 65537


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


@dataclass
class RsaKeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey

    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def private_pem(self) -> bytes:
        """Unencrypted PEM. Caller is responsible for secure storage —
        never write this next to ciphertext or commit it to source control."""
        return self.private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def generate_rsa_keypair(key_size_bits: int = RSA_KEY_SIZE_BITS) -> RsaKeyPair:
    private_key = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=key_size_bits)
    return RsaKeyPair(private_key=private_key, public_key=private_key.public_key())


def load_public_key_from_pem(pem_data: bytes) -> rsa.RSAPublicKey:
    return load_pem_public_key(pem_data)


def load_private_key_from_pem(pem_data: bytes) -> rsa.RSAPrivateKey:
    return load_pem_private_key(pem_data, password=None)


def wrap_key(aes_key: bytes, recipient_public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypts (wraps) an AES key using RSA-OAEP."""
    return recipient_public_key.encrypt(aes_key, _oaep_padding())


def unwrap_key(wrapped_key: bytes, recipient_private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypts (unwraps) an AES key using RSA-OAEP."""
    return recipient_private_key.decrypt(wrapped_key, _oaep_padding())
