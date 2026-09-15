import pytest

from crypto.algorithms.rsa_oaep_hybrid import (
    generate_rsa_keypair,
    wrap_key,
    unwrap_key,
    load_public_key_from_pem,
    load_private_key_from_pem,
)
from crypto.algorithms.aes_gcm import generate_aes_key, encrypt, decrypt


# Generating a 3072-bit RSA keypair is somewhat slow; do it once per test
# module rather than per test.
@pytest.fixture(scope="module")
def rsa_keypair():
    return generate_rsa_keypair()


def test_wrap_unwrap_roundtrip(rsa_keypair):
    aes_key = generate_aes_key()
    wrapped = wrap_key(aes_key, rsa_keypair.public_key)
    unwrapped = unwrap_key(wrapped, rsa_keypair.private_key)
    assert unwrapped == aes_key


def test_wrapped_key_differs_from_original(rsa_keypair):
    aes_key = generate_aes_key()
    wrapped = wrap_key(aes_key, rsa_keypair.public_key)
    assert wrapped != aes_key


def test_full_hybrid_flow(rsa_keypair):
    """RSA wraps the AES key; AES-GCM encrypts the actual payload —
    confirms RSA is never used to encrypt payload directly."""
    aes_key = generate_aes_key()
    plaintext = b"confidential intrusion log"
    ct = encrypt(plaintext, aes_key)
    wrapped_key = wrap_key(aes_key, rsa_keypair.public_key)

    # Recipient side
    recovered_key = unwrap_key(wrapped_key, rsa_keypair.private_key)
    decrypted = decrypt(ct, recovered_key)
    assert decrypted == plaintext


def test_wrong_private_key_fails_to_unwrap():
    kp1 = generate_rsa_keypair()
    kp2 = generate_rsa_keypair()
    aes_key = generate_aes_key()
    wrapped = wrap_key(aes_key, kp1.public_key)
    with pytest.raises(Exception):  # cryptography raises its own ValueError/InvalidKey-family error
        unwrap_key(wrapped, kp2.private_key)


def test_pem_serialization_roundtrip(rsa_keypair):
    pub_pem = rsa_keypair.public_pem()
    priv_pem = rsa_keypair.private_pem()

    restored_pub = load_public_key_from_pem(pub_pem)
    restored_priv = load_private_key_from_pem(priv_pem)

    aes_key = generate_aes_key()
    wrapped = wrap_key(aes_key, restored_pub)
    unwrapped = unwrap_key(wrapped, restored_priv)
    assert unwrapped == aes_key


def test_pem_is_actually_pem_format(rsa_keypair):
    pub_pem = rsa_keypair.public_pem()
    assert pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    priv_pem = rsa_keypair.private_pem()
    assert priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
