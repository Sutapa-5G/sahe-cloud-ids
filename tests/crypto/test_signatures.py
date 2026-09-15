import pytest

from crypto.algorithms.signatures import (
    generate_keypair,
    sign,
    verify,
    SignatureVerificationError,
    public_key_from_bytes,
    private_key_from_bytes,
)


def test_sign_verify_roundtrip():
    kp = generate_keypair()
    message = b"audit record: event=block_ip severity=CRITICAL"
    signature = sign(message, kp.private_key)
    verify(message, signature, kp.public_key)  # should not raise


def test_tampered_message_fails_verification():
    kp = generate_keypair()
    message = b"original audit record"
    signature = sign(message, kp.private_key)
    with pytest.raises(SignatureVerificationError):
        verify(b"tampered audit record", signature, kp.public_key)


def test_wrong_public_key_fails_verification():
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    message = b"audit record"
    signature = sign(message, kp1.private_key)
    with pytest.raises(SignatureVerificationError):
        verify(message, signature, kp2.public_key)


def test_tampered_signature_fails_verification():
    kp = generate_keypair()
    message = b"audit record"
    signature = bytearray(sign(message, kp.private_key))
    signature[0] ^= 0xFF
    with pytest.raises(SignatureVerificationError):
        verify(message, bytes(signature), kp.public_key)


def test_key_serialization_roundtrip():
    kp = generate_keypair()
    pub_bytes = kp.public_bytes()
    priv_bytes = kp.private_bytes()

    restored_pub = public_key_from_bytes(pub_bytes)
    restored_priv = private_key_from_bytes(priv_bytes)

    message = b"audit record"
    signature = sign(message, restored_priv)
    verify(message, signature, restored_pub)  # should not raise


def test_different_messages_produce_different_signatures():
    kp = generate_keypair()
    sig1 = sign(b"message one", kp.private_key)
    sig2 = sign(b"message two", kp.private_key)
    assert sig1 != sig2
