import pytest

from crypto.algorithms.aes_gcm import (
    generate_aes_key,
    encrypt,
    decrypt,
    DecryptionError,
    AES_KEY_SIZE_BYTES,
    AES_GCM_NONCE_SIZE_BYTES,
)


def test_generate_key_correct_length():
    key = generate_aes_key()
    assert len(key) == AES_KEY_SIZE_BYTES


def test_encrypt_decrypt_roundtrip():
    key = generate_aes_key()
    plaintext = b"the quick brown fox jumps over the lazy dog"
    ct = encrypt(plaintext, key)
    recovered = decrypt(ct, key)
    assert recovered == plaintext


def test_encrypt_produces_random_nonce_each_time():
    key = generate_aes_key()
    ct1 = encrypt(b"same message", key)
    ct2 = encrypt(b"same message", key)
    assert ct1.nonce != ct2.nonce
    assert len(ct1.nonce) == AES_GCM_NONCE_SIZE_BYTES


def test_ciphertext_differs_from_plaintext():
    key = generate_aes_key()
    plaintext = b"sensitive log data"
    ct = encrypt(plaintext, key)
    assert ct.ciphertext != plaintext


def test_wrong_key_fails_decryption():
    key1 = generate_aes_key()
    key2 = generate_aes_key()
    ct = encrypt(b"secret", key1)
    with pytest.raises(DecryptionError):
        decrypt(ct, key2)


def test_tampered_ciphertext_detected():
    key = generate_aes_key()
    ct = encrypt(b"secret payload", key)
    tampered_bytes = bytearray(ct.ciphertext)
    tampered_bytes[0] ^= 0xFF  # flip a bit
    ct.ciphertext = bytes(tampered_bytes)
    with pytest.raises(DecryptionError):
        decrypt(ct, key)


def test_tampered_nonce_detected():
    key = generate_aes_key()
    ct = encrypt(b"secret payload", key)
    tampered_nonce = bytearray(ct.nonce)
    tampered_nonce[0] ^= 0xFF
    ct.nonce = bytes(tampered_nonce)
    with pytest.raises(DecryptionError):
        decrypt(ct, key)


def test_associated_data_authenticated():
    key = generate_aes_key()
    ct = encrypt(b"payload", key, associated_data=b"event_id=123")
    # Correct AAD decrypts fine
    assert decrypt(ct, key) == b"payload"
    # Wrong AAD fails
    ct.associated_data = b"event_id=456"
    with pytest.raises(DecryptionError):
        decrypt(ct, key)


def test_invalid_key_length_rejected():
    with pytest.raises(ValueError):
        encrypt(b"data", b"too_short_key")


def test_empty_plaintext_roundtrip():
    key = generate_aes_key()
    ct = encrypt(b"", key)
    assert decrypt(ct, key) == b""


def test_large_payload_roundtrip():
    key = generate_aes_key()
    plaintext = b"A" * (5 * 1024 * 1024)  # 5 MB synthetic payload, testing code path not real data
    ct = encrypt(plaintext, key)
    assert decrypt(ct, key) == plaintext
