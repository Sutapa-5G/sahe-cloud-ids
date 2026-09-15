import pytest

from crypto.algorithms.ecdh_x25519 import (
    generate_keypair,
    derive_shared_key,
    sender_establish_key,
    recipient_recover_key,
    public_key_from_bytes,
    private_key_from_bytes,
    HKDF_OUTPUT_KEY_LENGTH,
)
from crypto.algorithms.aes_gcm import encrypt, decrypt


def test_keypair_generation_produces_valid_keys():
    kp = generate_keypair()
    assert len(kp.public_bytes()) == 32  # X25519 public keys are 32 bytes
    assert len(kp.private_bytes()) == 32


def test_shared_key_matches_both_directions():
    """
    Core ECDH property: both parties, using their own private key and the
    other's public key, must derive the SAME shared secret.
    """
    alice = generate_keypair()
    bob = generate_keypair()

    key_from_alice_side = derive_shared_key(alice.private_key, bob.public_key)
    key_from_bob_side = derive_shared_key(bob.private_key, alice.public_key)

    assert key_from_alice_side == key_from_bob_side
    assert len(key_from_alice_side) == HKDF_OUTPUT_KEY_LENGTH


def test_different_peer_produces_different_key():
    alice = generate_keypair()
    bob = generate_keypair()
    eve = generate_keypair()

    key_with_bob = derive_shared_key(alice.private_key, bob.public_key)
    key_with_eve = derive_shared_key(alice.private_key, eve.public_key)

    assert key_with_bob != key_with_eve


def test_sender_recipient_full_flow():
    """
    Full ECIES-like flow: recipient has a long-term keypair, sender
    establishes a key using an ephemeral keypair, encrypts a payload with
    AES-GCM using that key, and the recipient recovers the same key and
    decrypts.
    """
    recipient = generate_keypair()

    aes_key, context = sender_establish_key(recipient.public_key)
    plaintext = b"intrusion alert payload"
    ct = encrypt(plaintext, aes_key)

    recovered_key = recipient_recover_key(recipient.private_key, context)
    assert recovered_key == aes_key

    decrypted = decrypt(ct, recovered_key)
    assert decrypted == plaintext


def test_wrong_recipient_private_key_fails_to_recover_correct_key():
    recipient = generate_keypair()
    wrong_recipient = generate_keypair()

    aes_key, context = sender_establish_key(recipient.public_key)
    wrong_key = recipient_recover_key(wrong_recipient.private_key, context)

    assert wrong_key != aes_key


def test_public_private_key_serialization_roundtrip():
    kp = generate_keypair()
    pub_bytes = kp.public_bytes()
    priv_bytes = kp.private_bytes()

    restored_pub = public_key_from_bytes(pub_bytes)
    restored_priv = private_key_from_bytes(priv_bytes)

    # Using restored keys should reproduce the same shared secret as originals
    other = generate_keypair()
    original_shared = derive_shared_key(kp.private_key, other.public_key)
    restored_shared = derive_shared_key(restored_priv, other.public_key)
    assert original_shared == restored_shared


def test_hkdf_salt_changes_derived_key():
    alice = generate_keypair()
    bob = generate_keypair()
    key_no_salt = derive_shared_key(alice.private_key, bob.public_key, salt=None)
    key_with_salt = derive_shared_key(alice.private_key, bob.public_key, salt=b"some-salt-value")
    assert key_no_salt != key_with_salt


def test_hkdf_info_changes_derived_key():
    alice = generate_keypair()
    bob = generate_keypair()
    key_info_a = derive_shared_key(alice.private_key, bob.public_key, info=b"context-a")
    key_info_b = derive_shared_key(alice.private_key, bob.public_key, info=b"context-b")
    assert key_info_a != key_info_b
