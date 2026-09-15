import pytest

from crypto.sahe.engine import RecipientKeys, encrypt_with_sahe, decrypt_with_sahe
from crypto.sahe.policy import DataType, KeyEstablishmentMethod, SaheConfig
from crypto.algorithms import ecdh_x25519, rsa_oaep_hybrid, signatures
from ml.severity.severity_engine import Severity


@pytest.fixture(scope="module")
def recipient_keys():
    """
    Generates one full set of recipient key material once per test module
    (RSA keygen in particular is slow) — used across tests that don't
    need to mutate it.
    """
    x25519_kp = ecdh_x25519.generate_keypair()
    rsa_kp = rsa_oaep_hybrid.generate_rsa_keypair()
    ed_kp = signatures.generate_keypair()
    return RecipientKeys(
        x25519_private_key=x25519_kp.private_key,
        x25519_public_key=x25519_kp.public_key,
        rsa_private_key=rsa_kp.private_key,
        rsa_public_key=rsa_kp.public_key,
        ed25519_private_key=ed_kp.private_key,
        ed25519_public_key=ed_kp.public_key,
    )


def test_encrypt_decrypt_roundtrip_ecdh_path(recipient_keys):
    plaintext = b"intrusion alert: DDoS detected from 10.0.0.5"
    envelope = encrypt_with_sahe(
        plaintext,
        payload_size_bytes=len(plaintext),
        severity=Severity.HIGH,
        data_type=DataType.ALERT,
        recipient_keys=recipient_keys,
    )
    assert envelope.key_establishment_method == KeyEstablishmentMethod.ECDH_X25519
    assert envelope.signature is None  # ALERT, not AUDIT+CRITICAL

    recovered = decrypt_with_sahe(envelope, recipient_keys)
    assert recovered == plaintext


def test_encrypt_decrypt_roundtrip_rsa_path(recipient_keys):
    plaintext = b"large log file contents " * 1000
    config = SaheConfig(large_payload_threshold_bytes=1000)  # force RSA path for this test payload size

    from crypto.sahe.policy import decide
    decision = decide(len(plaintext), Severity.LOW, DataType.FILE, config=config)
    assert decision.key_establishment_method == KeyEstablishmentMethod.RSA_OAEP

    # encrypt_with_sahe uses the default SaheConfig internally; to exercise
    # the RSA path through the public API we construct a large enough
    # plaintext to cross the DEFAULT large threshold instead.
    large_plaintext = b"X" * (1024 * 1024 + 1)  # just over the 1MB default threshold
    envelope = encrypt_with_sahe(
        large_plaintext,
        payload_size_bytes=len(large_plaintext),
        severity=Severity.LOW,
        data_type=DataType.FILE,
        recipient_keys=recipient_keys,
    )
    assert envelope.key_establishment_method == KeyEstablishmentMethod.RSA_OAEP
    assert envelope.rsa_wrapped_key is not None
    assert envelope.ecdh_context is None

    recovered = decrypt_with_sahe(envelope, recipient_keys)
    assert recovered == large_plaintext


def test_audit_critical_produces_signature(recipient_keys):
    plaintext = b"audit: admin deleted firewall rule for 10.0.0.5"
    envelope = encrypt_with_sahe(
        plaintext,
        payload_size_bytes=len(plaintext),
        severity=Severity.CRITICAL,
        data_type=DataType.AUDIT,
        recipient_keys=recipient_keys,
    )
    assert envelope.signature is not None
    recovered = decrypt_with_sahe(envelope, recipient_keys)
    assert recovered == plaintext


def test_missing_signing_key_raises_when_signature_required():
    x25519_kp = ecdh_x25519.generate_keypair()
    rsa_kp = rsa_oaep_hybrid.generate_rsa_keypair()
    keys_without_signing = RecipientKeys(
        x25519_private_key=x25519_kp.private_key,
        x25519_public_key=x25519_kp.public_key,
        rsa_private_key=rsa_kp.private_key,
        rsa_public_key=rsa_kp.public_key,
        # ed25519 keys deliberately omitted
    )
    with pytest.raises(ValueError, match="Ed25519 signing key"):
        encrypt_with_sahe(
            b"critical audit event",
            payload_size_bytes=21,
            severity=Severity.CRITICAL,
            data_type=DataType.AUDIT,
            recipient_keys=keys_without_signing,
        )


def test_tampered_signature_detected_on_decrypt(recipient_keys):
    plaintext = b"audit record"
    envelope = encrypt_with_sahe(
        plaintext,
        payload_size_bytes=len(plaintext),
        severity=Severity.CRITICAL,
        data_type=DataType.AUDIT,
        recipient_keys=recipient_keys,
    )
    tampered_sig = bytearray(envelope.signature)
    tampered_sig[0] ^= 0xFF
    envelope.signature = bytes(tampered_sig)

    from crypto.algorithms.signatures import SignatureVerificationError
    with pytest.raises(SignatureVerificationError):
        decrypt_with_sahe(envelope, recipient_keys)


def test_wrong_recipient_cannot_decrypt_ecdh_path(recipient_keys):
    plaintext = b"secret alert"
    envelope = encrypt_with_sahe(
        plaintext,
        payload_size_bytes=len(plaintext),
        severity=Severity.MEDIUM,
        data_type=DataType.LOG,
        recipient_keys=recipient_keys,
    )

    wrong_x25519 = ecdh_x25519.generate_keypair()
    wrong_keys = RecipientKeys(
        x25519_private_key=wrong_x25519.private_key,
        x25519_public_key=wrong_x25519.public_key,
        rsa_private_key=recipient_keys.rsa_private_key,
        rsa_public_key=recipient_keys.rsa_public_key,
    )

    from crypto.algorithms.aes_gcm import DecryptionError
    with pytest.raises(DecryptionError):
        decrypt_with_sahe(envelope, wrong_keys)


def test_associated_data_passed_through(recipient_keys):
    plaintext = b"log entry"
    envelope = encrypt_with_sahe(
        plaintext,
        payload_size_bytes=len(plaintext),
        severity=Severity.LOW,
        data_type=DataType.LOG,
        recipient_keys=recipient_keys,
        associated_data=b"event_id=42",
    )
    recovered = decrypt_with_sahe(envelope, recipient_keys)
    assert recovered == plaintext
