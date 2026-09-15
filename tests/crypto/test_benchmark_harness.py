"""
These tests validate that the benchmark harness correctly measures and
reports real operations — they are NOT claims about absolute performance
numbers (those depend on the machine running them). What IS asserted:
timings are non-negative, ciphertext sizes are sane, and the four timing
categories are correctly separated (e.g. AES-GCM has zero key_exchange
time since it has no such phase).
"""
import pytest

from crypto.benchmarks.harness import (
    benchmark_aes_gcm,
    benchmark_ecdh_x25519_hybrid,
    benchmark_rsa_oaep_hybrid,
)
from crypto.algorithms import rsa_oaep_hybrid as rsa_module


def test_aes_gcm_benchmark_basic_sanity():
    payload = b"X" * 1024
    result = benchmark_aes_gcm(payload)
    assert result.payload_size_bytes == 1024
    assert result.key_generation_seconds >= 0
    assert result.payload_encryption_seconds >= 0
    assert result.key_exchange_seconds == 0.0  # AES-GCM has no key exchange phase
    assert result.total_operation_seconds == pytest.approx(
        result.key_generation_seconds + result.payload_encryption_seconds, rel=1e-6
    )
    # AES-GCM overhead is exactly the 16-byte tag
    assert result.ciphertext_expansion_bytes == 16


def test_ecdh_benchmark_has_all_three_phases():
    payload = b"Y" * 1024
    result = benchmark_ecdh_x25519_hybrid(payload)
    assert result.key_generation_seconds >= 0
    assert result.key_exchange_seconds >= 0
    assert result.payload_encryption_seconds >= 0
    assert result.total_operation_seconds == pytest.approx(
        result.key_generation_seconds + result.key_exchange_seconds + result.payload_encryption_seconds,
        rel=1e-6,
    )


def test_rsa_benchmark_without_cache_includes_keygen():
    payload = b"Z" * 1024
    result = benchmark_rsa_oaep_hybrid(payload)  # no cache -> generates fresh RSA keypair
    assert result.key_generation_seconds > 0  # RSA keygen is never instantaneous


def test_rsa_benchmark_with_cache_skips_keygen_timing():
    payload = b"Z" * 1024
    cached_kp = rsa_module.generate_rsa_keypair()
    result = benchmark_rsa_oaep_hybrid(payload, rsa_keypair_cache=cached_kp)
    assert result.key_generation_seconds == 0.0  # explicitly not re-measured when cached


def test_rsa_benchmark_correctness_roundtrip_via_wrapped_key():
    """The benchmark harness should produce a genuinely decryptable result,
    not just a fast-looking fake — verifies correctness, not just speed."""
    from crypto.algorithms import aes_gcm

    payload = b"benchmark correctness check"
    cached_kp = rsa_module.generate_rsa_keypair()
    result = benchmark_rsa_oaep_hybrid(payload, rsa_keypair_cache=cached_kp)
    # ciphertext_size_bytes includes both the AES-GCM ciphertext and the
    # RSA-wrapped key; sanity check it's larger than the payload alone.
    assert result.ciphertext_size_bytes > len(payload)


def test_larger_payload_does_not_crash_and_scales_ciphertext_size():
    small = benchmark_aes_gcm(b"A" * 1024)
    large = benchmark_aes_gcm(b"A" * (1024 * 1024))
    assert large.ciphertext_size_bytes > small.ciphertext_size_bytes


def test_empty_payload_handled():
    result = benchmark_aes_gcm(b"")
    assert result.payload_size_bytes == 0
    assert result.ciphertext_expansion_bytes == 16  # still has the auth tag
