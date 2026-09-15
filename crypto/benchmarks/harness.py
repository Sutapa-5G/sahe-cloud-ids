"""
crypto/benchmarks/harness.py

Benchmarking harness for the crypto primitives in crypto/algorithms/ and
the SAHE engine in crypto/sahe/. Per the Phase 0 correction, timing is
separated into four categories rather than one blended number:

  1. key_generation_seconds      - generating a fresh key pair (or AES key)
  2. key_exchange_seconds        - ECDH computation + HKDF derivation, or
                                    RSA-OAEP wrap/unwrap of the AES key
  3. payload_encryption_seconds  - AES-256-GCM (or legacy cipher) on the
                                    payload itself
  4. total_operation_seconds     - sum of the above, end-to-end, as the
                                    caller would experience it

Every timed value here comes from an ACTUAL executed operation using
Python's time.perf_counter() — nothing in this module is estimated,
interpolated, or fabricated. CPU/memory are sampled via psutil around
the operation; on a single-core sandbox (as this environment has),
per-operation CPU delta for microsecond-scale operations can be noisy —
this is noted in results, not hidden.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, asdict

import psutil

from crypto.algorithms import aes_gcm, ecdh_x25519, rsa_oaep_hybrid


@dataclass
class OperationTiming:
    key_generation_seconds: float
    key_exchange_seconds: float
    payload_encryption_seconds: float
    total_operation_seconds: float
    payload_size_bytes: int
    cpu_percent_during_op: float | None
    memory_delta_bytes: int | None
    ciphertext_size_bytes: int
    ciphertext_expansion_bytes: int  # ciphertext_size - payload_size (overhead)

    def to_dict(self) -> dict:
        return asdict(self)


def _measure_resource_usage(fn, *args, **kwargs):
    """
    Runs fn(*args, **kwargs), returning (result, elapsed_seconds,
    cpu_percent, memory_delta_bytes). CPU percent is sampled via a short
    psutil.cpu_percent() call bracketing the operation — on very fast
    operations (microseconds) this is inherently noisy since
    cpu_percent() has its own sampling granularity; this is a known,
    documented limitation, not a bug to hide.
    """
    process = psutil.Process()
    mem_before = process.memory_info().rss
    psutil.cpu_percent(interval=None)  # prime the internal counter

    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start

    cpu_percent = psutil.cpu_percent(interval=None)
    mem_after = process.memory_info().rss
    mem_delta = mem_after - mem_before

    return result, elapsed, cpu_percent, mem_delta


def benchmark_aes_gcm(payload: bytes) -> OperationTiming:
    """AES-GCM has no separate key-exchange step — key generation and
    payload encryption are the only two phases."""
    (key, keygen_time, keygen_cpu, keygen_mem) = _measure_resource_usage(aes_gcm.generate_aes_key)
    (ct, enc_time, enc_cpu, enc_mem) = _measure_resource_usage(aes_gcm.encrypt, payload, key)

    total = keygen_time + enc_time
    return OperationTiming(
        key_generation_seconds=keygen_time,
        key_exchange_seconds=0.0,
        payload_encryption_seconds=enc_time,
        total_operation_seconds=total,
        payload_size_bytes=len(payload),
        cpu_percent_during_op=enc_cpu,
        memory_delta_bytes=keygen_mem + enc_mem,
        ciphertext_size_bytes=len(ct.ciphertext),
        ciphertext_expansion_bytes=len(ct.ciphertext) - len(payload),
    )


def benchmark_ecdh_x25519_hybrid(payload: bytes) -> OperationTiming:
    """
    Full ECDH hybrid flow: recipient keypair generation (counted as
    'key_generation'), sender's ECDH+HKDF key establishment (counted as
    'key_exchange'), then AES-GCM payload encryption.
    """
    (recipient_kp, keygen_time, keygen_cpu, keygen_mem) = _measure_resource_usage(ecdh_x25519.generate_keypair)

    def _establish():
        return ecdh_x25519.sender_establish_key(recipient_kp.public_key)

    ((aes_key, ctx), exchange_time, exchange_cpu, exchange_mem) = _measure_resource_usage(_establish)

    (ct, enc_time, enc_cpu, enc_mem) = _measure_resource_usage(aes_gcm.encrypt, payload, aes_key)

    total = keygen_time + exchange_time + enc_time
    return OperationTiming(
        key_generation_seconds=keygen_time,
        key_exchange_seconds=exchange_time,
        payload_encryption_seconds=enc_time,
        total_operation_seconds=total,
        payload_size_bytes=len(payload),
        cpu_percent_during_op=enc_cpu,
        memory_delta_bytes=keygen_mem + exchange_mem + enc_mem,
        ciphertext_size_bytes=len(ct.ciphertext),
        ciphertext_expansion_bytes=len(ct.ciphertext) - len(payload),
    )


def benchmark_rsa_oaep_hybrid(payload: bytes, rsa_keypair_cache: rsa_oaep_hybrid.RsaKeyPair | None = None) -> OperationTiming:
    """
    Full RSA-OAEP hybrid flow: RSA key generation (counted as
    'key_generation' — this is the expensive, well-known-slow step),
    AES key generation + RSA-OAEP wrap (counted as 'key_exchange', since
    it is functionally the RSA analogue of ECDH's key-exchange step),
    then AES-GCM payload encryption.

    `rsa_keypair_cache`: RSA key generation (~3072-bit) is expensive
    enough (hundreds of ms) that benchmarking many payload sizes with a
    FRESH keypair each time would conflate "key generation cost" with
    "payload size" in a misleading way for the key_generation column
    specifically. When provided, key generation is measured ONCE
    separately and this parameter reuses that keypair for the
    per-payload-size sweep, so key_generation_seconds reflects a single
    representative measurement rather than being repeated (and gets
    reported once, not per payload-size row) — see run_benchmark_suite()
    for how this is used and documented in the resulting report.
    """
    if rsa_keypair_cache is not None:
        rsa_kp = rsa_keypair_cache
        keygen_time, keygen_cpu, keygen_mem = 0.0, None, 0
    else:
        (rsa_kp, keygen_time, keygen_cpu, keygen_mem) = _measure_resource_usage(rsa_oaep_hybrid.generate_rsa_keypair)

    def _wrap():
        aes_key = aes_gcm.generate_aes_key()
        wrapped = rsa_oaep_hybrid.wrap_key(aes_key, rsa_kp.public_key)
        return aes_key, wrapped

    ((aes_key, wrapped), exchange_time, exchange_cpu, exchange_mem) = _measure_resource_usage(_wrap)

    (ct, enc_time, enc_cpu, enc_mem) = _measure_resource_usage(aes_gcm.encrypt, payload, aes_key)

    total = keygen_time + exchange_time + enc_time
    return OperationTiming(
        key_generation_seconds=keygen_time,
        key_exchange_seconds=exchange_time,
        payload_encryption_seconds=enc_time,
        total_operation_seconds=total,
        payload_size_bytes=len(payload),
        cpu_percent_during_op=enc_cpu,
        memory_delta_bytes=keygen_mem + exchange_mem + enc_mem,
        ciphertext_size_bytes=len(ct.ciphertext) + len(wrapped),
        ciphertext_expansion_bytes=(len(ct.ciphertext) + len(wrapped)) - len(payload),
    )
