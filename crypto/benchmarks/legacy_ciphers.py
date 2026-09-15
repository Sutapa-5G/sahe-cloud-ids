"""
crypto/benchmarks/legacy_ciphers.py

DES, 3DES, and Blowfish — included ONLY for historical/performance
comparison, per the Phase 0 review. These are NOT proposed for use
anywhere in this system's actual security design; SAHE never selects
any of these. They exist solely so the benchmark report can show
"legacy vs modern" numbers, explicitly labeled as such in the output.

None of these provide authenticated encryption (no built-in integrity
tag) — CBC mode with a random IV is used here purely to give each cipher
a fair, working baseline for a timing/throughput comparison, not because
CBC-without-authentication is being proposed as secure. This caveat is
recorded in every result this module produces.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, asdict

from Crypto.Cipher import DES, DES3, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

LEGACY_DISCLAIMER = (
    "Legacy cryptographic algorithm included for historical/performance "
    "comparison only. NOT used anywhere in this system's actual security "
    "design (see docs/methodology/crypto_design.md). CBC mode without a "
    "separate authentication tag is used here to provide a fair timing "
    "baseline, not as a secure configuration recommendation."
)


@dataclass
class LegacyTiming:
    algorithm: str
    key_generation_seconds: float
    payload_encryption_seconds: float
    payload_decryption_seconds: float
    total_operation_seconds: float
    payload_size_bytes: int
    ciphertext_size_bytes: int
    ciphertext_expansion_bytes: int
    disclaimer: str = LEGACY_DISCLAIMER

    def to_dict(self) -> dict:
        return asdict(self)


def _time_it(fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return result, elapsed


def benchmark_des(payload: bytes) -> LegacyTiming:
    key, keygen_time = _time_it(get_random_bytes, 8)   # DES key: 64 bits (56 effective)
    iv, _ = _time_it(get_random_bytes, 8)

    def _encrypt():
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return cipher.encrypt(pad(payload, DES.block_size))

    ct, enc_time = _time_it(_encrypt)

    def _decrypt():
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), DES.block_size)

    pt, dec_time = _time_it(_decrypt)
    assert pt == payload, "DES round-trip correctness check failed during benchmarking"

    return LegacyTiming(
        algorithm="DES",
        key_generation_seconds=keygen_time,
        payload_encryption_seconds=enc_time,
        payload_decryption_seconds=dec_time,
        total_operation_seconds=keygen_time + enc_time + dec_time,
        payload_size_bytes=len(payload),
        ciphertext_size_bytes=len(ct),
        ciphertext_expansion_bytes=len(ct) - len(payload),
    )


def benchmark_3des(payload: bytes) -> LegacyTiming:
    # DES3.adjust_key_parity ensures a valid (non-degenerate) 3DES key;
    # pycryptodome requires this or raises.
    def _gen_key():
        while True:
            candidate = get_random_bytes(24)
            try:
                return DES3.adjust_key_parity(candidate)
            except ValueError:
                continue  # degenerate key (equivalent to single/double DES), regenerate

    key, keygen_time = _time_it(_gen_key)
    iv, _ = _time_it(get_random_bytes, 8)

    def _encrypt():
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        return cipher.encrypt(pad(payload, DES3.block_size))

    ct, enc_time = _time_it(_encrypt)

    def _decrypt():
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), DES3.block_size)

    pt, dec_time = _time_it(_decrypt)
    assert pt == payload, "3DES round-trip correctness check failed during benchmarking"

    return LegacyTiming(
        algorithm="3DES",
        key_generation_seconds=keygen_time,
        payload_encryption_seconds=enc_time,
        payload_decryption_seconds=dec_time,
        total_operation_seconds=keygen_time + enc_time + dec_time,
        payload_size_bytes=len(payload),
        ciphertext_size_bytes=len(ct),
        ciphertext_expansion_bytes=len(ct) - len(payload),
    )


def benchmark_blowfish(payload: bytes) -> LegacyTiming:
    key, keygen_time = _time_it(get_random_bytes, 16)  # 128-bit key (Blowfish supports 32-448 bits)
    iv, _ = _time_it(get_random_bytes, Blowfish.block_size)

    def _encrypt():
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        return cipher.encrypt(pad(payload, Blowfish.block_size))

    ct, enc_time = _time_it(_encrypt)

    def _decrypt():
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), Blowfish.block_size)

    pt, dec_time = _time_it(_decrypt)
    assert pt == payload, "Blowfish round-trip correctness check failed during benchmarking"

    return LegacyTiming(
        algorithm="Blowfish",
        key_generation_seconds=keygen_time,
        payload_encryption_seconds=enc_time,
        payload_decryption_seconds=dec_time,
        total_operation_seconds=keygen_time + enc_time + dec_time,
        payload_size_bytes=len(payload),
        ciphertext_size_bytes=len(ct),
        ciphertext_expansion_bytes=len(ct) - len(payload),
    )
