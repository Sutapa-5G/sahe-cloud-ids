"""
crypto/sahe/policy.py

SAHE (Size-and-Severity Adaptive Hybrid Encryption) policy engine.

SAHE is NOT a new cipher. It is an adaptive POLICY that decides, for a
given (payload_size, severity, data_type), which already-standard
cryptographic building blocks to use:

  - AES-256-GCM always encrypts the actual payload (crypto/algorithms/aes_gcm.py)
  - Key establishment is either:
      * ECDH/X25519 + HKDF (crypto/algorithms/ecdh_x25519.py), or
      * RSA-OAEP key-wrap (crypto/algorithms/rsa_oaep_hybrid.py)
  - A digital signature (crypto/algorithms/signatures.py) is added ONLY
    when specifically justified (see SIGNATURE_POLICY below) — not
    blanket-applied for high severity, per the Phase 0 correction.

Severity affects which KEY-MANAGEMENT/AUTHENTICATION properties are
required. It never changes AES/ECC/RSA's mathematical strength — that is
fixed by the algorithm and key size, not by policy.

Thresholds (SMALL/LARGE payload cutoffs) are configurable, not
hardcoded assumptions — see SaheConfig. Per Phase 0/8, these should be
derived experimentally from the Phase 7 benchmark suite before being
treated as final; the defaults here are explicitly documented
placeholders.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ml.severity.severity_engine import Severity


class DataType(str, Enum):
    LOG = "LOG"
    ALERT = "ALERT"
    FILE = "FILE"
    AUDIT = "AUDIT"


class KeyEstablishmentMethod(str, Enum):
    ECDH_X25519 = "ECDH_X25519"
    RSA_OAEP = "RSA_OAEP"


@dataclass
class SaheConfig:
    # PLACEHOLDER thresholds — see docs/methodology/crypto_design.md and
    # Phase 8 for the experimentally-derived replacement values.
    small_payload_threshold_bytes: int = 100 * 1024        # 100 KB
    large_payload_threshold_bytes: int = 1024 * 1024       # 1 MB
    # Default key-establishment method for the "typical" (non-large,
    # non-trivially-small) case.
    #
    # UPDATED per Phase 7/8 real benchmark data (see
    # docs/methodology/threshold_derivation.md): on the single-core
    # sandboxed hardware used for that benchmark run, RSA-OAEP-Hybrid's
    # per-message cost (key exchange + payload encryption, excluding each
    # algorithm's one-time keygen) was LOWER than ECDH/X25519's at every
    # payload size tested (1 KB to 100 MB) — the opposite of this
    # module's original assumption that ECDH would be cheaper for
    # small/medium payloads. No size-based crossover was found between
    # the two algorithms in that data.
    #
    # ECDH remains the default here despite that finding because the
    # measured difference is a raw-speed comparison on one specific
    # (non-representative) machine, and does NOT account for forward
    # secrecy: ECDH's ephemeral-key-per-message design means compromising
    # one message's key does not expose others, a property RSA's
    # long-term key wrapping does not provide. This is a deliberate
    # security-over-speed policy choice, not a performance-optimal one —
    # documented here so it isn't mistaken for an empirically-justified
    # speed default. Re-run the Phase 7 benchmark suite on the actual
    # deployment hardware and revisit this choice with that data plus an
    # explicit decision about how much forward secrecy is worth in
    # measured overhead.
    default_key_method: KeyEstablishmentMethod = KeyEstablishmentMethod.ECDH_X25519


@dataclass
class SaheDecision:
    key_establishment_method: KeyEstablishmentMethod
    requires_signature: bool
    signature_reason: str | None
    payload_size_bytes: int
    severity: Severity
    data_type: DataType
    rationale: str

    def to_dict(self) -> dict:
        return {
            "key_establishment_method": self.key_establishment_method.value,
            "requires_signature": self.requires_signature,
            "signature_reason": self.signature_reason,
            "payload_size_bytes": self.payload_size_bytes,
            "severity": self.severity.name,
            "data_type": self.data_type.value,
            "rationale": self.rationale,
        }


# --- Signature policy -------------------------------------------------
# Per the Phase 0 correction: a signature is added ONLY when it provides
# a property AES-GCM's tag does not — non-repudiation to a party that
# does NOT hold the shared AES key (e.g. an external auditor reviewing
# logs after the fact, without access to live decryption keys). This is
# NOT a blanket "HIGH/CRITICAL severity -> add HMAC/signature" rule.
#
# Documented policy: signature required only for AUDIT-type records at
# CRITICAL severity. This is deliberately narrow — every other
# combination relies on AES-GCM's native authentication alone.

def _signature_required(data_type: DataType, severity: Severity) -> tuple[bool, str | None]:
    if data_type == DataType.AUDIT and severity == Severity.CRITICAL:
        return True, (
            "AUDIT record at CRITICAL severity: a digital signature provides "
            "non-repudiation for a third-party auditor who does not hold the "
            "shared AES key. AES-GCM's tag alone authenticates to holders of "
            "the shared key only, which is insufficient for this specific "
            "use case."
        )
    return False, None


def decide(
    payload_size_bytes: int,
    severity: Severity,
    data_type: DataType,
    config: SaheConfig | None = None,
) -> SaheDecision:
    config = config or SaheConfig()

    if payload_size_bytes < 0:
        raise ValueError(f"payload_size_bytes must be >= 0, got {payload_size_bytes}")

    # Key-establishment method selection.
    #
    # UPDATED per Phase 7/8 real benchmark data (see
    # docs/methodology/threshold_derivation.md). The original assumption
    # here — that RSA becomes preferable only above a size threshold
    # because its per-operation cost "matters less relative to bulk AES
    # encryption time" — was tested against real measurements and NOT
    # supported: RSA-OAEP-Hybrid's per-message cost was lower than
    # ECDH/X25519's at EVERY tested size (1 KB-100 MB) on the benchmark
    # hardware, so no speed-based crossover was found to justify a
    # size-based switch in that direction. The size threshold below is
    # RETAINED as a policy choice for a different, non-performance reason:
    # very large payloads benefit from RSA's compatibility with existing
    # PKI/certificate infrastructure in a production deployment (a
    # deployment/operational consideration, not a speed argument) — the
    # speed-based justification originally given for this line has been
    # withdrawn now that real data contradicts it.
    if payload_size_bytes >= config.large_payload_threshold_bytes:
        method = KeyEstablishmentMethod.RSA_OAEP
        method_reason = (
            f"payload size {payload_size_bytes} bytes >= large threshold "
            f"{config.large_payload_threshold_bytes} bytes; RSA-OAEP selected "
            f"for PKI/certificate-infrastructure compatibility at scale — "
            f"NOT for a speed advantage, which Phase 7/8 real measurement "
            f"did not confirm (see docs/methodology/threshold_derivation.md)"
        )
    else:
        method = config.default_key_method
        method_reason = (
            f"payload size {payload_size_bytes} bytes below large threshold; "
            f"default key-establishment method ({method.value}) applied for "
            f"forward secrecy — a security property, not a measured speed "
            f"advantage (see docs/methodology/threshold_derivation.md for "
            f"the real per-message cost comparison)"
        )

    requires_sig, sig_reason = _signature_required(data_type, severity)

    rationale = (
        f"{method_reason}. "
        f"Signature: {'required — ' + sig_reason if requires_sig else 'not required — AES-GCM authentication tag is sufficient for this severity/data_type combination'}."
    )

    return SaheDecision(
        key_establishment_method=method,
        requires_signature=requires_sig,
        signature_reason=sig_reason,
        payload_size_bytes=payload_size_bytes,
        severity=severity,
        data_type=data_type,
        rationale=rationale,
    )
