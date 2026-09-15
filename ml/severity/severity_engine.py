"""
ml/severity/severity_engine.py

Threat Severity Engine.

Per the Phase 0 corrections, severity must NOT be derived from raw model
confidence alone. This module implements a documented, configurable
policy that combines:

  1. Attack-type impact tier (a documented table, not inferred)
  2. Confidence tier (bucketed, not used as a continuous multiplier)
  3. Optional policy overrides (e.g. "always escalate AUDIT-adjacent
     attack types to at least HIGH")

A 99%-confidence prediction of a low-impact attack type is NOT
automatically CRITICAL — impact tier sets a ceiling/floor that
confidence then adjusts within, not the other way around.

This module has no dependency on trained models, MongoDB, or FastAPI —
it is pure, testable policy logic that Phase 9 (backend) will call with
real (attack_type, confidence) pairs coming out of Phase 2/3's models.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """
    IntEnum gives correct rank-based ordering (LOW < MEDIUM < HIGH <
    CRITICAL) for free via <, <=, >, >=. An earlier version of this enum
    used `str, Enum`, which compares by string value and has NO defined
    ordering semantics — comparisons like `Severity.HIGH < Severity.CRITICAL`
    would silently give the wrong answer (or raise, or coincidentally work
    for some pairs and not others) rather than failing loudly. Caught by
    test_severity_ordering_comparable.

    .value is still the human-readable string name (via __str__ override
    below) so serialization (to_dict, JSON output) is unaffected.
    """
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name

    @property
    def value_str(self) -> str:
        return self.name


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _clamp(sev: Severity, floor: Severity | None, ceiling: Severity | None) -> Severity:
    idx = _SEVERITY_ORDER.index(sev)
    if floor is not None:
        idx = max(idx, _SEVERITY_ORDER.index(floor))
    if ceiling is not None:
        idx = min(idx, _SEVERITY_ORDER.index(ceiling))
    return _SEVERITY_ORDER[idx]


# --- Attack-type impact policy -------------------------------------------
# This table is a documented POLICY CHOICE, not an objective ground truth.
# It should be reviewed by the project team and revised as needed; the
# rationale is recorded per entry via `IMPACT_TIER_RATIONALE`.
#
# Impact tier expresses the BASELINE severity for an attack type BEFORE
# confidence adjustment. It sets a floor and ceiling that confidence can
# move within, but confidence can never push a LOW-impact attack type's
# final severity above its ceiling, and can never push a CRITICAL-impact
# type's severity below its floor.

@dataclass
class ImpactPolicy:
    floor: Severity
    ceiling: Severity
    baseline: Severity


DEFAULT_IMPACT_POLICY: dict[str, ImpactPolicy] = {
    "BENIGN": ImpactPolicy(floor=Severity.LOW, ceiling=Severity.LOW, baseline=Severity.LOW),
    "PortScan": ImpactPolicy(floor=Severity.LOW, ceiling=Severity.MEDIUM, baseline=Severity.LOW),
    "BruteForce": ImpactPolicy(floor=Severity.MEDIUM, ceiling=Severity.HIGH, baseline=Severity.MEDIUM),
    "DoS": ImpactPolicy(floor=Severity.MEDIUM, ceiling=Severity.HIGH, baseline=Severity.MEDIUM),
    "DDoS": ImpactPolicy(floor=Severity.HIGH, ceiling=Severity.CRITICAL, baseline=Severity.HIGH),
    "Bot": ImpactPolicy(floor=Severity.MEDIUM, ceiling=Severity.HIGH, baseline=Severity.MEDIUM),
    "WebAttack": ImpactPolicy(floor=Severity.MEDIUM, ceiling=Severity.HIGH, baseline=Severity.MEDIUM),
    "Infiltration": ImpactPolicy(floor=Severity.HIGH, ceiling=Severity.CRITICAL, baseline=Severity.HIGH),
    "Heartbleed": ImpactPolicy(floor=Severity.HIGH, ceiling=Severity.CRITICAL, baseline=Severity.CRITICAL),
}

IMPACT_TIER_RATIONALE: dict[str, str] = {
    "BENIGN": "No attack; severity is fixed at LOW regardless of confidence.",
    "PortScan": "Typically reconnaissance, not direct compromise; can precede a more severe attack, hence a MEDIUM ceiling rather than LOW.",
    "BruteForce": "Direct credential-compromise attempt; MEDIUM baseline reflects real but bounded risk unless confidence is high.",
    "DoS": "Availability impact on a single service/host; MEDIUM baseline, HIGH ceiling for high-confidence detections.",
    "DDoS": "Availability impact at larger scale, harder to mitigate; HIGH floor reflects that even a lower-confidence DDoS detection warrants prompt attention.",
    "Bot": "Indicates likely compromise and potential for lateral use (C2, further attacks); MEDIUM baseline.",
    "WebAttack": "Depends heavily on the specific vulnerability (XSS vs SQLi vs brute force); MEDIUM baseline pending sub-type detail, not currently modeled separately.",
    "Infiltration": "Indicates a foothold already established inside the network; HIGH floor because the confidentiality/integrity risk is severe even at moderate confidence.",
    "Heartbleed": "A known, specific, severe vulnerability with direct data-exposure impact; CRITICAL baseline given known real-world impact of this CVE class.",
}


# --- Confidence tiering ----------------------------------------------------
# Confidence is bucketed into tiers, not used as a continuous multiplier
# on cryptographic or severity strength (per the Phase 0 correction that
# severity must not scale cipher strength). Buckets adjust WITHIN the
# attack type's [floor, ceiling] band only.

@dataclass
class ConfidenceTierConfig:
    low_max: float = 0.60       # confidence <= this -> "low confidence" adjustment
    medium_max: float = 0.85    # confidence <= this -> "medium confidence"
    # anything above medium_max -> "high confidence"


def _confidence_adjustment(confidence: float, config: ConfidenceTierConfig) -> int:
    """
    Returns an integer step adjustment relative to the attack type's
    baseline severity: -1 (down a tier), 0 (stay at baseline), +1 (up a
    tier). Clamped by the attack type's floor/ceiling afterward.
    """
    if confidence <= config.low_max:
        return -1
    elif confidence <= config.medium_max:
        return 0
    else:
        return 1


@dataclass
class SeverityDecision:
    attack_type: str
    confidence: float
    baseline_severity: Severity
    confidence_adjustment: int
    final_severity: Severity
    floor: Severity
    ceiling: Severity
    rationale: str
    unknown_attack_type: bool

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "baseline_severity": self.baseline_severity.name,
            "confidence_adjustment": self.confidence_adjustment,
            "final_severity": self.final_severity.name,
            "floor": self.floor.name,
            "ceiling": self.ceiling.name,
            "rationale": self.rationale,
            "unknown_attack_type": self.unknown_attack_type,
        }


class SeverityEngine:
    def __init__(
        self,
        impact_policy: dict[str, ImpactPolicy] | None = None,
        confidence_config: ConfidenceTierConfig | None = None,
        unknown_attack_default: ImpactPolicy | None = None,
    ):
        self.impact_policy = impact_policy or DEFAULT_IMPACT_POLICY
        self.confidence_config = confidence_config or ConfidenceTierConfig()
        # An attack type the model predicts that isn't in our policy table
        # is NOT silently treated as benign or ignored — it gets a
        # conservative default (MEDIUM floor) and is explicitly flagged
        # via `unknown_attack_type=True` so it surfaces for review rather
        # than being silently mishandled.
        self.unknown_attack_default = unknown_attack_default or ImpactPolicy(
            floor=Severity.MEDIUM, ceiling=Severity.CRITICAL, baseline=Severity.MEDIUM
        )

    def assess(self, attack_type: str, confidence: float) -> SeverityDecision:
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {confidence}")

        unknown = attack_type not in self.impact_policy
        policy = self.impact_policy.get(attack_type, self.unknown_attack_default)

        adjustment = _confidence_adjustment(confidence, self.confidence_config)
        baseline_idx = _SEVERITY_ORDER.index(policy.baseline)
        adjusted_idx = max(0, min(len(_SEVERITY_ORDER) - 1, baseline_idx + adjustment))
        adjusted = _SEVERITY_ORDER[adjusted_idx]

        final = _clamp(adjusted, policy.floor, policy.ceiling)

        rationale_parts = [
            IMPACT_TIER_RATIONALE.get(attack_type, "Attack type not in documented policy table; conservative default applied."),
            f"Confidence {confidence:.2f} mapped to adjustment {adjustment:+d} relative to baseline {policy.baseline.name}.",
            f"Final severity clamped to policy band [{policy.floor.name}, {policy.ceiling.name}].",
        ]
        if unknown:
            rationale_parts.insert(0, f"WARNING: attack_type '{attack_type}' is not in the documented impact policy table — using conservative default.")

        return SeverityDecision(
            attack_type=attack_type,
            confidence=confidence,
            baseline_severity=policy.baseline,
            confidence_adjustment=adjustment,
            final_severity=final,
            floor=policy.floor,
            ceiling=policy.ceiling,
            rationale=" ".join(rationale_parts),
            unknown_attack_type=unknown,
        )
