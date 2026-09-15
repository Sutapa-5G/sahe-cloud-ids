# Severity Engine Methodology (Phase 4)

## Status

Fully implemented and tested — this module has NO dependency on the
CICIDS2017 dataset, trained models, or any other unavailable resource,
so it is complete and verified with real (non-synthetic-fixture)
confidence in its logic, though it has not yet been exercised with real
model output from Phase 2/3 trained on real data.

## Core Rule (per Phase 0 correction)

Severity is **not** derived from raw model confidence. It is computed
from two independent inputs combined via a documented policy:

1. **Attack-type impact tier** — a policy table
   (`DEFAULT_IMPACT_POLICY` in `severity_engine.py`) giving each known
   attack type a `floor`, `ceiling`, and `baseline` severity.
2. **Confidence tier** — confidence is bucketed (low/medium/high via
   `ConfidenceTierConfig`), not used as a continuous multiplier, and the
   resulting adjustment (-1/0/+1) shifts severity **within** the attack
   type's `[floor, ceiling]` band only.

This means a 99%-confidence PortScan detection (ceiling=MEDIUM) can never
reach CRITICAL, while even a 30%-confidence DDoS detection (floor=HIGH)
never drops below HIGH. This is enforced by `test_high_confidence_does_not_override_low_impact_ceiling`
and `test_low_confidence_ddos_still_at_least_high_floor`.

## Impact Policy Table

The full table and per-entry rationale live in `severity_engine.py`
(`DEFAULT_IMPACT_POLICY`, `IMPACT_TIER_RATIONALE`). This is a **documented
policy choice**, reviewable and revisable by the project team — it is
explicitly not presented as an objective ground truth in any report this
project produces.

| Attack type | Floor | Ceiling | Baseline |
|---|---|---|---|
| BENIGN | LOW | LOW | LOW |
| PortScan | LOW | MEDIUM | LOW |
| BruteForce | MEDIUM | HIGH | MEDIUM |
| DoS | MEDIUM | HIGH | MEDIUM |
| DDoS | HIGH | CRITICAL | HIGH |
| Bot | MEDIUM | HIGH | MEDIUM |
| WebAttack | MEDIUM | HIGH | MEDIUM |
| Infiltration | HIGH | CRITICAL | HIGH |
| Heartbleed | HIGH (floor) | CRITICAL | CRITICAL |

## Unknown Attack Types

An attack type the model predicts that is not in the policy table is
**not** silently ignored or defaulted to BENIGN. It receives a
conservative default policy (`MEDIUM` floor, `CRITICAL` ceiling) and is
explicitly flagged via `SeverityDecision.unknown_attack_type = True`, so
it surfaces for manual review rather than being silently mishandled —
this matters in particular because Phase 1's `LABEL_NORMALIZATION_MAP`
is itself an unvalidated placeholder (see Phase 1 docs), so unexpected
label strings are a real possibility once real data is loaded.

## Bug Found and Fixed During This Phase

The initial `Severity` enum was defined as `class Severity(str, Enum)`.
This compares by string value and has **no defined ordering semantics**
for `<`/`>`/etc. — `Severity.HIGH < Severity.CRITICAL` either raises or
gives an accidental/undefined result depending on Python version and
usage pattern. Caught immediately by
`test_severity_ordering_comparable`. Fixed by changing to
`class Severity(IntEnum)` with explicit rank values
(`LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4`), which gives correct comparison
operators for free. This was an important catch: severity ordering is
used throughout the clamping logic (`_clamp()`) that enforces the
floor/ceiling policy — a broken comparison here could have silently
produced wrong severities everywhere downstream, including in the future
SAHE policy engine (Phase 6), which will consume `Severity` values
directly.

## How to Use

```python
from ml.severity.severity_engine import SeverityEngine

engine = SeverityEngine()
decision = engine.assess(attack_type="DDoS", confidence=0.92)
print(decision.final_severity)   # Severity.CRITICAL
print(decision.to_dict())        # JSON-serializable dict for storage/API use
```

This will be called from the Phase 9 backend with real
`(attack_type, confidence)` pairs coming out of the Phase 2/3 trained
models once they're run on real data.

## Testing

`tests/severity/test_severity_engine.py` — 11 tests, all passing,
covering: BENIGN-always-LOW, ceiling enforcement under high confidence,
floor enforcement under low confidence, unknown-attack-type flagging,
out-of-range confidence rejection, custom policy overrides, custom
confidence thresholds, and the ordering regression test described above.

```bash
python -m pytest tests/severity/ -v
```

## Limitations

- The impact policy table's floor/ceiling/baseline values are a
  reasonable starting policy informed by general security knowledge
  (e.g. DDoS/Infiltration being more severe than PortScan), but they have
  not been validated against any formal risk framework or the project
  supervisor's input — this should be reviewed before being presented as
  final in the project report.
- The policy table only covers the attack-type categories anticipated
  from Phase 1's `LABEL_NORMALIZATION_MAP`. If real CICIDS2017 data
  surfaces label strings that don't map cleanly to these categories, the
  unknown-attack-type fallback will apply, and the policy table should be
  extended once real labels are confirmed.
- Confidence-tier thresholds (`low_max=0.60`, `medium_max=0.85`) are
  reasonable illustrative defaults, not empirically tuned against real
  model calibration — real model confidence values from Phase 2/3 on
  real data may not be well-calibrated at all (a known issue with RF/
  XGBoost probability outputs), which would need separate validation
  before these specific threshold values are relied upon.
