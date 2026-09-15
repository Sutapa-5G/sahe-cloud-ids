import pytest

from ml.severity.severity_engine import (
    SeverityEngine,
    Severity,
    ImpactPolicy,
    ConfidenceTierConfig,
)


def test_benign_always_low_regardless_of_confidence():
    engine = SeverityEngine()
    for conf in [0.1, 0.5, 0.99]:
        decision = engine.assess("BENIGN", conf)
        assert decision.final_severity == Severity.LOW


def test_high_confidence_does_not_override_low_impact_ceiling():
    """
    Core regression test for the Phase 0 correction: a 99%-confidence
    PortScan (ceiling=MEDIUM) must NOT become CRITICAL just because
    confidence is high.
    """
    engine = SeverityEngine()
    decision = engine.assess("PortScan", 0.99)
    assert decision.final_severity <= Severity.MEDIUM
    assert decision.final_severity != Severity.CRITICAL


def test_low_confidence_ddos_still_at_least_high_floor():
    """
    DDoS has a HIGH floor — even low confidence should not drop below HIGH,
    reflecting the documented policy that DDoS warrants prompt attention
    even at lower detection confidence.
    """
    engine = SeverityEngine()
    decision = engine.assess("DDoS", 0.30)
    assert decision.final_severity == Severity.HIGH


def test_high_confidence_ddos_reaches_critical():
    engine = SeverityEngine()
    decision = engine.assess("DDoS", 0.95)
    assert decision.final_severity == Severity.CRITICAL


def test_unknown_attack_type_flagged_not_silently_dropped():
    engine = SeverityEngine()
    decision = engine.assess("SomeNewAttackTypeNotInPolicy", 0.7)
    assert decision.unknown_attack_type is True
    assert "not in the documented impact policy table" in decision.rationale
    # Conservative default: MEDIUM floor
    assert decision.final_severity >= Severity.MEDIUM


def test_confidence_out_of_range_raises():
    engine = SeverityEngine()
    with pytest.raises(ValueError):
        engine.assess("DDoS", 1.5)
    with pytest.raises(ValueError):
        engine.assess("DDoS", -0.1)


def test_heartbleed_critical_baseline():
    engine = SeverityEngine()
    decision = engine.assess("Heartbleed", 0.5)  # medium confidence
    # Even at medium confidence, Heartbleed's CRITICAL baseline with a
    # HIGH floor and CRITICAL ceiling should not drop below HIGH.
    assert decision.final_severity >= Severity.HIGH


def test_custom_impact_policy_overrides_default():
    custom_policy = {
        "TestAttack": ImpactPolicy(floor=Severity.LOW, ceiling=Severity.LOW, baseline=Severity.LOW),
    }
    engine = SeverityEngine(impact_policy=custom_policy)
    decision = engine.assess("TestAttack", 0.99)
    assert decision.final_severity == Severity.LOW


def test_custom_confidence_thresholds():
    config = ConfidenceTierConfig(low_max=0.3, medium_max=0.6)
    engine = SeverityEngine(confidence_config=config)
    # 0.5 would be "medium" under defaults but should now register
    # according to the custom thresholds (falls in medium band: >0.3, <=0.6)
    decision = engine.assess("DoS", 0.5)
    assert decision.confidence_adjustment == 0


def test_severity_ordering_comparable():
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL > Severity.LOW


def test_decision_to_dict_serializable():
    engine = SeverityEngine()
    decision = engine.assess("DDoS", 0.8)
    d = decision.to_dict()
    assert d["attack_type"] == "DDoS"
    assert d["final_severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(d["confidence_adjustment"], int)
