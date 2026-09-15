import pytest

from crypto.sahe.policy import decide, SaheConfig, KeyEstablishmentMethod, DataType
from ml.severity.severity_engine import Severity


def test_small_payload_uses_default_method():
    decision = decide(payload_size_bytes=1024, severity=Severity.LOW, data_type=DataType.LOG)
    assert decision.key_establishment_method == KeyEstablishmentMethod.ECDH_X25519


def test_large_payload_uses_rsa():
    config = SaheConfig(large_payload_threshold_bytes=1_000_000)
    decision = decide(payload_size_bytes=2_000_000, severity=Severity.LOW, data_type=DataType.FILE, config=config)
    assert decision.key_establishment_method == KeyEstablishmentMethod.RSA_OAEP


def test_signature_required_only_for_audit_critical():
    decision = decide(payload_size_bytes=1024, severity=Severity.CRITICAL, data_type=DataType.AUDIT)
    assert decision.requires_signature is True
    assert decision.signature_reason is not None


def test_signature_not_required_for_high_severity_non_audit():
    """
    Core regression test for the Phase 0 correction: HIGH (or even
    CRITICAL) severity alone must NOT trigger a signature/extra
    authentication layer just because severity is elevated — only the
    specific AUDIT+CRITICAL combination does.
    """
    decision = decide(payload_size_bytes=1024, severity=Severity.CRITICAL, data_type=DataType.ALERT)
    assert decision.requires_signature is False

    decision2 = decide(payload_size_bytes=1024, severity=Severity.HIGH, data_type=DataType.AUDIT)
    assert decision2.requires_signature is False  # HIGH, not CRITICAL


def test_signature_not_required_for_audit_at_low_severity():
    decision = decide(payload_size_bytes=1024, severity=Severity.LOW, data_type=DataType.AUDIT)
    assert decision.requires_signature is False


def test_signature_not_required_for_low_severity_log():
    decision = decide(payload_size_bytes=1024, severity=Severity.LOW, data_type=DataType.LOG)
    assert decision.requires_signature is False


def test_negative_payload_size_rejected():
    with pytest.raises(ValueError):
        decide(payload_size_bytes=-1, severity=Severity.LOW, data_type=DataType.LOG)


def test_zero_payload_size_allowed():
    decision = decide(payload_size_bytes=0, severity=Severity.LOW, data_type=DataType.LOG)
    assert decision.payload_size_bytes == 0


def test_decision_rationale_is_populated():
    decision = decide(payload_size_bytes=1024, severity=Severity.LOW, data_type=DataType.LOG)
    assert len(decision.rationale) > 0


def test_decision_to_dict_serializable():
    decision = decide(payload_size_bytes=1024, severity=Severity.CRITICAL, data_type=DataType.AUDIT)
    d = decision.to_dict()
    assert d["requires_signature"] is True
    assert d["severity"] == "CRITICAL"
    assert d["data_type"] == "AUDIT"


def test_custom_config_thresholds_respected():
    config = SaheConfig(small_payload_threshold_bytes=10, large_payload_threshold_bytes=100)
    decision_small = decide(5, Severity.LOW, DataType.LOG, config=config)
    decision_large = decide(1000, Severity.LOW, DataType.LOG, config=config)
    assert decision_small.key_establishment_method == KeyEstablishmentMethod.ECDH_X25519
    assert decision_large.key_establishment_method == KeyEstablishmentMethod.RSA_OAEP
