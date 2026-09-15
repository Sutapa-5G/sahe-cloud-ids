"""SYNTHETIC data only — not real CICIDS2017 statistics."""
import pandas as pd

from ml.preprocessing.leakage_checks import audit_leakage


def test_high_risk_identifier_columns_flagged():
    df = pd.DataFrame({
        "flow_id": ["a", "b", "c"],
        "source_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "duration": [1.0, 2.0, 3.0],
        "label_original": ["BENIGN", "DDoS", "DoS"],
    })
    report = audit_leakage(df)
    assert "flow_id" in report.high_risk_columns
    assert "source_ip" in report.high_risk_columns
    assert "duration" not in report.high_risk_columns


def test_medium_risk_port_columns_flagged():
    df = pd.DataFrame({
        "destination_port": [80, 443, 22],
        "duration": [1.0, 2.0, 3.0],
        "label_original": ["BENIGN", "DDoS", "DoS"],
    })
    report = audit_leakage(df)
    assert "destination_port" in report.medium_risk_columns


def test_constant_column_flagged_low_risk():
    df = pd.DataFrame({
        "always_same": [5, 5, 5, 5],
        "duration": [1.0, 2.0, 3.0, 4.0],
        "label_original": ["BENIGN", "DDoS", "DoS", "BENIGN"],
    })
    report = audit_leakage(df)
    assert "always_same" in report.low_risk_columns
    assert "always_same" in report.constant_or_near_constant_columns


def test_normal_numeric_column_no_risk():
    df = pd.DataFrame({
        "packet_length_mean": [100.5, 200.1, 150.0, 300.2],
        "label_original": ["BENIGN", "DDoS", "DoS", "BENIGN"],
    })
    report = audit_leakage(df)
    col = next(c for c in report.columns_assessed if c.column == "packet_length_mean")
    assert col.risk_level == "NONE"


def test_empty_dataframe_does_not_crash():
    df = pd.DataFrame({"flow_id": [], "label_original": []})
    report = audit_leakage(df)
    assert isinstance(report.notes, list)
    assert len(report.notes) >= 1


def test_markdown_output_is_generated():
    df = pd.DataFrame({
        "flow_id": ["a", "b"],
        "duration": [1.0, 2.0],
        "label_original": ["BENIGN", "DDoS"],
    })
    report = audit_leakage(df)
    md = report.to_markdown()
    assert "Leakage Audit Report" in md
    assert "flow_id" in md
