"""SYNTHETIC data only — not real CICIDS2017 statistics."""
import pandas as pd

from ml.preprocessing.leakage_checks import audit_leakage
from ml.preprocessing.feature_selection import build_feature_manifest


def _synthetic_df():
    return pd.DataFrame({
        "flow_id": ["a", "b", "c"],
        "source_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "destination_port": [80, 443, 22],
        "duration": [1.0, 2.0, 3.0],
        "packet_count": [10, 20, 30],
        "label_original": ["BENIGN", "DDoS", "DoS"],
        "source_file": ["f1", "f1", "f1"],
        "_has_nan": [False, False, False],
    })


def test_high_risk_columns_removed():
    df = _synthetic_df()
    leakage_report = audit_leakage(df)
    manifest = build_feature_manifest(df, leakage_report)
    assert "flow_id" in manifest.removed_features
    assert "source_ip" in manifest.removed_features


def test_medium_risk_retained_by_default():
    df = _synthetic_df()
    leakage_report = audit_leakage(df)
    manifest = build_feature_manifest(df, leakage_report, drop_medium_risk=False)
    assert "destination_port" in manifest.retained_features


def test_medium_risk_dropped_when_policy_set():
    df = _synthetic_df()
    leakage_report = audit_leakage(df)
    manifest = build_feature_manifest(df, leakage_report, drop_medium_risk=True)
    assert "destination_port" in manifest.removed_features


def test_numeric_features_retained():
    df = _synthetic_df()
    leakage_report = audit_leakage(df)
    manifest = build_feature_manifest(df, leakage_report)
    assert "duration" in manifest.retained_features
    assert "packet_count" in manifest.retained_features


def test_metadata_columns_separated():
    df = _synthetic_df()
    leakage_report = audit_leakage(df)
    manifest = build_feature_manifest(df, leakage_report)
    assert "source_file" in manifest.metadata_columns
    assert "_has_nan" in manifest.metadata_columns


def test_label_column_classified_correctly():
    df = _synthetic_df()
    leakage_report = audit_leakage(df)
    manifest = build_feature_manifest(df, leakage_report)
    label_decision = next(d for d in manifest.decisions if d.column == "label_original")
    assert label_decision.category == "LABEL"
