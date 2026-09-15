"""SYNTHETIC data only — not real CICIDS2017 statistics."""
import pandas as pd

from ml.preprocessing.deduplication import analyze_duplicates


def test_exact_duplicates_detected():
    df = pd.DataFrame({
        "feature_a": [1, 1, 2, 3],
        "feature_b": [10, 10, 20, 30],
        "label_original": ["BENIGN", "BENIGN", "DDoS", "DoS"],
        "source_file": ["f1", "f1", "f1", "f2"],
    })
    tagged, report = analyze_duplicates(df)
    assert report.exact_duplicate_rows == 1  # row 1 duplicates row 0
    assert report.total_rows_considered == 4
    assert tagged["_is_exact_duplicate"].sum() == 1


def test_feature_duplicate_across_files_detected():
    df = pd.DataFrame({
        "feature_a": [1, 1],
        "feature_b": [10, 10],
        "label_original": ["BENIGN", "BENIGN"],
        "source_file": ["f1", "f2"],  # same features, different source files
    })
    tagged, report = analyze_duplicates(df)
    assert report.feature_duplicate_rows_excluding_label == 1
    assert report.duplicates_across_files == 1


def test_no_duplicates():
    df = pd.DataFrame({
        "feature_a": [1, 2, 3],
        "label_original": ["BENIGN", "DDoS", "DoS"],
        "source_file": ["f1", "f1", "f1"],
    })
    _, report = analyze_duplicates(df)
    assert report.exact_duplicate_rows == 0
    assert report.duplicates_across_files == 0


def test_sample_limit_scope_is_recorded():
    df = pd.DataFrame({
        "feature_a": list(range(10)),
        "label_original": ["BENIGN"] * 10,
        "source_file": ["f1"] * 10,
    })
    _, report = analyze_duplicates(df, sample_limit=5)
    assert report.total_rows_considered == 5
    assert "sample_limit=5" in report.analysis_scope_note
