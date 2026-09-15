"""SYNTHETIC data only — not real CICIDS2017 statistics."""
import numpy as np
import pandas as pd

from ml.preprocessing.cleaning import tag_quality_issues, strip_label_whitespace


def _synthetic_df():
    return pd.DataFrame({
        "feature_a": [1.0, np.nan, 3.0, np.inf, 5.0],
        "feature_b": [1.0, 2.0, -np.inf, 4.0, 5.0],
        "label_original": ["BENIGN", "DDoS", " BENIGN ", "", "DoS"],
        "source_file": ["f1"] * 5,
    })


def test_tag_quality_issues_counts_correctly():
    df = _synthetic_df()
    tagged, report = tag_quality_issues(df)

    assert report.input_rows == 5
    assert report.nan_rows == 1          # row index 1
    assert report.infinite_rows == 2     # row index 3 (feature_a=inf), row index 2 (feature_b=-inf)
    assert report.empty_label_rows == 1  # row index 3 has ""
    assert report.whitespace_label_rows == 1  # row index 2 has " BENIGN "

    # No rows deleted
    assert len(tagged) == 5
    assert "_has_nan" in tagged.columns
    assert "_has_inf" in tagged.columns


def test_strip_label_whitespace():
    df = _synthetic_df()
    stripped = strip_label_whitespace(df)
    assert stripped["label_original"].iloc[2] == "BENIGN"


def test_tag_quality_issues_no_numeric_columns():
    df = pd.DataFrame({"label_original": ["BENIGN", "DDoS"], "source_file": ["f1", "f1"]})
    tagged, report = tag_quality_issues(df)
    assert report.nan_rows == 0
    assert report.infinite_rows == 0
    assert report.numeric_columns_checked == []
