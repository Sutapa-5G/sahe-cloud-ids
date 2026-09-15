"""SYNTHETIC data only — not real CICIDS2017 statistics."""
from pathlib import Path

import pandas as pd
import pytest

from ml.training.data_loading import load_processed_splits, ProcessedDataNotFoundError


def _write_synthetic_split(path: Path, n_rows: int, label_values: list[str]):
    df = pd.DataFrame({
        "duration": [float(i) for i in range(n_rows)],
        "packet_count": [i * 2 for i in range(n_rows)],
        "label_original": (label_values * n_rows)[:n_rows],
        "source_file": ["synthetic.csv"] * n_rows,
    })
    df.to_parquet(path, index=False)


def test_load_processed_splits_missing_raises(tmp_path: Path):
    with pytest.raises(ProcessedDataNotFoundError):
        load_processed_splits(tmp_path)


def test_load_processed_splits_success(tmp_path: Path):
    _write_synthetic_split(tmp_path / "train.parquet", 10, ["BENIGN", "DDoS"])
    _write_synthetic_split(tmp_path / "validation.parquet", 4, ["BENIGN", "DDoS"])
    _write_synthetic_split(tmp_path / "test.parquet", 4, ["BENIGN", "DDoS"])

    train, val, test = load_processed_splits(tmp_path)

    assert len(train.X) == 10
    assert "duration" in train.feature_names
    assert "source_file" not in train.feature_names
    assert "label_original" not in train.feature_names
    assert len(val.X) == 4
    assert len(test.X) == 4


def test_load_processed_splits_feature_mismatch_raises(tmp_path: Path):
    _write_synthetic_split(tmp_path / "train.parquet", 4, ["BENIGN"])
    # Write a validation set with a DIFFERENT feature column to trigger mismatch
    df = pd.DataFrame({
        "duration": [1.0, 2.0],
        "different_feature": [1, 2],
        "label_original": ["BENIGN", "BENIGN"],
        "source_file": ["x.csv", "x.csv"],
    })
    df.to_parquet(tmp_path / "validation.parquet", index=False)
    _write_synthetic_split(tmp_path / "test.parquet", 2, ["BENIGN"])

    with pytest.raises(ValueError, match="differ across"):
        load_processed_splits(tmp_path)
