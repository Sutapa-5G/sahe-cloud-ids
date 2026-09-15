"""
Loads the Phase 1 processed parquet splits for use by training/evaluation
code. This module does NOT touch raw CSVs or the preprocessing pipeline —
it only reads what Phase 1 already produced and split.

If the processed files don't exist, this raises a clear error rather than
generating placeholder data.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd


class ProcessedDataNotFoundError(RuntimeError):
    pass


@dataclass
class DatasetSplit:
    X: pd.DataFrame
    y: pd.Series
    source_file: pd.Series
    feature_names: list[str]
    label_col: str


def _load_split(path: Path, label_col: str = "label_original", drop_cols: tuple[str, ...] = ("source_file",)) -> DatasetSplit:
    if not path.exists():
        raise ProcessedDataNotFoundError(
            f"Processed data file not found: {path}. Run Phase 1 "
            f"(python -m ml.preprocessing.pipeline) against real CICIDS2017 "
            f"data first."
        )
    df = pd.read_parquet(path)
    if label_col not in df.columns:
        raise ValueError(f"Expected label column '{label_col}' not found in {path}. Columns: {list(df.columns)}")

    source_file = df["source_file"] if "source_file" in df.columns else pd.Series([None] * len(df))
    feature_cols = [c for c in df.columns if c not in (label_col,) and c not in drop_cols]

    X = df[feature_cols].copy()
    y = df[label_col].copy()
    return DatasetSplit(X=X, y=y, source_file=source_file, feature_names=feature_cols, label_col=label_col)


def load_processed_splits(processed_dir: Path) -> tuple[DatasetSplit, DatasetSplit, DatasetSplit]:
    """
    Returns (train, validation, test) DatasetSplit objects loaded from
    ml/data/processed/{train,validation,test}.parquet as written by
    ml.preprocessing.pipeline.
    """
    train = _load_split(processed_dir / "train.parquet")
    val = _load_split(processed_dir / "validation.parquet")
    test = _load_split(processed_dir / "test.parquet")

    # Sanity check: feature columns must match across splits, since a model
    # trained on one feature set cannot be evaluated on another.
    if not (set(train.feature_names) == set(val.feature_names) == set(test.feature_names)):
        raise ValueError(
            "Feature columns differ across train/validation/test splits — "
            f"train={train.feature_names}, val={val.feature_names}, test={test.feature_names}. "
            "This should not happen if all splits came from the same Phase 1 run."
        )
    return train, val, test
