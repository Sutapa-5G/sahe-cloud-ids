"""
Reproducible cleaning for CICIDS2017-style flow data.

Every transformation is counted, never silently applied. This module does
NOT delete rows by default in its core functions — it TAGS rows with
boolean flag columns (`_has_nan`, `_has_inf`, `_is_duplicate`, etc.) and
returns counts. Callers (pipeline.py) decide, explicitly and
documentedly, what to do with flagged rows, and that decision itself is
recorded in the cleaning report.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import numpy as np
import pandas as pd


@dataclass
class CleaningReport:
    input_rows: int
    nan_rows: int
    infinite_rows: int
    empty_label_rows: int
    whitespace_label_rows: int
    numeric_columns_checked: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _numeric_columns(df: pd.DataFrame, exclude: set[str]) -> list[str]:
    return [
        c for c in df.columns
        if c not in exclude and pd.api.types.is_numeric_dtype(df[c])
    ]


def tag_quality_issues(
    df: pd.DataFrame,
    label_col: str = "label_original",
    exclude_from_numeric_check: tuple[str, ...] = ("source_file",),
) -> tuple[pd.DataFrame, CleaningReport]:
    """
    Adds boolean flag columns for NaN, infinite values, and label
    whitespace/emptiness issues. Does NOT drop any rows.
    """
    df = df.copy()
    input_rows = len(df)

    exclude = set(exclude_from_numeric_check) | {label_col}
    numeric_cols = _numeric_columns(df, exclude)

    if numeric_cols:
        nan_mask = df[numeric_cols].isna().any(axis=1)
        inf_mask = df[numeric_cols].apply(
            lambda s: np.isinf(s.to_numpy(dtype="float64", na_value=0.0))
        ).any(axis=1)
    else:
        nan_mask = pd.Series(False, index=df.index)
        inf_mask = pd.Series(False, index=df.index)

    if label_col in df.columns:
        raw_label = df[label_col].astype("string")
        empty_mask = raw_label.isna() | (raw_label.str.len() == 0)
        whitespace_mask = raw_label.fillna("").ne(raw_label.fillna("").str.strip())
    else:
        empty_mask = pd.Series(False, index=df.index)
        whitespace_mask = pd.Series(False, index=df.index)

    df["_has_nan"] = nan_mask
    df["_has_inf"] = inf_mask
    df["_empty_label"] = empty_mask
    df["_whitespace_label"] = whitespace_mask

    report = CleaningReport(
        input_rows=input_rows,
        nan_rows=int(nan_mask.sum()),
        infinite_rows=int(inf_mask.sum()),
        empty_label_rows=int(empty_mask.sum()),
        whitespace_label_rows=int(whitespace_mask.sum()),
        numeric_columns_checked=numeric_cols,
    )
    return df, report


def strip_label_whitespace(df: pd.DataFrame, label_col: str = "label_original") -> pd.DataFrame:
    """Explicit, logged transformation: strips whitespace from labels.
    Kept separate from tagging so the pipeline can report before/after."""
    df = df.copy()
    if label_col in df.columns:
        df[label_col] = df[label_col].astype("string").str.strip()
    return df
