"""
Duplicate analysis for CICIDS2017-style flow data.

Reports duplicates; does NOT delete them automatically. The pipeline
(pipeline.py) makes the explicit, documented decision about what to do
with duplicate rows, based on this report.

Scalability note: exact-duplicate detection via pandas.duplicated() is
O(n) with hashing and scales reasonably to the full CICIDS2017 dataset
(~2.8M rows) in memory-chunked form, but this module operates on whatever
DataFrame it is given — for the full dataset, pipeline.py is responsible
for either (a) loading the full frame if memory allows, or (b) using the
`near_duplicate_sample_limit` config to cap analysis and documenting that
cap in the report. This module does not silently downsample without the
caller recording that it did so.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import pandas as pd


@dataclass
class DuplicateReport:
    total_rows_considered: int
    exact_duplicate_rows: int
    exact_duplicate_pct: float
    feature_duplicate_rows_excluding_label: int
    feature_duplicate_pct_excluding_label: int | float
    duplicates_across_files: int
    analysis_scope_note: str

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_duplicates(
    df: pd.DataFrame,
    label_col: str = "label_original",
    source_col: str = "source_file",
    sample_limit: int | None = None,
) -> tuple[pd.DataFrame, DuplicateReport]:
    """
    Adds `_is_exact_duplicate` and `_is_feature_duplicate` boolean columns.
    If sample_limit is set and the frame exceeds it, analysis is performed
    on a deterministic head-sample of that size, and this is explicitly
    recorded in `analysis_scope_note` rather than hidden.
    """
    total = len(df)
    scope_note = "full dataset analyzed"
    analysis_df = df

    if sample_limit is not None and total > sample_limit:
        analysis_df = df.iloc[:sample_limit].copy()
        scope_note = (
            f"dataset exceeded sample_limit={sample_limit}; "
            f"analysis performed on first {sample_limit} rows only "
            f"(deterministic, not random) — this is a scalability "
            f"limitation, not a claim about the full dataset"
        )

    exact_dup_mask_analysis = analysis_df.duplicated(keep="first")

    # Feature columns EXCLUDE the label and internal flag columns. They also
    # EXCLUDE source_file, because the point of this check is to find rows
    # whose actual feature values repeat regardless of which file they came
    # from (that's what "duplicate across files" means) — including
    # source_file in the key would make cross-file duplicates undetectable
    # by definition, since two rows from different files would never match.
    feature_cols = [
        c for c in analysis_df.columns
        if c not in (label_col, source_col) and not c.startswith("_")
    ]
    feature_dup_mask_analysis = analysis_df.duplicated(subset=feature_cols, keep="first")

    cross_file_dup_count = 0
    if source_col in analysis_df.columns and feature_cols:
        # A feature-duplicate group is "cross-file" if it spans more than
        # one distinct source_file value.
        grp = analysis_df.groupby(feature_cols, dropna=False)[source_col].nunique()
        cross_file_dup_count = int((grp > 1).sum())

    df = df.copy()
    df["_is_exact_duplicate"] = False
    df["_is_feature_duplicate"] = False
    df.loc[analysis_df.index, "_is_exact_duplicate"] = exact_dup_mask_analysis.values
    df.loc[analysis_df.index, "_is_feature_duplicate"] = feature_dup_mask_analysis.values

    n_analyzed = len(analysis_df)
    report = DuplicateReport(
        total_rows_considered=n_analyzed,
        exact_duplicate_rows=int(exact_dup_mask_analysis.sum()),
        exact_duplicate_pct=round(100 * exact_dup_mask_analysis.sum() / n_analyzed, 4) if n_analyzed else 0.0,
        feature_duplicate_rows_excluding_label=int(feature_dup_mask_analysis.sum()),
        feature_duplicate_pct_excluding_label=round(100 * feature_dup_mask_analysis.sum() / n_analyzed, 4) if n_analyzed else 0.0,
        duplicates_across_files=cross_file_dup_count,
        analysis_scope_note=scope_note,
    )
    return df, report
