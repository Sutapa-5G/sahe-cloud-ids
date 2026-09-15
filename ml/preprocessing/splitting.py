"""
Day/file-aware train/validation/test split.

CICIDS2017 is captured as one file per day (sometimes split further into
morning/afternoon). A naive random row-level split risks near-duplicate
flows from the same capture window leaking across train/test. This
module splits by *source file* (i.e. by capture day/session), which is
a deliberate, documented choice over `train_test_split(random_state=42)`.

The assignment of specific files to train/validation/test is a config
decision (`file_assignment`), not hardcoded, because we cannot assume
every installation has exactly the 8 standard filenames. If the caller
does not supply an assignment, this module derives one by sorting
discovered source files deterministically and applying a configurable
split ratio, and it records exactly how the assignment was derived.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import pandas as pd


@dataclass
class SplitManifest:
    strategy: str
    seed: int
    train_files: list[str]
    validation_files: list[str]
    test_files: list[str]
    train_rows: int
    validation_rows: int
    test_rows: int
    dedup_policy: str
    rationale: str

    def to_dict(self) -> dict:
        return asdict(self)


def derive_file_assignment(
    source_files: list[str],
    train_ratio: float = 0.6,
    val_ratio: float = 0.2,
) -> tuple[list[str], list[str], list[str]]:
    """
    Deterministic (not random) assignment: sorts files alphabetically
    (which for CICIDS2017's standard filenames corresponds to day order:
    Friday.../Monday.../Thursday.../Tuesday.../Wednesday... — NOTE this is
    alphabetical, not calendar order; callers wanting calendar-day order
    should supply an explicit `file_assignment` instead) and slices by
    ratio. This is a fallback for when no explicit assignment is given;
    it is NOT a substitute for a human decision documented in
    docs/methodology/preprocessing.md once the real filenames are known.
    """
    files_sorted = sorted(source_files)
    n = len(files_sorted)
    n_train = max(1, round(n * train_ratio)) if n > 0 else 0
    n_val = max(1, round(n * val_ratio)) if n - n_train > 0 else 0
    train_files = files_sorted[:n_train]
    val_files = files_sorted[n_train:n_train + n_val]
    test_files = files_sorted[n_train + n_val:]
    return train_files, val_files, test_files


def split_by_file(
    df: pd.DataFrame,
    source_col: str,
    seed: int,
    train_files: list[str] | None = None,
    val_files: list[str] | None = None,
    test_files: list[str] | None = None,
    drop_exact_duplicates_flag_col: str | None = "_is_exact_duplicate",
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, SplitManifest]:
    all_files = sorted(df[source_col].dropna().unique().tolist())

    if train_files is None and val_files is None and test_files is None:
        train_files, val_files, test_files = derive_file_assignment(all_files)
        rationale = (
            "No explicit file_assignment supplied; derived deterministically "
            "by alphabetically sorting discovered source_file values and "
            "slicing 60/20/20. This is a placeholder policy — replace with "
            "an explicit, documented assignment once real CICIDS2017 "
            "filenames/days are confirmed (see docs/methodology/preprocessing.md)."
        )
    else:
        train_files = train_files or []
        val_files = val_files or []
        test_files = test_files or []
        rationale = "Explicit file_assignment supplied by caller/config."

    train_df = df[df[source_col].isin(train_files)].copy()
    val_df = df[df[source_col].isin(val_files)].copy()
    test_df = df[df[source_col].isin(test_files)].copy()

    dedup_policy = "none applied at split stage"
    if drop_exact_duplicates_flag_col and drop_exact_duplicates_flag_col in df.columns:
        # Within-split exact duplicates are informational only here;
        # cross-split contamination is prevented structurally because a
        # given source_file belongs to exactly one split.
        dedup_policy = (
            f"exact-duplicate rows (per '{drop_exact_duplicates_flag_col}') are "
            f"NOT automatically dropped at split time; cross-split "
            f"contamination is prevented by construction since each "
            f"source_file is assigned to exactly one split. Within-split "
            f"duplicate handling is a separate, explicit decision made in "
            f"pipeline.py."
        )

    manifest = SplitManifest(
        strategy="split-by-source-file (day/session aware)",
        seed=seed,
        train_files=train_files,
        validation_files=val_files,
        test_files=test_files,
        train_rows=len(train_df),
        validation_rows=len(val_df),
        test_rows=len(test_df),
        dedup_policy=dedup_policy,
        rationale=rationale,
    )
    return train_df, val_df, test_df, manifest
