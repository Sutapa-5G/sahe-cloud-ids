"""
Report generation: class distribution and the final preprocessing summary.
All functions here operate only on data actually passed in — nothing is
invented if the DataFrame is empty or absent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

import pandas as pd


@dataclass
class ClassDistributionReport:
    overall_counts: dict
    overall_percentages: dict
    per_source_file_counts: dict
    train_counts: dict | None
    validation_counts: dict | None
    test_counts: dict | None

    def to_dict(self) -> dict:
        return asdict(self)


def compute_class_distribution(
    df: pd.DataFrame,
    label_col: str = "label_original",
    source_col: str = "source_file",
    train_df: pd.DataFrame | None = None,
    val_df: pd.DataFrame | None = None,
    test_df: pd.DataFrame | None = None,
) -> ClassDistributionReport:
    if label_col not in df.columns or len(df) == 0:
        return ClassDistributionReport({}, {}, {}, None, None, None)

    overall_counts = df[label_col].value_counts(dropna=False).to_dict()
    total = len(df)
    overall_pct = {k: round(100 * v / total, 4) for k, v in overall_counts.items()}

    per_file = {}
    if source_col in df.columns:
        grouped = df.groupby(source_col)[label_col].value_counts(dropna=False)
        for (src, label), count in grouped.items():
            per_file.setdefault(src, {})[label] = int(count)

    def _counts_or_none(sub_df: pd.DataFrame | None) -> dict | None:
        if sub_df is None or len(sub_df) == 0 or label_col not in sub_df.columns:
            return None
        return {str(k): int(v) for k, v in sub_df[label_col].value_counts(dropna=False).items()}

    return ClassDistributionReport(
        overall_counts={str(k): int(v) for k, v in overall_counts.items()},
        overall_percentages={str(k): v for k, v in overall_pct.items()},
        per_source_file_counts={str(k): {str(kk): vv for kk, vv in v.items()} for k, v in per_file.items()},
        train_counts=_counts_or_none(train_df),
        validation_counts=_counts_or_none(val_df),
        test_counts=_counts_or_none(test_df),
    )


def write_json(obj_dict: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj_dict, f, indent=2, default=str)


def write_text(text: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(text)
