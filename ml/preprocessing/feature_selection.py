"""
Feature selection: separates columns into
  A. metadata/identifiers
  B. potential leakage columns (medium/low risk, kept visible not silently dropped)
  C. numeric ML features (retained)
  D. label column

Decisions here are informed by leakage_checks.audit_leakage() output but
made explicitly in this module, and every decision is recorded with a
reason in the returned FeatureManifest so it is reproducible and auditable.

Policy (documented, not hidden):
  - HIGH risk columns (leakage_checks) -> REMOVED, reason recorded
  - internal pipeline flag columns (leading "_") -> REMOVED (not features)
  - label_original / source_file -> METADATA, not treated as ML feature
  - MEDIUM risk columns (e.g. ports) -> RETAINED by default, but tagged so
    a later ablation study can test with/without them; this default can be
    overridden via `drop_medium_risk=True`
  - LOW risk / constant columns -> RETAINED but tagged; a constant column
    provides no signal but removing it is a modeling optimization, not a
    leakage fix, so it is left to feature_selection's numeric-feature
    export logic to decide, with the decision recorded either way
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import pandas as pd

from ml.preprocessing.leakage_checks import LeakageAuditReport


@dataclass
class FeatureDecision:
    column: str
    category: str        # METADATA | LEAKAGE_REMOVED | FEATURE | LABEL
    reason: str
    dtype: str
    missing_count: int
    leakage_risk: str    # HIGH | MEDIUM | LOW | NONE

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FeatureManifest:
    decisions: list[FeatureDecision]
    retained_features: list[str]
    removed_features: list[str]
    metadata_columns: list[str]
    label_column: str

    def to_dict(self) -> dict:
        return {
            "decisions": [d.to_dict() for d in self.decisions],
            "retained_features": self.retained_features,
            "removed_features": self.removed_features,
            "metadata_columns": self.metadata_columns,
            "label_column": self.label_column,
        }


_INTERNAL_FLAG_PREFIX = "_"
_METADATA_COLUMNS = {"label_original", "source_file"}


def build_feature_manifest(
    df: pd.DataFrame,
    leakage_report: LeakageAuditReport,
    label_col: str = "label_original",
    drop_medium_risk: bool = False,
) -> FeatureManifest:
    risk_by_col = {c.column: c.risk_level for c in leakage_report.columns_assessed}

    decisions: list[FeatureDecision] = []
    retained, removed, metadata = [], [], []

    for col in df.columns:
        dtype = str(df[col].dtype)
        missing = int(df[col].isna().sum())
        risk = risk_by_col.get(col, "NONE")

        if col == label_col:
            decisions.append(FeatureDecision(col, "LABEL", "designated label column", dtype, missing, risk))
            continue

        if col.startswith(_INTERNAL_FLAG_PREFIX):
            decisions.append(FeatureDecision(col, "METADATA", "internal pipeline flag column, not an ML feature", dtype, missing, risk))
            metadata.append(col)
            continue

        if col in _METADATA_COLUMNS:
            decisions.append(FeatureDecision(col, "METADATA", "provenance/metadata column, not an ML feature", dtype, missing, risk))
            metadata.append(col)
            continue

        if risk == "HIGH":
            decisions.append(FeatureDecision(col, "LEAKAGE_REMOVED", "classified HIGH risk by leakage audit (identifier-like)", dtype, missing, risk))
            removed.append(col)
            continue

        if risk == "MEDIUM" and drop_medium_risk:
            decisions.append(FeatureDecision(col, "LEAKAGE_REMOVED", "classified MEDIUM risk; drop_medium_risk=True policy applied", dtype, missing, risk))
            removed.append(col)
            continue

        if not pd.api.types.is_numeric_dtype(df[col]):
            decisions.append(FeatureDecision(col, "METADATA", "non-numeric column not currently used as an ML feature", dtype, missing, risk))
            metadata.append(col)
            continue

        reason = "retained as numeric ML feature"
        if risk == "MEDIUM":
            reason += " (MEDIUM leakage risk retained by default policy; consider ablation)"
        elif risk == "LOW":
            reason += " (flagged LOW risk / near-constant; retained, low expected value)"

        decisions.append(FeatureDecision(col, "FEATURE", reason, dtype, missing, risk))
        retained.append(col)

    return FeatureManifest(
        decisions=decisions,
        retained_features=retained,
        removed_features=removed,
        metadata_columns=metadata,
        label_column=label_col,
    )
