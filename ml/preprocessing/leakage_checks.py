"""
ml/preprocessing/leakage_checks.py

Investigates possible data-leakage sources in CICIDS2017-style flow data
and produces a classified, documented report. This module DETECTS and
CLASSIFIES risk — it does not unilaterally decide to drop columns. The
final feature-selection decision is made explicitly in
feature_selection.py, informed by this report.

Risk categories:
  HIGH    - near-certain leakage / identifier with no legitimate ML signal
            for a generalizing model (e.g. Flow ID, raw IP addresses,
            raw Timestamp)
  MEDIUM  - plausible legitimate signal but also plausible leakage/
            overfitting vector (e.g. source/destination port)
  LOW     - unlikely to leak but flagged for visibility (e.g. a column
            that is constant or near-constant across the whole dataset,
            which isn't "leakage" in the label sense but adds no value
            and should be documented)
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import pandas as pd


@dataclass
class ColumnRisk:
    column: str
    risk_level: str          # HIGH | MEDIUM | LOW | NONE
    reason: str
    example_values_sample: list[str]
    n_unique: int | None
    is_constant: bool


@dataclass
class LeakageAuditReport:
    columns_assessed: list[ColumnRisk]
    high_risk_columns: list[str]
    medium_risk_columns: list[str]
    low_risk_columns: list[str]
    constant_or_near_constant_columns: list[str]
    label_encoding_suspects: list[str]
    notes: list[str]

    def to_dict(self) -> dict:
        return {
            "columns_assessed": [asdict(c) for c in self.columns_assessed],
            "high_risk_columns": self.high_risk_columns,
            "medium_risk_columns": self.medium_risk_columns,
            "low_risk_columns": self.low_risk_columns,
            "constant_or_near_constant_columns": self.constant_or_near_constant_columns,
            "label_encoding_suspects": self.label_encoding_suspects,
            "notes": self.notes,
        }

    def to_markdown(self) -> str:
        lines = ["# Leakage Audit Report", ""]
        lines.append(f"- HIGH risk columns: {self.high_risk_columns or 'none found'}")
        lines.append(f"- MEDIUM risk columns: {self.medium_risk_columns or 'none found'}")
        lines.append(f"- LOW risk / near-constant columns: {self.low_risk_columns or 'none found'}")
        lines.append(f"- Suspected label-encoding columns: {self.label_encoding_suspects or 'none found'}")
        lines.append("")
        lines.append("## Per-column detail")
        lines.append("")
        lines.append("| Column | Risk | Reason | n_unique | Constant |")
        lines.append("|---|---|---|---|---|")
        for c in self.columns_assessed:
            lines.append(f"| {c.column} | {c.risk_level} | {c.reason} | {c.n_unique} | {c.is_constant} |")
        if self.notes:
            lines.append("")
            lines.append("## Notes")
            for n in self.notes:
                lines.append(f"- {n}")
        return "\n".join(lines)


_HIGH_RISK_NAME_HINTS = {"flow_id", "source_ip", "src_ip", "destination_ip", "dst_ip", "timestamp"}
_MEDIUM_RISK_NAME_HINTS = {"source_port", "src_port", "destination_port", "dst_port"}


def _sample_values(series: pd.Series, n: int = 3) -> list[str]:
    vals = series.dropna().astype(str).unique()[:n]
    return list(vals)


def audit_leakage(
    df: pd.DataFrame,
    label_col: str = "label_original",
    high_risk_hints: set[str] | None = None,
    medium_risk_hints: set[str] | None = None,
    near_constant_threshold: float = 0.999,
) -> LeakageAuditReport:
    high_hints = high_risk_hints or _HIGH_RISK_NAME_HINTS
    medium_hints = medium_risk_hints or _MEDIUM_RISK_NAME_HINTS

    assessed: list[ColumnRisk] = []
    high, medium, low, near_constant, label_suspects = [], [], [], [], []
    notes: list[str] = []

    n_rows = len(df)
    if n_rows == 0:
        notes.append("DataFrame passed to audit_leakage() had zero rows; no column statistics computed.")

    for col in df.columns:
        if col.startswith("_") or col in (label_col,):
            continue

        series = df[col]
        n_unique = int(series.nunique(dropna=True)) if n_rows else None
        is_constant = bool(n_rows and n_unique is not None and n_unique <= 1)
        near_const = bool(
            n_rows and n_unique is not None and n_rows > 0
            and (1 - (n_unique / n_rows)) >= near_constant_threshold
            and n_unique > 1
        )

        risk = "NONE"
        reason = "no known leakage indicator matched"

        if col in high_hints:
            risk = "HIGH"
            reason = "column name matches known high-risk identifier pattern (flow/IP/timestamp)"
        elif col in medium_hints:
            risk = "MEDIUM"
            reason = "column name matches known port-identifier pattern; may carry legitimate signal but also overfitting risk"
        elif is_constant:
            risk = "LOW"
            reason = "column is constant across the analyzed data (zero variance) — not leakage, but adds no ML signal"
        elif near_const:
            risk = "LOW"
            reason = f"column is near-constant (>= {near_constant_threshold * 100:.1f}% unique-per-row) — flagged for review"

        # Heuristic: a column whose values look like they might directly
        # encode the label text is flagged separately for manual review,
        # never auto-dropped.
        if series.dtype == object or pd.api.types.is_string_dtype(series):
            try:
                overlap = set(series.dropna().astype(str).unique()[:50])
                label_values = set(df[label_col].dropna().astype(str).unique()) if label_col in df.columns else set()
                if overlap & label_values:
                    label_suspects.append(col)
                    notes.append(f"Column '{col}' contains values overlapping the label set — review manually.")
            except Exception:  # noqa: BLE001 - audit must not crash the pipeline
                pass

        assessed.append(
            ColumnRisk(
                column=col,
                risk_level=risk,
                reason=reason,
                example_values_sample=_sample_values(series),
                n_unique=n_unique,
                is_constant=is_constant,
            )
        )

        if risk == "HIGH":
            high.append(col)
        elif risk == "MEDIUM":
            medium.append(col)
        elif risk == "LOW":
            low.append(col)
        if is_constant or near_const:
            near_constant.append(col)

    return LeakageAuditReport(
        columns_assessed=assessed,
        high_risk_columns=high,
        medium_risk_columns=medium,
        low_risk_columns=low,
        constant_or_near_constant_columns=near_constant,
        label_encoding_suspects=sorted(set(label_suspects)),
        notes=notes,
    )
