"""
Main Phase 1 pipeline entrypoint.

Usage:
    python -m ml.preprocessing.pipeline \\
        --raw-dir ml/data/raw \\
        --processed-dir ml/data/processed \\
        --output-dir experiments/results \\
        --seed 42

This orchestrates: discovery -> loading -> cleaning -> deduplication ->
leakage audit -> feature selection -> split -> class distribution ->
writes all required report files.

If ml/data/raw/ contains no CSV files, the pipeline stops with a clear
error and writes NO fabricated statistics anywhere.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from ml.preprocessing.config import PipelineConfig
from ml.preprocessing.discover import discover_csv_files, write_manifest
from ml.preprocessing.loader import load_csv_chunks
from ml.preprocessing.cleaning import tag_quality_issues, strip_label_whitespace
from ml.preprocessing.deduplication import analyze_duplicates
from ml.preprocessing.leakage_checks import audit_leakage
from ml.preprocessing.feature_selection import build_feature_manifest
from ml.preprocessing.splitting import split_by_file
from ml.preprocessing.reports import compute_class_distribution, write_json, write_text


class NoRawDataError(RuntimeError):
    pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CICIDS2017 Phase 1 preprocessing pipeline")
    p.add_argument("--raw-dir", type=Path, default=Path("ml/data/raw"))
    p.add_argument("--processed-dir", type=Path, default=Path("ml/data/processed"))
    p.add_argument("--output-dir", type=Path, default=Path("experiments/results"))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--chunk-size", type=int, default=100_000)
    p.add_argument("--drop-medium-risk", action="store_true", help="Drop MEDIUM leakage-risk columns (e.g. ports) instead of retaining them.")
    return p.parse_args(argv)


def run_pipeline(config: PipelineConfig, drop_medium_risk: bool = False) -> dict:
    """
    Returns a dict summary. Raises NoRawDataError if no CSVs are found —
    caller is responsible for exiting cleanly without writing fabricated
    outputs.
    """
    config.ensure_dirs()

    # --- 1. Discovery ---
    manifest = discover_csv_files(config.raw_dir, config.expected_filenames)
    write_manifest(manifest, config.output_dir / "data_manifest.json")

    if manifest.total_files_found == 0:
        raise NoRawDataError(
            f"No CSV files found under {config.raw_dir}. "
            f"Place real CICIDS2017 CSV files there before running Phase 1. "
            f"No dataset statistics have been written."
        )

    unreadable = [d for d in manifest.discovered_files if d.error and not d.error.startswith("UnicodeDecodeError")]
    if unreadable:
        print("WARNING: the following files could not be fully read and are excluded from loading:", file=sys.stderr)
        for u in unreadable:
            print(f"  - {u.filename}: {u.error}", file=sys.stderr)

    # --- 2. Loading (chunked, concatenated for this pipeline run) ---
    readable_files = [d for d in manifest.discovered_files if not (d.error and not d.error.startswith("UnicodeDecodeError"))]
    all_chunks = []
    for d in readable_files:
        for chunk in load_csv_chunks(Path(d.path), config.chunk_size, source_tag=d.filename):
            all_chunks.append(chunk)

    if not all_chunks:
        raise NoRawDataError("Files were discovered but none could be loaded into any chunks.")

    df = pd.concat(all_chunks, ignore_index=True)
    input_rows_total = len(df)

    # --- 3. Cleaning (tag, don't delete) ---
    df, cleaning_report = tag_quality_issues(df)
    df = strip_label_whitespace(df)

    # --- 4. Deduplication (tag, don't delete) ---
    df, dup_report = analyze_duplicates(
        df, sample_limit=config.near_duplicate_sample_limit
    )

    # --- 5. Leakage audit ---
    leakage_report = audit_leakage(df)
    write_json(leakage_report.to_dict(), config.output_dir / "leakage_audit.json")
    write_text(leakage_report.to_markdown(), config.output_dir / "leakage_audit.md")

    # --- 6. Feature selection ---
    feature_manifest = build_feature_manifest(df, leakage_report, drop_medium_risk=drop_medium_risk)
    write_json(feature_manifest.to_dict(), config.output_dir / "feature_manifest.json")

    # --- 7. Split (day/file aware) ---
    train_df, val_df, test_df, split_manifest = split_by_file(
        df, source_col="source_file", seed=config.seed
    )
    write_json(split_manifest.to_dict(), config.output_dir / "split_manifest.json")

    # --- 8. Class distribution ---
    class_dist = compute_class_distribution(df, train_df=train_df, val_df=val_df, test_df=test_df)
    write_json(class_dist.to_dict(), config.output_dir / "class_distribution.json")

    # --- 9. Duplicate report ---
    write_json(dup_report.to_dict(), config.output_dir / "duplicate_report.json")

    # --- 10. Processed data output (retained features + label + metadata only) ---
    export_cols = feature_manifest.retained_features + [feature_manifest.label_column, "source_file"]
    export_cols = [c for c in export_cols if c in df.columns]

    def _export(split_df: pd.DataFrame, name: str) -> Path:
        out_path = config.processed_dir / f"{name}.parquet"
        split_df[export_cols].to_parquet(out_path, index=False)
        return out_path

    train_path = _export(train_df, "train")
    val_path = _export(val_df, "validation")
    test_path = _export(test_df, "test")

    # --- 11. Summary ---
    summary = {
        "input_rows_total": input_rows_total,
        "cleaning_report": cleaning_report.to_dict(),
        "duplicate_report": dup_report.to_dict(),
        "leakage_summary": {
            "high_risk_columns": leakage_report.high_risk_columns,
            "medium_risk_columns": leakage_report.medium_risk_columns,
        },
        "feature_summary": {
            "retained_feature_count": len(feature_manifest.retained_features),
            "removed_feature_count": len(feature_manifest.removed_features),
        },
        "split_summary": split_manifest.to_dict(),
        "processed_outputs": {
            "train": str(train_path),
            "validation": str(val_path),
            "test": str(test_path),
        },
        "drop_medium_risk_policy_applied": drop_medium_risk,
    }
    write_json(summary, config.output_dir / "preprocessing_summary.json")

    return summary


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = PipelineConfig(
        raw_dir=args.raw_dir,
        processed_dir=args.processed_dir,
        output_dir=args.output_dir,
        seed=args.seed,
        chunk_size=args.chunk_size,
    )
    try:
        summary = run_pipeline(config, drop_medium_risk=args.drop_medium_risk)
    except NoRawDataError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print("Phase 1 pipeline completed successfully.")
    print(f"Input rows (all source files, pre-cleaning): {summary['input_rows_total']}")
    print(f"Reports written to: {config.output_dir}")
    print(f"Processed splits written to: {config.processed_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
