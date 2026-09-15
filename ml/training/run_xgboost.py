"""
Phase 3 entrypoint: train an XGBoost baseline and evaluate it, using the
same shared evaluation module as Phase 2 (Random Forest) for a fair,
consistent comparison.

Usage:
    python -m ml.training.run_xgboost \\
        --processed-dir ml/data/processed \\
        --output-dir experiments/results \\
        --model-dir ml/models \\
        --seed 42

If the processed parquet files don't exist, exits cleanly with no
fabricated output, same as run_random_forest.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ml.training.data_loading import load_processed_splits, ProcessedDataNotFoundError
from ml.training.train_xgboost import XGBTrainingConfig, train_xgboost, save_model, DecodingXGBWrapper
from ml.evaluation.metrics import evaluate_classifier
from ml.preprocessing.reports import write_json


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 3: XGBoost baseline training + evaluation")
    p.add_argument("--processed-dir", type=Path, default=Path("ml/data/processed"))
    p.add_argument("--output-dir", type=Path, default=Path("experiments/results"))
    p.add_argument("--model-dir", type=Path, default=Path("ml/models"))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-estimators", type=int, default=200)
    p.add_argument("--tune", action="store_true")
    return p.parse_args(argv)


def _maybe_write_comparison(output_dir: Path, xgb_summary: dict) -> None:
    """
    If Phase 2's random_forest_results.json already exists, write a small
    side-by-side comparison file. This ONLY reads numbers already written
    by an actual RF run — it never invents an RF result to compare against.
    """
    rf_path = output_dir / "random_forest_results.json"
    if not rf_path.exists():
        return

    with rf_path.open() as f:
        rf_summary = json.load(f)

    comparison = {"models_compared": ["RandomForestClassifier", "XGBoostClassifier"], "splits": {}}
    for split_name in ("validation", "test"):
        rf_eval = rf_summary.get("evaluation", {}).get(split_name)
        xgb_eval = xgb_summary.get("evaluation", {}).get(split_name)
        if rf_eval is None or xgb_eval is None:
            continue
        comparison["splits"][split_name] = {
            "random_forest": {
                "accuracy": rf_eval["accuracy"],
                "macro_f1": rf_eval["macro_f1"],
                "inference_throughput_rows_per_second": rf_eval["inference_throughput_rows_per_second"],
            },
            "xgboost": {
                "accuracy": xgb_eval["accuracy"],
                "macro_f1": xgb_eval["macro_f1"],
                "inference_throughput_rows_per_second": xgb_eval["inference_throughput_rows_per_second"],
            },
        }

    if comparison["splits"]:
        write_json(comparison, output_dir / "model_comparison_rf_vs_xgboost.json")
        print(f"Comparison written to {output_dir / 'model_comparison_rf_vs_xgboost.json'}")
    else:
        print("RF results file found but had no matching splits to compare — comparison not written.", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        train, val, test = load_processed_splits(args.processed_dir)
    except ProcessedDataNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if train.X.isna().any().any():
        print(
            "ERROR: training features contain NaN values. No model has been trained. "
            "Decide and document an explicit handling policy first.",
            file=sys.stderr,
        )
        return 1

    grid = None
    if args.tune:
        grid = {
            "n_estimators": [100, 200],
            "max_depth": [4, 6],
        }

    config = XGBTrainingConfig(
        n_estimators=args.n_estimators,
        random_state=args.seed,
        hyperparameter_grid=grid,
    )

    print(f"Training XGBoost on {train.X.shape[0]} rows, {train.X.shape[1]} features...")
    result = train_xgboost(train.X, train.y, config)
    print(f"Training completed in {result.training_time_seconds:.2f}s")

    model_path = args.model_dir / "xgboost.joblib"
    save_model(result, model_path)

    wrapped_model = DecodingXGBWrapper(result.model, result.label_encoder)

    reports = {}
    for split_name, split in (("validation", val), ("test", test)):
        if len(split.X) == 0:
            print(f"WARNING: {split_name} split has 0 rows — skipping evaluation, no metric fabricated.", file=sys.stderr)
            continue
        metrics = evaluate_classifier(wrapped_model, split.X, split.y)
        reports[split_name] = metrics.to_dict()

    summary = {
        "model": "XGBoostClassifier",
        "training": {
            "train_rows": result.train_rows,
            "n_features": result.n_features,
            "feature_names": result.feature_names,
            "training_time_seconds": result.training_time_seconds,
            "class_mapping": result.class_mapping,
            "config": {
                "n_estimators": result.config.n_estimators,
                "max_depth": result.config.max_depth,
                "learning_rate": result.config.learning_rate,
                "use_balanced_sample_weight": result.config.use_balanced_sample_weight,
                "random_state": result.config.random_state,
            },
            "best_params_if_tuned": result.best_params,
        },
        "evaluation": reports,
        "model_path": str(model_path),
    }

    write_json(summary, args.output_dir / "xgboost_results.json")
    print(f"Results written to {args.output_dir / 'xgboost_results.json'}")
    print(f"Model saved to {model_path}")

    if "validation" in reports:
        print(f"Validation accuracy: {reports['validation']['accuracy']:.4f}")
        print(f"Validation macro-F1: {reports['validation']['macro_f1']:.4f}")

    _maybe_write_comparison(args.output_dir, summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
