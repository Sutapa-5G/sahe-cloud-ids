"""
Phase 2 entrypoint: train a Random Forest baseline on the Phase 1
processed data and evaluate it.

Usage:
    python -m ml.training.run_random_forest \\
        --processed-dir ml/data/processed \\
        --output-dir experiments/results \\
        --model-dir ml/models \\
        --seed 42

If ml/data/processed/{train,validation,test}.parquet do not exist (i.e.
Phase 1 has not been run against real data), this exits with a clear
error and writes NO result files — no metric is fabricated.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ml.training.data_loading import load_processed_splits, ProcessedDataNotFoundError
from ml.training.train_random_forest import RFTrainingConfig, train_random_forest, save_model
from ml.evaluation.metrics import evaluate_classifier
from ml.preprocessing.reports import write_json


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 2: Random Forest baseline training + evaluation")
    p.add_argument("--processed-dir", type=Path, default=Path("ml/data/processed"))
    p.add_argument("--output-dir", type=Path, default=Path("experiments/results"))
    p.add_argument("--model-dir", type=Path, default=Path("ml/models"))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-estimators", type=int, default=200)
    p.add_argument("--tune", action="store_true", help="Run a small GridSearchCV instead of a fixed config.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        train, val, test = load_processed_splits(args.processed_dir)
    except ProcessedDataNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if train.X.isna().any().any():
        print(
            "ERROR: training features contain NaN values. Phase 1 tags but "
            "does not drop them. Decide and document an explicit handling "
            "policy (e.g. row drop or imputation) before running Phase 2. "
            "No model has been trained.",
            file=sys.stderr,
        )
        return 1

    grid = None
    if args.tune:
        grid = {
            "n_estimators": [100, 200],
            "max_depth": [None, 20],
        }

    config = RFTrainingConfig(
        n_estimators=args.n_estimators,
        random_state=args.seed,
        hyperparameter_grid=grid,
    )

    print(f"Training Random Forest on {train.X.shape[0]} rows, {train.X.shape[1]} features...")
    result = train_random_forest(train.X, train.y, config)
    print(f"Training completed in {result.training_time_seconds:.2f}s")

    model_path = args.model_dir / "random_forest.joblib"
    save_model(result, model_path)

    reports = {}
    for split_name, split in (("validation", val), ("test", test)):
        if len(split.X) == 0:
            print(f"WARNING: {split_name} split has 0 rows — skipping evaluation for this split, no metric fabricated.", file=sys.stderr)
            continue
        metrics = evaluate_classifier(result.model, split.X, split.y)
        reports[split_name] = metrics.to_dict()

    summary = {
        "model": "RandomForestClassifier",
        "training": {
            "train_rows": result.train_rows,
            "n_features": result.n_features,
            "feature_names": result.feature_names,
            "training_time_seconds": result.training_time_seconds,
            "config": {
                "n_estimators": result.config.n_estimators,
                "max_depth": result.config.max_depth,
                "class_weight": result.config.class_weight,
                "random_state": result.config.random_state,
            },
            "best_params_if_tuned": result.best_params,
        },
        "evaluation": reports,
        "model_path": str(model_path),
    }

    write_json(summary, args.output_dir / "random_forest_results.json")
    print(f"Results written to {args.output_dir / 'random_forest_results.json'}")
    print(f"Model saved to {model_path}")

    if "validation" in reports:
        print(f"Validation accuracy: {reports['validation']['accuracy']:.4f}")
        print(f"Validation macro-F1: {reports['validation']['macro_f1']:.4f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
