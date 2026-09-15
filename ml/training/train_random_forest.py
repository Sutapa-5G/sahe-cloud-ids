"""
Random Forest baseline training for CICIDS2017 attack classification.

This module trains a single, well-documented RF configuration on the
Phase 1 processed training split, and exposes the trained model plus its
hyperparameters for evaluation. It does NOT perform hyperparameter
search by default (kept simple/reproducible for the baseline); a
`hyperparameter_grid` option is provided for later tuning but is
off unless explicitly requested, to keep Phase 2 fast and interpretable
as a true baseline.

No accuracy/precision/recall numbers exist anywhere in this module's
docstrings or defaults — those are only produced by actually running
evaluation.py against a trained model and real held-out data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV


@dataclass
class RFTrainingConfig:
    n_estimators: int = 200
    max_depth: int | None = None
    min_samples_split: int = 2
    min_samples_leaf: int = 1
    class_weight: str | None = "balanced"  # documented choice: CICIDS2017 is known to be class-imbalanced
    n_jobs: int = -1
    random_state: int = 42
    hyperparameter_grid: dict | None = None  # if set, GridSearchCV is used instead of a fixed config


@dataclass
class TrainingResult:
    model: RandomForestClassifier
    config: RFTrainingConfig
    train_rows: int
    n_features: int
    feature_names: list[str]
    training_time_seconds: float
    best_params: dict | None  # populated only if hyperparameter_grid was used
    NOT_EXECUTED_YET: bool = False  # set True by callers that construct this without actually fitting


def train_random_forest(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    config: RFTrainingConfig | None = None,
) -> TrainingResult:
    """
    Fits a RandomForestClassifier on X_train/y_train. Any missing values in
    X_train will raise (RF in scikit-learn does not accept NaN) — Phase 1
    tags but does not drop NaN rows, so the caller (pipeline glue code, or
    a documented step in the training script) must decide how NaN rows are
    handled before calling this function. This function does not silently
    impute.
    """
    config = config or RFTrainingConfig()

    if X_train.isna().any().any():
        nan_cols = X_train.columns[X_train.isna().any()].tolist()
        raise ValueError(
            f"X_train contains NaN values in columns {nan_cols}. "
            f"RandomForestClassifier cannot handle NaN. Decide and document "
            f"an explicit imputation/row-drop policy before training "
            f"(see docs/methodology/preprocessing.md's cleaning_report "
            f"counts to understand how many rows are affected)."
        )

    start = time.perf_counter()
    best_params = None

    if config.hyperparameter_grid:
        base = RandomForestClassifier(
            class_weight=config.class_weight,
            n_jobs=config.n_jobs,
            random_state=config.random_state,
        )
        search = GridSearchCV(
            base, config.hyperparameter_grid, cv=3, scoring="f1_macro", n_jobs=config.n_jobs
        )
        search.fit(X_train, y_train)
        model = search.best_estimator_
        best_params = search.best_params_
    else:
        model = RandomForestClassifier(
            n_estimators=config.n_estimators,
            max_depth=config.max_depth,
            min_samples_split=config.min_samples_split,
            min_samples_leaf=config.min_samples_leaf,
            class_weight=config.class_weight,
            n_jobs=config.n_jobs,
            random_state=config.random_state,
        )
        model.fit(X_train, y_train)

    elapsed = time.perf_counter() - start

    return TrainingResult(
        model=model,
        config=config,
        train_rows=len(X_train),
        n_features=X_train.shape[1],
        feature_names=list(X_train.columns),
        training_time_seconds=elapsed,
        best_params=best_params,
    )


def save_model(result: TrainingResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": result.model,
            "feature_names": result.feature_names,
            "config": result.config,
        },
        path,
    )


def load_model(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Model file not found: {path}. Train a model first (not executed yet).")
    return joblib.load(path)
