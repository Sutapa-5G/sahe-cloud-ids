"""
XGBoost baseline training for CICIDS2017 attack classification.

Mirrors ml/training/train_random_forest.py in structure and discipline so
both models plug into the same evaluation pipeline for a fair comparison.
No accuracy/precision/recall numbers exist in this module — only
produced by actually running evaluation against real data.

Design note: XGBoost's sklearn API (XGBClassifier) requires integer-
encoded labels internally in older versions; modern xgboost (>=1.6)
handles string labels directly via its own internal LabelEncoder-like
handling when used through the sklearn wrapper. We encode labels
explicitly ourselves rather than relying on implicit behavior, so the
label mapping is visible, reproducible, and stored alongside the model
(needed to decode predictions back to attack-type strings later).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GridSearchCV
from xgboost import XGBClassifier


@dataclass
class XGBTrainingConfig:
    n_estimators: int = 200
    max_depth: int = 6
    learning_rate: float = 0.1
    subsample: float = 1.0
    colsample_bytree: float = 1.0
    # XGBoost has no direct class_weight="balanced" like sklearn RF.
    # For binary problems, scale_pos_weight approximates this; for
    # multiclass, per-sample weights computed from inverse class
    # frequency are used instead (see _compute_sample_weights). This
    # asymmetry vs. RF's class_weight is documented, not hidden.
    use_balanced_sample_weight: bool = True
    n_jobs: int = -1
    random_state: int = 42
    hyperparameter_grid: dict | None = None
    eval_metric: str = "mlogloss"


@dataclass
class XGBTrainingResult:
    model: XGBClassifier
    label_encoder: LabelEncoder
    config: XGBTrainingConfig
    train_rows: int
    n_features: int
    feature_names: list[str]
    training_time_seconds: float
    best_params: dict | None
    class_mapping: dict  # encoded_int -> original_label_string, for transparency


def _compute_sample_weights(y_encoded: np.ndarray) -> np.ndarray:
    """
    Inverse-frequency sample weighting: each sample's weight is
    n_total / (n_classes * n_samples_in_its_class). This achieves the
    same intent as sklearn's class_weight="balanced" but is computed
    explicitly here since XGBClassifier's sklearn wrapper has no
    equivalent parameter for multiclass problems.
    """
    classes, counts = np.unique(y_encoded, return_counts=True)
    n_total = len(y_encoded)
    n_classes = len(classes)
    weight_per_class = {c: n_total / (n_classes * cnt) for c, cnt in zip(classes, counts)}
    return np.array([weight_per_class[label] for label in y_encoded])


def train_xgboost(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    config: XGBTrainingConfig | None = None,
) -> XGBTrainingResult:
    config = config or XGBTrainingConfig()

    if X_train.isna().any().any():
        nan_cols = X_train.columns[X_train.isna().any()].tolist()
        raise ValueError(
            f"X_train contains NaN values in columns {nan_cols}. "
            f"While XGBoost can natively handle missing values (unlike "
            f"RandomForestClassifier), this pipeline enforces the same "
            f"explicit-handling discipline across both models so results "
            f"are comparable on identical input data. Decide and document "
            f"a row-handling policy before training."
        )

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_train)
    class_mapping = {int(i): str(cls) for i, cls in enumerate(label_encoder.classes_)}

    sample_weight = None
    if config.use_balanced_sample_weight:
        sample_weight = _compute_sample_weights(y_encoded)

    start = time.perf_counter()
    best_params = None

    base_kwargs = dict(
        max_depth=config.max_depth,
        learning_rate=config.learning_rate,
        subsample=config.subsample,
        colsample_bytree=config.colsample_bytree,
        n_jobs=config.n_jobs,
        random_state=config.random_state,
        eval_metric=config.eval_metric,
    )

    if config.hyperparameter_grid:
        base = XGBClassifier(n_estimators=config.n_estimators, **base_kwargs)
        search = GridSearchCV(
            base, config.hyperparameter_grid, cv=3, scoring="f1_macro", n_jobs=config.n_jobs
        )
        search.fit(X_train, y_encoded, sample_weight=sample_weight)
        model = search.best_estimator_
        best_params = search.best_params_
    else:
        model = XGBClassifier(n_estimators=config.n_estimators, **base_kwargs)
        model.fit(X_train, y_encoded, sample_weight=sample_weight)

    elapsed = time.perf_counter() - start

    return XGBTrainingResult(
        model=model,
        label_encoder=label_encoder,
        config=config,
        train_rows=len(X_train),
        n_features=X_train.shape[1],
        feature_names=list(X_train.columns),
        training_time_seconds=elapsed,
        best_params=best_params,
        class_mapping=class_mapping,
    )


class DecodingXGBWrapper:
    """
    Wraps a fitted XGBClassifier + LabelEncoder so it exposes
    .predict()/.predict_proba() returning ORIGINAL string labels, making
    it drop-in compatible with ml/evaluation/metrics.py, which expects
    predictions in the same label space as y_true (string attack names),
    exactly like RandomForestClassifier already does.
    """
    def __init__(self, model: XGBClassifier, label_encoder: LabelEncoder):
        self.model = model
        self.label_encoder = label_encoder
        self.classes_ = label_encoder.classes_

    def predict(self, X):
        encoded_preds = self.model.predict(X)
        return self.label_encoder.inverse_transform(encoded_preds)

    def predict_proba(self, X):
        return self.model.predict_proba(X)


def save_model(result: XGBTrainingResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": result.model,
            "label_encoder": result.label_encoder,
            "feature_names": result.feature_names,
            "config": result.config,
            "class_mapping": result.class_mapping,
        },
        path,
    )


def load_model(path: Path) -> DecodingXGBWrapper:
    if not path.exists():
        raise FileNotFoundError(f"Model file not found: {path}. Train a model first (not executed yet).")
    data = joblib.load(path)
    return DecodingXGBWrapper(data["model"], data["label_encoder"])
