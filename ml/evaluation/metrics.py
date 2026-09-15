"""
Model evaluation for CICIDS2017 attack classifiers.

Computes real metrics from real (model, X, y) inputs only. This module
never returns a placeholder metric value — if given empty/degenerate
input, it raises rather than returning a fabricated number like 0.0 or
1.0 that could be mistaken for a real result.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import time

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)


@dataclass
class ClassificationMetrics:
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_precision: float
    weighted_recall: float
    weighted_f1: float
    per_class_precision: dict
    per_class_recall: dict
    per_class_f1: dict
    per_class_support: dict
    false_positive_rate_overall: float | None
    roc_auc_ovr_macro: float | None
    confusion_matrix: list
    confusion_matrix_labels: list
    n_samples_evaluated: int
    inference_time_seconds: float
    inference_throughput_rows_per_second: float

    def to_dict(self) -> dict:
        return asdict(self)


def _overall_false_positive_rate(y_true: np.ndarray, y_pred: np.ndarray, benign_label: str) -> float | None:
    """
    FPR here is defined w.r.t. the BENIGN class: of all truly-benign
    samples, what fraction were misclassified as an attack (any non-benign
    class)? Returns None if the benign_label is not present in y_true,
    rather than fabricating a rate.
    """
    is_true_benign = y_true == benign_label
    n_true_benign = int(is_true_benign.sum())
    if n_true_benign == 0:
        return None
    false_positives = int(((y_true == benign_label) & (y_pred != benign_label)).sum())
    return false_positives / n_true_benign


def evaluate_classifier(
    model,
    X: pd.DataFrame,
    y_true: pd.Series,
    benign_label: str = "BENIGN",
) -> ClassificationMetrics:
    if len(X) == 0:
        raise ValueError("Cannot evaluate on an empty dataset (0 rows). No metric is computed.")

    start = time.perf_counter()
    y_pred = model.predict(X)
    elapsed = time.perf_counter() - start

    y_true_arr = np.asarray(y_true)
    y_pred_arr = np.asarray(y_pred)

    labels_sorted = sorted(set(y_true_arr) | set(y_pred_arr))

    accuracy = float(accuracy_score(y_true_arr, y_pred_arr))

    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, average="macro", zero_division=0, labels=labels_sorted
    )
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, average="weighted", zero_division=0, labels=labels_sorted
    )
    per_p, per_r, per_f1, per_support = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, average=None, zero_division=0, labels=labels_sorted
    )

    roc_auc = None
    if hasattr(model, "predict_proba") and len(labels_sorted) > 1:
        try:
            y_proba = model.predict_proba(X)
            if len(labels_sorted) == 2:
                # Binary case: sklearn's roc_auc_score wants the probability
                # of the positive class as a 1D array, not the full (n,2)
                # matrix, and does not accept multi_class='ovr' here.
                # model.classes_ (if present) tells us column order; fall
                # back to labels_sorted order otherwise.
                classes = list(getattr(model, "classes_", labels_sorted))
                positive_label = labels_sorted[1]
                pos_idx = classes.index(positive_label)
                roc_auc = float(roc_auc_score(y_true_arr, y_proba[:, pos_idx]))
            else:
                roc_auc = float(
                    roc_auc_score(y_true_arr, y_proba, multi_class="ovr", average="macro", labels=labels_sorted)
                )
        except (ValueError, IndexError):
            # e.g. a class present in labels_sorted has zero true samples in
            # this split, making AUC undefined — report None rather than
            # a fabricated value.
            roc_auc = None

    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=labels_sorted)

    fpr = _overall_false_positive_rate(y_true_arr, y_pred_arr, benign_label) if benign_label in labels_sorted else None

    n = len(X)
    throughput = n / elapsed if elapsed > 0 else float("inf")

    return ClassificationMetrics(
        accuracy=accuracy,
        macro_precision=float(macro_p),
        macro_recall=float(macro_r),
        macro_f1=float(macro_f1),
        weighted_precision=float(weighted_p),
        weighted_recall=float(weighted_r),
        weighted_f1=float(weighted_f1),
        per_class_precision={lbl: float(v) for lbl, v in zip(labels_sorted, per_p)},
        per_class_recall={lbl: float(v) for lbl, v in zip(labels_sorted, per_r)},
        per_class_f1={lbl: float(v) for lbl, v in zip(labels_sorted, per_f1)},
        per_class_support={lbl: int(v) for lbl, v in zip(labels_sorted, per_support)},
        false_positive_rate_overall=fpr,
        roc_auc_ovr_macro=roc_auc,
        confusion_matrix=cm.tolist(),
        confusion_matrix_labels=labels_sorted,
        n_samples_evaluated=n,
        inference_time_seconds=elapsed,
        inference_throughput_rows_per_second=throughput,
    )


def text_classification_report(model, X: pd.DataFrame, y_true: pd.Series) -> str:
    y_pred = model.predict(X)
    return classification_report(y_true, y_pred, zero_division=0)
