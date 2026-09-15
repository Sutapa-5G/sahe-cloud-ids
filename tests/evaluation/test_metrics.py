"""SYNTHETIC data only — not real CICIDS2017 statistics or accuracy numbers."""
import numpy as np
import pandas as pd
import pytest

from ml.evaluation.metrics import evaluate_classifier, _overall_false_positive_rate


class _PerfectMockModel:
    """A mock 'model' that just predicts the true label — used to test
    the metrics plumbing itself without depending on a real classifier."""
    def predict(self, X):
        return X["true_label_leak"].values

    def predict_proba(self, X):
        # Two classes: BENIGN, DDoS
        labels = X["true_label_leak"].values
        proba = np.zeros((len(labels), 2))
        for i, lbl in enumerate(labels):
            proba[i, 0 if lbl == "BENIGN" else 1] = 1.0
        return proba

    def __sklearn_is_fitted__(self):
        return True


class _AlwaysBenignModel:
    def predict(self, X):
        return np.array(["BENIGN"] * len(X))


def test_evaluate_classifier_perfect_predictions():
    X = pd.DataFrame({"feature_a": [1, 2, 3, 4], "true_label_leak": ["BENIGN", "DDoS", "BENIGN", "DDoS"]})
    y = pd.Series(["BENIGN", "DDoS", "BENIGN", "DDoS"])
    model = _PerfectMockModel()
    metrics = evaluate_classifier(model, X, y)
    assert metrics.accuracy == 1.0
    assert metrics.macro_f1 == 1.0
    assert metrics.n_samples_evaluated == 4


def test_evaluate_classifier_empty_raises():
    X = pd.DataFrame({"feature_a": []})
    y = pd.Series([], dtype=str)
    with pytest.raises(ValueError, match="empty"):
        evaluate_classifier(_AlwaysBenignModel(), X, y)


def test_false_positive_rate_computed_correctly():
    y_true = np.array(["BENIGN", "BENIGN", "BENIGN", "DDoS"])
    y_pred = np.array(["BENIGN", "DDoS", "DDoS", "DDoS"])
    fpr = _overall_false_positive_rate(y_true, y_pred, "BENIGN")
    # 2 of 3 true-benign samples misclassified as attack
    assert fpr == pytest.approx(2 / 3)


def test_false_positive_rate_none_when_no_benign_present():
    y_true = np.array(["DDoS", "DDoS"])
    y_pred = np.array(["DDoS", "BENIGN"])
    fpr = _overall_false_positive_rate(y_true, y_pred, "BENIGN")
    assert fpr is None


def test_evaluate_classifier_always_wrong_model():
    X = pd.DataFrame({"feature_a": [1, 2]})
    y = pd.Series(["DDoS", "DDoS"])
    model = _AlwaysBenignModel()
    metrics = evaluate_classifier(model, X, y)
    assert metrics.accuracy == 0.0


def test_evaluate_classifier_confusion_matrix_shape():
    X = pd.DataFrame({"feature_a": [1, 2, 3], "true_label_leak": ["BENIGN", "DDoS", "BENIGN"]})
    y = pd.Series(["BENIGN", "DDoS", "BENIGN"])
    model = _PerfectMockModel()
    metrics = evaluate_classifier(model, X, y)
    n_labels = len(metrics.confusion_matrix_labels)
    assert len(metrics.confusion_matrix) == n_labels
    assert all(len(row) == n_labels for row in metrics.confusion_matrix)


def test_evaluate_classifier_binary_roc_auc_is_computed_not_silently_none():
    """
    Regression test: sklearn's roc_auc_score has a different required call
    signature for exactly 2 classes vs 3+. An earlier version of this code
    always used the multi_class='ovr' path, which raises internally for
    the binary case and was being swallowed into roc_auc=None. This test
    ensures the binary case actually produces a real number.
    """
    X = pd.DataFrame({
        "feature_a": [1, 2, 3, 4],
        "true_label_leak": ["BENIGN", "DDoS", "BENIGN", "DDoS"],
    })
    y = pd.Series(["BENIGN", "DDoS", "BENIGN", "DDoS"])
    model = _PerfectMockModel()
    metrics = evaluate_classifier(model, X, y)
    assert metrics.roc_auc_ovr_macro is not None
    assert metrics.roc_auc_ovr_macro == pytest.approx(1.0)
