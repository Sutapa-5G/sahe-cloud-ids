"""SYNTHETIC data only — not real CICIDS2017 statistics or accuracy numbers."""
import numpy as np
import pandas as pd
import pytest

from ml.training.train_xgboost import XGBTrainingConfig, train_xgboost, DecodingXGBWrapper, _compute_sample_weights


def _synthetic_classification_data(n=200, seed=0, n_classes=2):
    rng = np.random.default_rng(seed)
    if n_classes == 2:
        X_a = rng.normal(loc=0.0, scale=1.0, size=(n // 2, 3))
        X_b = rng.normal(loc=5.0, scale=1.0, size=(n // 2, 3))
        X = np.vstack([X_a, X_b])
        y = np.array(["BENIGN"] * (n // 2) + ["DDoS"] * (n // 2))
    else:
        third = n // 3
        X_a = rng.normal(loc=0.0, scale=1.0, size=(third, 3))
        X_b = rng.normal(loc=5.0, scale=1.0, size=(third, 3))
        X_c = rng.normal(loc=10.0, scale=1.0, size=(n - 2 * third, 3))
        X = np.vstack([X_a, X_b, X_c])
        y = np.array(["BENIGN"] * third + ["DDoS"] * third + ["PortScan"] * (n - 2 * third))
    df = pd.DataFrame(X, columns=["feature_a", "feature_b", "feature_c"])
    return df, pd.Series(y)


def test_train_xgboost_basic_binary():
    X, y = _synthetic_classification_data(n_classes=2)
    config = XGBTrainingConfig(n_estimators=20, random_state=42)
    result = train_xgboost(X, y, config)

    assert result.train_rows == len(X)
    assert result.n_features == 3
    assert set(result.class_mapping.values()) == {"BENIGN", "DDoS"}

    wrapped = DecodingXGBWrapper(result.model, result.label_encoder)
    preds = wrapped.predict(X)
    assert set(preds) <= {"BENIGN", "DDoS"}
    assert len(preds) == len(X)


def test_train_xgboost_multiclass():
    X, y = _synthetic_classification_data(n_classes=3)
    result = train_xgboost(X, y, XGBTrainingConfig(n_estimators=20, random_state=42))
    wrapped = DecodingXGBWrapper(result.model, result.label_encoder)
    preds = wrapped.predict(X)
    assert set(preds) <= {"BENIGN", "DDoS", "PortScan"}


def test_train_xgboost_rejects_nan():
    X, y = _synthetic_classification_data()
    X.iloc[0, 0] = np.nan
    with pytest.raises(ValueError, match="NaN"):
        train_xgboost(X, y)


def test_train_xgboost_reproducible_with_seed():
    X, y = _synthetic_classification_data()
    config = XGBTrainingConfig(n_estimators=20, random_state=42)
    result1 = train_xgboost(X, y, config)
    result2 = train_xgboost(X, y, XGBTrainingConfig(n_estimators=20, random_state=42))
    wrapped1 = DecodingXGBWrapper(result1.model, result1.label_encoder)
    wrapped2 = DecodingXGBWrapper(result2.model, result2.label_encoder)
    assert list(wrapped1.predict(X)) == list(wrapped2.predict(X))


def test_train_xgboost_separable_synthetic_data_learns_something():
    """
    Sanity check only, validates the training code path — NOT a
    CICIDS2017 result.
    """
    X, y = _synthetic_classification_data(n=200)
    result = train_xgboost(X, y, XGBTrainingConfig(n_estimators=50, random_state=42))
    wrapped = DecodingXGBWrapper(result.model, result.label_encoder)
    preds = wrapped.predict(X)
    training_accuracy = (preds == y.values).mean()
    assert training_accuracy > 0.9


def test_compute_sample_weights_balances_imbalanced_classes():
    # 90 samples of class 0, 10 of class 1 — minority class should get
    # a much higher weight.
    y_encoded = np.array([0] * 90 + [1] * 10)
    weights = _compute_sample_weights(y_encoded)
    weight_class_0 = weights[0]
    weight_class_1 = weights[-1]
    assert weight_class_1 > weight_class_0
    # Sanity: weighted sum should roughly balance the two classes' influence
    total_weight_0 = weight_class_0 * 90
    total_weight_1 = weight_class_1 * 10
    assert total_weight_0 == pytest.approx(total_weight_1, rel=1e-6)


def test_decoding_wrapper_predict_proba_shape():
    X, y = _synthetic_classification_data(n_classes=2)
    result = train_xgboost(X, y, XGBTrainingConfig(n_estimators=20, random_state=42))
    wrapped = DecodingXGBWrapper(result.model, result.label_encoder)
    proba = wrapped.predict_proba(X)
    assert proba.shape == (len(X), 2)
