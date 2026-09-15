"""SYNTHETIC data only — not real CICIDS2017 statistics or accuracy numbers."""
import numpy as np
import pandas as pd
import pytest

from ml.training.train_random_forest import RFTrainingConfig, train_random_forest


def _synthetic_classification_data(n=200, seed=0):
    rng = np.random.default_rng(seed)
    # Two well-separated synthetic "classes" so a trained model can
    # reasonably be expected to do better than chance — this is a sanity
    # check of the training code path, NOT a claim about real-world
    # detection performance.
    X_benign = rng.normal(loc=0.0, scale=1.0, size=(n // 2, 3))
    X_attack = rng.normal(loc=5.0, scale=1.0, size=(n // 2, 3))
    X = np.vstack([X_benign, X_attack])
    y = np.array(["BENIGN"] * (n // 2) + ["DDoS"] * (n // 2))
    df = pd.DataFrame(X, columns=["feature_a", "feature_b", "feature_c"])
    return df, pd.Series(y)


def test_train_random_forest_basic():
    X, y = _synthetic_classification_data()
    config = RFTrainingConfig(n_estimators=20, random_state=42)
    result = train_random_forest(X, y, config)

    assert result.train_rows == len(X)
    assert result.n_features == 3
    assert result.training_time_seconds >= 0
    # Model should be fitted and usable
    preds = result.model.predict(X)
    assert len(preds) == len(X)


def test_train_random_forest_rejects_nan():
    X, y = _synthetic_classification_data()
    X.iloc[0, 0] = np.nan
    with pytest.raises(ValueError, match="NaN"):
        train_random_forest(X, y)


def test_train_random_forest_reproducible_with_seed():
    X, y = _synthetic_classification_data()
    config = RFTrainingConfig(n_estimators=20, random_state=42)
    result1 = train_random_forest(X, y, config)
    result2 = train_random_forest(X, y, RFTrainingConfig(n_estimators=20, random_state=42))
    preds1 = result1.model.predict(X)
    preds2 = result2.model.predict(X)
    assert list(preds1) == list(preds2)


def test_train_random_forest_separable_synthetic_data_learns_something():
    """
    Sanity check only: on well-separated synthetic clusters, the model
    should achieve high training accuracy. This validates the training
    code path works correctly — it is NOT a CICIDS2017 accuracy claim.
    """
    X, y = _synthetic_classification_data(n=200)
    result = train_random_forest(X, y, RFTrainingConfig(n_estimators=50, random_state=42))
    preds = result.model.predict(X)
    training_accuracy = (preds == y.values).mean()
    assert training_accuracy > 0.9  # synthetic, well-separated data only
