"""
This test trains a REAL RandomForestClassifier on small SYNTHETIC data
(not CICIDS2017), saves it to a temp ml/models/ directory, and verifies
the /detect endpoint's happy path works end-to-end. This validates the
route's code path, not any real-world detection accuracy claim.
"""
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from ml.training.train_random_forest import RFTrainingConfig, train_random_forest, save_model


def test_detect_happy_path_with_synthetic_trained_model(tmp_path, monkeypatch):
    # Train a tiny real model on synthetic, well-separated data.
    rng = np.random.default_rng(42)
    X = pd.DataFrame({
        "duration": np.concatenate([rng.normal(1, 0.1, 50), rng.normal(10, 0.1, 50)]),
        "packet_count": np.concatenate([rng.normal(5, 0.5, 50), rng.normal(500, 0.5, 50)]),
    })
    y = pd.Series(["BENIGN"] * 50 + ["DDoS"] * 50)

    result = train_random_forest(X, y, RFTrainingConfig(n_estimators=20, random_state=42))
    model_dir = tmp_path / "models"
    save_model(result, model_dir / "random_forest.joblib")

    monkeypatch.setenv("ML_MODEL_DIR", str(model_dir))
    monkeypatch.setenv("API_AUTH_TOKEN", "test-token-for-pytest")

    # Force settings to re-read the new env var (bypass the module-level cache).
    import backend.app.config as config_module
    config_module._settings = None

    from backend.app.main import create_app
    app = create_app()
    with TestClient(app) as client:
        r = client.post("/detect", json={"features": {"duration": 10.0, "packet_count": 500.0}})
        assert r.status_code == 200
        body = r.json()
        assert body["attack_type"] in ("BENIGN", "DDoS")
        assert 0.0 <= body["confidence"] <= 1.0
        assert body["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert body["model_used"] == "RandomForestClassifier"

    # Reset the cache so other tests aren't affected by this test's monkeypatching.
    config_module._settings = None


def test_detect_missing_features_rejected(tmp_path, monkeypatch):
    rng = np.random.default_rng(1)
    X = pd.DataFrame({"duration": rng.normal(1, 0.1, 20), "packet_count": rng.normal(5, 0.5, 20)})
    y = pd.Series(["BENIGN"] * 20)
    result = train_random_forest(X, y, RFTrainingConfig(n_estimators=10, random_state=1))
    model_dir = tmp_path / "models"
    save_model(result, model_dir / "random_forest.joblib")

    monkeypatch.setenv("ML_MODEL_DIR", str(model_dir))
    import backend.app.config as config_module
    config_module._settings = None

    from backend.app.main import create_app
    app = create_app()
    with TestClient(app) as client:
        r = client.post("/detect", json={"features": {"duration": 1.0}})  # missing packet_count
        assert r.status_code == 422

    config_module._settings = None
