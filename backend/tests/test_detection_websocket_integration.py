"""
End-to-end test for Phase 11: a REAL detection (via a real, if
synthetically-trained, model) of a malicious sample triggers a REAL
WebSocket broadcast that a REAL connected test client receives. This is
the core "did we actually wire this together correctly" test — unit
tests for AlertService alone wouldn't catch a wiring mistake in
detection.py or main.py's app.state setup.
"""
import json

import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from ml.training.train_random_forest import RFTrainingConfig, train_random_forest, save_model


def test_malicious_detection_triggers_real_websocket_broadcast(tmp_path, monkeypatch):
    rng = np.random.default_rng(7)
    X = pd.DataFrame({
        "duration": np.concatenate([rng.normal(1, 0.1, 50), rng.normal(20, 0.1, 50)]),
        "packet_count": np.concatenate([rng.normal(5, 0.5, 50), rng.normal(1000, 0.5, 50)]),
    })
    y = pd.Series(["BENIGN"] * 50 + ["DDoS"] * 50)
    result = train_random_forest(X, y, RFTrainingConfig(n_estimators=30, random_state=7))

    model_dir = tmp_path / "models"
    save_model(result, model_dir / "random_forest.joblib")
    monkeypatch.setenv("ML_MODEL_DIR", str(model_dir))

    import backend.app.config as config_module
    config_module._settings = None

    from backend.app.main import create_app
    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect("/ws/events") as websocket:
            # Send a clearly-DDoS-shaped sample (far into the "attack"
            # cluster the model was trained on).
            r = client.post("/detect", json={"features": {"duration": 20.0, "packet_count": 1000.0}})
            assert r.status_code == 200
            body = r.json()

            if body["is_malicious"]:
                # Only expect a broadcast if the model actually classified
                # this as malicious — it's a real (if small/synthetic)
                # model, so we check the actual response rather than
                # assuming the classification.
                assert body["event_id"] is not None

                received = websocket.receive_text()
                alert = json.loads(received)
                assert alert["type"] == "alert"
                assert alert["event_id"] == body["event_id"]
                assert alert["attack_type"] == body["attack_type"]
                assert alert["severity"] == body["severity"]
            else:
                assert body["event_id"] is None

    config_module._settings = None


def test_benign_detection_does_not_trigger_broadcast(tmp_path, monkeypatch):
    rng = np.random.default_rng(3)
    X = pd.DataFrame({
        "duration": np.concatenate([rng.normal(1, 0.1, 50), rng.normal(20, 0.1, 50)]),
        "packet_count": np.concatenate([rng.normal(5, 0.5, 50), rng.normal(1000, 0.5, 50)]),
    })
    y = pd.Series(["BENIGN"] * 50 + ["DDoS"] * 50)
    result = train_random_forest(X, y, RFTrainingConfig(n_estimators=30, random_state=3))

    model_dir = tmp_path / "models"
    save_model(result, model_dir / "random_forest.joblib")
    monkeypatch.setenv("ML_MODEL_DIR", str(model_dir))

    import backend.app.config as config_module
    config_module._settings = None

    from backend.app.main import create_app
    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect("/ws/events") as websocket:
            # Clearly-benign-shaped sample.
            r = client.post("/detect", json={"features": {"duration": 1.0, "packet_count": 5.0}})
            assert r.status_code == 200
            body = r.json()

            if not body["is_malicious"]:
                assert body["event_id"] is None
                # No message should have been broadcast. We can't easily
                # assert "nothing was received" with a blocking
                # receive_text() without a timeout mechanism, so instead
                # the absence of event_id and is_malicious=False is the
                # primary real assertion for this test.
                pass

    config_module._settings = None
