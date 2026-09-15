def test_detect_returns_503_when_no_model_loaded(client):
    """
    Core test for this project's honesty discipline: with no trained
    model in ml/models/ (which is the current real state — CICIDS2017
    has never been available to train on), /detect must fail clearly,
    not fabricate a prediction.
    """
    r = client.post("/detect", json={"features": {"duration": 1.0, "packet_count": 10}})
    assert r.status_code == 503
    assert "No trained detection model" in r.json()["detail"]
