def test_get_all_benchmarks_returns_real_phase7_data(client):
    """
    This asserts against the REAL experiments/results/crypto_benchmark_aggregated.json
    produced by Phase 7 — not synthetic data. If that file is absent
    (e.g. a fresh checkout before Phase 7 was run), this test should be
    skipped rather than fabricate an expectation.
    """
    r = client.get("/benchmarks")
    if r.status_code == 503:
        import pytest
        pytest.skip("Phase 7 benchmark results not present in this checkout.")
    assert r.status_code == 200
    body = r.json()
    assert "results" in body
    assert len(body["results"]) > 0
    algorithms = {entry["algorithm"] for entry in body["results"]}
    assert "AES-256-GCM" in algorithms


def test_get_benchmark_for_specific_algorithm(client):
    r = client.get("/benchmarks/AES-256-GCM")
    if r.status_code == 503:
        import pytest
        pytest.skip("Phase 7 benchmark results not present in this checkout.")
    assert r.status_code == 200
    body = r.json()
    assert body["algorithm"] == "AES-256-GCM"
    assert len(body["results"]) > 0


def test_get_benchmark_unknown_algorithm_404(client):
    r = client.get("/benchmarks/NotARealAlgorithm")
    if r.status_code == 503:
        import pytest
        pytest.skip("Phase 7 benchmark results not present in this checkout.")
    assert r.status_code == 404
