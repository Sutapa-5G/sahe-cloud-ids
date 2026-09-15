"""
backend/app/api/routes/benchmark.py

GET /benchmarks, GET /benchmarks/{algorithm}. Reads the REAL benchmark
results produced by Phase 7
(experiments/results/crypto_benchmark_aggregated.json) — never
fabricates a result if the file is absent.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/benchmarks", tags=["benchmarks"])

_RESULTS_PATH = Path("experiments/results/crypto_benchmark_aggregated.json")


def _load_results() -> dict:
    if not _RESULTS_PATH.exists():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"No benchmark results found at {_RESULTS_PATH}. Run "
                f"'python -m crypto.benchmarks.run_suite' first (Phase 7)."
            ),
        )
    with _RESULTS_PATH.open() as f:
        return json.load(f)


@router.get("")
async def get_all_benchmarks() -> dict:
    return _load_results()


@router.get("/{algorithm}")
async def get_benchmark_for_algorithm(algorithm: str) -> dict:
    data = _load_results()
    matching = [r for r in data["results"] if r["algorithm"].lower() == algorithm.lower()]
    if not matching:
        available = sorted({r["algorithm"] for r in data["results"]})
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No benchmark results for algorithm '{algorithm}'. Available: {available}",
        )
    return {"algorithm": algorithm, "results": matching, "metadata": data.get("metadata")}
