"""Phase 16–17 benchmark analysis for SAHE Cloud IDS/IPS.

This script consumes only measured benchmark outputs already present in
experiments/results/. It never creates CICIDS2017 model metrics. If the
real dataset/model result files are absent, the ML comparison is reported as
NOT EXECUTED YET rather than being synthesized.

Outputs:
  - phase16_17_summary.json
  - crypto_total_operation_seconds.png
  - crypto_throughput.png
  - crypto_overhead.png
  - policy_regret.csv
  - ml_model_comparison.png (only when real model result JSON files exist)
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt


APPROVED = {"AES-256-GCM", "ECDH-X25519-Hybrid", "RSA-OAEP-Hybrid"}
LEGACY = {"DES", "3DES", "Blowfish"}
PAYLOAD_SIZES = [1024, 10240, 51200, 102400, 256000, 512000, 1048576, 5242880, 10485760, 52428800, 104857600]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def flatten_aggregated(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    for key in ("results", "records", "benchmarks", "data"):
        if isinstance(data, dict) and isinstance(data.get(key), list):
            return data[key]
    raise ValueError("Unsupported aggregated benchmark JSON shape")


def mean_metric(row: dict[str, Any], metric: str) -> float | None:
    value = row.get(metric)
    if isinstance(value, dict):
        value = value.get("mean")
    return float(value) if isinstance(value, (int, float)) else None


def grouped(rows: list[dict[str, Any]], metric: str) -> dict[str, dict[int, float]]:
    out: dict[str, dict[int, float]] = {}
    for row in rows:
        algorithm = str(row.get("algorithm"))
        size = int(row.get("payload_size_bytes"))
        value = mean_metric(row, metric)
        if value is not None:
            out.setdefault(algorithm, {})[size] = value
    return out


def make_crypto_plots(rows: list[dict[str, Any]], output_dir: Path) -> None:
    series = grouped(rows, "total_operation_seconds")
    plt.figure(figsize=(10, 6))
    for algorithm, values in sorted(series.items()):
        if algorithm in APPROVED:
            xs = sorted(values)
            plt.plot(xs, [values[x] for x in xs], marker="o", label=algorithm)
    plt.xscale("log")
    plt.yscale("log")
    plt.xlabel("Payload size (bytes, logarithmic scale)")
    plt.ylabel("Mean total operation time (seconds, logarithmic scale)")
    plt.title("Measured approved hybrid operation cost")
    plt.grid(True, which="both", alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "crypto_total_operation_seconds.png", dpi=160)
    plt.close()

    throughput = grouped(rows, "throughput_mb_per_second")
    plt.figure(figsize=(10, 6))
    for algorithm, values in sorted(throughput.items()):
        if algorithm in APPROVED:
            xs = sorted(values)
            plt.plot(xs, [values[x] for x in xs], marker="o", label=algorithm)
    plt.xscale("log")
    plt.xlabel("Payload size (bytes, logarithmic scale)")
    plt.ylabel("Mean throughput (MiB/s)")
    plt.title("Measured approved throughput")
    plt.grid(True, which="both", alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "crypto_throughput.png", dpi=160)
    plt.close()

    overhead = grouped(rows, "ciphertext_expansion_bytes")
    plt.figure(figsize=(10, 6))
    for algorithm, values in sorted(overhead.items()):
        if algorithm in APPROVED:
            xs = sorted(values)
            plt.plot(xs, [values[x] for x in xs], marker="o", label=algorithm)
    plt.xscale("log")
    plt.xlabel("Payload size (bytes, logarithmic scale)")
    plt.ylabel("Ciphertext expansion (bytes)")
    plt.title("Measured ciphertext expansion")
    plt.grid(True, which="both", alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "crypto_overhead.png", dpi=160)
    plt.close()


def regret_analysis(rows: list[dict[str, Any]], output_dir: Path) -> dict[str, Any]:
    """Compare the configured policy's establishment method to measured minima.

    This is a benchmark-policy diagnostic, not a security ranking. AES-GCM is
    always the payload cipher. The comparison is between feasible key-
    establishment options only, and uses total_operation_seconds.mean.
    """
    by_size = grouped(rows, "total_operation_seconds")
    methods = [name for name in ("ECDH-X25519-Hybrid", "RSA-OAEP-Hybrid") if name in by_size]
    records: list[dict[str, Any]] = []
    for size in sorted(set().union(*(set(by_size[m]) for m in methods))):
        measured = {m: by_size[m][size] for m in methods if size in by_size[m]}
        if not measured:
            continue
        best = min(measured, key=measured.get)
        # Current policy is intentionally represented as its documented
        # threshold rule: small/medium selects ECDH; large selects RSA.
        policy_choice = "ECDH-X25519-Hybrid" if size <= 1024 * 1024 else "RSA-OAEP-Hybrid"
        chosen = measured.get(policy_choice)
        regret = (chosen - measured[best]) if chosen is not None else None
        records.append({
            "payload_size_bytes": size,
            "policy_choice": policy_choice,
            "measured_best_feasible_option": best,
            "policy_matches_measured_best": policy_choice == best,
            "policy_regret_seconds": regret,
            "measured_options": measured,
        })
    match_count = sum(r["policy_matches_measured_best"] for r in records)
    total = len(records)
    with (output_dir / "policy_regret.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["payload_size_bytes", "policy_choice", "measured_best_feasible_option", "policy_matches_measured_best", "policy_regret_seconds"])
        writer.writeheader()
        writer.writerows({k: r[k] for k in writer.fieldnames} for r in records)
    return {
        "status": "EXECUTED on existing measured Phase 7 benchmark output",
        "metric": "total_operation_seconds.mean",
        "feasible_options": methods,
        "policy_rule_modelled": "ECDH at <= 1 MiB; RSA above 1 MiB",
        "n_payload_sizes": total,
        "matches": match_count,
        "selection_accuracy": (match_count / total) if total else None,
        "records": records,
        "interpretation": "This diagnostic does not alter the security policy or claim that RSA is universally superior. It reports the measured ordering on this hardware and must be rerun on deployment hardware.",
    }


def model_result_status(results_dir: Path) -> dict[str, Any]:
    candidates = sorted(results_dir.glob("*random*forest*.json")) + sorted(results_dir.glob("*xgboost*.json"))
    if not candidates:
        return {"status": "NOT EXECUTED YET", "reason": "No real CICIDS2017 model-result JSON files were found.", "files": []}
    return {"status": "AVAILABLE FILES REQUIRE REVIEW", "files": [str(p) for p in candidates]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", type=Path, default=Path("experiments/results"))
    args = parser.parse_args()
    args.results_dir.mkdir(parents=True, exist_ok=True)
    aggregated_path = args.results_dir / "crypto_benchmark_aggregated.json"
    rows = flatten_aggregated(load_json(aggregated_path))
    make_crypto_plots(rows, args.results_dir)
    regret = regret_analysis(rows, args.results_dir)
    approved_rows = [r for r in rows if r.get("algorithm") in APPROVED]
    legacy_rows = [r for r in rows if r.get("algorithm") in LEGACY]
    summary = {
        "phase": "16-17",
        "status": "EXECUTED for cryptographic benchmark analysis; ML analysis remains NOT EXECUTED YET",
        "source_file": str(aggregated_path),
        "n_aggregated_rows": len(rows),
        "approved_algorithms": sorted({r.get("algorithm") for r in approved_rows}),
        "legacy_baselines": sorted({r.get("algorithm") for r in legacy_rows}),
        "payload_sizes_bytes": sorted({int(r.get("payload_size_bytes")) for r in rows}),
        "crypto_benchmark_note": "These are the previously measured Phase 7 results on the sandbox hardware, not new deployment-hardware measurements.",
        "ml_model_results": model_result_status(args.results_dir),
        "policy_regret": regret,
        "generated_files": [
            "crypto_total_operation_seconds.png",
            "crypto_throughput.png",
            "crypto_overhead.png",
            "policy_regret.csv",
            "phase16_17_summary.json",
        ],
    }
    (args.results_dir / "phase16_17_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"status": summary["status"], "rows": len(rows), "selection_accuracy": regret["selection_accuracy"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# Keep math/statistics imports explicit for downstream notebooks that import
# this module; no fabricated statistic is emitted by this script.
_ = (math, statistics)
        
