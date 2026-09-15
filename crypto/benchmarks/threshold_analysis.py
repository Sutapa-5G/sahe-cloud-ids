"""
crypto/benchmarks/threshold_analysis.py

Phase 8: analyzes the REAL benchmark results produced by
crypto/benchmarks/run_suite.py to determine whether a meaningful
crossover point exists between ECDH/X25519 and RSA-OAEP hybrid schemes,
and reports it honestly — including reporting "no meaningful crossover
found" if that is what the data shows, per the project's scientific
honesty requirement.

This module does NOT force a crossover to exist. It reads
experiments/results/crypto_benchmark_aggregated.json (produced by an
ACTUAL run of run_suite.py) and computes where the total_operation_seconds
(or throughput) curves for ECDH-X25519-Hybrid and RSA-OAEP-Hybrid cross,
if they do.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class CrossoverFinding:
    metric: str
    algorithm_a: str
    algorithm_b: str
    crossover_found: bool
    crossover_payload_size_bytes: int | None
    explanation: str
    data_points: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


def _load_aggregated(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"Aggregated benchmark results not found at {path}. "
            f"Run Phase 7 first: python -m crypto.benchmarks.run_suite"
        )
    with path.open() as f:
        return json.load(f)


def _series_for_algorithm(aggregated: dict, algorithm: str, metric_path: tuple[str, ...]) -> list[tuple[int, float]]:
    """
    Extracts (payload_size_bytes, metric_value) pairs for a given
    algorithm from the aggregated results, sorted by payload size.
    metric_path e.g. ("total_operation_seconds", "mean").
    """
    points = []
    for entry in aggregated["results"]:
        if entry["algorithm"] != algorithm:
            continue
        value = entry
        for key in metric_path:
            if value is None:
                break
            value = value.get(key)
        if value is not None:
            points.append((entry["payload_size_bytes"], value))
    return sorted(points)


def find_crossover(
    aggregated: dict,
    algorithm_a: str = "ECDH-X25519-Hybrid",
    algorithm_b: str = "RSA-OAEP-Hybrid",
    metric_path: tuple[str, ...] = ("total_operation_seconds", "mean"),
) -> CrossoverFinding:
    series_a = _series_for_algorithm(aggregated, algorithm_a, metric_path)
    series_b = _series_for_algorithm(aggregated, algorithm_b, metric_path)

    sizes_a = {s for s, _ in series_a}
    sizes_b = {s for s, _ in series_b}
    common_sizes = sorted(sizes_a & sizes_b)

    if len(common_sizes) < 2:
        return CrossoverFinding(
            metric=".".join(metric_path),
            algorithm_a=algorithm_a,
            algorithm_b=algorithm_b,
            crossover_found=False,
            crossover_payload_size_bytes=None,
            explanation=(
                f"Fewer than 2 common payload sizes with data for both "
                f"{algorithm_a} and {algorithm_b} — cannot assess a crossover. "
                f"This is a data-coverage limitation, not a claim about crypto behavior."
            ),
            data_points=[],
        )

    a_by_size = dict(series_a)
    b_by_size = dict(series_b)

    data_points = [
        {"payload_size_bytes": s, algorithm_a: a_by_size[s], algorithm_b: b_by_size[s]}
        for s in common_sizes
    ]

    # Look for a sign change in (a - b) across consecutive sizes.
    crossover_size = None
    prev_size, prev_diff = None, None
    for s in common_sizes:
        diff = a_by_size[s] - b_by_size[s]
        if prev_diff is not None and (prev_diff > 0) != (diff > 0) and prev_diff != 0 and diff != 0:
            # Sign changed between prev_size and s — report the LARGER of
            # the two sizes as the observed crossover point (i.e. the
            # first size at which the relationship has flipped), which is
            # a conservative, defensible choice rather than interpolating
            # a value that was never actually measured.
            crossover_size = s
            break
        prev_size, prev_diff = s, diff

    if crossover_size is not None:
        return CrossoverFinding(
            metric=".".join(metric_path),
            algorithm_a=algorithm_a,
            algorithm_b=algorithm_b,
            crossover_found=True,
            crossover_payload_size_bytes=crossover_size,
            explanation=(
                f"Between the measured payload sizes surrounding {crossover_size} bytes, "
                f"{algorithm_a} and {algorithm_b} swap which one has the lower {metric_path[0]}. "
                f"The reported crossover size is the larger of the two measured sizes "
                f"bracketing the swap — an exact crossover point was not interpolated, "
                f"only observed between real measured points."
            ),
            data_points=data_points,
        )
    else:
        # Report honestly which algorithm was consistently better/worse
        # rather than fabricating a crossover that the data doesn't show.
        a_wins = sum(1 for s in common_sizes if a_by_size[s] < b_by_size[s])
        b_wins = len(common_sizes) - a_wins
        if a_wins == len(common_sizes):
            summary = f"{algorithm_a} had lower {metric_path[0]} at every measured payload size."
        elif b_wins == len(common_sizes):
            summary = f"{algorithm_b} had lower {metric_path[0]} at every measured payload size."
        else:
            summary = (
                f"{algorithm_a} was lower at {a_wins}/{len(common_sizes)} sizes and "
                f"{algorithm_b} at {b_wins}/{len(common_sizes)}, with no consistent "
                f"single crossover point (the ordering did not change monotonically)."
            )
        return CrossoverFinding(
            metric=".".join(metric_path),
            algorithm_a=algorithm_a,
            algorithm_b=algorithm_b,
            crossover_found=False,
            crossover_payload_size_bytes=None,
            explanation=(
                f"No sign-change crossover found across the measured payload sizes "
                f"{common_sizes}. {summary} This is reported as-is; SAHE's threshold "
                f"policy should NOT claim an empirically-derived crossover if none "
                f"was observed — see docs/methodology/threshold_derivation.md."
            ),
            data_points=data_points,
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 8: derive SAHE thresholds from real Phase 7 benchmark data")
    p.add_argument("--results-dir", type=Path, default=Path("experiments/results"))
    p.add_argument("--metric", nargs="+", default=["total_operation_seconds", "mean"])
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    aggregated_path = args.results_dir / "crypto_benchmark_aggregated.json"

    try:
        aggregated = _load_aggregated(aggregated_path)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1

    finding = find_crossover(aggregated, metric_path=tuple(args.metric))

    output_path = args.results_dir / "threshold_analysis.json"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(finding.to_dict(), f, indent=2)

    print(f"Crossover found: {finding.crossover_found}")
    if finding.crossover_found:
        print(f"Crossover payload size: {finding.crossover_payload_size_bytes} bytes")
    print(finding.explanation)
    print(f"Full analysis written to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
