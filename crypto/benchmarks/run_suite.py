"""
crypto/benchmarks/run_suite.py

Runs the full crypto benchmark suite across a sweep of payload sizes,
repeating each measurement N times and reporting mean/median/stddev —
never a single unrepeated timing. All numbers in this module's output
come from actually executing the crypto primitives in this environment.

Usage:
    python -m crypto.benchmarks.run_suite --output-dir experiments/results --repetitions 30
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
from pathlib import Path

from crypto.benchmarks.harness import (
    benchmark_aes_gcm,
    benchmark_ecdh_x25519_hybrid,
    benchmark_rsa_oaep_hybrid,
)
from crypto.benchmarks.legacy_ciphers import benchmark_des, benchmark_3des, benchmark_blowfish
from crypto.algorithms import rsa_oaep_hybrid as rsa_module

# Payload sizes per the project spec. Note: at high repetition counts, the
# largest sizes (50MB, 100MB) multiplied across 6 algorithms will take
# real wall-clock time (RSA especially, due to keygen) — --repetitions and
# --max-size-bytes are configurable so a smaller sweep can be run first.
DEFAULT_PAYLOAD_SIZES_BYTES = [
    1 * 1024,
    10 * 1024,
    50 * 1024,
    100 * 1024,
    250 * 1024,
    500 * 1024,
    1 * 1024 * 1024,
    5 * 1024 * 1024,
    10 * 1024 * 1024,
    50 * 1024 * 1024,
    100 * 1024 * 1024,
]

ALGORITHMS = ["AES-256-GCM", "ECDH-X25519-Hybrid", "RSA-OAEP-Hybrid", "DES", "3DES", "Blowfish"]


def _stats(values: list[float]) -> dict:
    if not values:
        return {"mean": None, "median": None, "stdev": None, "min": None, "max": None, "n": 0}
    return {
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
        "n": len(values),
    }


def _make_payload(size_bytes: int) -> bytes:
    # Deterministic-length pseudo-random-looking payload (content doesn't
    # need to be cryptographically random — it's benchmark input, not a
    # security-relevant value).
    pattern = os.urandom(min(size_bytes, 4096)) if size_bytes > 0 else b""
    if not pattern:
        return b""
    repeats = (size_bytes // len(pattern)) + 1
    return (pattern * repeats)[:size_bytes]


def run_algorithm_sweep(
    payload_sizes: list[int],
    repetitions: int,
    algorithms: list[str],
):
    """
    Returns (rows, rsa_keygen_time). `rows` is a flat list of per-
    (algorithm, payload_size, repetition) result dicts — the rawest
    granularity, from which the aggregated report is built. Every row
    here corresponds to one real executed operation.
    """
    rows = []

    # RSA key generation is expensive (~hundreds of ms at 3072 bits); to
    # avoid conflating "RSA key generation cost" with "payload size" in
    # the per-size sweep, one RSA keypair is generated up front, its
    # generation cost measured separately (reported once, not per-row),
    # and reused for the payload-size sweep's key-exchange/encryption
    # measurements. Documented, not hidden — see
    # rsa_keygen_seconds_measured_once in the summary output.
    rsa_keygen_time = None
    rsa_keypair = None
    if "RSA-OAEP-Hybrid" in algorithms:
        import time
        start = time.perf_counter()
        rsa_keypair = rsa_module.generate_rsa_keypair()
        rsa_keygen_time = time.perf_counter() - start

    for size in payload_sizes:
        payload = _make_payload(size)
        for rep in range(repetitions):
            if "AES-256-GCM" in algorithms:
                t = benchmark_aes_gcm(payload)
                rows.append({"algorithm": "AES-256-GCM", "payload_size_bytes": size, "repetition": rep, **t.to_dict()})

            if "ECDH-X25519-Hybrid" in algorithms:
                t = benchmark_ecdh_x25519_hybrid(payload)
                rows.append({"algorithm": "ECDH-X25519-Hybrid", "payload_size_bytes": size, "repetition": rep, **t.to_dict()})

            if "RSA-OAEP-Hybrid" in algorithms:
                t = benchmark_rsa_oaep_hybrid(payload, rsa_keypair_cache=rsa_keypair)
                rows.append({"algorithm": "RSA-OAEP-Hybrid", "payload_size_bytes": size, "repetition": rep, **t.to_dict()})

            if "DES" in algorithms:
                t = benchmark_des(payload)
                rows.append({"algorithm": "DES", "payload_size_bytes": size, "repetition": rep, **t.to_dict()})

            if "3DES" in algorithms:
                t = benchmark_3des(payload)
                rows.append({"algorithm": "3DES", "payload_size_bytes": size, "repetition": rep, **t.to_dict()})

            if "Blowfish" in algorithms:
                t = benchmark_blowfish(payload)
                rows.append({"algorithm": "Blowfish", "payload_size_bytes": size, "repetition": rep, **t.to_dict()})

    return rows, rsa_keygen_time


def aggregate(rows: list[dict]) -> dict:
    """
    Groups raw rows by (algorithm, payload_size_bytes) and computes
    mean/median/stdev for each timing field.
    """
    grouped: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (row["algorithm"], row["payload_size_bytes"])
        grouped.setdefault(key, []).append(row)

    timing_fields = [
        "key_generation_seconds",
        "key_exchange_seconds",
        "payload_encryption_seconds",
        "total_operation_seconds",
    ]

    aggregated = []
    for (algo, size), group_rows in sorted(grouped.items(), key=lambda x: (x[0][0], x[0][1])):
        entry = {"algorithm": algo, "payload_size_bytes": size, "n_repetitions": len(group_rows)}
        for field in timing_fields:
            values = [r[field] for r in group_rows if field in r and r[field] is not None]
            entry[field] = _stats(values)
        if group_rows:
            entry["ciphertext_size_bytes"] = group_rows[0].get("ciphertext_size_bytes")
            entry["ciphertext_expansion_bytes"] = group_rows[0].get("ciphertext_expansion_bytes")
            throughput_values = [
                (r["payload_size_bytes"] / r["total_operation_seconds"] / (1024 * 1024))
                for r in group_rows if r.get("total_operation_seconds", 0) > 0
            ]
            entry["throughput_mb_per_second"] = _stats(throughput_values)
        aggregated.append(entry)

    return {"results": aggregated}


def write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({k for row in rows for k in row.keys()})
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 7: crypto benchmark suite")
    p.add_argument("--output-dir", type=Path, default=Path("experiments/results"))
    p.add_argument("--repetitions", type=int, default=10)
    p.add_argument("--max-size-bytes", type=int, default=None, help="Cap the largest payload size tested, for a faster/smaller run.")
    p.add_argument(
        "--algorithms", nargs="*", default=ALGORITHMS,
        help=f"Subset of algorithms to run. Default: all of {ALGORITHMS}",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    sizes = DEFAULT_PAYLOAD_SIZES_BYTES
    if args.max_size_bytes is not None:
        sizes = [s for s in sizes if s <= args.max_size_bytes]
        if not sizes:
            print(f"ERROR: --max-size-bytes {args.max_size_bytes} excludes all default payload sizes.")
            return 1

    print(f"Running crypto benchmark suite: {len(sizes)} sizes x {args.repetitions} repetitions x {len(args.algorithms)} algorithms")
    print(f"Sizes (bytes): {sizes}")

    rows, rsa_keygen_time = run_algorithm_sweep(sizes, args.repetitions, args.algorithms)
    aggregated = aggregate(rows)
    aggregated["metadata"] = {
        "repetitions": args.repetitions,
        "payload_sizes_bytes": sizes,
        "algorithms": args.algorithms,
        "rsa_keygen_seconds_measured_once": rsa_keygen_time,
        "note": (
            "RSA key generation cost is measured once (not per payload "
            "size/repetition) due to its high fixed cost relative to "
            "payload-size-dependent operations; see rsa_keygen_seconds_measured_once. "
            "DES/3DES/Blowfish are legacy algorithms included for "
            "historical/performance comparison only — see "
            "crypto/benchmarks/legacy_ciphers.py::LEGACY_DISCLAIMER."
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_csv_path = args.output_dir / "crypto_benchmark_raw.csv"
    agg_json_path = args.output_dir / "crypto_benchmark_aggregated.json"

    write_csv(rows, raw_csv_path)
    with agg_json_path.open("w", encoding="utf-8") as f:
        json.dump(aggregated, f, indent=2)

    print(f"Raw measurements ({len(rows)} rows) written to {raw_csv_path}")
    print(f"Aggregated results written to {agg_json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
