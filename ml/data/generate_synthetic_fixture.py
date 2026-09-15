"""Generate a small synthetic CICIDS2017-like fixture for software testing.

IMPORTANT:
- This is synthetic data, not CICIDS2017 and not a research benchmark.
- It exists so students can verify preprocessing and training commands
  before obtaining the official dataset.
- Never use its metrics as real IDS accuracy or as a replacement for the
  official CICIDS2017 evaluation.

The generator is deterministic for reproducibility and writes eight CSV files
with CICFlowMeter-style column names and common CICIDS2017 label strings.
"""
from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
LABELS = ["BENIGN", "DoS Hulk", "DDoS", "PortScan", "Bot", "FTP-Patator", "SSH-Patator", "Heartbleed"]
HEADERS = [
    "Flow ID", "Source IP", "Destination IP", "Source Port", "Destination Port",
    "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s",
    "Label",
]


def row_for(rng: random.Random, file_index: int, row_index: int) -> dict[str, object]:
    label = LABELS[(row_index + file_index) % len(LABELS)]
    attack_factor = 1 if label == "BENIGN" else 2 + ((row_index + file_index) % 4)
    duration = 50_000 + attack_factor * 12_000 + rng.randint(0, 5_000)
    fwd_packets = 10 + attack_factor * 5 + rng.randint(0, 4)
    bwd_packets = 8 + (attack_factor % 3) * 4 + rng.randint(0, 3)
    fwd_len = fwd_packets * (80 + attack_factor * 20)
    bwd_len = bwd_packets * (60 + attack_factor * 15)
    total_bytes = fwd_len + bwd_len
    return {
        "Flow ID": f"synthetic-{file_index:02d}-{row_index:04d}",
        "Source IP": f"192.0.2.{(row_index % 200) + 1}",
        "Destination IP": f"198.51.100.{(file_index % 200) + 1}",
        "Source Port": 10_000 + ((row_index * 17 + file_index) % 50_000),
        "Destination Port": 80 if label == "BENIGN" else 443 if label == "Heartbleed" else 22,
        "Protocol": 6 if row_index % 5 else 17,
        "Timestamp": f"2017-07-{3 + file_index:02d} 09:{(row_index % 60):02d}:00",
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": bwd_packets,
        "Total Length of Fwd Packets": fwd_len,
        "Total Length of Bwd Packets": bwd_len,
        "Fwd Packet Length Mean": round(fwd_len / fwd_packets, 3),
        "Bwd Packet Length Mean": round(bwd_len / bwd_packets, 3),
        "Flow Bytes/s": round(total_bytes / (duration / 1_000_000), 3),
        "Flow Packets/s": round((fwd_packets + bwd_packets) / (duration / 1_000_000), 3),
        "Label": label,
    }


def generate(output_dir: Path, rows_per_file: int, seed: int) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    written: list[Path] = []
    for file_index, filename in enumerate(FILES):
        path = output_dir / filename
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=HEADERS)
            writer.writeheader()
            for row_index in range(rows_per_file):
                writer.writerow(row_for(rng, file_index, row_index))
        written.append(path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic CICIDS2017-like CSVs for software testing only")
    parser.add_argument("--output-dir", type=Path, default=Path("ml/data/synthetic_raw"))
    parser.add_argument("--rows-per-file", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20260915)
    args = parser.parse_args()
    paths = generate(args.output_dir, args.rows_per_file, args.seed)
    print("SYNTHETIC DATA ONLY — not CICIDS2017 and not for research metrics")
    print(f"Generated {len(paths)} CSV files with {args.rows_per_file} rows each under {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
