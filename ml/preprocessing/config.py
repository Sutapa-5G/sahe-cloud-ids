"""
Configuration for the CICIDS2017 preprocessing pipeline.

IMPORTANT: The label-normalization mapping below is a PLACEHOLDER derived
from the publicly documented CICIDS2017 label set. It has NOT been
validated against the actual CSV files in this environment because the
real dataset is not present here. When the pipeline is run against the
real files, `discover.py` / `loader.py` will report the *actual* labels
observed, and any label not present in LABEL_NORMALIZATION_MAP will be
surfaced as an "unknown label" in the pipeline output rather than
silently coerced. Update this map once real labels are confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# Filenames commonly seen in public CICIDS2017 distributions. This list is
# used only to report which "expected" files were found or missing — the
# pipeline does NOT require these exact names and will discover and process
# any *.csv file placed under raw_dir.
EXPECTED_FILENAMES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# Columns treated as identifier/metadata rather than ML features.
# This list is a starting point based on the publicly documented CICIDS2017
# schema (CICFlowMeter output columns). It MUST be reconciled against the
# actual columns discovered in the real CSVs — the pipeline reports any
# mismatch rather than assuming this list is exhaustive or correct.
KNOWN_IDENTIFIER_COLUMNS = [
    "flow id",
    "source ip",
    "src ip",
    "destination ip",
    "dst ip",
    "timestamp",
]

# Columns that are identifiers but may carry weak, legitimate signal
# (e.g. port numbers can matter for some attack types). These are flagged
# as MEDIUM leakage risk rather than auto-dropped like the ones above.
PORT_COLUMNS = [
    "source port",
    "src port",
    "destination port",
    "dst port",
]

# Placeholder label -> normalized-category mapping based on publicly
# documented CICIDS2017 label strings. NOT verified against real data yet.
# The pipeline will report any label it encounters that is NOT a key here.
LABEL_NORMALIZATION_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack \x96 XSS": "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Heartbleed": "Heartbleed",
}


@dataclass
class PipelineConfig:
    raw_dir: Path
    processed_dir: Path
    output_dir: Path
    seed: int = 42
    chunk_size: int = 100_000
    near_duplicate_sample_limit: int = 200_000
    expected_filenames: list[str] = field(default_factory=lambda: list(EXPECTED_FILENAMES))
    identifier_columns: list[str] = field(default_factory=lambda: list(KNOWN_IDENTIFIER_COLUMNS))
    port_columns: list[str] = field(default_factory=lambda: list(PORT_COLUMNS))
    label_map: dict[str, str] = field(default_factory=lambda: dict(LABEL_NORMALIZATION_MAP))

    def ensure_dirs(self) -> None:
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
