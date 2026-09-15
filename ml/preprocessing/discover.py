"""
Discovers CSV files under a raw-data directory and produces a manifest
describing what was found, what was expected but missing, and any files
that could not be read at all (malformed/unreadable).

This module never fabricates statistics: if a file cannot be read, it is
recorded as unreadable with the error message, not skipped silently.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class DiscoveredFile:
    filename: str
    path: str
    size_bytes: int
    readable: bool
    error: str | None
    row_count: int | None       # None if not safely countable / not attempted
    column_count: int | None
    columns: list[str] | None


@dataclass
class DiscoveryManifest:
    raw_dir: str
    discovered_files: list[DiscoveredFile]
    expected_filenames: list[str]
    expected_found: list[str]
    expected_missing: list[str]
    unexpected_files: list[str]
    total_files_found: int
    total_size_bytes: int

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _count_rows_and_peek_columns(path: Path) -> tuple[int | None, list[str] | None, str | None]:
    """
    Count data rows (excluding header) and capture the header row.
    Uses a plain line-count pass; robust to being large by not loading the
    whole file into memory as a DataFrame.
    Returns (row_count, columns, error).
    """
    try:
        with path.open("r", encoding="utf-8", errors="strict", newline="") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                return 0, [], None
            columns = [c.strip() for c in header]
            row_count = sum(1 for _ in reader)
            return row_count, columns, None
    except UnicodeDecodeError as e:
        # Retry with a permissive encoding so we can still report structure,
        # but flag the encoding issue explicitly rather than hiding it.
        try:
            with path.open("r", encoding="latin-1", newline="") as f:
                reader = csv.reader(f)
                header = next(reader, [])
                columns = [c.strip() for c in header]
                row_count = sum(1 for _ in reader)
            return row_count, columns, f"UnicodeDecodeError under utf-8 (read via latin-1 fallback): {e}"
        except Exception as e2:  # noqa: BLE001 - report, don't hide
            return None, None, f"Failed under utf-8 and latin-1 fallback: {e2}"
    except Exception as e:  # noqa: BLE001 - report, don't hide
        return None, None, str(e)


def discover_csv_files(raw_dir: Path, expected_filenames: list[str]) -> DiscoveryManifest:
    if not raw_dir.exists():
        raise FileNotFoundError(f"raw_dir does not exist: {raw_dir}")

    csv_paths = sorted(raw_dir.glob("*.csv"))

    discovered: list[DiscoveredFile] = []
    total_size = 0

    for p in csv_paths:
        size = p.stat().st_size
        total_size += size
        row_count, columns, error = _count_rows_and_peek_columns(p)
        discovered.append(
            DiscoveredFile(
                filename=p.name,
                path=str(p),
                size_bytes=size,
                readable=error is None or error.startswith("UnicodeDecodeError"),
                error=error,
                row_count=row_count,
                column_count=len(columns) if columns is not None else None,
                columns=columns,
            )
        )

    found_names = {d.filename for d in discovered}
    expected_found = [f for f in expected_filenames if f in found_names]
    expected_missing = [f for f in expected_filenames if f not in found_names]
    unexpected = [f for f in found_names if f not in expected_filenames]

    return DiscoveryManifest(
        raw_dir=str(raw_dir),
        discovered_files=discovered,
        expected_filenames=list(expected_filenames),
        expected_found=expected_found,
        expected_missing=expected_missing,
        unexpected_files=sorted(unexpected),
        total_files_found=len(discovered),
        total_size_bytes=total_size,
    )


def write_manifest(manifest: DiscoveryManifest, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2)
