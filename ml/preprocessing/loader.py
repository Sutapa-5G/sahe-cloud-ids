"""
Robust, chunked CICIDS2017 CSV loading.

- Normalizes column names (strips whitespace, lowercases, collapses
  internal whitespace to single underscores) so that inconsistent headers
  across the 8 CICIDS2017 files (a known quirk of this dataset) don't
  silently create duplicate/near-duplicate columns.
- Preserves the ORIGINAL label string in a separate column
  (`label_original`) before any normalization is applied downstream.
- Loads via pandas chunked reader to avoid pulling a multi-GB dataset
  fully into memory at once.
- Never silently drops unparseable rows: rows pandas cannot parse raise
  during iteration and are surfaced, not swallowed.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

import pandas as pd


_WS_RE = re.compile(r"\s+")


def normalize_column_name(col: str) -> str:
    col = col.strip()
    col = col.replace("/", "_")
    col = _WS_RE.sub("_", col)
    return col.lower()


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={c: normalize_column_name(c) for c in df.columns})
    return df


def find_label_column(columns: list[str]) -> str | None:
    for c in columns:
        if c == "label":
            return c
    return None


def load_csv_chunks(path: Path, chunk_size: int, source_tag: str) -> Iterator[pd.DataFrame]:
    """
    Yields normalized DataFrame chunks from a single CICIDS2017 CSV file.

    Each chunk gains:
      - `source_file`: the originating filename (for day/file-aware split
        and per-file leakage/duplicate analysis)
      - `label_original`: the untouched label string, captured before any
        normalization, so provenance is never lost.
    """
    reader = pd.read_csv(
        path,
        chunksize=chunk_size,
        low_memory=False,
        encoding="utf-8",
        engine="c",
        on_bad_lines="error",  # never silently skip malformed rows
    )
    for chunk in reader:
        chunk = normalize_columns(chunk)
        label_col = find_label_column(list(chunk.columns))
        if label_col is not None:
            chunk["label_original"] = chunk[label_col].astype(str).str.strip()
        else:
            chunk["label_original"] = pd.NA
        chunk["source_file"] = source_tag
        yield chunk
