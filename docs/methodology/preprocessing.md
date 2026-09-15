# Preprocessing Methodology (Phase 1)

## Status

This document describes the Phase 1 preprocessing pipeline architecture
and policies. **Real CICIDS2017 statistics are generated only when the
actual dataset is present under `ml/data/raw/` and the pipeline is
executed.** As of this writing, the dataset has not been placed in this
environment, so no real dataset statistics exist yet anywhere in this
repository. Everything validated so far used small synthetic fixtures
for unit/integration testing only (see "Testing" below) — those numbers
are not CICIDS2017 statistics and must never be cited as such.

## Dataset Location

Place the raw CICIDS2017 CSV files at:

```
ml/data/raw/*.csv
```

The pipeline does not require exactly the 8 standard filenames — it
discovers any `*.csv` file in that directory. It separately reports
which of the commonly-known standard filenames were found or are
missing, purely for informational cross-checking (see
`ml/preprocessing/config.py::EXPECTED_FILENAMES`).

## Architecture

```
discover.py       -> data_manifest.json
loader.py         -> normalized, chunk-loaded DataFrame (in-memory concat for now)
cleaning.py       -> tags NaN/inf/label-whitespace issues, does not delete
deduplication.py  -> tags exact + feature duplicates, does not delete
leakage_checks.py -> classifies every column HIGH/MEDIUM/LOW/NONE risk
feature_selection.py -> makes the explicit, documented column decision
splitting.py      -> day/file-aware train/val/test split
reports.py        -> class distribution + summary writers
pipeline.py       -> CLI orchestrator, wires the above together
```

Crypto and ML code are intentionally decoupled: this pipeline has no
dependency on FastAPI, MongoDB, or any backend code, so it is testable
and runnable standalone.

## Cleaning Rules

NaN, infinite values, and label whitespace/emptiness are **tagged**, not
deleted, in `cleaning.py::tag_quality_issues`. Every tagged category is
counted and reported in `preprocessing_summary.json` under
`cleaning_report`. The decision of what to do with tagged rows (drop,
impute, keep) is a separate, explicit step — as of Phase 1, no rows are
dropped by the pipeline itself; that decision is deferred to Phase 2+
once we know which model needs what.

Known caveat: `label` (pandas' auto-derived normalized column name for
the original `Label` header) currently survives as a metadata column
alongside `label_original`, since `label_original` is captured
separately before renaming. This is redundant but harmless (excluded
from `retained_features`); it will be explicitly dropped from metadata
output when this doc is next revised, once real data confirms actual
column names.

## Duplicate Policy

`deduplication.py` tags exact duplicates and feature-duplicates
(features excluding label and source_file) but does **not** delete
either automatically. `duplicate_report.json` records counts and
percentages. If the real dataset is too large for full in-memory
duplicate analysis, `PipelineConfig.near_duplicate_sample_limit` caps
the analysis to a deterministic (not random) head-sample, and this cap
is explicitly recorded in `analysis_scope_note` — never silently
applied.

## Leakage Policy

`leakage_checks.py` classifies every non-label, non-internal column as
HIGH / MEDIUM / LOW / NONE risk:

- **HIGH**: identifier-like columns with no generalizing ML signal —
  Flow ID, source/destination IP, Timestamp. Removed by
  `feature_selection.py` by default.
- **MEDIUM**: source/destination port. Plausibly useful signal for some
  attack types (e.g. port scans), but also a plausible shortcut/overfit
  vector. **Retained by default**, with the option to drop via
  `--drop-medium-risk` for an ablation comparison. This is a documented
  policy choice, not an assumption that ports are safe.
- **LOW**: constant or near-constant columns. Not leakage in the label
  sense, but flagged since they carry little/no ML signal.
- **NONE**: no known leakage indicator matched.

The final removal/retention decision per column is recorded in
`feature_manifest.json` with an explicit reason for every column — this
manifest is the reproducible record of what was decided and why.

## Feature Selection Policy

Columns are split into exactly one of: METADATA, LEAKAGE_REMOVED,
FEATURE, LABEL. Internal pipeline flag columns (prefixed `_`) and
provenance columns (`source_file`, `label`, `label_original`) are always
METADATA, never treated as ML features. No feature scaling/normalization
is applied in Phase 1, since Random Forest and XGBoost (the core models
for Phase 2/3) do not require it; the fit/transform discipline (see
below) is nonetheless already in place for future models that would need
it.

## Split Strategy

The pipeline splits **by source file** (`splitting.py::split_by_file`),
not by random row shuffling. This is deliberate: CICIDS2017 is captured
per-day/session, and a naive random split risks near-duplicate flows
from the same capture window appearing in both train and test.

If no explicit file-to-split assignment is supplied, the pipeline falls
back to a deterministic alphabetical-sort 60/20/20 slice
(`splitting.py::derive_file_assignment`) — this is a **placeholder**
policy, clearly logged in `split_manifest.json::rationale`, and should
be replaced with an explicit, human-decided assignment once the real
CICIDS2017 filenames are confirmed (e.g. deliberately holding out
Friday's DDoS/PortScan files as the test set, since they contain attack
types not present on other days).

A source file is assigned to exactly one split, which structurally
prevents cross-split contamination regardless of within-file duplicates.

## Fit/Transform Discipline

No preprocessing statistic (mean, scale, encoding vocabulary, etc.) is
fit on the full dataset before splitting. Phase 1 does not yet fit any
such statistic (RF/XGBoost don't need scaling), but the code structure
(discovery → load → clean/tag → split → THEN any future fit step) is
already ordered correctly so this discipline holds for future phases.

## How to Run Phase 1 Locally

```bash
# 1. Install dependencies
pip install -r backend/requirements.txt   # or a minimal subset: pandas numpy pyarrow pytest

# 2. Place real CICIDS2017 CSVs
cp /path/to/your/cicids2017/*.csv ml/data/raw/

# 3. Run the pipeline
python -m ml.preprocessing.pipeline \
    --raw-dir ml/data/raw \
    --processed-dir ml/data/processed \
    --output-dir experiments/results \
    --seed 42

# Optional: drop MEDIUM-risk (port) columns instead of retaining them
python -m ml.preprocessing.pipeline --drop-medium-risk
```

If `ml/data/raw/` contains no CSV files, the pipeline exits with code 1
and writes only `data_manifest.json` (showing zero files found) — no
other report is written, and no statistics are fabricated.

## Outputs (produced only on a real run with data present)

```
experiments/results/
├── data_manifest.json
├── leakage_audit.json
├── leakage_audit.md
├── duplicate_report.json
├── class_distribution.json
├── feature_manifest.json
├── split_manifest.json
└── preprocessing_summary.json

ml/data/processed/
├── train.parquet
├── validation.parquet
└── test.parquet
```

## Testing

Unit and integration tests (`tests/preprocessing/*`) use small,
hand-written **synthetic** DataFrames and temporary CSVs — e.g. rows
like `10.0.0.1`, `BENIGN`, `DDoS` with fabricated feature values used
purely to exercise code paths (duplicate detection, leakage
classification, split contamination checks, malformed-file handling).
**These synthetic numbers are not CICIDS2017 statistics** and must never
be reported as such in any results section.

Run tests with:

```bash
python -m pytest tests/preprocessing/ -v
```

## Limitations

- Duplicate/leakage analysis of the full CICIDS2017 dataset (~2.8M rows
  across 8 files, several GB) has not yet been executed anywhere — this
  requires the real files.
- The label-normalization mapping in `config.py::LABEL_NORMALIZATION_MAP`
  is a placeholder derived from publicly documented CICIDS2017 label
  strings and has not been validated against the real files' actual
  label text (including known encoding quirks in the original dataset,
  e.g. non-UTF8 characters in "Web Attack" labels). It must be
  reconciled once real data is loaded, and any unrecognized label will
  surface for manual review rather than being silently miscategorized.
- The fallback file-to-split assignment (alphabetical 60/20/20) is a
  placeholder, not a methodologically justified split — a deliberate,
  documented assignment (e.g. by calendar day, or holding out specific
  attack-only files) should replace it before any model results are
  reported.
- Cross-file exact-duplicate detection scales linearly with row count in
  the current implementation (pandas `.duplicated()` on the full frame);
  for the full multi-GB dataset this may require the
  `near_duplicate_sample_limit` cap, which trades completeness for
  tractability and is reported transparently when triggered.
