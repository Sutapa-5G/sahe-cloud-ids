# XGBoost Baseline Methodology (Phase 3)

## Status

Code implemented and tested with synthetic fixtures only. No real
CICIDS2017 performance numbers exist yet.

## What This Phase Does

Trains an XGBoost classifier (`ml/training/train_xgboost.py`) on the same
Phase 1 processed data as Phase 2's Random Forest, using the same shared
`ml/evaluation/metrics.py` module — so RF and XGBoost results are
directly comparable once run on real data.

## Design Decisions

- **Explicit label encoding.** XGBoost's sklearn wrapper works with
  integer labels; a `LabelEncoder` is fit explicitly and stored alongside
  the model (`class_mapping` in the training result) so the
  integer-to-attack-type mapping is transparent and reproducible, not an
  implicit internal detail.
- **`DecodingXGBWrapper`**: wraps the fitted model + encoder so
  `.predict()` returns the original string labels (e.g. `"DDoS"`), making
  it drop-in compatible with `ml/evaluation/metrics.py`, which expects
  predictions in the same label space as `y_true` — exactly like
  `RandomForestClassifier` already provides natively.
- **No `class_weight="balanced"` equivalent exists in XGBoost's sklearn
  API for multiclass problems.** Instead, `_compute_sample_weights()`
  computes explicit inverse-class-frequency sample weights, achieving the
  same intent as RF's `class_weight="balanced"`. This asymmetry between
  the two models' imbalance-handling mechanisms is documented here, not
  hidden — it's a genuine difference between the two libraries' APIs, not
  an oversight.
- **No hyperparameter search by default**, same rationale as Phase 2's
  RF baseline: a fixed, documented config is the true baseline; `--tune`
  opts into a small `GridSearchCV`.
- **NaN handling matches Phase 2's discipline**, even though XGBoost can
  natively handle missing values (unlike RF) — this pipeline enforces
  identical input-handling across both models so any accuracy difference
  reflects the models, not different data-cleaning treatment.

## Model Comparison Output

If `random_forest_results.json` already exists in the output directory
when `run_xgboost.py` runs, a `model_comparison_rf_vs_xgboost.json` file
is written, containing only numbers read from files that were themselves
produced by actual runs — never a fabricated RF baseline to compare
against.

## How to Run Phase 3 Locally

Requires Phase 1's real processed output.

```bash
pip install xgboost

python -m ml.training.run_xgboost \
    --processed-dir ml/data/processed \
    --output-dir experiments/results \
    --model-dir ml/models \
    --seed 42
```

## Outputs (produced only on a real run)

```
experiments/results/xgboost_results.json
experiments/results/model_comparison_rf_vs_xgboost.json   (if RF results also present)
ml/models/xgboost.joblib
```

## Testing

`tests/training/test_train_xgboost.py` — 7 tests, synthetic data only
(binary and 3-class well-separated synthetic clusters, used to validate
the training/label-encoding/sample-weighting code paths, not to claim
any real-world performance).

A full end-to-end CLI run was performed against synthetic parquet
fixtures, running both `run_random_forest.py` and `run_xgboost.py` back
to back to confirm the comparison-file logic triggers and reads real
(if synthetic) numbers correctly. Fixtures and output were deleted after
verification.

Run tests:

```bash
python -m pytest tests/training/test_train_xgboost.py -v
```

## Limitations

- No real CICIDS2017 performance numbers exist yet.
- The inverse-frequency sample weighting and sklearn's `class_weight="balanced"`
  are conceptually similar but not mathematically identical — a rigorous
  comparison would need to verify they produce comparable effective
  reweighting on the real, actually-imbalanced CICIDS2017 label
  distribution, which hasn't been observed yet.
