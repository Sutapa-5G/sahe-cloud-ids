# Random Forest Baseline Methodology (Phase 2)

## Status

Code implemented and tested with **synthetic fixtures only**. No real
CICIDS2017 accuracy, precision, recall, F1, or any other performance
number exists yet anywhere in this repository. Those will only be
produced once Phase 1 has been run against the real dataset and Phase 2
is run against its real output.

## What This Phase Does

Trains a single, documented Random Forest configuration
(`ml/training/train_random_forest.py`) on the Phase 1 processed training
split, then evaluates it on validation and test splits using a shared,
reusable metrics module (`ml/evaluation/metrics.py`) that will also be
used by Phase 3 (XGBoost) for a fair, consistent comparison.

## Design Decisions

- **`class_weight="balanced"`** is used by default, not left unset. This
  is a deliberate response to CICIDS2017's documented class imbalance
  (BENIGN heavily outnumbers most attack classes) — an unweighted RF
  would likely default to predicting the majority class and still score
  high raw accuracy while missing most attacks. This choice is
  overridable via `RFTrainingConfig.class_weight`.
- **No hyperparameter search by default.** A fixed, documented
  configuration (`n_estimators=200`, unlimited depth) is used as the
  true baseline. A `--tune` flag runs a small `GridSearchCV` as an
  explicit, opt-in alternative — this keeps the baseline reproducible
  and interpretable rather than silently picking whatever a search
  landed on.
- **No feature scaling.** Consistent with Phase 1's decision: tree-based
  models don't require it.
- **NaN handling is NOT silently imputed.** `train_random_forest()`
  raises if the training features contain NaN, pointing back to Phase
  1's `cleaning_report` counts so the row-handling policy is decided
  explicitly before training, not accidentally inside this module.

## Metrics Computed

Accuracy, macro/weighted precision-recall-F1, per-class precision-recall-F1
and support, confusion matrix, overall false-positive rate (relative to
the BENIGN class), ROC-AUC (macro, one-vs-rest for 3+ classes; the
correct binary formulation for exactly 2 classes — see "Bug Found and
Fixed" below), inference latency and throughput.

None of these are computed with a placeholder or default value on empty
input — `evaluate_classifier()` raises on a 0-row dataset rather than
returning a fabricated 0.0 or 1.0.

## Bug Found and Fixed During This Phase

During synthetic-data validation, `roc_auc_ovr_macro` was silently
returning `None` for a 2-class problem even when there were no errors
worth suppressing. Root cause: `sklearn.metrics.roc_auc_score` requires
a *different call signature* for exactly 2 classes (1D array of
positive-class probability, no `multi_class` argument) than for 3+
classes (`multi_class='ovr'` with the full probability matrix). The
original code always used the 3+-class signature, which raises
internally for the binary case, and that exception was being caught and
converted to `None`. Fixed in `metrics.py` to branch on class count; a
regression test
(`test_evaluate_classifier_binary_roc_auc_is_computed_not_silently_none`)
now guards against this recurring.

## How to Run Phase 2 Locally

Requires Phase 1 to have been run first against real data (so
`ml/data/processed/{train,validation,test}.parquet` exist).

```bash
pip install scikit-learn joblib

python -m ml.training.run_random_forest \
    --processed-dir ml/data/processed \
    --output-dir experiments/results \
    --model-dir ml/models \
    --seed 42

# Optional: small hyperparameter search instead of the fixed baseline config
python -m ml.training.run_random_forest --tune
```

If the processed parquet files don't exist, this exits with code 1 and
writes no result file.

## Outputs (produced only on a real run)

```
experiments/results/random_forest_results.json
ml/models/random_forest.joblib
```

## Testing

`tests/training/test_data_loading.py`, `test_train_random_forest.py`,
and `tests/evaluation/test_metrics.py` use small synthetic
DataFrames — including one deliberately well-separated synthetic
two-cluster dataset used only to confirm the training code path
produces a usable, learnable model. **The ">90% training accuracy"
assertion in that test is about validating the code, not a CICIDS2017
result, and is explicitly commented as such in the test file.**

Additionally, a full end-to-end CLI run was performed against
hand-written synthetic parquet files mimicking Phase 1's output schema,
confirming the training → evaluation → report-writing → model-saving
pipeline works correctly together. These synthetic files and their
output were deleted after verification and are not included in this
repository.

Run tests with:

```bash
python -m pytest tests/training/ tests/evaluation/ -v
```

## Limitations

- No real CICIDS2017 performance numbers exist yet.
- The `class_weight="balanced"` choice is reasonable given documented
  literature about CICIDS2017's imbalance, but its actual effect on this
  specific pipeline's features/split has not been empirically verified
  yet — that comparison (balanced vs. unbalanced) would be a reasonable
  ablation once real data is available.
- ROC-AUC for the multiclass case (3+ attack types) has not been
  exercised against real multi-class label data yet — only synthetic
  binary and small synthetic multi-class-shaped mock data.
