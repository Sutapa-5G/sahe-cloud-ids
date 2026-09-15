# Dataset directories

## Official CICIDS2017 data

Place the official CICIDS2017 CSV files under `ml/data/raw/`. The preprocessing pipeline discovers all CSV files in that directory.

```text
ml/data/raw/*.csv
```

The official dataset is not bundled with this project.

## Synthetic fixture for software testing

This project also contains `generate_synthetic_fixture.py`, which creates a small deterministic CICIDS2017-like fixture under `ml/data/synthetic_raw/`. It is intended only to verify that preprocessing and model-training commands execute before the official dataset is available.

The synthetic fixture is **not CICIDS2017**. Its rows, labels, distributions, and model metrics must not be used as scientific findings or presented as real IDS performance. Synthetic processed files, models, and result JSON files are kept under `ml/data/synthetic_processed/`, `ml/models/synthetic_fixture/`, and `experiments/results/synthetic_fixture/` to keep them separate from real-data outputs.

Generate it with:

```bash
python ml/data/generate_synthetic_fixture.py --output-dir ml/data/synthetic_raw --rows-per-file 40
```
