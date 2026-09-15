"""SYNTHETIC data only — not real CICIDS2017 statistics."""
import pandas as pd

from ml.preprocessing.splitting import split_by_file, derive_file_assignment


def _synthetic_df():
    rows = []
    for f in ["Monday.csv", "Tuesday.csv", "Wednesday.csv", "Thursday.csv", "Friday.csv"]:
        for i in range(4):
            rows.append({"feature_a": i, "label_original": "BENIGN", "source_file": f})
    return pd.DataFrame(rows)


def test_derive_file_assignment_no_overlap():
    files = ["Monday.csv", "Tuesday.csv", "Wednesday.csv", "Thursday.csv", "Friday.csv"]
    train, val, test = derive_file_assignment(files, train_ratio=0.6, val_ratio=0.2)
    all_assigned = set(train) | set(val) | set(test)
    assert all_assigned == set(files)
    # No file appears in more than one split
    assert not (set(train) & set(val))
    assert not (set(train) & set(test))
    assert not (set(val) & set(test))


def test_split_by_file_no_row_level_contamination():
    df = _synthetic_df()
    train_df, val_df, test_df, manifest = split_by_file(df, source_col="source_file", seed=42)

    train_files_in_data = set(train_df["source_file"].unique())
    val_files_in_data = set(val_df["source_file"].unique())
    test_files_in_data = set(test_df["source_file"].unique())

    # A source_file must never appear in more than one split
    assert not (train_files_in_data & val_files_in_data)
    assert not (train_files_in_data & test_files_in_data)
    assert not (val_files_in_data & test_files_in_data)

    # Row counts add up
    assert len(train_df) + len(val_df) + len(test_df) == len(df)
    assert manifest.train_rows + manifest.validation_rows + manifest.test_rows == len(df)


def test_split_reproducible_given_same_input():
    df = _synthetic_df()
    result1 = split_by_file(df, source_col="source_file", seed=42)
    result2 = split_by_file(df, source_col="source_file", seed=42)
    assert result1[3].train_files == result2[3].train_files
    assert result1[3].test_files == result2[3].test_files


def test_explicit_file_assignment_respected():
    df = _synthetic_df()
    train_df, val_df, test_df, manifest = split_by_file(
        df,
        source_col="source_file",
        seed=42,
        train_files=["Monday.csv", "Tuesday.csv"],
        val_files=["Wednesday.csv"],
        test_files=["Thursday.csv", "Friday.csv"],
    )
    assert set(train_df["source_file"].unique()) == {"Monday.csv", "Tuesday.csv"}
    assert set(val_df["source_file"].unique()) == {"Wednesday.csv"}
    assert set(test_df["source_file"].unique()) == {"Thursday.csv", "Friday.csv"}
