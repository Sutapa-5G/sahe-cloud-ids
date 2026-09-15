"""
NOTE: All fixtures in this file are SYNTHETIC data created for unit
testing only. None of the numbers here represent real CICIDS2017
statistics.
"""
from pathlib import Path

import pytest

from ml.preprocessing.discover import discover_csv_files


def test_discover_no_files(tmp_path: Path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    manifest = discover_csv_files(raw_dir, expected_filenames=["Monday-WorkingHours.pcap_ISCX.csv"])
    assert manifest.total_files_found == 0
    assert manifest.expected_missing == ["Monday-WorkingHours.pcap_ISCX.csv"]
    assert manifest.expected_found == []


def test_discover_missing_raw_dir(tmp_path: Path):
    raw_dir = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError):
        discover_csv_files(raw_dir, expected_filenames=[])


def test_discover_finds_expected_and_unexpected_files(tmp_path: Path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "Monday-WorkingHours.pcap_ISCX.csv").write_text(
        "Flow ID,Source IP,Label\n1,10.0.0.1,BENIGN\n2,10.0.0.2,DDoS\n"
    )
    (raw_dir / "SomeOtherFile.csv").write_text("a,b\n1,2\n")

    manifest = discover_csv_files(
        raw_dir, expected_filenames=["Monday-WorkingHours.pcap_ISCX.csv", "Tuesday-WorkingHours.pcap_ISCX.csv"]
    )
    assert manifest.total_files_found == 2
    assert manifest.expected_found == ["Monday-WorkingHours.pcap_ISCX.csv"]
    assert manifest.expected_missing == ["Tuesday-WorkingHours.pcap_ISCX.csv"]
    assert manifest.unexpected_files == ["SomeOtherFile.csv"]

    monday = next(d for d in manifest.discovered_files if d.filename == "Monday-WorkingHours.pcap_ISCX.csv")
    assert monday.row_count == 2
    assert monday.columns == ["Flow ID", "Source IP", "Label"]
    assert monday.readable is True
    assert monday.error is None


def test_discover_malformed_file_is_reported_not_skipped(tmp_path: Path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    bad_file = raw_dir / "bad.csv"
    # Write bytes that are invalid utf-8
    bad_file.write_bytes(b"col1,col2\n\xff\xfe,2\n")

    manifest = discover_csv_files(raw_dir, expected_filenames=[])
    assert manifest.total_files_found == 1
    bad = manifest.discovered_files[0]
    # Should not silently skip: either flagged unreadable or readable via fallback with an error note
    assert bad.error is not None
