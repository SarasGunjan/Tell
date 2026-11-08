"""Tests for ThreatRank Member 2 data loading and normalization."""
import pandas as pd
import pytest
from pathlib import Path
from src.granite.load_data import (
    load_and_prepare_vulnerabilities,
    normalize_cve_id,
    validate_cleaned_dataframe,
)


def test_missing_input_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_and_prepare_vulnerabilities(tmp_path / "nonexistent_file_12345.csv")


def test_incorrect_column_names(tmp_path: Path):
    csv_path = tmp_path / "bad_cols.csv"
    pd.DataFrame({"wrong_id": ["CVE-2024-0001"], "wrong_text": ["desc"]}).to_csv(csv_path, index=False)
    with pytest.raises(ValueError, match="Missing required column"):
        load_and_prepare_vulnerabilities(csv_path)


def test_missing_descriptions_and_duplicate_cves(tmp_path: Path):
    csv_path = tmp_path / "dirty_vulns.csv"
    df = pd.DataFrame({
        "cve_id": [
            "cve-2024-1001 ",
            "CVE-2024-1001",  # duplicate after normalization
            "CVE-2024-1002",  # empty description
            "CVE-2024-1003",  # null description
            "",               # empty CVE ID
            "CVE-2024-1004",  # valid with technical terms
        ],
        "description": [
            "Unauthenticated remote code execution (RCE) and SQL injection in web portal.",
            "Duplicate description that should be dropped.",
            "   ",
            None,
            "Description with missing ID.",
            "Local privilege escalation via buffer overflow and memory corruption.",
        ],
    })
    df.to_csv(csv_path, index=False)

    cleaned = load_and_prepare_vulnerabilities(csv_path, require_cve_pattern=True)
    assert len(cleaned) == 2
    assert list(cleaned["cve_id"]) == ["CVE-2024-1001", "CVE-2024-1004"]
    # Verify technical security terms preserved
    assert "RCE" in cleaned.loc[0, "description"]
    assert "SQL injection" in cleaned.loc[0, "description"]
    assert "memory corruption" in cleaned.loc[1, "description"]


def test_inconsistent_cve_formats(tmp_path: Path):
    assert normalize_cve_id("  cve\u20132025\u20149999 ") == "CVE-2025-9999"
    bad_df = pd.DataFrame({"cve_id": ["INVALID-ID-99"], "description": ["Valid description text"]})
    with pytest.raises(ValueError, match="non-standard CVE IDs"):
        validate_cleaned_dataframe(bad_df, require_cve_pattern=True)

