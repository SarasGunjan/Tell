"""Tests for CSV deliverable schema validation and export contracts."""
import pandas as pd
import pytest
from pathlib import Path
from src.granite.export import validate_outputs, export_deliverables


def _make_valid_tables():
    feat = pd.DataFrame({
        "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
        "family_id": [0, 0, 1],
        "remote_local": ["remote", "remote", "local"],
        "auth_required": ["no", "yes", "unknown"],
    })
    fam = pd.DataFrame({
        "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
        "family_id": [0, 0, 1],
    })
    summ = pd.DataFrame({
        "family_id": [0, 1],
        "family_name": ["Remote Web Injection", "Local Privilege Escalation"],
        "family_size": [2, 1],
    })
    return feat, fam, summ


def test_valid_exports_pass(tmp_path: Path):
    feat, fam, summ = _make_valid_tables()
    paths = export_deliverables(feat, fam, summ, tmp_path)
    assert paths["granite_features"].exists()
    assert paths["families"].exists()
    assert paths["family_summary"].exists()


def test_missing_family_assignment_fails():
    feat, fam, summ = _make_valid_tables()
    fam.loc[1, "family_id"] = None
    with pytest.raises(ValueError, match="Missing \\(NaN\\) family_id"):
        validate_outputs(feat, fam, summ)


def test_family_size_mismatch_fails():
    feat, fam, summ = _make_valid_tables()
    summ.loc[0, "family_size"] = 99
    with pytest.raises(ValueError, match="Family size mismatch"):
        validate_outputs(feat, fam, summ)


def test_invalid_extracted_characteristic_fails():
    feat, fam, summ = _make_valid_tables()
    feat.loc[0, "remote_local"] = "guessed_value"
    with pytest.raises(ValueError, match="Invalid remote_local"):
        validate_outputs(feat, fam, summ)


def test_missing_required_column_fails():
    feat, fam, summ = _make_valid_tables()
    feat_bad = feat.drop(columns=["auth_required"])
    with pytest.raises(ValueError, match="missing required column"):
        validate_outputs(feat_bad, fam, summ)

