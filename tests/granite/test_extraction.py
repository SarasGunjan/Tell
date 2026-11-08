"""Tests for structured and deterministic feature extraction."""
import pandas as pd
from src.granite.extraction import extract_record_characteristics, extract_features_dataframe


def test_structured_cvss_mapping_takes_precedence():
    res = extract_record_characteristics(
        description="An unspecified vulnerability exists in the component.",
        attack_vector="NETWORK",
        privileges_required="NONE",
    )
    assert res["remote_local"] == "remote"
    assert res["auth_required"] == "no"
    assert "structured_cvss" in res["extraction_method"]
    assert res["extraction_confidence"] == "high"


def test_deterministic_fallback_when_cvss_missing():
    res = extract_record_characteristics(
        description="An unauthenticated remote attacker can execute arbitrary OS commands via command injection.",
        attack_vector=None,
        privileges_required=None,
    )
    assert res["remote_local"] == "remote"
    assert res["auth_required"] == "no"
    assert res["vulnerability_type"] == "Remote Code Execution / Command Injection"
    assert res["extraction_method"] == "deterministic_rule"


def test_ambiguous_or_missing_returns_unknown_without_guessing():
    # Contains both remote and local, and neither auth pattern
    res = extract_record_characteristics(
        description="A remote or local attacker may trigger an issue under certain conditions.",
        attack_vector=None,
        privileges_required=None,
    )
    assert res["remote_local"] == "unknown"
    assert res["auth_required"] == "unknown"
    assert res["vulnerability_type"] == "unknown"


def test_dataframe_extraction_preserves_rows():
    df = pd.DataFrame({
        "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
        "description": [
            "A local user with admin privileges can escalate privileges.",
            "Ambiguous flaw in software module.",
        ],
    })
    out = extract_features_dataframe(df)
    assert len(out) == 2
    assert out.loc[0, "remote_local"] == "local"
    assert out.loc[0, "auth_required"] == "yes"
    assert out.loc[1, "remote_local"] == "unknown"
    assert out.loc[1, "auth_required"] == "unknown"

