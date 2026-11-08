"""Tests for CWE vs. semantic family comparison and time-safe KEV analysis."""
import numpy as np
import pandas as pd
from src.granite.cwe_analysis import compute_cwe_semantic_table, find_cross_cwe_semantic_pairs
from src.granite.family_analysis import compute_family_kev_statistics, evaluate_granite_vs_baselines


def test_cwe_semantic_table_and_cross_cwe_pairs():
    df = pd.DataFrame({
        "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
        "family_id": [0, 0, 1],
        "cwe_ids": ["CWE-79", "CWE-89", "CWE-787"],
        "description": [
            "Unauthenticated web input injection in parameter id.",
            "Unauthenticated web input injection in query parameter id.",
            "Stack-based buffer overflow in local daemon.",
        ],
    })
    cwe_tab = compute_cwe_semantic_table(df)
    assert set(["family_id", "cwe_id", "cve_count", "family_share"]).issubset(cwe_tab.columns)
    assert len(cwe_tab) == 3

    # Identical embeddings for row 0 and 1 in family 0 with different CWEs
    emb = np.array([
        [1.0, 0.0, 0.0],
        [0.99, 0.01, 0.0],
        [0.0, 1.0, 0.0],
    ], dtype=np.float32)
    pairs = find_cross_cwe_semantic_pairs(df, emb, top_k=5)
    assert len(pairs) == 1
    assert pairs[0]["cve_1"] == "CVE-2024-0001"
    assert pairs[0]["cve_2"] == "CVE-2024-0002"


def test_temporal_leakage_cutoff_in_kev_statistics():
    df = pd.DataFrame({
        "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2026-0001"],
        "family_id": [0, 0, 0],
        "published": ["2024-02-01", "2024-03-01", "2026-02-01"],
    })
    kev_df = pd.DataFrame({
        "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
        "date_added": ["2024-05-01", "2025-06-01"],  # second one added after 2024-12-31 cutoff
    })
    stats_2024, meta_2024 = compute_family_kev_statistics(
        df=df,
        kev_df=kev_df,
        cutoff_date="2024-12-31",
        exclude_published_after="2024-12-31",
    )
    # Only 2 historical CVEs from 2024 included (2026 excluded), and only 1 KEV added by 2024-12-31
    assert meta_2024["historical_n"] == 2
    assert meta_2024["historical_kev_total"] == 1
    assert stats_2024.loc[0, "historical_kev_rate"] == 0.5
    assert "population_kev_rate" in stats_2024.columns
    assert "population_lift" in stats_2024.columns


def test_full_historical_and_benchmark_csv_deliverables():
    from pathlib import Path
    from src.granite.export import validate_outputs

    hist_dir = Path("outputs/granite")
    bench_dir = Path("outputs/granite/benchmark_2026")
    if hist_dir.exists() and bench_dir.exists():
        h_feat = pd.read_csv(hist_dir / "granite_features.csv")
        h_fam = pd.read_csv(hist_dir / "families.csv")
        h_sum = pd.read_csv(hist_dir / "family_summary.csv")
        res_h = validate_outputs(h_feat, h_fam, h_sum)
        assert res_h["valid"] is True
        assert res_h["total_cves"] == 2500

        b_feat = pd.read_csv(bench_dir / "granite_features.csv")
        b_fam = pd.read_csv(bench_dir / "families.csv")
        b_sum = pd.read_csv(bench_dir / "family_summary.csv")
        res_b = validate_outputs(b_feat, b_fam, b_sum)
        assert res_b["valid"] is True
        assert res_b["total_cves"] == 72670
        assert list(h_sum["family_id"]) == list(b_sum["family_id"])


