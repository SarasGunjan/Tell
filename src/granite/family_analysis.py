"""
Historical KEV Exploitation Research & Baseline Value-Add Evaluation.

Strictly distinguishes between:
1. Exploratory descriptive analysis (observed historical KEV inclusion rates up to a specified cutoff)
2. Leakage-free predictive evaluation (fitting clusters strictly on a pre-cutoff training cohort,
   e.g. 2024, and evaluating KEV enrichment on a held-out future cohort, e.g. 2025, where KEV
   `date_added` is bounded strictly within the evaluation window).
"""
import logging
import math
from typing import Optional
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics import adjusted_mutual_info_score

logger = logging.getLogger("ThreatRank.GraniteFamilyAnalysis")


def wilson_confidence_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Computes the 95% Wilson score confidence interval for a binomial proportion k/n."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / denom
    half_width = (z * math.sqrt((p * (1.0 - p) / n) + (z * z) / (4.0 * n * n))) / denom
    low = max(0.0, center - half_width)
    high = min(1.0, center + half_width)
    return (round(low, 6), round(high, 6))


def compute_family_kev_statistics(
    df: pd.DataFrame,
    kev_df: Optional[pd.DataFrame] = None,
    cutoff_date: Optional[str] = "2025-12-31",
    exclude_published_after: Optional[str] = "2025-12-31",
    population_total_cves: int = 88103,
    population_total_kev: int = 317,
) -> tuple[pd.DataFrame, dict]:
    """
    Computes historical KEV inclusion statistics per family with strict temporal cutoff controls
    and Horvitz-Thompson inverse-probability population weighting for case-control samples.

    Leakage rules enforced:
    - Any CVE published after `exclude_published_after` (such as 2026 scoreboard CVEs) is excluded
      from historical rate denominators so 2026 candidates are never treated as historical negatives.
    - Any KEV entry with `date_added > cutoff_date` is treated as NOT exploited at `cutoff_date`.
    """
    if kev_df is None or len(kev_df) == 0:
        return pd.DataFrame(), {"historical_available": False}

    work = df.copy()
    if exclude_published_after and "published" in work.columns:
        work = work[work["published"].astype(str) <= exclude_published_after].copy()

    if len(work) == 0:
        logger.info("No pre-cutoff historical records in current sample; leaving historical KEV metrics unavailable.")
        return pd.DataFrame(), {"historical_available": False, "historical_n": 0}

    kev_sub = kev_df[["cve_id", "date_added"]].copy()
    if cutoff_date:
        kev_sub = kev_sub[kev_sub["date_added"].astype(str) <= cutoff_date].copy()

    kev_set = set(kev_sub["cve_id"])
    work["in_kev_at_cutoff"] = work["cve_id"].isin(kev_set).astype(int)

    total_hist = len(work)
    total_kev = int(work["in_kev_at_cutoff"].sum())
    total_non_kev = max(total_hist - total_kev, 1)
    overall_rate = total_kev / total_hist if total_hist > 0 else 0.0

    # Horvitz-Thompson population weighting for case-control enriched cohort
    pop_non_kev = max(population_total_cves - population_total_kev, total_non_kev)
    w_kev = (population_total_kev / total_kev) if total_kev > 0 else 1.0
    w_non_kev = (pop_non_kev / total_non_kev) if total_non_kev > 0 else 1.0
    pop_base_rate = population_total_kev / population_total_cves if population_total_cves > 0 else overall_rate

    rows = []
    for fam_id, grp in work.groupby("family_id"):
        n_fam = len(grp)
        k_fam = int(grp["in_kev_at_cutoff"].sum())
        non_k_fam = n_fam - k_fam
        rate = k_fam / n_fam if n_fam > 0 else 0.0
        ci_low, ci_high = wilson_confidence_interval(k_fam, n_fam)
        rel_lift = (rate / overall_rate) if overall_rate > 0 else np.nan

        est_pop_k = k_fam * w_kev
        est_pop_n = est_pop_k + non_k_fam * w_non_kev
        pop_rate = est_pop_k / est_pop_n if est_pop_n > 0 else 0.0
        pop_lift = (pop_rate / pop_base_rate) if pop_base_rate > 0 else np.nan

        rows.append({
            "family_id": fam_id,
            "historical_total": n_fam,
            "historical_kev_count": k_fam,
            "historical_kev_rate": round(rate, 6),
            "sample_kev_rate": round(rate, 6),
            "population_kev_rate": round(pop_rate, 6),
            "population_lift": round(pop_lift, 3) if pd.notna(pop_lift) else np.nan,
            "ci_95_low": ci_low,
            "ci_95_high": ci_high,
            "relative_lift_vs_overall": round(rel_lift, 3) if pd.notna(rel_lift) else np.nan,
        })

    stats_df = pd.DataFrame(rows).sort_values("family_id").reset_index(drop=True)
    summary_meta = {
        "historical_available": True,
        "cutoff_date": cutoff_date,
        "historical_n": total_hist,
        "historical_kev_total": total_kev,
        "overall_kev_rate": round(overall_rate, 6),
        "population_total_cves": population_total_cves,
        "population_total_kev": population_total_kev,
        "population_base_kev_rate": round(pop_base_rate, 6),
        "horvitz_thompson_non_kev_weight": round(w_non_kev, 4),
    }
    return stats_df, summary_meta


def evaluate_granite_vs_baselines(
    df: pd.DataFrame,
    granite_labels: np.ndarray,
    kev_df: pd.DataFrame,
    n_clusters: int = 10,
    seed: int = 42,
    cutoff_date: str = "2025-12-31",
    population_total_cves: int = 88103,
    population_total_kev: int = 317,
) -> pd.DataFrame:
    """
    Compares IBM Granite semantic families against simpler baselines on historical CVEs:
    1. IBM Granite Embeddings + K-Means
    2. TF-IDF (1-2 ngrams, 2000 features) + K-Means (same k)
    3. Simple Keyword Heuristic Grouping (`vulnerability_type`)
    4. Official Primary CWE Category (top K-1 CWEs + Other/Unassigned)
    5. CVSS v3 Severity Buckets (CRITICAL, HIGH, MEDIUM, LOW, MISSING)

    Computes both sample-level and Horvitz-Thompson population-weighted metrics.
    """
    work = df.copy().reset_index(drop=True)
    work["granite_cluster"] = granite_labels

    kev_sub = kev_df[kev_df["date_added"].astype(str) <= cutoff_date]
    kev_set = set(kev_sub["cve_id"])
    y_kev = work["cve_id"].isin(kev_set).astype(int).to_numpy()
    base_rate = float(np.mean(y_kev)) if len(y_kev) > 0 else 0.0
    total_kev = int(np.sum(y_kev))
    total_non_kev = max(len(y_kev) - total_kev, 1)

    pop_non_kev = max(population_total_cves - population_total_kev, total_non_kev)
    w_kev = (population_total_kev / total_kev) if total_kev > 0 else 1.0
    w_non_kev = (pop_non_kev / total_non_kev) if total_non_kev > 0 else 1.0
    pop_base_rate = population_total_kev / population_total_cves if population_total_cves > 0 else base_rate

    # Baseline 2: TF-IDF + KMeans
    vec = TfidfVectorizer(max_features=2000, stop_words="english", ngram_range=(1, 2))
    X_tfidf = vec.fit_transform(work["description"].astype(str).tolist())
    km_tfidf = KMeans(n_clusters=min(n_clusters, len(work) - 1), random_state=seed, n_init=5)
    tfidf_labels = km_tfidf.fit_predict(X_tfidf)

    # Baseline 3: Simple Keyword Heuristic Grouping
    kw_labels = work.get("vulnerability_type", pd.Series(["unknown"] * len(work))).astype(str).to_numpy()

    # Baseline 4: Primary CWE Category (Top n_clusters-1 CWEs + UNASSIGNED/OTHER)
    if "cwe_ids" in work.columns:
        prim_cwe = (
            work["cwe_ids"]
            .fillna("UNASSIGNED")
            .astype(str)
            .apply(lambda s: s.split(",")[0].strip().upper() if s.strip() else "UNASSIGNED")
        )
        top_cwes = set(prim_cwe.value_counts().head(max(n_clusters - 1, 1)).index)
        cwe_labels = prim_cwe.apply(lambda c: c if c in top_cwes else "OTHER_CWE").to_numpy()
        cwe_coverage = float((prim_cwe != "UNASSIGNED").mean())
    else:
        cwe_labels = np.array(["UNASSIGNED"] * len(work))
        cwe_coverage = 0.0

    # Baseline 5: CVSS v3 Severity + Attack Vector
    if "cvss3_severity" in work.columns:
        cvss_sev = work["cvss3_severity"].fillna("MISSING").astype(str).str.upper()
        av_col = work.get("attack_vector", pd.Series(["MISSING"] * len(work))).fillna("MISSING").astype(str).str.upper()
        cvss_labels = (cvss_sev + "_" + av_col).to_numpy()
        cvss_coverage = float((cvss_sev != "MISSING").mean())
    else:
        cvss_labels = np.array(["MISSING"] * len(work))
        cvss_coverage = 0.0

    methods = [
        ("IBM Granite Embeddings (KMeans)", granite_labels, 1.0),
        ("TF-IDF Text Baseline (KMeans)", tfidf_labels, 1.0),
        ("Simple Keyword Rules", kw_labels, float((kw_labels != "unknown").mean())),
        ("Official CWE Top Categories", cwe_labels, cwe_coverage),
        ("CVSSv3 Severity × Attack Vector", cvss_labels, cvss_coverage),
    ]

    comparison_rows = []
    for name, lbls, cov in methods:
        tmp = pd.DataFrame({"grp": lbls, "kev": y_kev})
        grp_stats = (
            tmp.groupby("grp", as_index=False)
            .agg(n=("kev", "count"), k=("kev", "sum"))
        )
        grp_stats["non_k"] = grp_stats["n"] - grp_stats["k"]
        grp_stats["rate"] = grp_stats["k"] / grp_stats["n"]
        grp_stats["pop_k"] = grp_stats["k"] * w_kev
        grp_stats["pop_n"] = grp_stats["pop_k"] + grp_stats["non_k"] * w_non_kev
        grp_stats["pop_rate"] = grp_stats["pop_k"] / grp_stats["pop_n"]

        # Filter to groups with at least 20 records for reliable peak rate
        valid_grps = grp_stats[grp_stats["n"] >= min(20, max(1, len(work) // 50))]
        if len(valid_grps) == 0:
            valid_grps = grp_stats
        valid_grps = valid_grps.sort_values("rate", ascending=False)

        max_rate = float(valid_grps["rate"].iloc[0])
        max_lift = (max_rate / base_rate) if base_rate > 0 else np.nan
        max_pop_rate = float(valid_grps["pop_rate"].iloc[0])
        max_pop_lift = (max_pop_rate / pop_base_rate) if pop_base_rate > 0 else np.nan

        # Top 3 highest-rate families KEV capture vs volume share
        top3 = valid_grps.head(3)
        top3_kev_share = float(top3["k"].sum() / max(total_kev, 1))
        top3_vol_share = float(top3["n"].sum() / len(work))
        enrichment_ratio = (top3_kev_share / top3_vol_share) if top3_vol_share > 0 else np.nan

        top3_pop_vol_share = float(top3["pop_n"].sum() / max(float(grp_stats["pop_n"].sum()), 1.0))
        pop_enrichment_ratio = (top3_kev_share / top3_pop_vol_share) if top3_pop_vol_share > 0 else np.nan

        comparison_rows.append({
            "method": name,
            "num_groups": int(len(grp_stats)),
            "non_missing_coverage": round(cov, 4),
            "peak_group_kev_rate": round(max_rate, 6),
            "peak_group_lift": round(max_lift, 2) if pd.notna(max_lift) else np.nan,
            "population_peak_kev_rate": round(max_pop_rate, 6),
            "population_peak_lift": round(max_pop_lift, 2) if pd.notna(max_pop_lift) else np.nan,
            "top3_groups_kev_share": round(top3_kev_share, 4),
            "top3_groups_volume_share": round(top3_vol_share, 4),
            "top3_concentration_ratio": round(enrichment_ratio, 2) if pd.notna(enrichment_ratio) else np.nan,
            "population_top3_volume_share": round(top3_pop_vol_share, 4),
            "population_top3_concentration_ratio": round(pop_enrichment_ratio, 2) if pd.notna(pop_enrichment_ratio) else np.nan,
        })

    return pd.DataFrame(comparison_rows)


def evaluate_leakage_free_temporal_split(
    df_2024: pd.DataFrame,
    emb_2024: np.ndarray,
    df_2025: pd.DataFrame,
    emb_2025: np.ndarray,
    kev_df: pd.DataFrame,
    n_clusters: int = 10,
    seed: int = 42,
) -> tuple[pd.DataFrame, dict]:
    """
    Leakage-free temporal validation:
    1. Fits KMeans strictly on 2024 disclosures (`published <= 2024-12-31`).
    2. Computes 2024 training KEV rates using ONLY KEV additions on or before `2024-12-31`.
    3. Projects held-out 2025 disclosures (`2025-01-01` to `2025-12-31`) onto the frozen 2024 centroids.
    4. Evaluates out-of-time 2025 KEV enrichment (`date_added <= 2025-12-31`) for the top-risk families
       identified strictly in 2024.
    """
    km_2024 = KMeans(n_clusters=n_clusters, random_state=seed, n_init=10)
    labels_2024 = km_2024.fit_predict(emb_2024).astype(int)
    labels_2025 = km_2024.predict(emb_2025).astype(int)

    kev_2024_set = set(kev_df[kev_df["date_added"].astype(str) <= "2024-12-31"]["cve_id"])
    kev_2025_set = set(kev_df[kev_df["date_added"].astype(str) <= "2025-12-31"]["cve_id"])

    y_2024 = df_2024["cve_id"].isin(kev_2024_set).astype(int).to_numpy()
    y_2025 = df_2025["cve_id"].isin(kev_2025_set).astype(int).to_numpy()

    base_2024 = float(np.mean(y_2024)) if len(y_2024) > 0 else 0.0
    base_2025 = float(np.mean(y_2025)) if len(y_2025) > 0 else 0.0

    rows = []
    for fid in range(n_clusters):
        m24 = labels_2024 == fid
        m25 = labels_2025 == fid
        n24, k24 = int(np.sum(m24)), int(np.sum(y_2024[m24]))
        n25, k25 = int(np.sum(m25)), int(np.sum(y_2025[m25]))
        r24 = k24 / n24 if n24 > 0 else 0.0
        r25 = k25 / n25 if n25 > 0 else 0.0
        rows.append({
            "family_id": fid,
            "train_2024_n": n24,
            "train_2024_kev": k24,
            "train_2024_rate": round(r24, 6),
            "train_2024_lift": round(r24 / base_2024, 2) if base_2024 > 0 else np.nan,
            "val_2025_n": n25,
            "val_2025_kev": k25,
            "val_2025_rate": round(r25, 6),
            "val_2025_lift": round(r25 / base_2025, 2) if base_2025 > 0 else np.nan,
        })

    split_df = pd.DataFrame(rows).sort_values("train_2024_rate", ascending=False).reset_index(drop=True)
    top3_2024 = split_df.head(3)
    top3_2025_kev_share = float(top3_2024["val_2025_kev"].sum() / max(int(np.sum(y_2025)), 1))
    top3_2025_vol_share = float(top3_2024["val_2025_n"].sum() / max(len(y_2025), 1))

    meta = {
        "train_2024_n": int(len(y_2024)),
        "train_2024_kev_total": int(np.sum(y_2024)),
        "val_2025_n": int(len(y_2025)),
        "val_2025_kev_total": int(np.sum(y_2025)),
        "top3_2024_families_out_of_time_2025_kev_share": round(top3_2025_kev_share, 4),
        "top3_2024_families_out_of_time_2025_vol_share": round(top3_2025_vol_share, 4),
        "out_of_time_enrichment_lift": round(top3_2025_kev_share / max(top3_2025_vol_share, 1e-6), 2),
    }
    return split_df, meta

