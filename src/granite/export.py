"""
Export and schema validation module for Member 2 deliverables.

Produces and validates:
1. granite_features.csv
   Required: cve_id,family_id,remote_local,auth_required
   Optional: vulnerability_type,attack_surface,product_or_vendor,extraction_method,extraction_confidence,evidence
2. families.csv
   Required: cve_id,family_id
3. family_summary.csv
   Required: family_id,family_name,family_size
   Optional: historical_kev_count,historical_kev_rate,representative_cves,top_characteristics
"""
import logging
from pathlib import Path
from typing import Optional
import numpy as np
import pandas as pd

logger = logging.getLogger("ThreatRank.GraniteExport")

GRANITE_FEATURES_REQUIRED_COLS = ["cve_id", "family_id", "remote_local", "auth_required"]
GRANITE_FEATURES_OPTIONAL_COLS = [
    "vulnerability_type",
    "attack_surface",
    "product_or_vendor",
    "extraction_method",
    "extraction_confidence",
    "evidence",
]
FAMILIES_REQUIRED_COLS = ["cve_id", "family_id"]
FAMILY_SUMMARY_REQUIRED_COLS = ["family_id", "family_name", "family_size"]
FAMILY_SUMMARY_OPTIONAL_COLS = [
    "historical_kev_count",
    "historical_kev_rate",
    "representative_cves",
    "top_characteristics",
]


def build_output_tables(
    df: pd.DataFrame,
    family_name_map: dict,
    cluster_details: dict,
    kev_stats_df: Optional[pd.DataFrame] = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Builds the three standardized output DataFrames (`granite_features`, `families`, `family_summary`)."""
    work = df.copy()
    if "product_or_vendor" not in work.columns:
        work["product_or_vendor"] = "unknown"

    feat_cols = GRANITE_FEATURES_REQUIRED_COLS + [
        c for c in GRANITE_FEATURES_OPTIONAL_COLS if c in work.columns
    ]
    granite_features_df = work[feat_cols].copy().reset_index(drop=True)

    families_df = work[FAMILIES_REQUIRED_COLS].copy().reset_index(drop=True)

    # Build family_summary.csv matching actual assignments in work
    actual_counts = work.groupby("family_id")["cve_id"].count().to_dict()
    all_fam_ids = sorted(set(actual_counts.keys()) | set(family_name_map.keys()))

    kev_lookup = {}
    if kev_stats_df is not None and len(kev_stats_df) > 0:
        for r in kev_stats_df.itertuples(index=False):
            kev_lookup[getattr(r, "family_id")] = (
                getattr(r, "historical_kev_count", np.nan),
                getattr(r, "historical_kev_rate", np.nan),
            )

    summary_rows = []
    for fid in all_fam_ids:
        size = int(actual_counts.get(fid, 0))
        if size == 0 and fid not in actual_counts:
            continue
        fname = str(family_name_map.get(fid, f"Semantic Family {fid}"))
        det = cluster_details.get(fid, {})
        rep_cves = det.get("representative_cves", "")
        top_chars = det.get("top_characteristics", "")

        k_count, k_rate = kev_lookup.get(fid, (np.nan, np.nan))
        summary_rows.append({
            "family_id": fid,
            "family_name": fname,
            "family_size": size,
            "historical_kev_count": k_count,
            "historical_kev_rate": k_rate,
            "representative_cves": rep_cves,
            "top_characteristics": top_chars,
        })

    family_summary_df = pd.DataFrame(summary_rows)
    return granite_features_df, families_df, family_summary_df


def validate_outputs(
    granite_features_df: pd.DataFrame,
    families_df: pd.DataFrame,
    family_summary_df: pd.DataFrame,
) -> dict:
    """
    Validates all required schema, uniqueness, referential integrity, and size consistency checks.
    Raises ValueError on any contract violation.
    """
    # 1. Required columns
    for col in GRANITE_FEATURES_REQUIRED_COLS:
        if col not in granite_features_df.columns:
            raise ValueError(f"granite_features.csv missing required column: '{col}'")

    for col in FAMILIES_REQUIRED_COLS:
        if col not in families_df.columns:
            raise ValueError(f"families.csv missing required column: '{col}'")

    for col in FAMILY_SUMMARY_REQUIRED_COLS:
        if col not in family_summary_df.columns:
            raise ValueError(f"family_summary.csv missing required column: '{col}'")

    # 2. Non-empty & identical CVE row counts
    if len(granite_features_df) == 0:
        raise ValueError("granite_features.csv is empty.")
    if len(granite_features_df) != len(families_df):
        raise ValueError(
            f"Row count mismatch between granite_features ({len(granite_features_df)}) "
            f"and families ({len(families_df)})."
        )

    # 3. CVE ID uniqueness
    if granite_features_df["cve_id"].duplicated().any():
        raise ValueError("Duplicate CVE IDs detected in granite_features.csv.")
    if families_df["cve_id"].duplicated().any():
        raise ValueError("Duplicate CVE IDs detected in families.csv.")
    if set(granite_features_df["cve_id"]) != set(families_df["cve_id"]):
        raise ValueError("CVE ID sets in granite_features.csv and families.csv do not match.")

    # 4. No missing family assignments
    if granite_features_df["family_id"].isna().any() or families_df["family_id"].isna().any():
        raise ValueError("Missing (NaN) family_id assignments found.")

    # 5. Valid remote_local and auth_required values
    valid_remote = {"remote", "local", "unknown", "REMOTE", "LOCAL", "UNKNOWN"}
    valid_auth = {"yes", "no", "unknown", "NONE", "REQUIRED", "UNKNOWN"}
    bad_rem = set(granite_features_df["remote_local"].dropna().astype(str)) - valid_remote
    bad_auth = set(granite_features_df["auth_required"].dropna().astype(str)) - valid_auth
    if bad_rem:
        raise ValueError(f"Invalid remote_local values found: {bad_rem}")
    if bad_auth:
        raise ValueError(f"Invalid auth_required values found: {bad_auth}")

    # 6. Every assigned family_id exists in family_summary.csv
    summary_fams = set(family_summary_df["family_id"])
    assigned_fams = set(families_df["family_id"])
    missing_fams = assigned_fams - summary_fams
    if missing_fams:
        raise ValueError(f"family_id(s) {missing_fams} missing from family_summary.csv.")

    # 7. Family sizes match actual assignments
    actual_sizes = families_df.groupby("family_id")["cve_id"].count().to_dict()
    for row in family_summary_df.itertuples(index=False):
        fid = getattr(row, "family_id")
        reported_size = int(getattr(row, "family_size"))
        true_size = int(actual_sizes.get(fid, 0))
        if reported_size != true_size:
            raise ValueError(
                f"Family size mismatch for family_id={fid}: "
                f"family_summary reports {reported_size}, actual assignments={true_size}."
            )

    if int(family_summary_df["family_size"].sum()) != len(families_df):
        raise ValueError(
            f"Sum of family_size ({family_summary_df['family_size'].sum()}) "
            f"!= total assigned CVEs ({len(families_df)})."
        )

    # 8. Join verification
    joined = pd.merge(
        granite_features_df[["cve_id", "family_id"]],
        family_summary_df[["family_id", "family_name"]],
        on="family_id",
        how="inner",
    )
    if len(joined) != len(granite_features_df):
        raise ValueError("Inner join between granite_features and family_summary lost rows.")

    return {
        "valid": True,
        "total_cves": len(granite_features_df),
        "total_families": len(family_summary_df),
    }


def export_deliverables(
    granite_features_df: pd.DataFrame,
    families_df: pd.DataFrame,
    family_summary_df: pd.DataFrame,
    output_dir: str | Path,
) -> dict[str, Path]:
    """Validates and exports the three required CSV files to `output_dir`."""
    validate_outputs(granite_features_df, families_df, family_summary_df)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    feat_path = out_dir / "granite_features.csv"
    fam_path = out_dir / "families.csv"
    sum_path = out_dir / "family_summary.csv"

    granite_features_df.to_csv(feat_path, index=False)
    families_df.to_csv(fam_path, index=False)
    family_summary_df.to_csv(sum_path, index=False)

    logger.info(
        f"Exported validated Granite deliverables to {out_dir.resolve()} "
        f"({len(granite_features_df):,} CVEs across {len(family_summary_df)} families)."
    )
    return {
        "granite_features": feat_path,
        "families": fam_path,
        "family_summary": sum_path,
    }

