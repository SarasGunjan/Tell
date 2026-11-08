"""Reusable preprocessing and validation module for vulnerability datasets."""
import re
import logging
from pathlib import Path
from typing import Optional
import pandas as pd

from src.granite.config import resolve_dataset_path

logger = logging.getLogger("ThreatRank.GraniteData")

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

OPTIONAL_STRUCTURED_COLS = [
    "published",
    "last_modified",
    "nvd_status",
    "assigner",
    "cvss3_version",
    "cvss3_score",
    "cvss3_severity",
    "cvss3_vector",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "cwe_ids",
]


def normalize_cve_id(val: object) -> str:
    """Normalizes CVE IDs consistently (uppercase, stripped whitespace, normalized hyphens)."""
    if pd.isna(val):
        return ""
    s = str(val).strip().upper()
    # Replace unicode dashes with standard ASCII hyphen
    s = re.sub(r"[\u2010-\u2015\u2212]", "-", s)
    s = re.sub(r"\s+", "", s)
    return s


def clean_description(val: object) -> str:
    """Cleans description whitespace while preserving all technical security terminology."""
    if pd.isna(val):
        return ""
    s = str(val).strip()
    # Collapse repeated internal whitespace/newlines without stripping technical tokens
    s = re.sub(r"\s+", " ", s)
    return s


def validate_cleaned_dataframe(df: pd.DataFrame, require_cve_pattern: bool = False) -> dict:
    """Validates a cleaned vulnerability DataFrame and returns quality statistics."""
    if "cve_id" not in df.columns or "description" not in df.columns:
        raise ValueError(f"Cleaned DataFrame must contain 'cve_id' and 'description'. Found: {list(df.columns)}")

    if len(df) == 0:
        raise ValueError("Cleaned DataFrame is empty after removing missing/invalid records.")

    null_ids = int(df["cve_id"].isna().sum() + (df["cve_id"] == "").sum())
    null_descs = int(df["description"].isna().sum() + (df["description"] == "").sum())
    dup_ids = int(df["cve_id"].duplicated().sum())

    if null_ids > 0:
        raise ValueError(f"Validation failed: {null_ids} empty/null CVE IDs remain.")
    if null_descs > 0:
        raise ValueError(f"Validation failed: {null_descs} empty/null descriptions remain.")
    if dup_ids > 0:
        raise ValueError(f"Validation failed: {dup_ids} duplicate CVE IDs remain.")

    valid_cve_mask = df["cve_id"].str.match(CVE_REGEX, na=False)
    non_standard_count = int((~valid_cve_mask).sum())
    if require_cve_pattern and non_standard_count > 0:
        bad_examples = df.loc[~valid_cve_mask, "cve_id"].head(5).tolist()
        raise ValueError(f"Found {non_standard_count} non-standard CVE IDs: {bad_examples}")

    return {
        "row_count": len(df),
        "unique_cves": int(df["cve_id"].nunique()),
        "non_standard_cve_ids": non_standard_count,
        "has_attack_vector": "attack_vector" in df.columns,
        "has_privileges_required": "privileges_required" in df.columns,
        "has_cwe_ids": "cwe_ids" in df.columns,
    }


def load_and_prepare_vulnerabilities(
    input_path: str | Path,
    id_column: str = "cve_id",
    text_column: str = "description",
    limit: Optional[int] = None,
    require_cve_pattern: bool = False,
    filter_cve_ids: Optional[set[str]] = None,
    published_after: Optional[str] = None,
    published_before: Optional[str] = None,
    stratified_kev_cves: Optional[set[str]] = None,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Loads, normalizes, deduplicates, and validates vulnerability records.

    Preserves security terminology (RCE, XSS, SQL injection, authentication bypass,
    privilege escalation, memory corruption, command injection, etc.) and retains
    structured columns (attack_vector, privileges_required, cvss3_score, cwe_ids)
    when available.
    """
    resolved_path = resolve_dataset_path(input_path)
    logger.info(f"Loading vulnerabilities from {resolved_path}...")

    # Read header first to check columns efficiently
    header_df = pd.read_csv(resolved_path, nrows=0)
    available_cols = list(header_df.columns)
    missing_req = [c for c in [id_column, text_column] if c not in available_cols]
    if missing_req:
        raise ValueError(
            f"Missing required column(s) {missing_req} in {resolved_path.name}. "
            f"Available columns: {available_cols}"
        )

    usecols = [id_column, text_column] + [
        c for c in OPTIONAL_STRUCTURED_COLS if c in available_cols and c not in (id_column, text_column)
    ]

    # If simple head limit is requested without date/set/stratified filters, read small chunk for speed
    read_nrows = None
    if (
        limit is not None
        and limit > 0
        and filter_cve_ids is None
        and published_after is None
        and published_before is None
        and stratified_kev_cves is None
    ):
        read_nrows = max(limit * 3, 500)

    df = pd.read_csv(resolved_path, usecols=usecols, nrows=read_nrows, low_memory=False)
    if id_column != "cve_id" or text_column != "description":
        df = df.rename(columns={id_column: "cve_id", text_column: "description"})

    initial_rows = len(df)
    df["cve_id"] = df["cve_id"].map(normalize_cve_id)
    df["description"] = df["description"].map(clean_description)

    # Drop missing or empty cve_id / description explicitly
    valid_mask = (df["cve_id"] != "") & (df["description"] != "")
    dropped_missing = int((~valid_mask).sum())
    if dropped_missing > 0:
        logger.warning(f"Dropped {dropped_missing} records with missing/empty cve_id or description.")
    df = df[valid_mask].copy()

    # Remove exact duplicate records and duplicate CVE IDs (keep first)
    before_dedup = len(df)
    df = df.drop_duplicates(subset=["cve_id"], keep="first")
    dropped_dups = before_dedup - len(df)
    if dropped_dups > 0:
        logger.info(f"Removed {dropped_dups} duplicate CVE ID records.")

    # Optional date cohort filtering
    if published_after is not None and "published" in df.columns:
        df = df[df["published"].astype(str) >= published_after].copy()
    if published_before is not None and "published" in df.columns:
        df = df[df["published"].astype(str) <= published_before].copy()

    # Optional CVE set filtering
    if filter_cve_ids is not None:
        norm_set = {normalize_cve_id(c) for c in filter_cve_ids}
        df = df[df["cve_id"].isin(norm_set)].copy()

    if limit is not None and limit > 0 and len(df) > limit:
        if stratified_kev_cves is not None:
            norm_kev = {normalize_cve_id(c) for c in stratified_kev_cves}
            kev_part = df[df["cve_id"].isin(norm_kev)]
            non_kev_part = df[~df["cve_id"].isin(norm_kev)]
            if len(kev_part) >= limit:
                df = kev_part.sample(n=limit, random_state=seed).sort_index().copy()
            else:
                needed = limit - len(kev_part)
                sampled_non_kev = non_kev_part.sample(n=needed, random_state=seed)
                df = pd.concat([kev_part, sampled_non_kev], ignore_index=False).sort_index().copy()
        else:
            df = df.head(limit).copy()

    df = df.reset_index(drop=True)
    validate_cleaned_dataframe(df, require_cve_pattern=require_cve_pattern)
    logger.info(
        f"Prepared {len(df):,} valid vulnerability records (from {initial_rows:,} raw rows read)."
    )
    return df


def load_kev_catalog(kev_path: Optional[str | Path] = None) -> pd.DataFrame:
    """Loads CISA Known Exploited Vulnerabilities (KEV) dataset."""
    path = resolve_dataset_path(kev_path or "known_exploited.csv")
    df = pd.read_csv(path, low_memory=False)
    df["cve_id"] = df["cve_id"].map(normalize_cve_id)
    df = df[df["cve_id"] != ""].drop_duplicates(subset=["cve_id"]).reset_index(drop=True)
    return df


def load_weakness_types(weakness_path: Optional[str | Path] = None) -> pd.DataFrame:
    """Loads CWE weakness definitions from weakness_types.csv."""
    path = resolve_dataset_path(weakness_path or "weakness_types.csv")
    df = pd.read_csv(path, low_memory=False)
    df["cwe_id"] = df["cwe_id"].astype(str).str.strip().str.upper()
    df = df.drop_duplicates(subset=["cwe_id"]).reset_index(drop=True)
    return df


def load_scoreboard_2026(scoreboard_path: Optional[str | Path] = None) -> pd.DataFrame:
    """Loads official 2026 target benchmark CVEs from scoreboard_2026.csv."""
    path = resolve_dataset_path(scoreboard_path or "scoreboard_2026.csv")
    df = pd.read_csv(path, low_memory=False)
    df["cve_id"] = df["cve_id"].map(normalize_cve_id)
    df = df.drop_duplicates(subset=["cve_id"]).reset_index(drop=True)
    return df
