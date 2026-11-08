"""
CWE vs. IBM Granite Semantic Family Comparison Analysis (Member 2 Research Goal).

Investigates:
1. Whether a semantic cluster corresponds primarily to one CWE
2. Whether one semantic family spans multiple CWE categories
3. Whether one CWE appears across several different semantic families
4. Whether some descriptions are semantically similar despite different CWE classifications
"""
import logging
from pathlib import Path
from typing import Optional
import numpy as np
import pandas as pd

logger = logging.getLogger("ThreatRank.GraniteCWEAnalysis")


def expand_cwe_records(df: pd.DataFrame) -> pd.DataFrame:
    """Expands comma-separated `cwe_ids` into one row per (cve_id, family_id, cwe_id)."""
    if "cwe_ids" not in df.columns:
        return pd.DataFrame(columns=["cve_id", "family_id", "cwe_id"])

    rows = []
    for row in df.itertuples(index=False):
        cid = getattr(row, "cve_id")
        fid = getattr(row, "family_id")
        raw_cwe = getattr(row, "cwe_ids", None)
        if pd.isna(raw_cwe) or str(raw_cwe).strip() == "":
            rows.append({"cve_id": cid, "family_id": fid, "cwe_id": "UNASSIGNED"})
        else:
            parts = [p.strip().upper() for p in str(raw_cwe).split(",") if p.strip()]
            for p in parts:
                rows.append({"cve_id": cid, "family_id": fid, "cwe_id": p})
    return pd.DataFrame(rows)


def compute_cwe_semantic_table(
    df: pd.DataFrame,
    weakness_df: Optional[pd.DataFrame] = None,
    output_path: Optional[str | Path] = None,
) -> pd.DataFrame:
    """
    Produces the `cwe_semantic_analysis.csv` table with columns:
    `family_id,cwe_id,cve_count,family_share` (plus optional `cwe_name`, `cwe_share_across_families`).
    """
    expanded = expand_cwe_records(df)
    if len(expanded) == 0:
        return pd.DataFrame(columns=["family_id", "cwe_id", "cve_count", "family_share"])

    fam_totals = df.groupby("family_id")["cve_id"].nunique().to_dict()
    cwe_totals = expanded.groupby("cwe_id")["cve_id"].nunique().to_dict()

    grouped = (
        expanded.groupby(["family_id", "cwe_id"], as_index=False)["cve_id"]
        .nunique()
        .rename(columns={"cve_id": "cve_count"})
    )
    grouped["family_share"] = grouped.apply(
        lambda r: round(r["cve_count"] / max(fam_totals.get(r["family_id"], 1), 1), 4),
        axis=1,
    )
    grouped["cwe_share_across_families"] = grouped.apply(
        lambda r: round(r["cve_count"] / max(cwe_totals.get(r["cwe_id"], 1), 1), 4),
        axis=1,
    )

    if weakness_df is not None and "cwe_id" in weakness_df.columns and "name" in weakness_df.columns:
        w_map = dict(zip(weakness_df["cwe_id"], weakness_df["name"]))
        grouped["cwe_name"] = grouped["cwe_id"].map(lambda c: w_map.get(c, "Unmapped / Missing CWE"))

    grouped = grouped.sort_values(
        by=["family_id", "cve_count"], ascending=[True, False]
    ).reset_index(drop=True)

    if output_path is not None:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        grouped.to_csv(out_p, index=False)
        logger.info(f"Saved CWE vs. semantic family analysis to {out_p} ({len(grouped)} rows)")

    return grouped


def find_cross_cwe_semantic_pairs(
    df: pd.DataFrame,
    embeddings: np.ndarray,
    top_k: int = 10,
    max_search_rows: int = 2500,
) -> list[dict]:
    """
    Finds concrete pairs of CVEs within the same Granite semantic family that have
    high cosine similarity (>= 0.80) despite different official CWE classifications.
    """
    if "cwe_ids" not in df.columns or len(df) < 2:
        return []

    sub_df = df.head(max_search_rows).copy().reset_index(drop=True)
    sub_emb = embeddings[: len(sub_df)]

    norms = np.linalg.norm(sub_emb, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    norm_emb = sub_emb / norms

    valid_mask = (
        sub_df["cwe_ids"].notna()
        & (sub_df["cwe_ids"].astype(str).str.strip() != "")
        & (~sub_df["cwe_ids"].astype(str).str.contains("NVD-CWE", case=False, na=False))
    )
    valid_indices = np.where(valid_mask)[0]
    if len(valid_indices) < 2:
        return []

    pairs = []
    for fam_id, group in sub_df.loc[valid_indices].groupby("family_id"):
        idxs = group.index.to_numpy()
        if len(idxs) < 2:
            continue
        # Cap per-family matrix size for fast execution
        idxs = idxs[:400]
        sim_mat = np.dot(norm_emb[idxs], norm_emb[idxs].T)
        cwes = sub_df.loc[idxs, "cwe_ids"].astype(str).str.strip().tolist()

        for i in range(len(idxs)):
            for j in range(i + 1, len(idxs)):
                if cwes[i] != cwes[j] and sim_mat[i, j] >= 0.80:
                    r_i = sub_df.loc[idxs[i]]
                    r_j = sub_df.loc[idxs[j]]
                    if str(r_i["description"]).strip().lower() == str(r_j["description"]).strip().lower():
                        continue
                    pairs.append({
                        "family_id": fam_id,
                        "cosine_similarity": round(float(sim_mat[i, j]), 4),
                        "cve_1": r_i["cve_id"],
                        "cwe_1": cwes[i],
                        "desc_1": str(r_i["description"])[:180],
                        "cve_2": r_j["cve_id"],
                        "cwe_2": cwes[j],
                        "desc_2": str(r_j["description"])[:180],
                    })

    pairs.sort(key=lambda x: x["cosine_similarity"], reverse=True)
    # Deduplicate so a single CVE doesn't dominate all top pairs
    seen_cves = set()
    unique_pairs = []
    for p in pairs:
        if p["cve_1"] not in seen_cves and p["cve_2"] not in seen_cves:
            unique_pairs.append(p)
            seen_cves.add(p["cve_1"])
            seen_cves.add(p["cve_2"])
            if len(unique_pairs) >= top_k:
                break
    return unique_pairs

