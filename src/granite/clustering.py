"""
Semantic clustering of IBM Granite vulnerability embeddings.

Supports:
- Fitting KMeans / MiniBatchKMeans with reproducible random seeds
- Saving and loading fitted clustering models for 2026 benchmark consistency
- Cohesion, silhouette, and representative CVE selection (nearest to centroid)
- Data-driven human-readable family naming based on representative descriptions,
  frequent technical terminology, CWE distributions, and shared attack traits
"""
import json
import logging
import pickle
import re
from collections import Counter
from pathlib import Path
from typing import Optional
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, MiniBatchKMeans
from sklearn.metrics import silhouette_score

logger = logging.getLogger("ThreatRank.GraniteClustering")

SECURITY_TERMS = [
    ("SQL Injection", [r"\bsql injection\b", r"\bsqli\b"]),
    ("Cross-Site Scripting (XSS)", [r"\bcross-site scripting\b", r"\bxss\b"]),
    ("Remote Code Execution", [r"\bremote code execution\b", r"\brce\b", r"\barbitrary code\b"]),
    ("Command Injection", [r"\bcommand injection\b", r"\bos command\b", r"\bshell command\b"]),
    ("Buffer & Memory Corruption", [r"\bbuffer overflow\b", r"\bheap-based\b", r"\bstack-based\b", r"\buse-after-free\b", r"\bout-of-bounds\b", r"\bmemory corruption\b"]),
    ("Path Traversal & File Upload", [r"\bpath traversal\b", r"\bdirectory traversal\b", r"\barbitrary file\b", r"\bfile upload\b", r"\bfile inclusion\b"]),
    ("Auth Bypass & Access Control", [r"\bauthentication bypass\b", r"\bimproper authentication\b", r"\bmissing authorization\b", r"\baccess control\b", r"\bhardcoded\b"]),
    ("Privilege Escalation", [r"\bprivilege escalation\b", r"\belevation of privilege\b", r"\bescalate privileges\b"]),
    ("Cross-Site Request Forgery (CSRF)", [r"\bcross-site request forgery\b", r"\bcsrf\b"]),
    ("Server-Side Request Forgery (SSRF)", [r"\bserver-side request forgery\b", r"\bssrf\b"]),
    ("Insecure Deserialization", [r"\bdeserialization\b", r"\bobject injection\b"]),
    ("Denial of Service & Crash", [r"\bdenial of service\b", r"\bdenial-of-service\b", r"\bnull pointer\b", r"\bcrash\b", r"\binfinite loop\b"]),
    ("Information Disclosure", [r"\binformation disclosure\b", r"\bsensitive information\b", r"\bcleartext\b", r"\bexposure of sensitive\b"]),
]


def format_family_id(cluster_idx: int, prefix: str = "FAM") -> str:
    """Formats integer cluster index into a stable string family ID (e.g. FAM-00 or int)."""
    return f"{prefix}-{cluster_idx:02d}"


def fit_semantic_clusters(
    embeddings: np.ndarray,
    n_clusters: int = 5,
    seed: int = 42,
    use_minibatch: bool = False,
) -> tuple[KMeans | MiniBatchKMeans, np.ndarray, dict]:
    """
    Fits K-Means (or MiniBatchKMeans for very large cohorts) on L2-normalized Granite embeddings.
    """
    if len(embeddings) < 2:
        raise ValueError(f"Need at least 2 records to cluster; got {len(embeddings)}.")
    if n_clusters < 2 or n_clusters > len(embeddings):
        raise ValueError(
            f"Invalid n_clusters={n_clusters} for dataset of size {len(embeddings)} "
            f"(must be between 2 and {len(embeddings)})."
        )

    if use_minibatch or len(embeddings) > 50000:
        model = MiniBatchKMeans(
            n_clusters=n_clusters,
            random_state=seed,
            batch_size=2048,
            n_init=10,
        )
    else:
        model = KMeans(
            n_clusters=n_clusters,
            random_state=seed,
            n_init=10,
        )

    labels = model.fit_predict(embeddings).astype(int)

    # Calculate cohesion (mean cosine similarity to assigned centroid) and silhouette
    centroids = model.cluster_centers_
    norms = np.linalg.norm(centroids, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    norm_centroids = centroids / norms

    emb_norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    emb_norms[emb_norms == 0] = 1.0
    norm_emb = embeddings / emb_norms

    assigned_centroids = norm_centroids[labels]
    cosine_sims = np.sum(norm_emb * assigned_centroids, axis=1)
    mean_cohesion = float(np.mean(cosine_sims))

    sil_score = None
    if 2 <= n_clusters < len(embeddings):
        sample_size = min(len(embeddings), 5000)
        sil_score = float(
            silhouette_score(
                norm_emb,
                labels,
                metric="cosine",
                sample_size=sample_size if len(embeddings) > sample_size else None,
                random_state=seed,
            )
        )

    cluster_cohesion = {}
    for c_idx in range(n_clusters):
        mask = labels == c_idx
        cluster_cohesion[c_idx] = float(np.mean(cosine_sims[mask])) if np.any(mask) else 0.0

    metrics = {
        "n_clusters": int(n_clusters),
        "n_records": int(len(embeddings)),
        "seed": int(seed),
        "algorithm": type(model).__name__,
        "mean_cosine_cohesion": round(mean_cohesion, 4),
        "silhouette_cosine": round(sil_score, 4) if sil_score is not None else None,
        "per_cluster_cohesion": cluster_cohesion,
        "point_cosine_similarities": cosine_sims,
    }
    return model, labels, metrics


def predict_semantic_clusters(
    model: KMeans | MiniBatchKMeans,
    embeddings: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Assigns new/benchmark embeddings to existing fitted cluster centroids without refitting."""
    labels = model.predict(embeddings).astype(int)
    centroids = model.cluster_centers_
    norms = np.linalg.norm(centroids, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    norm_centroids = centroids / norms

    emb_norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    emb_norms[emb_norms == 0] = 1.0
    norm_emb = embeddings / emb_norms

    cosine_sims = np.sum(norm_emb * norm_centroids[labels], axis=1)
    return labels, cosine_sims


def save_cluster_model(
    model: KMeans | MiniBatchKMeans,
    family_name_map: dict[int, str],
    save_path: str | Path,
    metadata: Optional[dict] = None,
) -> Path:
    """Saves fitted clustering model and stable family ID/name mappings for benchmark inference."""
    path = Path(save_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "family_name_map": family_name_map,
        "metadata": metadata or {},
    }
    with open(path, "wb") as f:
        pickle.dump(payload, f)
    logger.info(f"Saved fitted cluster model to {path}")
    return path


def load_cluster_model(load_path: str | Path) -> dict:
    """Loads a saved clustering model and family mapping."""
    path = Path(load_path)
    if not path.exists():
        raise FileNotFoundError(f"Saved cluster model not found at {path}")
    with open(path, "rb") as f:
        return pickle.load(f)


def derive_family_names_and_representatives(
    df: pd.DataFrame,
    embeddings: np.ndarray,
    model: KMeans | MiniBatchKMeans,
    labels: np.ndarray,
    weakness_lookup: Optional[dict[str, str]] = None,
    top_k_reps: int = 3,
) -> tuple[dict[int, str], dict[int, dict]]:
    """
    Inspects representative CVE descriptions (nearest to centroid), frequent technical
    terminology, CWE distributions, and cohesion to generate truthful human-readable labels.

    If a cluster mixes unrelated vulnerabilities with low term concentration and low cohesion,
    labels it honestly as a mixed/general cluster rather than inventing a false narrative.
    """
    n_clusters = model.cluster_centers_.shape[0]
    centroids = model.cluster_centers_
    c_norms = np.linalg.norm(centroids, axis=1, keepdims=True)
    c_norms[c_norms == 0] = 1.0
    norm_centroids = centroids / c_norms

    e_norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    e_norms[e_norms == 0] = 1.0
    norm_emb = embeddings / e_norms

    name_map: dict[int, str] = {}
    details_map: dict[int, dict] = {}
    used_names: Counter = Counter()

    for c_idx in range(n_clusters):
        mask = labels == c_idx
        indices = np.where(mask)[0]
        if len(indices) == 0:
            name_map[c_idx] = f"Empty Cluster ({c_idx})"
            details_map[c_idx] = {
                "size": 0,
                "cohesion": 0.0,
                "representative_cves": "",
                "top_characteristics": "none",
                "representative_descriptions": [],
            }
            continue

        sub_df = df.iloc[indices]
        sims = np.dot(norm_emb[indices], norm_centroids[c_idx])
        cohesion = float(np.mean(sims))

        # Top representative CVEs closest to centroid
        order = np.argsort(-sims)[:top_k_reps]
        rep_rows = sub_df.iloc[order]
        rep_cves = rep_rows["cve_id"].tolist()
        rep_descs = rep_rows["description"].tolist()

        # Count security terminology frequency across descriptions in this cluster
        term_counts: Counter = Counter()
        for desc in sub_df["description"].astype(str):
            d_low = desc.lower()
            for term_label, pats in SECURITY_TERMS:
                if any(re.search(p, d_low) for p in pats):
                    term_counts[term_label] += 1

        # Count CWE frequency if available
        top_cwe_str = ""
        top_cwe_name = ""
        if "cwe_ids" in sub_df.columns:
            cwe_counter: Counter = Counter()
            for val in sub_df["cwe_ids"].dropna().astype(str):
                for part in val.split(","):
                    p = part.strip().upper()
                    if p.startswith("CWE-"):
                        cwe_counter[p] += 1
            if cwe_counter:
                top_cwe, cwe_cnt = cwe_counter.most_common(1)[0]
                cwe_share = cwe_cnt / len(sub_df)
                top_cwe_str = f"{top_cwe} ({cwe_share*100:.0f}%)"
                if weakness_lookup and top_cwe in weakness_lookup and cwe_share >= 0.25:
                    top_cwe_name = weakness_lookup[top_cwe]

        # Dominant exposure & auth trait
        rem_share = float((sub_df.get("remote_local", pd.Series(dtype=str)).astype(str).str.lower() == "remote").mean()) if "remote_local" in sub_df.columns else 0.0
        loc_share = float((sub_df.get("remote_local", pd.Series(dtype=str)).astype(str).str.lower() == "local").mean()) if "remote_local" in sub_df.columns else 0.0
        noauth_share = float((sub_df.get("auth_required", pd.Series(dtype=str)).astype(str).str.lower().isin(["no", "none"])).mean()) if "auth_required" in sub_df.columns else 0.0

        # Construct human-readable name from empirical cluster evidence
        top_terms = term_counts.most_common(2)
        if top_terms and (top_terms[0][1] / len(sub_df)) >= 0.15:
            primary_term = top_terms[0][0]
            if len(top_terms) > 1 and (top_terms[1][1] / len(sub_df)) >= 0.15:
                secondary_term = top_terms[1][0]
                base_name = f"{primary_term} & {secondary_term}"
            else:
                base_name = primary_term
        elif top_cwe_name:
            base_name = f"{top_cwe_name[:48]}"
        elif cohesion < 0.45:
            base_name = "Mixed / General Application Vulnerabilities"
        else:
            if loc_share >= 0.5:
                base_name = "Local System & Component Flaws"
            elif rem_share >= 0.6:
                base_name = "Remote Network & Web Service Flaws"
            else:
                base_name = "Mixed Logic & Access Control Weaknesses"

        # Disambiguate if two clusters share the same base name
        used_names[base_name] += 1
        if used_names[base_name] > 1:
            if noauth_share >= 0.5:
                final_name = f"{base_name} (Unauthenticated / Network)"
            elif loc_share >= 0.4:
                final_name = f"{base_name} (Local / Host)"
            elif top_cwe_str:
                final_name = f"{base_name} [{top_cwe_str.split()[0]}]"
            else:
                final_name = f"{base_name} (Group {used_names[base_name]})"
        else:
            final_name = base_name

        # Build top_characteristics summary string
        trait_parts = [f"cohesion={cohesion:.2f}"]
        if top_terms:
            terms_fmt = ", ".join(f"{t} ({cnt/len(sub_df)*100:.0f}%)" for t, cnt in top_terms)
            trait_parts.append(f"terms: {terms_fmt}")
        if top_cwe_str:
            trait_parts.append(f"top_cwe: {top_cwe_str}")
        if rem_share > 0 or loc_share > 0:
            trait_parts.append(f"remote={rem_share*100:.0f}%/local={loc_share*100:.0f}%")

        name_map[c_idx] = final_name
        details_map[c_idx] = {
            "size": int(len(sub_df)),
            "cohesion": round(cohesion, 4),
            "representative_cves": ", ".join(rep_cves),
            "top_characteristics": "; ".join(trait_parts),
            "representative_descriptions": rep_descs,
            "top_cwe": top_cwe_str,
        }

    return name_map, details_map

