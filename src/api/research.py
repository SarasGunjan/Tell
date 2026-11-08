"""Research Discoveries payload (Member 2's historical cohort). Every number is computed from the CSV/JSON files.

Never mixed with the 2026 benchmark: this describes the historical research cohort only.
"""
import re
from typing import Any, Dict, List, Optional

import pandas as pd

PROV = "Observed (historical), population-weighted - IBM Granite embeddings, Member 2"
PROV_SAMPLE = "Observed (historical), 2,500-CVE research cohort sample - Member 2"
DEFAULT_CAPTION = (
    "Sample KEV rates reflect the 2,500-CVE historical research cohort (which includes all 317 KEVs from "
    "2024–2025, a 12.68% sample base rate). Use population_kev_rate (base rate 0.36%) for true "
    "population-wide exploitation probabilities.")
TOP_CWES = 12


def _rows(df: pd.DataFrame) -> List[Dict[str, Any]]:
    import json
    return json.loads(df.to_json(orient="records"))


def _g(d: Optional[Dict[str, Any]], *path: str) -> Any:
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


def _num(df: pd.DataFrame) -> pd.DataFrame:
    for c in df.columns:
        if c not in ("family_id", "method", "family_name", "cwe_id", "cwe_name", "representative_cves",
                     "top_characteristics"):
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def build_research(raw: Dict[str, Optional[pd.DataFrame]], meta: Optional[Dict[str, Any]],
                   bench_summary: Optional[pd.DataFrame]) -> Dict[str, Any]:
    hist, base, temp, cwe = (raw.get("hist_family_summary"), raw.get("baselines"), raw.get("temporal"),
                             raw.get("cwe"))
    if hist is None and base is None and temp is None and cwe is None and not meta:
        return {"available": False,
                "waiting": "Not computed yet - waiting on Member 2's historical research files (outputs/granite)."}

    n = _g(meta, "kev_summary", "historical_n") or _g(meta, "clustering_metrics", "n_records")
    if n is None and hist is not None and "family_size" in hist.columns:
        n = int(pd.to_numeric(hist["family_size"], errors="coerce").sum())
    years = None
    if temp is not None:
        yrs = sorted({int(y) for c in temp.columns for y in re.findall(r"(?:train|val)_(\d{4})", c)})
        years = yrs or None
    span = "%d–%d" % (years[0], years[-1]) if years else "historical"
    cohort_label = "Historical research cohort (%s CVEs, %s)" % ("{:,}".format(int(n)) if n else "n/a", span)

    kev_total = _g(meta, "kev_summary", "historical_kev_total")
    sample_rate = _g(meta, "kev_summary", "overall_kev_rate")
    pop_rate = _g(meta, "kev_summary", "population_base_kev_rate")
    caption = DEFAULT_CAPTION
    if n and kev_total and sample_rate and pop_rate:
        caption = (
            "Sample KEV rates reflect the %s-CVE historical research cohort (which includes all %s KEVs from %s, "
            "a %.2f%% sample base rate). Use population_kev_rate (base rate %.2f%%) for true population-wide "
            "exploitation probabilities." % ("{:,}".format(int(n)), int(kev_total), span, sample_rate * 100,
                                              pop_rate * 100))
    cohort = {
        "label": cohort_label, "n": n, "kev_total": kev_total, "sample_base_rate": sample_rate,
        "population_total_cves": _g(meta, "kev_summary", "population_total_cves"),
        "population_base_rate": pop_rate, "years": years, "cutoff_date": _g(meta, "kev_summary", "cutoff_date"),
        "n_clusters": _g(meta, "clustering_metrics", "n_clusters"),
        "mean_cosine_cohesion": _g(meta, "clustering_metrics", "mean_cosine_cohesion"),
        "silhouette_cosine": _g(meta, "clustering_metrics", "silhouette_cosine"),
        "embedding_model": _g(meta, "embedding_metadata", "model_id"),
        "embedding_dim": _g(meta, "embedding_metadata", "embedding_dim"),
    }
    names = {}
    if hist is not None:
        names = dict(zip(hist["family_id"], hist["family_name"]))

    def block(data: Any, prov: str = PROV, **kw: Any) -> Dict[str, Any]:
        return dict(kw, data=data, provenance=prov, cohort_label=cohort_label)

    out = {"available": True, "cohort": cohort, "sample_caption": caption, "cohort_label": cohort_label,
           "provenance": PROV, "families": None, "concentration": None, "baselines": None, "temporal": None,
           "cwe": None, "bench_names": None,
           "caveats": ["Family rates describe historical patterns. They are not the probability for any individual "
                       "2026 CVE.", "Population-weighted rates re-weight the research sample to the full CVE "
                       "population; sample rates are inflated because every KEV was kept in the sample."]}  # type: Dict[str, Any]
    if bench_summary is not None:
        out["bench_names"] = dict(zip(bench_summary["family_id"], bench_summary["family_name"]))

    if hist is not None:
        h = _num(hist.copy())
        keep = [c for c in ("family_id", "family_name", "family_size", "historical_kev_count", "population_kev_rate",
                            "population_lift", "sample_kev_rate", "sample_lift", "ci_95_low", "ci_95_high",
                            "representative_cves", "top_characteristics") if c in h.columns]
        out["families"] = block(_rows(h[keep]))

    if base is not None:
        b = _num(base.copy())
        out["baselines"] = block(_rows(b), PROV, note="Population-weighted concentration ratio by grouping method; "
                                 "non_missing_coverage is the share of CVEs the method could place in a group.")
        g = b[b["method"].astype(str).str.contains("granite", case=False)]
        if len(g) and {"top3_groups_kev_share", "population_top3_volume_share",
                       "population_top3_concentration_ratio"} <= set(b.columns):
            r = g.iloc[0]
            out["concentration"] = block({
                "method": r["method"],
                "kev_share": float(r["top3_groups_kev_share"]),
                "population_volume_share": float(r["population_top3_volume_share"]),
                "population_ratio": float(r["population_top3_concentration_ratio"]),
                "sample_volume_share": None if "top3_groups_volume_share" not in b.columns
                else float(r["top3_groups_volume_share"]),
                "sample_ratio": None if "top3_concentration_ratio" not in b.columns
                else float(r["top3_concentration_ratio"]),
                "peak_population_lift": None if "population_peak_lift" not in b.columns
                else float(r["population_peak_lift"]),
            }, PROV, note="The three families with the most KEVs hold this share of all KEVs, but only the "
                          "population share of CVE volume.")

    if temp is not None:
        t = _num(temp.copy())
        t["family_name"] = t["family_id"].map(names)
        ranked = t.sort_values(["train_2024_rate", "family_id"], ascending=[False, True], kind="stable")
        top3 = ranked.head(3)
        tot_kev, tot_n = float(t["val_2025_kev"].sum()), float(t["val_2025_n"].sum())
        head = None
        if tot_kev > 0 and tot_n > 0:
            ks, vs = float(top3["val_2025_kev"].sum()) / tot_kev, float(top3["val_2025_n"].sum()) / tot_n
            rep = _g(meta, "kev_summary", "temporal_validation_2024_2025") or {}
            reported = {"kev_share": rep.get("top3_2024_families_out_of_time_2025_kev_share"),
                        "volume_share": rep.get("top3_2024_families_out_of_time_2025_vol_share"),
                        "lift": rep.get("out_of_time_enrichment_lift")}
            matches = None
            if all(v is not None for v in reported.values()):
                matches = (abs(ks - reported["kev_share"]) < 5e-4 and abs(vs - reported["volume_share"]) < 5e-4
                           and abs(ks / vs - reported["lift"]) < 5e-3)
            head = {"top3_family_ids": top3["family_id"].tolist(),
                    "top3_family_names": [names.get(f) for f in top3["family_id"]],
                    "ranked_by": "train_2024_rate", "kev_share": ks, "volume_share": vs, "lift": ks / vs,
                    "val_kev_top3": int(top3["val_2025_kev"].sum()), "val_kev_total": int(tot_kev),
                    "val_n_top3": int(top3["val_2025_n"].sum()), "val_n_total": int(tot_n),
                    "reported": reported, "matches_reported": matches}
        out["temporal"] = block({"rows": _rows(t), "headline": head, "train_year": years[0] if years else None,
                                 "val_year": years[-1] if years else None}, PROV_SAMPLE,
                                note="Families are ranked on 2024 data only, then checked on 2025 CVEs "
                                     "(out-of-time). Rates here are sample rates.")

    if cwe is not None:
        c = _num(cwe.copy())
        fams = sorted(c["family_id"].dropna().unique(), key=lambda f: (0, int(f)) if str(f).isdigit() else (1, str(f)))
        real = c[c["cwe_id"].astype(str).str.upper() != "UNASSIGNED"]
        tot = real.groupby("cwe_id")["cve_count"].sum().sort_values(ascending=False)
        rows = []
        for cid in tot.head(TOP_CWES).index:
            sub = real[real["cwe_id"] == cid]
            nm = sub["cwe_name"].dropna().iloc[0] if "cwe_name" in sub.columns and sub["cwe_name"].notna().any() else None
            cells = {}
            for r in sub.itertuples():
                cells[str(r.family_id)] = {"count": int(r.cve_count),
                                           "share": None if pd.isna(r.family_share) else float(r.family_share)}
            rows.append({"cwe_id": cid, "cwe_name": nm, "total": int(tot[cid]), "cells": cells})
        un = c[c["cwe_id"].astype(str).str.upper() == "UNASSIGNED"]["cve_count"].sum()
        out["cwe"] = block({"families": [str(f) for f in fams], "rows": rows, "unassigned": int(un)}, PROV_SAMPLE,
                           note="Cell = share of the family's historical CVEs carrying that CWE (blank = not in "
                                "the family's listed top CWEs).")
    return out
