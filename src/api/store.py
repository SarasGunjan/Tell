"""Loads and merges Tell CSVs; schema-tolerant, hot-reloading, read-only query helpers.

Spec for the drop-in files lives in docs/WEB_PLATFORM.md ("Integration with Members 1 & 2").
A missing file or missing required column makes that dataset unavailable (None); nothing is invented.
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger("Tell.Store")

ROOT = Path(__file__).resolve().parents[2]
SIGNALS = ["exploitdb", "metasploit", "nuclei", "poc_github"]
VULN_COLS = ["description", "cvss3_score", "attack_vector", "cwe_ids"]
OUT_COLS = [
    "cve_id", "rank", "prediction_score", "epss", "exploitdb", "metasploit", "nuclei",
    "poc_github", "published", "snapshot_month", "in_top500", "family_id", "family_name",
    "remote_local", "auth_required", "attack_type", "description", "cvss3_score",
    "attack_vector", "cwe_ids",
]
PRED_OPTIONAL = SIGNALS + ["published", "snapshot_month"]
FAM_COLS = ["family_id", "family_name", "family_size", "hist_kev_rate", "avg_epss_2026", "high_risk", "key_traits"]
METRIC_COLS = [
    "model", "hits_100", "precision_100", "recall_100", "hits_250", "precision_250", "recall_250",
    "hits_500", "precision_500", "recall_500", "roc_auc", "pr_auc",
]
SORTS = {"rank": ("rank", True), "epss": ("epss", False), "score": ("prediction_score", False)}
RELOAD_INTERVAL = 2.0  # seconds between results-file stat checks

# key -> spec. `names`: accepted filenames (first = canonical). `cols`: column aliases.
SPECS = {
    "predictions": dict(names=["predictions.csv", "predictions_2026.csv"], owner="Member 1",
                        required=["cve_id", "rank", "prediction_score", "epss"], cols={"score": "prediction_score"}),
    "metrics": dict(names=["metrics.csv", "model_comparison.csv"], owner="Member 1",
                    required=["model", "hits_100", "hits_250", "hits_500"], cols={}),
    "top500": dict(names=["top500.csv"], owner="Member 1", required=["cve_id"], cols={}, optional=True),
    "families": dict(names=["families.csv"], owner="Member 2", required=["cve_id", "family_id"], cols={},
                     optional=True),
    "granite": dict(names=["granite_features.csv"], owner="Member 2",
                    required=["cve_id", "family_id", "remote_local", "auth_required"], cols={}),
    "family_summary": dict(names=["family_summary.csv"], owner="Member 2",
                           required=["family_id", "family_name", "family_size"], cols={}),
}
WAITING = {  # dataset -> "who / which file" for honest empty states
    "predictions": ("Member 1", "predictions.csv"),
    "metrics": ("Member 1", "metrics.csv"),
    "families": ("Member 2", "family_summary.csv"),
}


def waiting_text(dataset: str) -> str:
    who, f = WAITING[dataset]
    return "Not computed yet - waiting on %s's %s." % (who, f)


def to_py(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """DataFrame -> list of JSON-safe dicts (NaN -> None, numpy -> python)."""
    return json.loads(df.to_json(orient="records"))


def results_dir() -> Path:
    p = Path(os.environ.get("TELL_RESULTS_DIR") or "results")
    return p if p.is_absolute() else ROOT / p


def data_label() -> str:
    v = (os.environ.get("TELL_DATA_LABEL") or "demo").strip().lower()
    return v if v in ("demo", "final") else "demo"


def _data_dir() -> Path:
    return Path(os.environ.get("THREATRANK_DATA_DIR") or ROOT / "data")


def find_file(rd: Path, spec: Dict[str, Any]) -> Optional[Path]:
    for n in spec["names"]:
        if (rd / n).is_file():
            return rd / n
    return None


def read_dataset(rd: Path, key: str) -> Tuple[Optional[pd.DataFrame], Dict[str, Any]]:
    """Read one results file. Returns (df or None if unavailable, status info). Never raises."""
    spec = SPECS[key]
    path = find_file(rd, spec)
    info = {"name": path.name if path else spec["names"][0], "owner": spec["owner"], "present": path is not None,
            "rows": None, "columns": [], "missing_required": [], "modified": None}  # type: Dict[str, Any]
    if spec.get("optional"):
        info["optional"] = True
    if path is None:
        return None, info
    st = path.stat()
    info["modified"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
    try:
        df = pd.read_csv(path)
    except Exception as e:
        logger.warning("%s: cannot read (%s); dataset unavailable", path.name, type(e).__name__)
        info["error"] = "unreadable"
        return None, info
    df = df.rename(columns={a: c for a, c in spec["cols"].items() if a in df.columns and c not in df.columns})
    info["rows"] = int(len(df))
    info["columns"] = [str(c) for c in df.columns]
    missing = [c for c in spec["required"] if c not in df.columns]
    info["missing_required"] = missing
    if missing:
        logger.warning("%s: missing required column(s) %s; dataset unavailable until fixed", path.name, missing)
        return None, info
    return df, info


def _hist(values: np.ndarray, edges: np.ndarray) -> List[int]:
    v = np.clip(values, edges[0], edges[-1])
    return np.histogram(v, bins=edges)[0].astype(int).tolist()


def _num(df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


class Store:
    def __init__(self, results_path: Optional[Path] = None, data_dir: Optional[Path] = None,
                 label: Optional[str] = None):
        rd = Path(results_path) if results_path else results_dir()
        data_dir = Path(data_dir) if data_dir else _data_dir()
        self.label = label or data_label()
        try:
            self.results_rel = str(rd.resolve().relative_to(ROOT))
        except ValueError:
            self.results_rel = rd.name  # never expose absolute paths
        infos = {}  # type: Dict[str, Dict[str, Any]]
        raw = {}
        for k in SPECS:
            raw[k], infos[k] = read_dataset(rd, k)
        self.files = [infos[k] for k in SPECS if not (SPECS[k].get("optional") and k == "families" and not infos[k]["present"])]

        # ---- predictions
        preds = raw["predictions"]
        self.has_predictions = preds is not None
        if preds is None:
            preds = pd.DataFrame(columns=["cve_id", "rank", "prediction_score", "epss"])
        preds = _num(preds.drop_duplicates("cve_id"), ["rank", "prediction_score", "epss"] + SIGNALS)
        for c in PRED_OPTIONAL:
            if c not in preds.columns:
                preds[c] = np.nan if c in SIGNALS else None
        self.signals_available = [s for s in SIGNALS if self.has_predictions and preds[s].notna().any()]

        # ---- top500
        t5 = raw["top500"]
        if t5 is not None:
            self.top500_ids = set(t5["cve_id"].astype(str))
            self.top500_source = "file"  # type: Optional[str]
        elif self.has_predictions:
            self.top500_ids = set(preds.loc[preds["rank"] <= 500, "cve_id"])
            self.top500_source = "derived"
        else:
            self.top500_ids = set()
            self.top500_source = None

        # ---- metrics
        m = raw["metrics"]
        self.metrics = None if m is None else _num(m.reindex(columns=METRIC_COLS), METRIC_COLS[1:])

        # ---- family summary + per-CVE family info
        fs = raw["family_summary"]
        self.fam_summary = None if fs is None else fs.reindex(columns=FAM_COLS)
        self.family_ids = set(self.fam_summary["family_id"]) if self.fam_summary is not None else set()
        self.families_source = None  # type: Optional[str]
        fam = None
        if raw["families"] is not None:
            fam = raw["families"].drop(columns=["epss"], errors="ignore")
            self.families_source = infos["families"]["name"]
        elif raw["granite"] is not None:
            fam = raw["granite"].copy()
            self.families_source = infos["granite"]["name"]
            if fs is not None:
                fam = fam.merge(fs[["family_id", "family_name"]].drop_duplicates("family_id"),
                                on="family_id", how="left")
        if fam is not None:
            fam = fam.drop_duplicates("cve_id")
            for c in ("family_name", "remote_local", "auth_required", "attack_type"):
                if c not in fam.columns:
                    fam[c] = None
            fam = fam[["cve_id", "family_id", "family_name", "remote_local", "auth_required", "attack_type"]]
        else:
            fam = pd.DataFrame(columns=["cve_id", "family_id", "family_name", "remote_local", "auth_required",
                                        "attack_type"])
        self.has_cve_families = raw["families"] is not None or raw["granite"] is not None

        # ---- merge
        df = preds.merge(fam, on="cve_id", how="left")
        self.has_descriptions = False
        vulns = self._load_vulns(data_dir, set(df["cve_id"])) if self.has_predictions else None
        if vulns is not None:
            df = df.merge(vulns, on="cve_id", how="left")
            self.has_descriptions = True
        else:
            for c in VULN_COLS:
                df[c] = None
        df["in_top500"] = df["cve_id"].isin(self.top500_ids)
        df = df.sort_values("rank").reset_index(drop=True)
        self.df = df
        self._pos = {c: i for i, c in enumerate(df["cve_id"])}
        self._id_l = df["cve_id"].astype(str).str.lower()
        self._desc_l = df["description"].fillna("").astype(str).str.lower()

        self._compute_aggregates()

    # ---------- loading ----------
    @staticmethod
    def _load_vulns(data_dir: Path, ids: set) -> Optional[pd.DataFrame]:
        path = data_dir / "vulnerabilities.csv"
        if not path.is_file():
            logger.warning("vulnerabilities.csv not found; descriptions disabled")
            return None
        try:
            header = list(pd.read_csv(path, nrows=0).columns)
            av = "attack_vector" if "attack_vector" in header else (
                "cvss3_attack_vector" if "cvss3_attack_vector" in header else None)
            want = ["cve_id", "description", "cvss3_score", "cwe_ids"] + ([av] if av else [])
            want = [c for c in want if c in header]
            parts = []
            for chunk in pd.read_csv(path, usecols=want, chunksize=50000):
                parts.append(chunk[chunk["cve_id"].isin(ids)])
            v = pd.concat(parts).drop_duplicates("cve_id", keep="last")
            if av and av != "attack_vector":
                v = v.rename(columns={av: "attack_vector"})
            for c in VULN_COLS:
                if c not in v.columns:
                    v[c] = None
            return v[["cve_id"] + VULN_COLS]
        except Exception as e:  # never block startup on the optional file
            logger.warning("could not read vulnerabilities.csv (%s)", type(e).__name__)
            return None

    # ---------- availability ----------
    def available(self, dataset: str) -> bool:
        if dataset == "predictions":
            return self.has_predictions
        if dataset == "metrics":
            return self.metrics is not None
        if dataset == "families":
            return self.fam_summary is not None
        return False

    # ---------- aggregates ----------
    def _signal_counts(self, d: pd.DataFrame) -> Optional[Dict[str, Optional[int]]]:
        if not self.has_predictions:
            return None
        out = {s: (int((d[s] > 0).sum()) if s in self.signals_available else None) for s in SIGNALS}  # type: Dict[str, Optional[int]]
        if self.signals_available:
            anyv = (d[self.signals_available] > 0).any(axis=1)
            out["any"] = int(anyv.sum())
            out["none"] = int((~anyv).sum())
        else:
            out["any"] = out["none"] = None
        return out

    def _compute_aggregates(self) -> None:
        df = self.df
        top = df[df["in_top500"]]
        self.top500_df = top
        if not self.has_predictions or df.empty:
            self.distributions = {"score_hist": None, "epss_hist": None, "published_by_month": None,
                                  "remote_local": [], "auth_required": []}
            self.signal_counts = None
            self.top500_arrays = {"cve_id": [], "prediction_score": [], "epss": []}
            self.stats = {}
            return

        s_edges = np.linspace(df["prediction_score"].min(), df["prediction_score"].max(), 31)
        pos = df.loc[df["epss"] > 0, "epss"]
        if len(pos):
            lo = 10.0 ** np.floor(np.log10(pos.min()))
            hi = 1.0 if df["epss"].max() <= 1 else 10.0 ** np.ceil(np.log10(df["epss"].max()))
            e_edges = np.logspace(np.log10(lo), np.log10(hi), 31) if hi > lo else None
        else:
            e_edges = None

        def counts(col: str) -> List[Dict[str, Any]]:
            if df[col].isna().all():
                return []
            vc = df[col].fillna("UNKNOWN").value_counts()
            return [{"label": str(k), "count": int(v)} for k, v in vc.items()]

        pub = None
        if df["published"].notna().any():
            pa = df["published"].astype(str).str[:7]
            months = sorted(pa[df["published"].notna()].unique())
            pm_all = pa.value_counts()
            pm_top = top["published"].astype(str).str[:7].value_counts()
            pub = {"months": months, "all": [int(pm_all.get(m, 0)) for m in months],
                   "top500": [int(pm_top.get(m, 0)) for m in months]}
        self.distributions = {
            "score_hist": {"edges": s_edges.tolist(),
                           "all": _hist(df["prediction_score"].values, s_edges),
                           "top500": _hist(top["prediction_score"].values, s_edges)},
            "epss_hist": None if e_edges is None else {
                "edges": e_edges.tolist(), "all": _hist(df["epss"].values, e_edges),
                "top500": _hist(top["epss"].values, e_edges)},
            "published_by_month": pub,
            "remote_local": counts("remote_local"),
            "auth_required": counts("auth_required"),
        }
        self.signal_counts = {"all": self._signal_counts(df), "top500": self._signal_counts(top)}
        self.top500_arrays = {
            "cve_id": top["cve_id"].tolist(),
            "prediction_score": top["prediction_score"].tolist(),
            "epss": top["epss"].tolist(),
        }
        q = [0.25, 0.5, 0.75, 0.95]
        self.stats = {
            "score_q_all": dict(zip(q, df["prediction_score"].quantile(q).tolist())),
            "score_q_top500": dict(zip(q, top["prediction_score"].quantile(q).tolist())),
            "epss_q_all": dict(zip(q, df["epss"].quantile(q).tolist())),
            "epss_q_top500": dict(zip(q, top["epss"].quantile(q).tolist())),
            "score_max": float(df["prediction_score"].max()),
            "score_min_top500": float(top["prediction_score"].min()) if len(top) else None,
            "epss_lt_001_all": float((df["epss"] < 0.01).mean()),
            "epss_lt_001_top500": float((top["epss"] < 0.01).mean()) if len(top) else None,
        }

    # ---------- public helpers ----------
    @property
    def metrics_list(self) -> List[Dict[str, Any]]:
        return [] if self.metrics is None else to_py(self.metrics)

    def status_files(self) -> List[Dict[str, Any]]:
        return self.files

    def overview(self) -> Dict[str, Any]:
        out = {"total_cves": None, "top500_count": None, "family_count": None, "positives_2025": None,
               "best_hits_500": None, "epss_hits_500": None, "tell": None,
               "signal_counts": self.signal_counts}  # type: Dict[str, Any]
        if self.has_predictions:
            out["total_cves"] = int(len(self.df))
            out["top500_count"] = int(len(self.top500_df))
        if self.fam_summary is not None:
            out["family_count"] = int(len(self.fam_summary))
        m = self.metrics
        if m is not None and len(m):
            ml = self.metrics_list
            hits = m["hits_500"]
            if hits.notna().any():
                out["best_hits_500"] = ml[int(m.index.get_loc(hits.idxmax()))]
            rec = m["recall_500"].iloc[0]
            if pd.notna(rec) and rec > 0 and pd.notna(m["hits_500"].iloc[0]):
                out["positives_2025"] = int(round(m["hits_500"].iloc[0] / rec))
            e = m[m["model"].astype(str).str.contains("EPSS", case=False)]
            if len(e) and pd.notna(e.iloc[0]["hits_500"]):
                out["epss_hits_500"] = int(e.iloc[0]["hits_500"])
            t = m[m["model"].astype(str).str.contains("Tell", case=False)]
            if len(t):
                out["tell"] = ml[int(m.index.get_loc(t.index[0]))]
        return out

    def families(self) -> List[Dict[str, Any]]:
        return [] if self.fam_summary is None else to_py(self.fam_summary)

    def family(self, fid: str) -> Optional[Dict[str, Any]]:
        if self.fam_summary is None:
            return None
        r = self.fam_summary[self.fam_summary["family_id"] == fid]
        return to_py(r)[0] if len(r) else None

    def family_detail(self, fid: str) -> Optional[Dict[str, Any]]:
        fam = self.family(fid)
        if fam is None:
            return None
        d = self.df[self.df["family_id"] == fid]
        return {
            "family": fam,
            "top_cves": to_py(d.head(20)[OUT_COLS]),  # df is sorted by rank
            "in_top500": int(d["in_top500"].sum()) if self.has_predictions else None,
            "signal_counts": self._signal_counts(d),
        }

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        i = self._pos.get(cve_id.upper())
        if i is None:
            return None
        return to_py(self.df.iloc[[i]][OUT_COLS])[0]

    def cves_by_ids(self, ids: List[str]) -> List[Dict[str, Any]]:
        idx = [self._pos[i] for i in ids if i in self._pos]
        return to_py(self.df.iloc[idx][OUT_COLS]) if idx else []

    def search(self, q: Optional[str] = None, family_id: Optional[str] = None,
               min_epss: Optional[float] = None, signals: Optional[List[str]] = None,
               scope: str = "top500", sort: str = "rank", limit: int = 50,
               offset: int = 0) -> Tuple[int, List[Dict[str, Any]]]:
        df = self.df
        if not self.has_predictions:
            return 0, []
        mask = pd.Series(True, index=df.index)
        if scope == "top500":
            mask &= df["in_top500"]
        if q:
            ql = q.strip().lower()
            mask &= self._id_l.str.contains(ql, regex=False) | self._desc_l.str.contains(ql, regex=False)
        if family_id:
            mask &= df["family_id"] == family_id
        if min_epss is not None:
            mask &= df["epss"] >= min_epss
        for s in signals or []:
            if s in SIGNALS:
                mask &= df[s] > 0
        sub = df[mask]
        col, asc = SORTS.get(sort, SORTS["rank"])
        if col != "rank":
            sub = sub.sort_values([col, "rank"], ascending=[asc, True], kind="stable")
        return int(len(sub)), to_py(sub.iloc[offset:offset + limit][OUT_COLS])


# ---------------------------------------------------------------- hot reload
_store = None  # type: Optional[Store]
_key = None  # type: Optional[tuple]
_sig = None  # type: Optional[tuple]
_checked = 0.0
_lock = threading.Lock()


def _signature(rd: Path) -> tuple:
    out = []
    for spec in SPECS.values():
        for n in spec["names"]:
            try:
                st = (rd / n).stat()
                out.append((n, st.st_mtime_ns, st.st_size))
            except OSError:
                out.append((n, None, None))
    return tuple(out)


def get_store() -> Store:
    """Current store; re-stats results files at most once per RELOAD_INTERVAL and swaps atomically."""
    global _store, _key, _sig, _checked
    rd, label = results_dir(), data_label()
    key = (str(rd), label, str(_data_dir()))
    with _lock:
        now = time.monotonic()
        if _store is not None and key == _key and now - _checked < RELOAD_INTERVAL:
            return _store
        sig = _signature(rd)
        if _store is not None and key == _key and sig == _sig:
            _checked = now
            return _store
        try:
            new = Store(rd, label=label)
        except Exception as e:
            if _store is None:
                raise
            logger.error("reload failed (%s: %s); keeping previous data", type(e).__name__, e)
            _checked = now
            return _store
        if _store is not None:
            logger.info("results changed; reloaded")
        _store, _key, _sig, _checked = new, key, sig, now
        return _store
