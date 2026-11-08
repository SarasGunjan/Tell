"""Validate a data drop (Member 1 results + Member 2 Granite outputs).
Usage: python -m src.api.validate [--dir RESULTS] [--granite-dir GRANITE]. Exit 1 on any failure."""
import argparse
import os
import sys
from pathlib import Path
from typing import List

import pandas as pd

from .store import (SPECS, ROOT, RESEARCH_JSON, find_file, granite_dir, make_dirs, method_display, read_dataset,
                    results_dir, DEFAULT_RANKING_METHOD)


def _ok(msg: str) -> None:
    print("  PASS  " + msg)


def run(rd: Path, gd: Path) -> int:
    fails = []  # type: List[str]

    def bad(msg: str) -> None:
        fails.append(msg)
        print("  FAIL  " + msg)

    dirs = make_dirs(rd, gd)
    print("Results dir: %s\nGranite dir: %s" % (rd, gd))
    data = {}
    for key, spec in SPECS.items():
        df, info = read_dataset(dirs, key)
        data[key] = df
        print("\n%s (%s)" % (info["name"], spec["owner"]))
        if not info["present"]:
            if spec.get("optional"):
                print("  skip  not present (optional)")
            elif key == "granite":
                if find_file(dirs, SPECS["families"]):
                    print("  skip  not present (families.csv supplies family info)")
                else:
                    bad("granite_features.csv missing (and no families.csv)")
            else:
                bad("file missing")
            continue
        print("  info  %s: %s rows, columns: %s" % (info["name"], info["rows"], ", ".join(info["columns"])))
        if info.get("error"):
            bad("cannot be read as CSV")
            continue
        if info["missing_required"]:
            bad("missing required column(s): %s" % ", ".join(info["missing_required"]))
            continue
        _ok("required columns present: %s" % ", ".join(spec["required"]))
        raw = data[key]
        if "cve_id" in raw.columns:
            d = int(raw["cve_id"].duplicated().sum())
            _ok("no duplicate cve_id") if d == 0 else bad("%d duplicate cve_id value(s)" % d)
        nan = {c: int(raw[c].isna().sum()) for c in spec["required"] if raw[c].isna().any()}
        _ok("no NaNs in required columns") if not nan else bad("NaNs in required columns: %s" % nan)

    print("\ntop500 checks")
    path = find_file(dirs, SPECS["top500"])
    preds = data["predictions"]
    if path is None:
        print("  skip  top500.csv not present (the API derives it from predictions rank <= 500)")
    else:
        raw = pd.read_csv(path)
        cols = list(raw.columns)
        _ok("single column cve_id") if cols == ["cve_id"] else bad("columns must be exactly [cve_id], found %s" % cols)
        _ok("exactly 500 rows") if len(raw) == 500 else bad("expected 500 rows, found %d" % len(raw))
        if "cve_id" in raw.columns:
            ids = raw["cve_id"].astype(str)
            _ok("IDs unique") if not ids.duplicated().any() else bad("%d duplicate ID(s)" % ids.duplicated().sum())
            ddir = Path(os.environ.get("THREATRANK_DATA_DIR") or ROOT / "data")
            sb = ddir / "scoreboard_2026.csv"
            if sb.is_file():
                sdf = pd.read_csv(sb)
                col = "cve_id" if "cve_id" in sdf.columns else sdf.columns[0]
                miss = sorted(set(ids) - set(sdf[col].astype(str)))
                _ok("every ID in scoreboard_2026.csv") if not miss else bad(
                    "%d ID(s) not in scoreboard_2026.csv, e.g. %s" % (len(miss), miss[:3]))
            else:
                print("  skip  scoreboard check (no scoreboard_2026.csv in %s)" % ddir)
            if preds is not None:
                miss = sorted(set(ids) - set(preds["cve_id"].astype(str)))
                _ok("every ID in predictions") if not miss else bad(
                    "%d ID(s) not in predictions, e.g. %s" % (len(miss), miss[:3]))
                top = set(preds.loc[pd.to_numeric(preds["rank"], errors="coerce") <= 500, "cve_id"].astype(str))
                _ok("top500 equals predictions rank <= 500") if top == set(ids) else bad(
                    "top500.csv differs from predictions rank <= 500 (%d differing)" % len(top ^ set(ids)))
            else:
                print("  skip  predictions check (predictions unavailable)")

    print("\nmetrics checks")
    m, pb = data["metrics"], data["patch_budget"]
    if m is not None:
        method = DEFAULT_RANKING_METHOD
        if preds is not None and "ranking_method" in preds.columns and preds["ranking_method"].notna().any():
            method = method_display(preds["ranking_method"].dropna().iloc[0])
        names = m["model"].astype(str).str.strip().str.lower()
        _ok("ranking method %r has a metrics row" % method) if (names == method.lower()).any() else bad(
            "no metrics row named %r (ranking method)" % method)
        _ok("an EPSS baseline row exists") if (names == "epss").any() else bad("no 'EPSS' row in metrics")
        if pb is not None:
            mm = {(str(r.model), k): getattr(r, "hits_%d" % k) for r in m.itertuples() for k in (100, 250, 500)}
            diff = [(r.model, r.budget, r.hits) for r in pb.itertuples()
                    if (str(r.model), int(r.budget)) in mm and mm[(str(r.model), int(r.budget))] != r.hits]
            _ok("patch_budget hits agree with model_metrics") if not diff else bad(
                "patch_budget disagrees with model_metrics: %s" % diff[:3])
    else:
        print("  skip  metrics unavailable")

    print("\nbenchmark (2026) family checks")
    fam, gr, fs = data["families"], data["granite"], data["family_summary"]
    src = gr if gr is not None else fam
    if src is not None and preds is not None:
        miss = set(preds["cve_id"].astype(str)) - set(src["cve_id"].astype(str))
        _ok("benchmark families cover every prediction cve_id") if not miss else bad(
            "%d predictions CVE(s) have no family, e.g. %s" % (len(miss), sorted(miss)[:3]))
    else:
        print("  skip  coverage check (families or predictions unavailable)")
    if src is not None and fs is not None:
        unk = set(src["family_id"].dropna()) - set(fs["family_id"])
        _ok("every family_id has a family_summary row") if not unk else bad("family_id(s) without summary: %s" % sorted(unk))
        cnt = src["family_id"].value_counts()
        wrong = [(f, int(r), int(cnt.get(f, 0))) for f, r in zip(fs["family_id"], pd.to_numeric(fs["family_size"]))
                 if int(cnt.get(f, 0)) != int(r)]
        _ok("family_size matches member counts") if not wrong else bad(
            "family_size != member count (family, summary, actual): %s" % wrong[:3])
        trunc = [str(n) for n in fs["family_name"] if str(n).endswith("...")]
        if trunc:
            print("  warn  truncated family_name(s) ending in '...': %s" % trunc)
    if fam is not None and gr is not None:
        a = fam.drop_duplicates("cve_id").set_index("cve_id")["family_id"]
        b = gr.drop_duplicates("cve_id").set_index("cve_id")["family_id"]
        n = int((a.reindex(b.index) != b).sum())
        _ok("families.csv and granite_features.csv agree") if n == 0 else bad("%d CVE(s) with different family_id" % n)

    print("\nresearch (historical cohort) checks")
    hist_ids = set()
    for fn in ("granite_features.csv", "families.csv"):
        p = gd / fn
        if p.is_file():
            hist_ids = set(pd.read_csv(p, usecols=["cve_id"])["cve_id"].astype(str))
            break
    if hist_ids and src is not None:
        print("  info  historical cohort (%d CVEs) overlaps benchmark_2026 in %d CVE(s); the two are never mixed in the UI"
              % (len(hist_ids), len(hist_ids & set(src["cve_id"].astype(str)))))
    if (gd / RESEARCH_JSON).is_file():
        _ok("%s present" % RESEARCH_JSON)
    else:
        print("  skip  %s not present (optional)" % RESEARCH_JSON)
    from .store import read_research_json
    from .research import build_research
    meta, _ = read_research_json(dirs)
    rs = build_research(data, meta, fs)
    t = (rs.get("temporal") or {}).get("data", {}).get("headline") if rs.get("available") else None
    if t:
        print("  info  temporal headline: top3=%s KEV share %.2f%%, volume share %.2f%%, lift %.2fx" % (
            t["top3_family_ids"], t["kev_share"] * 100, t["volume_share"] * 100, t["lift"]))
        if t["matches_reported"] is True:
            _ok("computed temporal headline matches research_metrics.json")
        elif t["matches_reported"] is False:
            bad("computed temporal headline differs from research_metrics.json: %s" % t["reported"])
    else:
        print("  skip  temporal headline (no temporal file)")

    print("\n%s" % ("FAILED: %d problem(s)" % len(fails) if fails else "ALL CHECKS PASSED"))
    return 1 if fails else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate Tell data files")
    ap.add_argument("--dir", help="results folder (default: $TELL_RESULTS_DIR or results/)")
    ap.add_argument("--granite-dir", help="Granite outputs folder (default: $TELL_GRANITE_DIR or outputs/granite)")
    a = ap.parse_args(argv)
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")  # THREATRANK_DATA_DIR (scoreboard check) lives there
    rd = Path(a.dir) if a.dir else results_dir()
    gd = Path(a.granite_dir) if a.granite_dir else granite_dir()
    rd = rd if rd.is_absolute() else Path.cwd() / rd
    gd = gd if gd.is_absolute() else Path.cwd() / gd
    return run(rd, gd)


if __name__ == "__main__":
    sys.exit(main())
