"""Validate a results drop. Usage: python -m src.api.validate [--dir PATH]. Exit 1 on any failure."""
import argparse
import os
import sys
from pathlib import Path
from typing import List

import pandas as pd

from .store import SPECS, ROOT, find_file, read_dataset, results_dir


def _ok(msg: str) -> None:
    print("  PASS  " + msg)


def run(rd: Path) -> int:
    fails = []  # type: List[str]

    def bad(msg: str) -> None:
        fails.append(msg)
        print("  FAIL  " + msg)

    print("Results dir: %s" % rd)
    data = {}
    for key, spec in SPECS.items():
        df, info = read_dataset(rd, key)
        data[key] = df
        print("\n%s (%s)" % (spec["names"][0] + (" | " + " | ".join(spec["names"][1:]) if len(spec["names"]) > 1 else ""),
                              spec["owner"]))
        if not info["present"]:
            if spec.get("optional"):
                print("  skip  not present (optional)")
            elif key == "granite":
                if find_file(rd, SPECS["families"]):
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
        raw = pd.read_csv(find_file(rd, spec))
        raw = raw.rename(columns={a: c for a, c in spec["cols"].items() if a in raw.columns and c not in raw.columns})
        if "cve_id" in raw.columns:
            d = int(raw["cve_id"].duplicated().sum())
            _ok("no duplicate cve_id") if d == 0 else bad("%d duplicate cve_id value(s)" % d)
        nan = {c: int(raw[c].isna().sum()) for c in spec["required"] if raw[c].isna().any()}
        _ok("no NaNs in required columns") if not nan else bad("NaNs in required columns: %s" % nan)

    print("\ntop500 checks")
    t5 = data["top500"]
    path = find_file(rd, SPECS["top500"])
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
            if data["predictions"] is not None:
                miss = sorted(set(ids) - set(data["predictions"]["cve_id"].astype(str)))
                _ok("every ID in predictions") if not miss else bad(
                    "%d ID(s) not in predictions, e.g. %s" % (len(miss), miss[:3]))
            else:
                print("  skip  predictions check (predictions unavailable)")

    print("\n%s" % ("FAILED: %d problem(s)" % len(fails) if fails else "ALL CHECKS PASSED"))
    return 1 if fails else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate Tell results files")
    ap.add_argument("--dir", help="results folder (default: $TELL_RESULTS_DIR or results/)")
    a = ap.parse_args(argv)
    rd = Path(a.dir) if a.dir else results_dir()
    return run(rd if rd.is_absolute() else (Path.cwd() / rd))


if __name__ == "__main__":
    sys.exit(main())
