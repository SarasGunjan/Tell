"""Chat: Gemini function-calling loop with an offline regex intent router.

Both paths return {reply, actions, cves, source, grounding}.
"""
import logging
import os
import re
from typing import Any, Dict, List, Optional

import requests

from src.ai.evidence_grounding import EvidenceGroundingEngine

from .store import SIGNALS, Store, waiting_text

logger = logging.getLogger("Tell.Chat")

PAGES = ["overview", "top500", "families", "models", "analyst"]
HIGHLIGHT_TARGETS = [
    "kpi-candidates", "kpi-hits500", "kpi-lift", "chart-score-dist", "chart-epss-dist",
    "chart-signals", "chart-published", "chart-family-size", "chart-family-kev",
    "chart-family-bubble", "chart-hits", "chart-precision-recall", "table-auc",
    "table-top500", "panel-cve", "panel-brief", "panel-grounding",
]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GEMINI_TIMEOUT = 12
MAX_ROUNDS = 4

SYSTEM_PROMPT = (
    "You are Tell's friendly security-analyst assistant (tagline: Every attack has a tell). Tell ranks 2026 CVEs by the "
    "predicted likelihood of entering CISA's KEV catalog. Answer ONLY from tool results; call tools "
    "to get data instead of guessing. Cite CVE IDs you mention. NEVER state or imply that a 2026 CVE "
    "is already in KEV: ranks and scores are predictions, not confirmed exploitation. Acknowledge "
    "uncertainty (e.g. the historical backtest has only a few dozen positives). If the tools cannot answer, "
    "say so. If a tool says data is not computed yet, tell the user which member/file it is waiting on and "
    "never guess numbers. Be concise and friendly; use short Markdown. UI tools (navigate, highlight, open_cve, "
    "filter_top500) may be called to show the user things on screen."
)


def _obj(props: Dict[str, Any], required: Optional[List[str]] = None) -> Dict[str, Any]:
    d = {"type": "OBJECT", "properties": props}
    if required:
        d["required"] = required
    return d


_S = {"type": "STRING"}
_SIG = {"type": "ARRAY", "items": {"type": "STRING", "enum": SIGNALS}}
FILTER_PROPS = {
    "q": {"type": "STRING", "description": "text matched against CVE id or description"},
    "family_id": {"type": "STRING", "description": "e.g. FAM-01"},
    "min_epss": {"type": "NUMBER"},
    "signals": _SIG,
}
TOOLS = [
    {"name": "search_cves", "description": "Search/filter CVEs (max 10 returned).",
     "parameters": _obj(dict(FILTER_PROPS, **{
         "scope": {"type": "STRING", "enum": ["top500", "all"]},
         "sort": {"type": "STRING", "enum": ["rank", "epss", "score"]},
         "limit": {"type": "INTEGER"}}))},
    {"name": "get_cve", "description": "Full record for one CVE.",
     "parameters": _obj({"cve_id": _S}, ["cve_id"])},
    {"name": "list_families", "description": "All exploit families with historical KEV rate."},
    {"name": "get_family", "description": "One family with its top CVEs.",
     "parameters": _obj({"family_id": _S}, ["family_id"])},
    {"name": "get_metrics", "description": "Model evaluation metrics (historical backtest; metrics.csv does not state the year)."},
    {"name": "get_distributions", "description": "Summary of score/EPSS/signal/month distributions."},
    {"name": "navigate", "description": "Switch the UI page.",
     "parameters": _obj({"page": {"type": "STRING", "enum": PAGES}}, ["page"])},
    {"name": "highlight", "description": "Highlight a chart/element in the UI.",
     "parameters": _obj({"target": {"type": "STRING", "enum": HIGHLIGHT_TARGETS}}, ["target"])},
    {"name": "open_cve", "description": "Open a CVE in the UI drawer.",
     "parameters": _obj({"cve_id": _S}, ["cve_id"])},
    {"name": "filter_top500", "description": "Apply filters on the Top 500 page.",
     "parameters": _obj(FILTER_PROPS)},
]

COMPACT = ["cve_id", "rank", "prediction_score", "epss", "exploitdb", "metasploit", "nuclei",
           "poc_github", "published", "family_name", "in_top500"]


def _compact(c: Dict[str, Any]) -> Dict[str, Any]:
    return {k: c.get(k) for k in COMPACT}


def gemini_call(payload: Dict[str, Any], timeout: int = GEMINI_TIMEOUT) -> Dict[str, Any]:
    """POST to Gemini with the key in a header. Raises on any failure (callers fall back)."""
    key = os.environ.get("GEMINI_API_KEY", "")
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    url = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent" % model
    r = requests.post(url, json=payload, headers={"x-goog-api-key": key}, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError("gemini http %d" % r.status_code)
    return r.json()


def gemini_enabled() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


class ToolRunner:
    """Executes tools against the store; collects UI actions and touched CVEs."""

    def __init__(self, store: Store):
        self.store = store
        self.actions: List[Dict[str, Any]] = []
        self.cve_ids: List[str] = []

    def touch(self, ids: List[str]) -> None:
        for i in ids:
            if i not in self.cve_ids:
                self.cve_ids.append(i)

    def run(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        s = self.store
        args = args or {}
        need = {"search_cves": "predictions", "get_cve": "predictions", "get_distributions": "predictions",
                "list_families": "families", "get_family": "families", "get_metrics": "metrics",
                "open_cve": "predictions"}.get(name)
        if need and not s.available(need):
            return {"unavailable": waiting_text(need)}
        try:
            if name == "search_cves":
                limit = max(1, min(int(args.get("limit") or 5), 10))
                total, items = s.search(
                    q=args.get("q"), family_id=args.get("family_id"), min_epss=args.get("min_epss"),
                    signals=[x for x in args.get("signals") or [] if x in SIGNALS],
                    scope=args.get("scope") if args.get("scope") in ("top500", "all") else "top500",
                    sort=args.get("sort") if args.get("sort") in ("rank", "epss", "score") else "rank",
                    limit=limit)
                self.touch([i["cve_id"] for i in items])
                return {"total": total, "items": [_compact(i) for i in items]}
            if name == "get_cve":
                c = s.get_cve(str(args.get("cve_id", "")))
                if not c:
                    return {"error": "CVE not found in the 2026 scored set"}
                self.touch([c["cve_id"]])
                c["description"] = (c.get("description") or "")[:600] or None
                return c
            if name == "list_families":
                return {"families": s.families()}
            if name == "get_family":
                d = s.family_detail(str(args.get("family_id", "")))
                if not d:
                    return {"error": "unknown family"}
                self.touch([c["cve_id"] for c in d["top_cves"][:5]])
                d["top_cves"] = [_compact(c) for c in d["top_cves"][:5]]
                return d
            if name == "get_metrics":
                return {"metrics": s.metrics_list, "positives_2025": s.overview()["positives_2025"]}  # null = not computed yet
            if name == "get_distributions":
                d = s.distributions
                return {"stats": {k: v for k, v in s.stats.items()},
                        "signal_counts": s.signal_counts,
                        "published_by_month": d["published_by_month"],
                        "remote_local": d["remote_local"], "auth_required": d["auth_required"]}
            if name == "navigate":
                if args.get("page") in PAGES:
                    self.actions.append({"type": "navigate", "page": args["page"]})
                    return {"ok": True}
                return {"error": "unknown page"}
            if name == "highlight":
                if args.get("target") in HIGHLIGHT_TARGETS:
                    self.actions.append({"type": "highlight", "target": args["target"]})
                    return {"ok": True}
                return {"error": "unknown target"}
            if name == "open_cve":
                c = s.get_cve(str(args.get("cve_id", "")))
                if not c:
                    return {"error": "CVE not found"}
                self.actions.append({"type": "open_cve", "cve_id": c["cve_id"]})
                self.touch([c["cve_id"]])
                return {"ok": True}
            if name == "filter_top500":
                a = {"type": "filter_top500"}  # type: Dict[str, Any]
                for k in ("q", "family_id", "min_epss"):
                    if args.get(k) not in (None, ""):
                        a[k] = args[k]
                sig = [x for x in args.get("signals") or [] if x in SIGNALS]
                if sig:
                    a["signals"] = sig
                self.actions.append(a)
                return {"ok": True}
        except Exception as e:
            logger.warning("tool %s failed (%s)", name, type(e).__name__)
            return {"error": "tool failed"}
        return {"error": "unknown tool"}


def _finish(store: Store, engine: EvidenceGroundingEngine, runner: ToolRunner, reply: str,
            source: str, cards: bool = True) -> Dict[str, Any]:
    mentioned = CVE_RE.findall(reply)
    target = mentioned[0].upper() if mentioned else None
    grounding = engine.verify_response(reply, target)
    if grounding["hallucinations"]:
        reply += ("\n\n> Heads up: part of this answer could not be verified against the data. "
                  "Remember that 2026 ranks are predictions, not confirmed KEV status.")
    ids = list(runner.cve_ids)
    for m in mentioned:
        if m.upper() not in ids:
            ids.append(m.upper())
    if not cards:  # canned help text mentions an example CVE; it must not attach a card
        ids = []
    return {"reply": reply, "actions": runner.actions, "cves": store.cves_by_ids(ids)[:10],
            "source": source, "grounding": grounding}


# ---------------------------------------------------------------- Gemini path
def _gemini_chat(store, engine, messages, page, selection) -> Optional[Dict[str, Any]]:
    runner = ToolRunner(store)
    ctx = "The user is on the '%s' page." % page
    if selection:
        ctx += " Current selection: %s" % str(selection)[:300]
    contents = [{"role": "model" if m["role"] == "assistant" else "user",
                 "parts": [{"text": m["content"]}]} for m in messages]
    base = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT + " " + ctx}]},
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1200},
        "tools": [{"functionDeclarations": TOOLS}],
    }
    for round_no in range(MAX_ROUNDS + 1):
        payload = dict(base, contents=contents)
        if round_no == MAX_ROUNDS:  # tool budget spent: force a text answer
            payload["toolConfig"] = {"functionCallingConfig": {"mode": "NONE"}}
        cand = gemini_call(payload)["candidates"][0]["content"]
        parts = cand.get("parts", [])
        calls = [p["functionCall"] for p in parts if "functionCall" in p]
        if calls and round_no < MAX_ROUNDS:
            contents.append(cand)
            contents.append({"role": "user", "parts": [
                {"functionResponse": {"name": c["name"],
                                      "response": {"result": runner.run(c["name"], c.get("args") or {})}}}
                for c in calls]})
            continue
        text = "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
        return _finish(store, engine, runner, text, "gemini") if text else None
    return None


# ---------------------------------------------------------------- offline path
HELP = (
    "I'm running offline (no AI key), so I can answer a few kinds of questions from the data:\n\n"
    "- **A CVE**, e.g. `CVE-2025-14558`\n"
    "- **An exploit family**, e.g. `SQL injection` or `FAM-01`\n"
    "- **Top CVEs**, e.g. `top 5 riskiest`\n"
    "- **Exploit signals**, e.g. `metasploit` or `nuclei`\n"
    "- **Models**, e.g. `which model has the best hits and precision?`\n"
    "- **Overview**, e.g. `how many CVEs are there?`"
)


METRICS_RE = re.compile(
    r"\b(models?|hits?|precision|recall|accuracy|auc|baseline|ensemble|lightgbm|backtest|heuristic|"
    r"compare[sd]?|comparison|vs|versus|better|outperforms?|outperformed)\b")
EPSS_RE = re.compile(r"\bepss\b")
RANK_RE = re.compile(r"\b(top|highest|riskiest|most|worst|lowest)\b")


def _fmt_cve(c: Dict[str, Any]) -> str:
    sig = [k for k in SIGNALS if c.get(k)]
    fam = ", family: %s" % c["family_name"] if c.get("family_name") else ""
    return "**%s** - rank #%s, score %.2f, EPSS %.4f, signals: %s%s" % (
        c["cve_id"], c["rank"], c["prediction_score"], c["epss"], ", ".join(sig) if sig else "none", fam)


def _family_aliases(store: Store) -> List[Any]:
    extra = {"FAM-01": ["rce", "command injection"], "FAM-09": ["dos"], "FAM-07": ["sqli", "sql"],
             "FAM-02": ["auth bypass", "session hijacking"], "FAM-04": ["file upload"],
             "FAM-06": ["use after free", "buffer overflow"], "FAM-10": ["info leak"]}
    out = []
    for f in store.families():
        names = {f["family_id"].lower(), f["family_name"].lower()}
        base = re.sub(r"\(.*?\)", "", f["family_name"]).lower()
        names.update(p.strip() for p in base.split("&"))
        names.update(m.lower() for m in re.findall(r"\(([A-Za-z ]+)\)", f["family_name"]))
        names.update(extra.get(f["family_id"], []))
        out.append((f["family_id"], sorted((n for n in names if len(n) >= 3), key=len, reverse=True)))
    return out


def _offline_chat(store, engine, messages, page, selection) -> Dict[str, Any]:
    text = messages[-1]["content"]
    low = text.lower()
    r = ToolRunner(store)
    lines = []  # type: List[str]

    ids = []  # type: List[str]
    for m in CVE_RE.findall(text):
        if m.upper() not in ids:
            ids.append(m.upper())
    fam_id = None
    for fid, names in (_family_aliases(store) if store.available("families") else []):
        if any(re.search(r"(?<![a-z])%s(?![a-z])" % re.escape(n), low) for n in names):
            fam_id = fid
            break
    sigs = [s for s in SIGNALS if s in low or s.replace("_github", "") in low]
    if re.search(r"\bpocs?\b", low) and "poc_github" not in sigs:
        sigs.append("poc_github")

    if ids and not store.available("predictions"):
        lines.append(waiting_text("predictions"))
    elif ids:
        for cid in ids[:3]:
            c = r.run("get_cve", {"cve_id": cid})
            if "error" in c:
                lines.append("I could not find **%s** in the 2026 scored set." % cid)
                continue
            lines.append(_fmt_cve(c))
            if c.get("description"):
                lines.append("> " + c["description"][:300])
            lines.append("_This is a model prediction of KEV likelihood, not confirmed exploitation._")
        r.run("open_cve", {"cve_id": ids[0]})
    elif fam_id:
        d = r.run("get_family", {"family_id": fam_id})
        f = d["family"]
        parts = ["%s CVEs" % "{:,}".format(f["family_size"])]
        if f.get("hist_kev_rate") is not None:
            parts.append("historical KEV rate %.1f%%" % (f["hist_kev_rate"] * 100))
        if f.get("avg_epss_2026") is not None:
            parts.append("avg 2026 EPSS %.4f" % f["avg_epss_2026"])
        if d.get("in_top500") is not None:
            parts.append("%d in the Top 500" % d["in_top500"])
        lines.append("**%s** (%s): %s." % (f["family_name"], fam_id, ", ".join(parts)))
        lines.append("_The KEV rate is a historical observation; 2026 scores are predictions._")
        lines += ["- " + _fmt_cve(c) for c in d["top_cves"][:3]]
        r.run("navigate", {"page": "families"})
        r.run("highlight", {"target": "chart-family-kev"})
    elif METRICS_RE.search(low) or (EPSS_RE.search(low) and not RANK_RE.search(low)):
        got = r.run("get_metrics", {})
        if "unavailable" in got:
            lines.append(got["unavailable"])
        else:
            m = got["metrics"]
            best = max(m, key=lambda x: x["hits_500"])
            tell = [x for x in m if "Tell" in x["model"]]
            epss = [x for x in m if "EPSS" in x["model"]]
            pos = got["positives_2025"]
            txt = "In the historical backtest%s, **%s** led Hits@500 with %d" % (
                " (%d positives)" % pos if pos else "", best["model"], best["hits_500"])
            if tell:
                txt += "; the Tell ensemble got %d" % tell[0]["hits_500"]
                if tell[0].get("roc_auc") is not None:
                    txt += " (ROC AUC %.3f)" % tell[0]["roc_auc"]
            if epss:
                txt += " vs. %d for the EPSS baseline" % epss[0]["hits_500"]
            lines.append(txt + ".")
            lines.append("_Few positives means these numbers are noisy._")
        r.run("navigate", {"page": "models"})
        r.run("highlight", {"target": "chart-hits"})
    elif (sigs or re.search(r"\b(top|highest|riskiest|most likely|worst|best)\b", low)) \
            and not store.available("predictions"):
        lines.append(waiting_text("predictions"))
    elif sigs or re.search(r"\b(top|highest|riskiest|most likely|worst|best)\b", low):
        n = re.search(r"\b(\d{1,2})\b", low)
        n = max(1, min(int(n.group(1)) if n else 5, 10))
        total, items = store.search(signals=sigs, scope="top500", limit=n)
        r.touch([i["cve_id"] for i in items])
        what = "with %s signal(s)" % ", ".join(sigs) if sigs else "by predicted risk"
        lines.append("Top %d of %d Top-500 CVEs %s:" % (len(items), total, what))
        lines += ["- " + _fmt_cve(c) for c in items]
        r.run("navigate", {"page": "top500"})
        if sigs:
            r.run("filter_top500", {"signals": sigs})
    elif re.search(r"\b(overview|summary|how many|total|distribution)\b", low):
        o = store.overview()
        if o["total_cves"] is None:
            lines.append(waiting_text("predictions"))
        else:
            txt = "Tell scored **%s** 2026 CVEs" % "{:,}".format(o["total_cves"])
            if o["family_count"] is not None:
                txt += " across **%d** exploit families" % o["family_count"]
            lines.append(txt + " and shortlisted the Top **%d**. These are predictions of future KEV entry."
                         % o["top500_count"])
        r.run("navigate", {"page": "overview"})
    else:
        lines.append(HELP)
        return _finish(store, engine, r, HELP, "offline", cards=False)
    return _finish(store, engine, r, "\n\n".join(lines), "offline")


def chat(store: Store, engine: EvidenceGroundingEngine, messages: List[Dict[str, str]],
         page: str = "overview", selection: Any = None) -> Dict[str, Any]:
    if gemini_enabled():
        try:
            out = _gemini_chat(store, engine, messages, page, selection)
            if out:
                return out
        except Exception as e:
            logger.warning("gemini chat failed (%s); using offline router", type(e).__name__)
    return _offline_chat(store, engine, messages, page, selection)
