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

PAGES = ["dashboard", "overview", "top500", "families", "research", "models", "analyst"]
HIGHLIGHT_TARGETS = [
    "kpi-candidates", "kpi-hits500", "kpi-lift", "chart-rank-epss", "chart-epss-dist",
    "chart-signals", "chart-published", "chart-family-size", "chart-family-kev",
    "chart-family-bubble", "chart-hits", "table-ap",
    "table-top500", "panel-cve", "panel-brief", "panel-grounding",
    "chart-galaxy", "dash-kpis", "chart-scatter", "chart-budget",
    "research-concentration", "research-temporal", "research-baselines", "research-cwe",
]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GEMINI_TIMEOUT = 12
MAX_ROUNDS = 4

SYSTEM_PROMPT = (
    "You are Tell's friendly security-analyst assistant (tagline: Every attack has a tell). Tell ranks 2026 CVEs with a "
    "transparent public-code-then-EPSS ranking (not a calibrated probability) to surface those most likely to enter "
    "CISA's KEV catalog. Answer ONLY from tool results; call tools to get data instead of guessing. Cite CVE IDs you "
    "mention. NEVER state or imply that a 2026 CVE is already in KEV: ranks are predictions, not confirmed exploitation. "
    "Families come from IBM Granite embeddings (Member 2). Family KEV rates and lifts are historical, "
    "population-weighted observations about a family, never the probability for one CVE; the 2,500-CVE research cohort "
    "is separate from the 2026 benchmark and must not be mixed with it. Sample KEV rates are inflated by sampling: "
    "prefer population_kev_rate. If you discuss Family 8, say it mixes web XSS/CSRF with browser-engine zero-days. "
    "Patch budget has three measured points (100, 250, 500), not a curve. Acknowledge that the validation cohort is "
    "small. If the tools cannot answer, say so. If a tool says data is not computed yet, tell the user which "
    "member/file it is waiting on and never guess numbers. Be concise and friendly; use short Markdown. UI tools "
    "(navigate, highlight, open_cve, filter_top500) may be called to show the user things on screen."
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
    "family_id": {"type": "STRING", "description": "Granite family id, 0 to 9"},
    "min_epss": {"type": "NUMBER"},
    "signals": _SIG,
}
TOOLS = [
    {"name": "search_cves", "description": "Search/filter CVEs (max 10 returned).",
     "parameters": _obj(dict(FILTER_PROPS, **{
         "scope": {"type": "STRING", "enum": ["top500", "all"]},
         "sort": {"type": "STRING", "enum": ["rank", "epss"]},
         "limit": {"type": "INTEGER"}}))},
    {"name": "get_cve", "description": "Full record for one CVE.",
     "parameters": _obj({"cve_id": _S}, ["cve_id"])},
    {"name": "list_families", "description": "All Granite exploit families: 2026 size, historical population KEV rate and lift."},
    {"name": "get_family", "description": "One family with its top CVEs, attack-surface breakdown, and caveat if any.",
     "parameters": _obj({"family_id": _S}, ["family_id"])},
    {"name": "get_metrics", "description": "Model evaluation: hits at 100/250/500, average precision where computed, and the measured patch-budget points."},
    {"name": "get_distributions", "description": "Summary of score/EPSS/signal/month distributions."},
    {"name": "get_research", "description": "Research Discoveries from the historical cohort: concentration, out-of-time validation, baselines, top CWEs."},
    {"name": "navigate", "description": "Switch the UI page.",
     "parameters": _obj({"page": {"type": "STRING", "enum": PAGES}}, ["page"])},
    {"name": "highlight", "description": "Highlight a chart/element in the UI.",
     "parameters": _obj({"target": {"type": "STRING", "enum": HIGHLIGHT_TARGETS}}, ["target"])},
    {"name": "open_cve", "description": "Open a CVE in the UI drawer.",
     "parameters": _obj({"cve_id": _S}, ["cve_id"])},
    {"name": "filter_top500", "description": "Apply filters on the Top 500 page.",
     "parameters": _obj(FILTER_PROPS)},
]

COMPACT = ["cve_id", "rank", "epss", "exploitdb", "metasploit", "nuclei",
           "poc_github", "published", "family_name", "vulnerability_type", "in_top500"]


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
                "get_research": "research",
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
                    sort=args.get("sort") if args.get("sort") in ("rank", "epss") else "rank",
                    limit=limit)
                self.touch([i["cve_id"] for i in items])
                return {"total": total, "items": [_compact(i) for i in items]}
            if name == "get_cve":
                c = s.get_cve(str(args.get("cve_id", "")))
                if not c:
                    return {"error": "CVE not found in the 2026 scored set"}
                self.touch([c["cve_id"]])
                c["description"] = (c.get("description") or "")[:600] or None
                c["family_note"] = "Family rates are historical patterns, not this CVE's probability."
                return c
            if name == "list_families":
                keys = ("family_id", "family_name", "family_size", "historical_kev_count", "population_kev_rate",
                        "population_lift", "in_top500", "caveat")
                return {"families": [{k: f.get(k) for k in keys} for f in s.families()],
                        "basis": "Observed (historical), population-weighted"}
            if name == "get_family":
                d = s.family_detail(str(args.get("family_id", "")))
                if not d:
                    return {"error": "unknown family"}
                self.touch([c["cve_id"] for c in d["top_cves"][:5]])
                d["top_cves"] = [_compact(c) for c in d["top_cves"][:5]]
                return d
            if name == "get_metrics":
                return {"ranking_method": s.ranking_method, "metrics": s.metrics_list, "patch_budget": s.patch_budget(),
                        "note": "Patch budget has three measured points; validation cohort is small."}
            if name == "get_distributions":
                d = s.distributions
                return {"stats": {k: v for k, v in s.stats.items()},
                        "signal_counts": s.signal_counts,
                        "published_by_month": d["published_by_month"],
                        "remote_local": d["remote_local"], "auth_required": d["auth_required"]}
            if name == "get_research":
                return research_summary(s)
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


def research_summary(s: Store) -> Dict[str, Any]:
    """Compact, grounded facts for the Research page (tool + offline router)."""
    r = s.research
    out = {"cohort": r["cohort"]["label"], "sample_caption": r["sample_caption"],
           "caveats": r["caveats"]}  # type: Dict[str, Any]
    if r.get("concentration"):
        out["concentration"] = r["concentration"]["data"]
    if r.get("temporal"):
        out["temporal_headline"] = r["temporal"]["data"]["headline"]
    if r.get("baselines"):
        out["baselines"] = [{k: b.get(k) for k in ("method", "non_missing_coverage",
                                                   "population_top3_concentration_ratio")}
                            for b in r["baselines"]["data"]]
    if r.get("cwe"):
        out["top_cwes"] = [{"cwe_id": x["cwe_id"], "cve_count": x["total"]} for x in r["cwe"]["data"]["rows"][:5]]
    if r.get("families"):
        out["families_population_lift"] = [{"family_id": f["family_id"], "family_name": f["family_name"],
                                            "population_lift": f["population_lift"]} for f in r["families"]["data"]]
    return out


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
    "- **An exploit family**, e.g. `SQL injection` or `family 7`\n"
    "- **Top CVEs**, e.g. `top 5 riskiest`\n"
    "- **Exploit signals**, e.g. `metasploit` or `nuclei`\n"
    "- **Models**, e.g. `which model has the most hits?`\n"
    "- **Research findings**, e.g. `what did the research discover?`\n"
    "- **Overview**, e.g. `how many CVEs are there?`"
)


METRICS_RE = re.compile(
    r"\b(models?|hits?|precision|recall|accuracy|auc|baseline|ensemble|lightgbm|logistic|backtest|heuristic|budget|"
    r"compare[sd]?|comparison|vs|versus|better|outperforms?|outperformed)\b")
RESEARCH_RE = re.compile(r"\b(research|discover\w*|findings?|concentrat\w*|out[- ]of[- ]time|temporal|validation)\b")
FAMILY_NUM_RE = re.compile(r"\bfamily\s*#?\s*(\d{1,2})\b")
EPSS_RE = re.compile(r"\bepss\b")
RANK_RE = re.compile(r"\b(top|highest|riskiest|most|worst|lowest)\b")


def _fmt_cve(c: Dict[str, Any]) -> str:
    sig = [k for k in SIGNALS if c.get(k)]
    fam = ", family: %s" % c["family_name"] if c.get("family_name") else ""
    return "**%s** - rank #%s, EPSS %.4f, signals: %s%s" % (
        c["cve_id"], c["rank"], c["epss"], ", ".join(sig) if sig else "none", fam)


def _family_aliases(store: Store) -> List[Any]:
    extra = {"rce": "Remote Code Execution", "sqli": "SQL Injection", "xss": "Cross-Site Scripting",
             "dos": "Denial of Service", "csrf": "Cross-Site Request Forgery", "auth bypass": "Auth Bypass",
             "privesc": "Privilege Escalation", "file upload": "File Upload", "buffer overflow": "Buffer"}
    out = []
    for f in store.families():
        nm = f["family_name"].lower()
        names = {nm}
        base = re.sub(r"[\(\[].*?[\)\]]", "", nm)
        names.update(p.strip() for p in re.split(r"&", base))
        names.update(m.lower() for m in re.findall(r"\(([A-Za-z ]+)\)", f["family_name"]))
        names.update(k for k, v in extra.items() if v.lower() in nm)
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
    mnum = FAMILY_NUM_RE.search(low)
    if mnum and store.available("families") and store.family(mnum.group(1)):
        fam_id = mnum.group(1)
    for fid, names in ([] if fam_id else (_family_aliases(store) if store.available("families") else [])):
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
        parts = ["%s CVEs in 2026" % "{:,}".format(f["family_size"])]
        if f.get("population_kev_rate") is not None:
            parts.append("historical population KEV rate %.2f%% (%.2fx lift)" % (
                f["population_kev_rate"] * 100, f["population_lift"]))
        if d.get("in_top500") is not None:
            parts.append("%d in the Top 500" % d["in_top500"])
        lines.append("**%s** (family %s): %s." % (f["family_name"], fam_id, ", ".join(parts)))
        lines.append("_Observed (historical), population-weighted. This is a family pattern, not the probability "
                     "for any 2026 CVE._")
        if d.get("caveat"):
            lines.append("> Caveat: " + d["caveat"])
        lines += ["- " + _fmt_cve(c) for c in d["top_cves"][:3]]
        r.run("navigate", {"page": "families"})
        r.run("highlight", {"target": "chart-family-kev"})
    elif RESEARCH_RE.search(low) and not store.available("research"):
        lines.append(waiting_text("research"))
    elif RESEARCH_RE.search(low):
        rs = r.run("get_research", {})
        h = rs.get("temporal_headline")
        c = rs.get("concentration")
        if c:
            lines.append("In the %s, the three most-exploited Granite families hold **%.1f%%** of KEVs but only "
                         "**%.1f%%** of CVE volume (population-weighted, %.2fx concentration)."
                         % (rs["cohort"], c["kev_share"] * 100, c["population_volume_share"] * 100,
                            c["population_ratio"]))
        if h:
            lines.append("Out of time: the 2024 top-3 families (%s) held **%.1f%%** of 2025 KEVs with **%.1f%%** of 2025 "
                         "CVEs, a **%.2fx** enrichment." % (", ".join(h["top3_family_ids"]), h["kev_share"] * 100,
                                                            h["volume_share"] * 100, h["lift"]))
        if not lines:
            lines.append("The research files are present but contain no headline results yet.")
        lines.append("_Historical patterns, not predictions for any 2026 CVE. " + rs["sample_caption"] + "_")
        r.run("navigate", {"page": "research"})
        r.run("highlight", {"target": "research-concentration"})
    elif METRICS_RE.search(low) or (EPSS_RE.search(low) and not RANK_RE.search(low)):
        got = r.run("get_metrics", {})
        if "unavailable" in got:
            lines.append(got["unavailable"])
        else:
            m = got["metrics"]
            best = max(m, key=lambda x: x["hits_500"])
            rank_m = [x for x in m if x["model"].lower() == got["ranking_method"].lower()]
            epss = [x for x in m if x["model"].strip().lower() == "epss"]
            txt = "In the validation backtest, **%s** led Hits@500 with %d" % (best["model"], best["hits_500"])
            if rank_m and rank_m[0]["model"] != best["model"]:
                txt += "; %s got %d" % (rank_m[0]["model"], rank_m[0]["hits_500"])
            if epss:
                txt += " vs. %d for the EPSS baseline" % epss[0]["hits_500"]
            lines.append(txt + ".")
            ap = [x for x in m if x.get("average_precision") is not None]
            if ap:
                lines.append("Average precision: " + ", ".join("%s %.3f" % (x["model"], x["average_precision"])
                                                                for x in ap) + " (not computed for the others).")
            lines.append("_The validation cohort is small, so these numbers are noisy. Patch budget has three measured points._")
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
