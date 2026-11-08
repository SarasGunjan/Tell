"""Pet narration for highlight targets: grounded template, optionally rephrased by Gemini."""
import json
import logging
import os
import re
from typing import Any, Dict, Optional

from .chat import HIGHLIGHT_TARGETS, gemini_call, gemini_enabled
from .store import Store, waiting_text

logger = logging.getLogger("Tell.Explain")

CAVEAT_HIST = "KEV rates are historical observations; 2026 scores are predictions, not confirmed exploitation."
_cache = {}  # type: Dict[Any, Dict[str, Any]]


def _pct(x: float, d: int = 1) -> str:
    return "%.*f%%" % (d, x * 100)


def _n(x: int) -> str:
    return "{:,}".format(int(x))


def _best(metrics, col):
    return max(metrics, key=lambda m: m[col])


def _facts(store: Store, target: str) -> Dict[str, Any]:
    """Return {title, shows, read, takeaway, caveat, data} built only from store numbers."""
    o = store.overview()
    m = store.metrics_list
    fam = store.families()
    sc = store.signal_counts
    st = store.stats
    tell = o["tell"]
    n_all, n_top = o["total_cves"], o["top500_count"]

    if target == "kpi-candidates":
        return dict(
            title="Candidates scored",
            shows="How many 2026 CVEs Tell scored and how many it shortlisted.",
            read="The big number is the full scored pool; the Top 500 is the slice analysts should look at first.",
            takeaway="%s CVEs were scored across %d families and %d were shortlisted (%s of the pool)."
                     % (_n(n_all), o["family_count"], n_top, _pct(n_top / n_all, 2)),
            caveat="The shortlist is a prediction of likely KEV entry, not a list of confirmed exploited CVEs.",
            data=dict(total=n_all, top500=n_top, families=o["family_count"]))
    if target == "kpi-hits500":
        b = o["best_hits_500"]
        return dict(
            title="Hits in the top 500",
            shows="How many of the historical KEV additions each approach caught in its top 500 (backtest).",
            read="A hit is a CVE that really entered KEV and was ranked within the first 500.",
            takeaway="The Tell ensemble caught %d of about %d positives; the best model, %s, caught %d."
                     % (tell["hits_500"], o["positives_2025"], b["model"], b["hits_500"]),
            caveat="With about %d positives, a few hits more or less swing these numbers a lot." % o["positives_2025"],
            data=dict(tell_hits=tell["hits_500"], best_model=b["model"], best_hits=b["hits_500"],
                      positives=o["positives_2025"]))
    if target == "kpi-lift":
        lift = tell["hits_500"] / max(o["epss_hits_500"], 1)
        return dict(
            title="Lift over EPSS",
            shows="Tell's Hits@500 compared with the EPSS-only baseline.",
            read="Lift is Tell's hits divided by the EPSS baseline's hits at the same cutoff.",
            takeaway="Tell found %d hits vs %d for EPSS, about %.2fx as many."
                     % (tell["hits_500"], o["epss_hits_500"], lift),
            caveat="The simple exploit+EPSS heuristic still leads Hits@500 with %d, and the sample is small."
                   % _best(m, "hits_500")["hits_500"],
            data=dict(tell_hits=tell["hits_500"], epss_hits=o["epss_hits_500"], lift=round(lift, 2)))
    if target == "chart-score-dist":
        return dict(
            title="Prediction score distribution",
            shows="How model scores are spread for all CVEs versus the Top 500 (log-scaled counts).",
            read="Taller bars mean more CVEs in that score range; the Top 500 should sit in the high-score tail.",
            takeaway="The median score is %.2f across all CVEs; the Top 500 starts at %.2f and the highest is %.2f."
                     % (st["score_q_all"][0.5], st["score_min_top500"], st["score_max"]),
            caveat="Scores are rankings for ordering CVEs, not calibrated probabilities.",
            data=dict(median_all=round(st["score_q_all"][0.5], 3), min_top500=round(st["score_min_top500"], 3),
                      max=round(st["score_max"], 3)))
    if target == "chart-epss-dist":
        return dict(
            title="EPSS distribution",
            shows="How EPSS (a public exploit-likelihood estimate) is spread for all CVEs versus the Top 500.",
            read="The x-axis is log-scaled; bars further right are CVEs with higher EPSS.",
            takeaway="Median EPSS is %.4f for all CVEs and %.4f for the Top 500; %s of all CVEs sit below 0.01."
                     % (st["epss_q_all"][0.5], st["epss_q_top500"][0.5], _pct(st["epss_lt_001_all"])),
            caveat="EPSS was taken at snapshot time, so it reflects what was known then.",
            data=dict(median_all=round(st["epss_q_all"][0.5], 4), median_top500=round(st["epss_q_top500"][0.5], 4),
                      share_below_001=_pct(st["epss_lt_001_all"])))
    if target == "chart-signals":
        a, t = sc["all"], sc["top500"]
        return dict(
            title="Exploit signals",
            shows="How often public exploit signals (ExploitDB, Metasploit, Nuclei, GitHub PoC) appear in all CVEs versus the Top 500.",
            read="Each bar is the share of CVEs with that signal; a bigger gap means the signal drives the ranking.",
            takeaway="%s of the Top 500 have at least one signal, against %s of all CVEs."
                     % (_pct(t["any"] / n_top), _pct(a["any"] / n_all)),
            caveat="A signal means exploit code exists publicly; it does not prove attacks in the wild.",
            data=dict(top500_any=t["any"], all_any=a["any"], top500_metasploit=t["metasploit"],
                      top500_nuclei=t["nuclei"]))
    if target == "chart-published":
        pm = store.distributions["published_by_month"]
        i = max(range(len(pm["months"])), key=lambda k: pm["all"][k])
        j = max(range(len(pm["months"])), key=lambda k: pm["top500"][k])
        return dict(
            title="CVEs by publication month",
            shows="How many 2026 CVEs were published each month, all versus the Top 500.",
            read="Each pair of bars is one month; compare the Top 500 bar to the total to see where risk concentrates.",
            takeaway="%s had the most CVEs (%s); %s had the most Top 500 entries (%d)."
                     % (pm["months"][i], _n(pm["all"][i]), pm["months"][j], pm["top500"][j]),
            caveat="Recent months have had less time for exploit code and KEV listings to appear.",
            data=dict(busiest_month=pm["months"][i], busiest_count=pm["all"][i],
                      top500_peak_month=pm["months"][j], top500_peak=pm["top500"][j]))
    if target == "chart-family-size":
        big, small = max(fam, key=lambda f: f["family_size"]), min(fam, key=lambda f: f["family_size"])
        return dict(
            title="Family sizes",
            shows="How many CVEs fall into each exploit family.",
            read="Longer bars are bigger families; families come from semantic grouping of descriptions.",
            takeaway="%s is largest with %s CVEs; %s is smallest with %s."
                     % (big["family_name"], _n(big["family_size"]), small["family_name"], _n(small["family_size"])),
            caveat="Size is not risk: a big family can have a low KEV rate.",
            data=dict(largest=big["family_name"], largest_size=big["family_size"],
                      smallest=small["family_name"], smallest_size=small["family_size"]))
    if target == "chart-family-kev":
        hi, lo = max(fam, key=lambda f: f["hist_kev_rate"]), min(fam, key=lambda f: f["hist_kev_rate"])
        return dict(
            title="Historical KEV rate by family",
            shows="The share of past CVEs in each family that entered CISA KEV.",
            read="Taller bars mean the family was more often exploited in the past.",
            takeaway="%s has the highest rate (%s); %s the lowest (%s). %d families are flagged high-risk."
                     % (hi["family_name"], _pct(hi["hist_kev_rate"]), lo["family_name"], _pct(lo["hist_kev_rate"]),
                        sum(1 for f in fam if f["high_risk"])),
            caveat=CAVEAT_HIST,
            data=dict(highest=hi["family_name"], highest_rate=_pct(hi["hist_kev_rate"]),
                      lowest=lo["family_name"], lowest_rate=_pct(lo["hist_kev_rate"])))
    if target == "chart-family-bubble":
        hi = max(fam, key=lambda f: f["avg_epss_2026"])
        return dict(
            title="Family size, KEV rate and EPSS",
            shows="Each bubble is a family: size by CVE count, plotted by historical KEV rate and average 2026 EPSS.",
            read="Look top-right for families that were exploited often and still score high on EPSS.",
            takeaway="%s has the highest average 2026 EPSS (%.4f) with a historical KEV rate of %s."
                     % (hi["family_name"], hi["avg_epss_2026"], _pct(hi["hist_kev_rate"])),
            caveat=CAVEAT_HIST,
            data=dict(family=hi["family_name"], avg_epss=hi["avg_epss_2026"], kev_rate=_pct(hi["hist_kev_rate"])))
    if target == "chart-hits":
        parts = []
        for k in (100, 250, 500):
            b = _best(m, "hits_%d" % k)
            parts.append("top %d: %s (%d)" % (k, b["model"], b["hits_%d" % k]))
        return dict(
            title="Hits at 100, 250 and 500",
            shows="Real KEV additions each model caught within its top 100, 250 and 500 (historical backtest).",
            read="Taller bars catch more true positives at the same cutoff.",
            takeaway="Leaders by cutoff - " + "; ".join(parts) + ".",
            caveat="About %d positives only, so differences of a hit or two are noise." % o["positives_2025"],
            data=dict(leaders=parts))
    if target == "chart-precision-recall":
        b = _best(m, "precision_500")
        return dict(
            title="Precision and recall",
            shows="Precision (share of the top K that were real) and recall (share of all positives found) at K=100, 250, 500.",
            read="Precision tends to fall and recall to rise as K grows.",
            takeaway="At K=500 the best precision is %s and recall %s, from %s."
                     % (_pct(b["precision_500"]), _pct(b["recall_500"]), b["model"]),
            caveat="Positives are rare, so precision stays low for every model.",
            data=dict(model=b["model"], precision_500=b["precision_500"], recall_500=b["recall_500"]))
    if target == "table-auc":
        r, p = _best(m, "roc_auc"), _best(m, "pr_auc")
        return dict(
            title="AUC table",
            shows="ROC AUC and PR AUC for each model on the historical backtest.",
            read="Higher is better; PR AUC matters more when positives are rare.",
            takeaway="%s has the best ROC AUC (%.3f); %s has the best PR AUC (%.3f). Tell's are %.3f and %.3f."
                     % (r["model"], r["roc_auc"], p["model"], p["pr_auc"], tell["roc_auc"], tell["pr_auc"]),
            caveat="AUC and Hits@K can disagree; no single metric tells the whole story here.",
            data=dict(best_roc=r["model"], best_pr=p["model"], tell_roc=tell["roc_auc"], tell_pr=tell["pr_auc"]))
    if target == "table-top500":
        top = store.df.iloc[0]
        return dict(
            title="Top 500 table",
            shows="The 500 CVEs ranked most likely to enter KEV.",
            read="Sort or filter by EPSS, family and exploit signals; click a row for details.",
            takeaway="Rank 1 is %s with score %.2f; %s of the Top 500 have a public exploit signal."
                     % (top["cve_id"], top["prediction_score"], _pct(sc["top500"]["any"] / n_top)),
            caveat="Rank is a prediction; none of these 2026 CVEs is confirmed in KEV.",
            data=dict(rank1=top["cve_id"], score=round(float(top["prediction_score"]), 2)))
    if target == "panel-cve":
        return dict(
            title="CVE details",
            shows="Everything known about one CVE: score, rank, EPSS, exploit signals, family and description.",
            read="Scores and ranks are model output; signals and descriptions are observed data.",
            takeaway="Scores here range up to %.2f and ranks run from 1 to %s." % (st["score_max"], _n(n_all)),
            caveat="A high rank is not proof of exploitation.",
            data=dict(max_score=round(st["score_max"], 2), total=n_all))
    if target == "panel-brief":
        return dict(
            title="AI brief",
            shows="A short analyst-style write-up of the selected CVE, generated by an AI model from its data.",
            read="It is labelled with its source; treat it as a draft summary and check it against the fields.",
            takeaway="The brief only restates the CVE's own data: rank, score, EPSS, signals and family.",
            caveat="AI text can be wrong, so check the grounding report.",
            data={})
    if target == "panel-grounding":
        return dict(
            title="Grounding report",
            shows="An automatic check of AI text against the real data.",
            read="It checks CVE IDs, EPSS values, Metasploit and Nuclei mentions, and claims that a CVE is already in KEV.",
            takeaway="A green result means every checkable claim matched the data.",
            caveat="It only checks claims it can match to the data, not everything the AI says.",
            data={})
    if target == "chart-galaxy":
        d = store.galaxy()
        sig = sum(1 for x in d["sig"] if x)
        return dict(
            title="Threat Galaxy",
            shows="Every scored CVE as a star. Colour is its family, size is EPSS, and the closer to the centre, the higher the current ranking method (%s) ranks it." % store.ranking_method,
            read="Bright stars with a glow are the Top 500; twinkling stars have public exploit code. Rings mark the Top 100, 250 and 500 cut-offs.",
            takeaway="%s CVEs are plotted; %d are in the Top 500 and %s (%s) have at least one public exploit signal."
                     % (_n(d["n"]), n_top, _n(sig), _pct(sig / d["n"])),
            caveat="Position is a rank from the current ranking method, not a calibrated probability and not confirmed exploitation.",
            data=dict(total=d["n"], top500=n_top, with_signal=sig, share_with_signal=_pct(sig / d["n"])))
    if target == "dash-kpis":
        return dict(
            title="Selection summary",
            shows="Live counts for whatever the filters on the left currently select: CVEs matching, how many are Top 500, share with exploit signals and median EPSS.",
            read="Change the scope, family, signals or minimum EPSS and the tiles update straight away.",
            takeaway="With no filters, %s CVEs are selected, %d of them in the Top 500; median EPSS is %.4f across all CVEs."
                     % (_n(n_all), n_top, st["epss_q_all"][0.5]),
            caveat="Counts are from the 2026 snapshot; ranks are predictions.",
            data=dict(total=n_all, top500=n_top, median_epss=round(st["epss_q_all"][0.5], 4)))
    if target == "chart-scatter":
        return dict(
            title="EPSS versus model score",
            shows="Each dot is a CVE: EPSS (log scale) across, ranking score up. All Top 500 CVEs plus a fixed 4,000-CVE sample of the rest.",
            read="Dots high on the chart are ranked high by the current method; dots to the right already have high EPSS.",
            takeaway="The Top 500 score at least %.2f, while the median score across all CVEs is %.2f."
                     % (st["score_min_top500"], st["score_q_all"][0.5]),
            caveat="The sample is for readability only; EPSS is a snapshot signal and the ranking score is not a probability.",
            data=dict(min_top500=round(st["score_min_top500"], 2), median_all=round(st["score_q_all"][0.5], 2)))
    if target == "chart-budget":
        parts = []
        for k in (100, 250, 500):
            b = _best(m, "hits_%d" % k)
            parts.append("K=%d: %s (%d)" % (k, b["model"], b["hits_%d" % k]))
        return dict(
            title="Patch budget",
            shows="How many real KEV additions each model catches if a team can only review the top K CVEs (historical backtest). Only budgets 100, 250 and 500 were measured.",
            read="Lines that climb faster catch more true positives for the same review effort.",
            takeaway="Leaders by budget - " + "; ".join(parts) + ". Tell ensemble: %d, %d and %d."
                     % (tell["hits_100"], tell["hits_250"], tell["hits_500"]),
            caveat="About %d positives only, so differences of a hit or two are noise." % o["positives_2025"],
            data=dict(leaders=parts))
    raise KeyError(target)


def _template(f: Dict[str, Any]) -> str:
    return ("**%s.** %s %s\n\n**Takeaway:** %s\n\n_Caveat: %s_"
            % (f["title"], f["shows"], f["read"], f["takeaway"], f["caveat"]))


_NUM = re.compile(r"\d[\d,]*\.?\d*")


def _numbers_ok(text: str, allowed_src: str) -> bool:
    allowed = {x.rstrip(".").replace(",", "") for x in _NUM.findall(allowed_src)}
    for x in _NUM.findall(text):
        x = x.rstrip(".").replace(",", "")
        if x not in allowed and not (x.isdigit() and int(x) < 10):
            return False
    return True


def _rephrase(f: Dict[str, Any]) -> Optional[str]:
    facts = json.dumps({k: f[k] for k in ("title", "shows", "read", "takeaway", "caveat", "data")})
    prompt = (
        "You are Tell's friendly pet mascot explaining a dashboard element. Using ONLY the JSON facts "
        "below, write a warm, conversational explanation in at most 90 words: what it shows, how to read it, "
        "the key takeaway, and the caveat. Copy numbers exactly as written; never invent numbers. Never say "
        "a 2026 CVE is in KEV. No emojis, no headings.\n\nFACTS: " + facts)
    data = gemini_call({"contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"temperature": 0.5, "maxOutputTokens": 600}})
    parts = data["candidates"][0]["content"].get("parts", [])
    text = "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
    if not text or len(text.split()) > 130 or not _numbers_ok(text, facts):
        return None
    return text


_NEEDS = {"kpi-hits500": "metrics", "kpi-lift": "metrics", "chart-hits": "metrics",
          "chart-precision-recall": "metrics", "table-auc": "metrics", "chart-family-size": "families",
          "chart-family-kev": "families", "chart-family-bubble": "families", "chart-budget": "metrics"}


def explain(store: Store, target: str, page: str) -> Optional[Dict[str, Any]]:
    """None if target unknown."""
    if target not in HIGHLIGHT_TARGETS:
        return None
    need = _NEEDS.get(target, "predictions")
    try:
        if not store.available(need):
            raise LookupError(need)
        f = _facts(store, target)
    except (LookupError, TypeError, KeyError, ValueError, IndexError, ZeroDivisionError) as e:
        if not isinstance(e, LookupError):
            logger.info("explain %s: data incomplete (%s)", target, type(e).__name__)
        need = next((d for d in (need, "predictions", "metrics", "families") if not store.available(d)), need)
        return {"title": "Not computed yet", "text": waiting_text(need), "source": "offline", "actions": []}
    out = {"title": f["title"], "text": _template(f), "source": "offline", "actions": []}
    if gemini_enabled():
        key = (target, os.environ.get("GEMINI_MODEL", ""))
        if key in _cache:
            return dict(_cache[key])
        try:
            text = _rephrase(f)
            if text:
                out["text"] = text
                out["source"] = "gemini"
                _cache[key] = dict(out)
        except Exception as e:
            logger.warning("gemini explain failed (%s); using template", type(e).__name__)
    return out
