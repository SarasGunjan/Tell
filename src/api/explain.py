"""Pet narration for highlight targets: grounded template, optionally rephrased by Gemini."""
import json
import logging
import os
import re
from typing import Any, Dict, Optional

from .chat import HIGHLIGHT_TARGETS, gemini_call, gemini_enabled
from .store import Store, waiting_text

logger = logging.getLogger("Tell.Explain")

CAVEAT_HIST = ("Observed (historical), population-weighted. Family rates describe past patterns, not the probability "
               "for any individual 2026 CVE.")
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
    rk = o["ranking"]
    rm = store.ranking_method
    n_all, n_top = o["total_cves"], o["top500_count"]

    if target == "kpi-candidates":
        return dict(
            title="Candidates ranked",
            shows="How many 2026 CVEs Tell ranked and how many it shortlisted.",
            read="The big number is the full ranked pool; the Top 500 is the slice analysts should look at first.",
            takeaway="%s CVEs were ranked across %d Granite families and %d were shortlisted (%s of the pool)."
                     % (_n(n_all), o["family_count"] or 0, n_top, _pct(n_top / n_all, 2)),
            caveat="The shortlist is a prediction of likely KEV entry, not a list of confirmed exploited CVEs.",
            data=dict(total=n_all, top500=n_top, families=o["family_count"]))
    if target == "kpi-hits500":
        b = o["best_hits_500"]
        return dict(
            title="Hits in the top 500",
            shows="How many KEV additions each approach caught in its top 500 (validation backtest).",
            read="A hit is a CVE that really entered KEV and was ranked within the first 500.",
            takeaway="%s caught %d hits in its top 500 versus %d for EPSS alone; the most hits belong to %s with %d."
                     % (rm, rk["hits_500"], o["epss_hits_500"], b["model"], b["hits_500"]),
            caveat="The validation cohort is small, so a few hits more or less swing these numbers a lot.",
            data=dict(ranking_hits=rk["hits_500"], epss_hits=o["epss_hits_500"], best_model=b["model"],
                      best_hits=b["hits_500"]))
    if target == "kpi-lift":
        lift = rk["hits_500"] / max(o["epss_hits_500"], 1)
        return dict(
            title="Lift over EPSS",
            shows="%s Hits@500 compared with the EPSS-only baseline." % rm,
            read="Lift is the ranking method's hits divided by the EPSS baseline's hits at the same cutoff.",
            takeaway="%s found %d hits vs %d for EPSS, about %.2fx as many." % (rm, rk["hits_500"], o["epss_hits_500"], lift),
            caveat="Hits come from a small validation cohort; treat the ratio as indicative, not precise.",
            data=dict(ranking_hits=rk["hits_500"], epss_hits=o["epss_hits_500"], lift=round(lift, 2)))
    if target == "chart-rank-epss":
        bands = store.distributions["rank_epss"]
        top, last = bands[0], bands[-1]
        return dict(
            title="EPSS by rank band",
            shows="Median EPSS for groups of ranks, from the Top 100 down to the tail.",
            read="Each bar is a band of ranks; a falling bar means higher-ranked CVEs tend to have higher EPSS.",
            takeaway="Median EPSS is %.4f for ranks %s and %.4f for ranks %s."
                     % (top["median_epss"], top["label"], last["median_epss"], last["label"]),
            caveat="The ranking is %s, which puts public exploit code first and uses EPSS to order within groups; it is not a calibrated probability." % rm,
            data=dict(top_band=top["label"], top_median=round(top["median_epss"], 4), last_band=last["label"],
                      last_median=round(last["median_epss"], 4)))
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
            title="Family sizes (2026)",
            shows="How many 2026 CVEs fall into each IBM Granite exploit family.",
            read="Longer bars are bigger families; families come from Granite embeddings of CVE descriptions.",
            takeaway="%s is largest with %s CVEs; %s is smallest with %s."
                     % (big["family_name"], _n(big["family_size"]), small["family_name"], _n(small["family_size"])),
            caveat="Size is not risk: a big family can have a low historical KEV rate.",
            data=dict(largest=big["family_name"], largest_size=big["family_size"],
                      smallest=small["family_name"], smallest_size=small["family_size"]))
    if target == "chart-family-kev":
        hi = max(fam, key=lambda f: f["population_lift"] or 0)
        lo = min(fam, key=lambda f: f["population_lift"] if f["population_lift"] is not None else 1e9)
        return dict(
            title="Historical population KEV lift by family",
            shows="How much more (or less) often each family's past CVEs entered CISA KEV than the average CVE, population-weighted.",
            read="A lift of 1.0x is the average CVE; taller bars mean the family was exploited more often in the past.",
            takeaway="%s has the highest lift (%.2fx, population KEV rate %s); %s the lowest (%.2fx)."
                     % (hi["family_name"], hi["population_lift"], _pct(hi["population_kev_rate"], 2),
                        lo["family_name"], lo["population_lift"]),
            caveat=CAVEAT_HIST,
            data=dict(highest=hi["family_name"], highest_lift=round(hi["population_lift"], 2),
                      lowest=lo["family_name"], lowest_lift=round(lo["population_lift"], 2)))
    if target == "chart-family-bubble":
        hi = max(fam, key=lambda f: f["historical_kev_count"] or 0)
        return dict(
            title="Family size, lift and KEV count",
            shows="Each bubble is a family: 2026 size across, historical population lift up, bubble size and colour by historical KEV count.",
            read="Look top-right for big families that were also exploited often in the past.",
            takeaway="%s has the most historical KEVs (%d) with a population lift of %.2fx and %s CVEs in 2026."
                     % (hi["family_name"], hi["historical_kev_count"], hi["population_lift"], _n(hi["family_size"])),
            caveat=CAVEAT_HIST,
            data=dict(family=hi["family_name"], kev_count=hi["historical_kev_count"], lift=round(hi["population_lift"], 2)))
    if target == "chart-hits":
        parts = []
        for k in (100, 250, 500):
            b = _best(m, "hits_%d" % k)
            parts.append("top %d: %s (%d)" % (k, b["model"], b["hits_%d" % k]))
        return dict(
            title="Hits at 100, 250 and 500",
            shows="Real KEV additions each model caught within its top 100, 250 and 500 (validation backtest).",
            read="Taller bars catch more true positives at the same cutoff.",
            takeaway="Leaders by cutoff - " + "; ".join(parts) + ".",
            caveat="Small validation cohort, so differences of a hit or two are noise.",
            data=dict(leaders=parts))
    if target == "table-ap":
        withap = [x for x in m if x.get("average_precision") is not None]
        if not withap:
            raise LookupError("metrics")
        b = _best(withap, "average_precision")
        return dict(
            title="Average precision",
            shows="Average precision (AP) for the models that report it; the rule-based rankings have none.",
            read="Higher is better; AP rewards putting real KEV additions near the top of the list.",
            takeaway="%s has the best AP (%.3f) among %d models that report it." % (b["model"], b["average_precision"], len(withap)),
            caveat="AP is shown only where Member 1 computed it; other rows are not computed.",
            data=dict(model=b["model"], ap=round(b["average_precision"], 3)))
    if target == "table-top500":
        top = store.df.iloc[0]
        return dict(
            title="Top 500 table",
            shows="The 500 CVEs ranked most likely to enter KEV by %s." % rm,
            read="Sort or filter by EPSS, family and exploit signals; click a row for details.",
            takeaway="Rank 1 is %s with EPSS %.4f; %s of the Top 500 have a public exploit signal."
                     % (top["cve_id"], top["epss"], _pct(sc["top500"]["any"] / n_top)),
            caveat="Rank is a prediction; none of these 2026 CVEs is confirmed in KEV.",
            data=dict(rank1=top["cve_id"], epss=round(float(top["epss"]), 4)))
    if target == "panel-cve":
        return dict(
            title="CVE details",
            shows="Everything known about one CVE: rank, EPSS, exploit signals, Granite extraction, family and description.",
            read="Rank is model output; signals and descriptions are observed data; Granite fields are extracted from the text.",
            takeaway="Ranks run from 1 to %s." % _n(n_all),
            caveat="A high rank is not proof of exploitation, and the family rate is a historical pattern, not this CVE's probability.",
            data=dict(total=n_all))
    if target == "panel-brief":
        return dict(
            title="AI brief",
            shows="A short analyst-style write-up of the selected CVE, generated by an AI model from its data.",
            read="It is labelled with its source; treat it as a draft summary and check it against the fields.",
            takeaway="The brief only restates the CVE's own data: rank, EPSS, signals and family.",
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
            shows="Every ranked CVE as a star. Colour is its Granite family, size is EPSS, and the closer to the centre, the higher the current ranking method (%s) ranks it." % rm,
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
            title="EPSS versus rank",
            shows="Each dot is a CVE: EPSS (log scale) across, rank up (rank 1 on top). All Top 500 CVEs plus a fixed 4,000-CVE sample of the rest.",
            read="Dots high on the chart are ranked high by %s; dots to the right already have high EPSS." % rm,
            takeaway="The median EPSS of the Top 500 is %.4f against %.4f for all CVEs."
                     % (st["epss_q_top500"][0.5], st["epss_q_all"][0.5]),
            caveat="The sample is for readability only; EPSS is a snapshot signal and rank is not a probability.",
            data=dict(median_top500=round(st["epss_q_top500"][0.5], 4), median_all=round(st["epss_q_all"][0.5], 4)))
    if target == "chart-budget":
        pb = store.patch_budget()
        budgets = sorted({r["budget"] for r in pb})
        parts = []
        for k in budgets:
            rows = [r for r in pb if r["budget"] == k and r["hits"] is not None]
            b = max(rows, key=lambda r: r["hits"])
            parts.append("K=%d: %s (%d)" % (k, b["model"], b["hits"]))
        return dict(
            title="Patch budget",
            shows="How many real KEV additions each model catches if a team can only review the top K CVEs (validation backtest). Only budgets %s were measured."
                  % ", ".join(str(int(k)) for k in budgets),
            read="Taller bars catch more true positives for the same review effort. These are three measured points, not a curve.",
            takeaway="Leaders by budget - " + "; ".join(parts) + ".",
            caveat="Small validation cohort, so differences of a hit or two are noise.",
            data=dict(leaders=parts))
    if target.startswith("research-"):
        return _research_facts(store, target)
    raise KeyError(target)


def _research_facts(store: Store, target: str) -> Dict[str, Any]:
    r = store.research
    cap = r["sample_caption"]
    if target == "research-concentration":
        c = r["concentration"]["data"]
        return dict(
            title="Where exploitation concentrates",
            shows="How much of all KEVs the three most-exploited Granite families hold compared with how many CVEs they contain.",
            read="Compare the two shares: when KEVs share is far above volume share, those families are over-represented.",
            takeaway="The top three families hold %s of KEVs but only %s of CVE volume, a %.2fx concentration (population-weighted)."
                     % (_pct(c["kev_share"]), _pct(c["population_volume_share"]), c["population_ratio"]),
            caveat="Observed (historical), population-weighted. " + cap,
            data=dict(kev_share=_pct(c["kev_share"]), volume_share=_pct(c["population_volume_share"]),
                      ratio=round(c["population_ratio"], 2)))
    if target == "research-temporal":
        t = r["temporal"]["data"]
        h = t["headline"]
        return dict(
            title="Out-of-time validation",
            shows="Families ranked on 2024 data only, then checked on 2025 CVEs the ranking never saw.",
            read="If the 2024 top three still hold a large share of 2025 KEVs, the pattern persisted.",
            takeaway="The 2024 top three families hold %s of 2025 KEVs with %s of 2025 CVEs, a %.2fx enrichment."
                     % (_pct(h["kev_share"]), _pct(h["volume_share"]), h["lift"]),
            caveat="Sample rates from the research cohort: " + cap,
            data=dict(kev_share=_pct(h["kev_share"]), volume_share=_pct(h["volume_share"]), lift=round(h["lift"], 2)))
    if target == "research-baselines":
        rows = r["baselines"]["data"]
        best = max((x for x in rows if x.get("population_top3_concentration_ratio") is not None),
                   key=lambda x: x["population_top3_concentration_ratio"])
        g = next((x for x in rows if "granite" in str(x["method"]).lower()), None)
        return dict(
            title="Granite versus simpler groupings",
            shows="How strongly each grouping method concentrates KEVs in its top three groups, with the share of CVEs each method could place.",
            read="Higher concentration ratio is better, but check coverage: a method that skips many CVEs looks sharper than it is.",
            takeaway="%s has the highest ratio (%.2fx); Granite embeddings score %.2fx with %s coverage."
                     % (best["method"], best["population_top3_concentration_ratio"],
                        g["population_top3_concentration_ratio"], _pct(g["non_missing_coverage"], 0)) if g else
                     "%s has the highest ratio (%.2fx)." % (best["method"], best["population_top3_concentration_ratio"]),
            caveat="Observed (historical), population-weighted. Some baselines do not cover every CVE.",
            data=dict(best=best["method"], best_ratio=round(best["population_top3_concentration_ratio"], 2)))
    if target == "research-cwe":
        rows = r["cwe"]["data"]["rows"]
        top = rows[0]
        return dict(
            title="CWE by family",
            shows="The twelve most common weakness types (CWE) in the research cohort and how each splits across Granite families.",
            read="Darker cells mean a larger share of that family's CVEs carry the CWE.",
            takeaway="%s is the most common CWE (%d cohort CVEs)." % (top["cwe_id"], top["total"]),
            caveat="Counts come from the 2,500-CVE research cohort, not the 2026 set.",
            data=dict(top_cwe=top["cwe_id"], count=top["total"]))
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
        "You are Telly, Tell's friendly astronaut guide, explaining a dashboard element. If you introduce yourself, say you are Telly (never Tell). Using ONLY the JSON facts "
        "below, write a warm, conversational explanation in at most 90 words: what it shows, how to read it, "
        "the key takeaway, and the caveat. Copy numbers exactly as written; never invent numbers. Never say "
        "a 2026 CVE is in KEV. No emojis, no headings.\n\nFACTS: " + facts)
    data = gemini_call({"contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"temperature": 0.5, "maxOutputTokens": 600,
                                             "thinkingConfig": {"thinkingBudget": 0}}})
    parts = data["candidates"][0]["content"].get("parts", [])
    text = "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
    if not text or len(text.split()) > 130 or not _numbers_ok(text, facts):
        return None
    return text


_NEEDS = {"kpi-hits500": "metrics", "kpi-lift": "metrics", "chart-hits": "metrics", "table-ap": "metrics",
          "chart-family-size": "families", "chart-family-kev": "families", "chart-family-bubble": "families",
          "chart-budget": "metrics", "research-concentration": "research", "research-temporal": "research",
          "research-baselines": "research", "research-cwe": "research"}


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
        need = next((d for d in (need, "predictions", "metrics", "families", "research") if not store.available(d)), need)
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
