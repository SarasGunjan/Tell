"""API tests (offline mode). Run: .venv/bin/python -m pytest tests/test_api.py"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.api import chat as chat_mod  # noqa: E402
from src.api.server import app  # noqa: E402

TOP = "CVE-2026-8037"  # rank 1 in results/predictions.csv


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    for k in ("GEMINI_API_KEY", "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD"):
        monkeypatch.delenv(k, raising=False)


def test_status(client):
    j = client.get("/api/status").json()
    assert j["gemini"] is False and j["snowflake"] is False
    assert j["counts"] == {"cves": 72670, "top500": 500, "families": 10}
    assert j["ranking_method"] == "Public Code + EPSS" and j["has_score"] is False
    assert "api_key" not in str(j).lower()
    by = {f["name"]: f for f in j["files"]}
    for n in ("predictions.csv", "top500.csv", "model_metrics.csv", "patch_budget.csv"):
        assert by[n]["owner"] == "Member 1" and by[n]["present"], n
    for n in ("benchmark_2026/families.csv", "benchmark_2026/granite_features.csv",
              "benchmark_2026/family_summary.csv", "granite/temporal_validation_2024_2025.csv",
              "granite/research_metrics.json"):
        assert by[n]["owner"] == "Member 2" and by[n]["present"], n
    assert by["benchmark_2026/granite_features.csv"]["missing_required"] == []


def test_overview(client):
    j = client.get("/api/overview").json()
    assert j["total_cves"] == 72670 and j["top500_count"] == 500 and j["family_count"] == 10
    assert j["best_hits_500"]["hits_500"] == 18 and j["ranking"]["model"] == "Public Code + EPSS"
    assert j["epss_hits_500"] == 8 and j["lift_over_epss"] == pytest.approx(2.25)
    assert "tell" not in j and "positives_2025" not in j
    assert set(j["signal_counts"]) == {"all", "top500"}
    assert j["signal_counts"]["all"]["any"] + j["signal_counts"]["all"]["none"] == 72670


def test_metrics(client):
    j = client.get("/api/metrics").json()
    assert [m["model"] for m in j] == ["EPSS", "Public Code + EPSS", "Logistic Regression", "LightGBM"]
    assert j[0]["average_precision"] is None and j[3]["average_precision"] > 0
    assert j[1]["precision_100"] is None  # absent columns stay null, never invented


def test_patch_budget(client):
    j = client.get("/api/patch-budget").json()
    assert len(j) == 12 and {r["budget"] for r in j} == {100, 250, 500}
    assert all(r["derived"] is False for r in j)
    pc = {r["budget"]: r["hits"] for r in j if r["model"] == "Public Code + EPSS"}
    assert pc == {100: 8, 250: 15, 500: 18}


def test_distributions(client):
    j = client.get("/api/distributions").json()
    assert j["score_hist"] is None  # rank-only predictions: no score distribution
    for k in ("epss_hist",):
        h = j[k]
        assert len(h["edges"]) == 31 and len(h["all"]) == 30 and len(h["top500"]) == 30
        assert sum(h["all"]) == 72670 and sum(h["top500"]) == 500
    re_ = j["rank_epss"]
    assert sum(b["count"] for b in re_) == 72670 and re_[0]["from"] == 1 and re_[0]["to"] == 100
    assert j["epss_hist"]["edges"][1] / j["epss_hist"]["edges"][0] == pytest.approx(
        j["epss_hist"]["edges"][2] / j["epss_hist"]["edges"][1])  # log spaced
    p = j["published_by_month"]
    assert sum(p["all"]) == 72670 and len(p["months"]) == len(p["top500"])
    assert sum(x["count"] for x in j["remote_local"]) == 72670
    assert sum(x["count"] for x in j["auth_required"]) == 72670


def test_families(client):
    fams = client.get("/api/families").json()
    assert [f["family_id"] for f in fams] == [str(i) for i in range(10)]
    f7 = fams[7]
    assert f7["family_name"] == "Privilege Escalation" and f7["population_lift"] == pytest.approx(3.338)
    assert f7["population_kev_rate"] == pytest.approx(0.012011) and f7["historical_kev_count"] == 66
    assert f7["family_size"] == 3907 and f7["high_risk"] is None  # no column, no invented threshold
    assert f7["ci_95_low"] is not None and len(f7["representative_cves"]) == 3 and f7["top_characteristics"]
    assert sum(f["family_size"] for f in fams) == 72670 and sum(f["in_top500"] for f in fams) == 500
    d = client.get("/api/families/3").json()
    assert d["family"]["family_id"] == "3" and len(d["top_cves"]) == 20
    assert all(c["family_id"] == "3" for c in d["top_cves"])
    ranks = [c["rank"] for c in d["top_cves"]]
    assert ranks == sorted(ranks)
    assert 0 <= d["in_top500"] <= 500 and "any" in d["signal_counts"]
    assert sum(x["count"] for x in d["attack_surface"]) == 9162
    assert sum(x["count"] for x in d["vulnerability_type"]) == 9162
    assert d["historical_examples"] and d["caveat"] is None
    assert client.get("/api/families/99").status_code == 404


def test_family8_caveat(client):
    d = client.get("/api/families/8").json()
    assert "browser-engine" in d["caveat"] and d["family"]["caveat"] == d["caveat"]
    assert d["attack_surface"]  # breakdown comes from the data
    assert [f["caveat"] for f in client.get("/api/families").json()].count(None) == 9


def test_cves_search_filter_paging(client):
    j = client.get("/api/cves").json()
    assert j["total"] == 500 and len(j["items"]) == 50 and j["items"][0]["cve_id"] == TOP
    assert all(i["in_top500"] for i in j["items"])
    p2 = client.get("/api/cves?limit=10&offset=10").json()
    assert [i["rank"] for i in p2["items"]] == list(range(11, 21))
    assert client.get("/api/cves?q=cve-2025-14558").json()["total"] == 1
    allc = client.get("/api/cves?scope=all&limit=1").json()
    assert allc["total"] == 72670
    sig = client.get("/api/cves?signals=metasploit,exploitdb&scope=all&limit=200").json()
    assert sig["total"] > 0 and all(i["metasploit"] and i["exploitdb"] for i in sig["items"])
    by_epss = client.get("/api/cves?sort=epss&limit=5").json()["items"]
    assert [i["epss"] for i in by_epss] == sorted([i["epss"] for i in by_epss], reverse=True)
    me = client.get("/api/cves?min_epss=0.2&scope=all&limit=200").json()
    assert me["total"] > 0 and all(i["epss"] >= 0.2 for i in me["items"])
    fam = client.get("/api/cves?family_id=3&scope=all&limit=5").json()
    assert fam["items"] and all(i["family_id"] == "3" for i in fam["items"])
    lean = fam["items"][0]
    assert "vulnerability_type" in lean and "remote_local" in lean and "evidence" not in lean and "attack_surface" not in lean
    # validation
    assert client.get("/api/cves?limit=201").status_code == 422
    assert client.get("/api/cves?offset=-1").status_code == 422
    assert client.get("/api/cves?signals=bogus").status_code == 422
    assert client.get("/api/cves?scope=nope").status_code == 422


def test_cve_detail(client):
    r = client.get("/api/cves/" + TOP)
    assert r.status_code == 200
    j = r.json()
    for k in ("cve_id", "rank", "prediction_score", "epss", "exploitdb", "metasploit", "nuclei", "poc_github",
              "published", "snapshot_month", "in_top500", "family_id", "family_name", "remote_local",
              "auth_required", "vulnerability_type", "attack_surface", "product_or_vendor", "extraction_method",
              "extraction_confidence", "evidence", "description", "cvss3_score", "attack_vector", "cwe_ids"):
        assert k in j
    assert j["rank"] == 1 and j["in_top500"] is True and j["prediction_score"] is None  # never fabricated
    assert j["family_id"] == "3" and j["extraction_method"] and j["extraction_source"].startswith("IBM Granite")
    assert client.get("/api/cves/CVE-2099-99999").status_code == 404
    assert client.get("/api/cves/not-a-cve").status_code == 422


def test_brief_offline(client):
    j = client.post("/api/brief", json={"cve_id": TOP}).json()
    assert TOP in j["content"] and "Offline" in j["source"]
    assert j["grounding"]["target_cve"] == TOP
    assert client.post("/api/brief", json={"cve_id": "CVE-2099-99999"}).status_code == 404
    assert client.post("/api/brief", json={"cve_id": "bad"}).status_code == 422


def test_ask_offline(client):
    j = client.post("/api/ask", json={"cve_id": TOP, "question": "Why is it ranked high?"}).json()
    assert TOP in j["response"] and "Grounded" in j["source"]
    assert "grounding" in j
    assert client.post("/api/ask", json={"cve_id": TOP, "question": "x" * 1001}).status_code == 422


def _chat(client, text, **kw):
    r = client.post("/api/chat", json=dict({"messages": [{"role": "user", "content": text}],
                                            "page": "overview"}, **kw))
    assert r.status_code == 200, r.text
    return r.json()


def test_chat_offline_intents(client):
    j = _chat(client, "Tell me about " + TOP)
    assert j["source"] == "offline" and TOP in j["reply"] and "grounding" in j
    assert {"type": "open_cve", "cve_id": TOP} in j["actions"]
    assert j["cves"][0]["cve_id"] == TOP

    j = _chat(client, "what about sql injection?")
    assert {"type": "navigate", "page": "families"} in j["actions"]
    assert any(a["type"] == "highlight" for a in j["actions"])
    j = _chat(client, "tell me about family 8")
    assert "browser-engine" in j["reply"] and "not the probability" in j["reply"]

    for q in ("what did the research discover?", "any findings?", "out-of-time validation"):
        j = _chat(client, q)
        assert {"type": "navigate", "page": "research"} in j["actions"], q
        assert "64.2%" in j["reply"] and "1.93x" in j["reply"] and "12.68%" in j["reply"], q

    j = _chat(client, "which model has the best precision?")
    assert {"type": "navigate", "page": "models"} in j["actions"]

    j = _chat(client, "show me metasploit ones")
    assert {"type": "filter_top500", "signals": ["metasploit"]} in j["actions"]
    assert j["cves"] and all(c["metasploit"] for c in j["cves"])

    j = _chat(client, "top 3 riskiest")
    assert len(j["cves"]) == 3 and j["cves"][0]["cve_id"] == TOP

    for q in ("How does Tell compare to EPSS?", "Tell vs EPSS", "is the heuristic better than LightGBM?"):
        j = _chat(client, q)
        assert {"type": "navigate", "page": "models"} in j["actions"], q
        assert {"type": "highlight", "target": "chart-hits"} in j["actions"], q
        assert "EPSS" in j["reply"] and "Hits@500" in j["reply"] and j["cves"] == [], q

    # Chat starters must all get a real offline answer (not help text).
    for q, page in (("Why is %s ranked #1?" % TOP, None), ("Explain " + TOP, None),
                    ("Which model has the best hits and precision?", "models"),
                    ("Show top CVEs with Metasploit modules", "top500"), ("Top 5 riskiest", "top500")):
        j = _chat(client, q)
        assert "running offline" not in j["reply"], q
        assert j["actions"], q
        if page:
            assert {"type": "navigate", "page": page} in j["actions"], q

    j = _chat(client, "hello there")
    assert j["actions"] == [] and "offline" in j["reply"]
    assert j["cves"] == []  # help text must not attach an unrelated CVE card


def test_chat_validation(client):
    bad = [
        {"messages": [], "page": "x"},
        {"messages": [{"role": "user", "content": "x" * 2001}]},
        {"messages": [{"role": "user", "content": "hi"}] * 21},
        {"messages": [{"role": "system", "content": "hi"}]},
    ]
    for b in bad:
        assert client.post("/api/chat", json=b).status_code == 422


def test_chat_gemini_loop_and_failure(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    calls = []

    def fake(payload, timeout=12):
        calls.append(payload)
        if len(calls) == 1:
            return {"candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": "get_cve", "args": {"cve_id": TOP}}},
                {"functionCall": {"name": "navigate", "args": {"page": "top500"}}}]}}]}
        fr = payload["contents"][-1]["parts"][0]["functionResponse"]["response"]["result"]
        assert fr["cve_id"] == TOP
        return {"candidates": [{"content": {"role": "model", "parts": [
            {"text": "%s is ranked #%d. It is a prediction, not confirmed." % (TOP, fr["rank"])}]}}]}

    monkeypatch.setattr(chat_mod, "gemini_call", fake)
    j = _chat(client, "tell me about the top cve")
    assert j["source"] == "gemini" and "#1" in j["reply"]
    assert {"type": "navigate", "page": "top500"} in j["actions"] and j["cves"][0]["cve_id"] == TOP

    def boom(payload, timeout=12):
        raise RuntimeError("down")

    monkeypatch.setattr(chat_mod, "gemini_call", boom)
    j = _chat(client, "top 2")
    assert j["source"] == "offline" and len(j["cves"]) == 2


def test_explain_all_targets_offline(client):
    for t in chat_mod.HIGHLIGHT_TARGETS:
        r = client.post("/api/explain", json={"target": t, "page": "overview"})
        assert r.status_code == 200, t
        j = r.json()
        assert j["source"] == "offline" and j["title"] and j["text"] and j["actions"] == []
    j = client.post("/api/explain", json={"target": "research-temporal", "page": "research"}).json()
    assert "64.2%" in j["text"] and "33.3%" in j["text"] and "1.93x" in j["text"]
    j = client.post("/api/explain", json={"target": "chart-family-kev", "page": "families"}).json()
    assert "Privilege Escalation" in j["text"] and "not the probability" in j["text"]
    assert "Tell ensemble" not in client.post("/api/explain", json={"target": "kpi-hits500", "page": "o"}).json()["text"]
    assert client.post("/api/explain", json={"target": "nope", "page": "x"}).status_code == 404


def test_explain_gemini_rephrase_guard(client, monkeypatch):
    from src.api import explain as ex
    ex._cache.clear()
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    monkeypatch.setattr(ex, "gemini_call", lambda p, timeout=12: {"candidates": [{"content": {"parts": [
        {"text": "Invented 98765 hits!"}]}}]})
    assert client.post("/api/explain", json={"target": "kpi-hits500", "page": "o"}).json()["source"] == "offline"
    ex._cache.clear()


def test_galaxy_shape_and_bitmask(client):
    j = client.get("/api/galaxy").json()
    assert j["available"] is True and j["n"] == 72670
    for k in ("ids", "rank", "epss", "fam", "sig", "top500"):
        assert len(j[k]) == j["n"], k
    assert "score" not in j  # rank-only predictions
    assert j["ids"][0] == TOP and j["rank"] == sorted(j["rank"]) and j["rank"][0] == 1
    assert sum(j["top500"]) == 500 and all(i == -1 or 0 <= i < len(j["families"]) for i in j["fam"])
    assert [f["family_id"] for f in j["families"]] == [str(i) for i in range(10)]
    assert set(j["families"][0]) == {"family_id", "family_name", "high_risk"}
    assert j["ranking_method"] == "Public Code + EPSS"
    c = client.get("/api/cves/" + TOP).json()
    want = c["exploitdb"] * 1 + c["metasploit"] * 2 + c["nuclei"] * 4 + c["poc_github"] * 8
    assert j["sig"][0] == want and want > 0
    assert j["families"][j["fam"][0]]["family_id"] == c["family_id"]
    assert "x" not in j and "y" not in j  # real results carry no embedding columns


def test_research(client):
    j = client.get("/api/research").json()
    assert j["available"] is True and j["cohort"]["label"] == "Historical research cohort (2,500 CVEs, 2024\u20132025)"
    assert j["cohort"]["kev_total"] == 317 and j["cohort"]["silhouette_cosine"] == pytest.approx(0.0804)
    assert "12.68% sample base rate" in j["sample_caption"] and "base rate 0.36%" in j["sample_caption"]
    assert len(j["families"]["data"]) == 10 and len(j["baselines"]["data"]) == 5
    for blk in ("families", "concentration", "baselines", "temporal", "cwe"):
        assert j[blk]["provenance"] and j[blk]["cohort_label"] == j["cohort"]["label"], blk
    h = j["temporal"]["data"]["headline"]
    assert h["top3_family_ids"] == ["5", "7", "9"] and h["matches_reported"] is True
    assert h["kev_share"] == pytest.approx(0.6424, abs=1e-4) and h["volume_share"] == pytest.approx(0.3328, abs=1e-4)
    assert h["lift"] == pytest.approx(1.93, abs=0.005)
    c = j["concentration"]["data"]
    assert c["kev_share"] == pytest.approx(0.6467) and c["population_volume_share"] == pytest.approx(0.3145)
    assert c["population_ratio"] == pytest.approx(2.06)
    cw = j["cwe"]["data"]
    assert len(cw["rows"]) == 12 and cw["rows"][0]["cwe_id"] == "CWE-79" and "UNASSIGNED" not in str(cw["rows"])
    assert "5" in cw["rows"][0]["cells"]


def test_temporal_headline_computation(client, tell_dir):
    gran = tell_dir.parent / "gran"
    (gran).mkdir(exist_ok=True)
    (gran / "temporal_validation_2024_2025.csv").write_text(
        "family_id,train_2024_n,train_2024_kev,train_2024_rate,train_2024_lift,val_2025_n,val_2025_kev,val_2025_rate,val_2025_lift\n"
        "0,10,5,0.5,1,10,6,0.6,1\n1,10,4,0.4,1,10,2,0.2,1\n2,10,3,0.3,1,10,1,0.1,1\n3,10,0,0.0,1,10,1,0.1,1\n")
    j = client.get("/api/research").json()
    h = j["temporal"]["data"]["headline"]
    assert h["top3_family_ids"] == ["0", "1", "2"]
    assert h["kev_share"] == pytest.approx(9 / 10) and h["volume_share"] == pytest.approx(30 / 40)
    assert h["lift"] == pytest.approx(1.2) and h["matches_reported"] is None  # no research_metrics.json
    assert j["concentration"] is None and j["cwe"] is None  # blocks without files stay null
    assert j["cohort"]["label"].startswith("Historical research cohort (n/a CVEs")


def test_unknown_api_route(client):
    assert client.get("/api/nope").status_code == 404


# ---------------------------------------------------------------- integration / drop-in data
import time  # noqa: E402

from src.api import store as store_mod  # noqa: E402
from src.api import validate as validate_mod  # noqa: E402

PRED = "cve_id,rank,{score},epss\nCVE-2026-0001,1,9.5,0.5\nCVE-2026-0002,2,8.0,0.1\nCVE-2026-0003,3,1.0,0.01\n"
PRED_NS = "cve_id,rank,epss,ranking_method\nCVE-2026-0001,1,0.5,public_code_then_epss\nCVE-2026-0002,2,0.1,public_code_then_epss\nCVE-2026-0003,3,0.01,public_code_then_epss\n"
METRICS = "model,hits_100,hits_250,hits_500\nPublic Code + EPSS,1,2,3\nEPSS,0,1,1\n"
FAMS = "family_id,family_name,family_size\n0,RCE,2\n"
GRANITE = "cve_id,family_id,remote_local,auth_required\nCVE-2026-0001,0,remote,no\n"


def _drop(d, **files):
    for n, txt in files.items():
        (d / n.replace("__", ".")).write_text(txt)


def _bench(d, **files):  # Member 2 benchmark_2026 files live beside the results dir in the fixture
    _drop(d.parent / "gran" / "benchmark_2026", **files)


@pytest.fixture
def tell_dir(tmp_path, monkeypatch):
    rd = tmp_path / "res"
    rd.mkdir()
    (tmp_path / "data").mkdir()
    monkeypatch.setenv("TELL_RESULTS_DIR", str(rd))
    monkeypatch.setenv("TELL_GRANITE_DIR", str(tmp_path / "gran"))
    (tmp_path / "gran" / "benchmark_2026").mkdir(parents=True)
    monkeypatch.setenv("THREATRANK_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("TELL_DATA_LABEL", "demo")
    monkeypatch.setattr(store_mod, "RELOAD_INTERVAL", 0)
    return rd


def test_alias_predictions_2026_score_column(client, tell_dir):
    _drop(tell_dir, predictions_2026__csv=PRED.format(score="score"), model_comparison__csv=METRICS)
    j = client.get("/api/cves", params={"scope": "all"}).json()
    assert j["total"] == 3 and j["items"][0]["prediction_score"] == 9.5  # a score is shown only when present
    assert j["items"][0]["exploitdb"] is None and j["items"][0]["family_id"] is None  # optional -> null
    assert len(client.get("/api/metrics").json()) == 2
    o = client.get("/api/overview").json()
    assert o["ranking"]["hits_500"] == 3 and o["epss_hits_500"] == 1 and o["has_score"] is True
    assert o["lift_over_epss"] == pytest.approx(3.0)
    assert o["signal_counts"]["all"]["any"] is None
    assert client.get("/api/distributions").json()["score_hist"] is not None


def test_scoreless_predictions(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED_NS, model_metrics__csv=METRICS)
    s = client.get("/api/status").json()
    assert s["has_score"] is False and s["ranking_method"] == "Public Code + EPSS"
    c = client.get("/api/cves/CVE-2026-0001").json()
    assert c["prediction_score"] is None
    j = client.get("/api/cves?scope=all&sort=score").json()  # no score -> falls back to rank order
    assert [i["rank"] for i in j["items"]] == [1, 2, 3]
    g = client.get("/api/galaxy").json()
    assert g["available"] and "score" not in g
    assert client.get("/api/distributions").json()["score_hist"] is None


def test_metrics_alias_preference(client, tell_dir):
    stale = "model,hits_100,hits_250,hits_500\nTell Ensemble,9,9,9\n"
    _drop(tell_dir, predictions__csv=PRED_NS, metrics__csv=stale)
    assert [m["model"] for m in client.get("/api/metrics").json()] == ["Tell Ensemble"]
    _drop(tell_dir, model_metrics__csv=METRICS)  # model_metrics.csv beats a stale metrics.csv
    assert [m["model"] for m in client.get("/api/metrics").json()] == ["Public Code + EPSS", "EPSS"]
    assert client.get("/api/status").json()["metrics_source"] == "model_metrics.csv"


def test_patch_budget_file_and_derived(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED_NS, model_metrics__csv=METRICS)
    j = client.get("/api/patch-budget").json()
    assert len(j) == 6 and all(r["derived"] is True for r in j)
    _drop(tell_dir, patch_budget__csv="model,budget,hits\nEPSS,100,4\n")
    j = client.get("/api/patch-budget").json()
    assert j == [{"model": "EPSS", "budget": 100, "hits": 4, "derived": False}]


def test_ranking_row_and_lift_are_generic(client, tell_dir, monkeypatch):
    _drop(tell_dir, predictions__csv=PRED_NS, model_metrics__csv="model,hits_100,hits_250,hits_500\nEPSS,1,1,2\nFoo,1,1,6\n")
    monkeypatch.setenv("TELL_RANKING_METHOD", "Foo")
    o = client.get("/api/overview").json()
    assert o["ranking"]["model"] == "Foo" and o["lift_over_epss"] == pytest.approx(3.0)


def test_missing_metrics_and_families_degrade(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"))
    assert client.get("/api/metrics").json() == []
    o = client.get("/api/overview").json()
    assert o["ranking"] is None and o["best_hits_500"] is None and o["family_count"] is None and o["total_cves"] == 3
    assert client.get("/api/families").json() == []
    assert client.get("/api/families/0").status_code == 404
    assert client.get("/api/research").json()["available"] is False
    assert client.get("/api/patch-budget").json() == []


def test_galaxy_waiting_without_predictions(client, tell_dir):
    j = client.get("/api/galaxy").json()
    assert j["available"] is False and "predictions.csv" in j["waiting"]


def test_galaxy_missing_signals_flagged(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"))
    j = client.get("/api/galaxy").json()
    assert j["n"] == 3 and j["sig"] == [0, 0, 0] and j["signals_available"] == [] and j["fam"] == [-1, -1, -1]


def test_galaxy_embedding_optional(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"))
    _bench(tell_dir, granite_features__csv=GRANITE)
    assert "x" not in client.get("/api/galaxy").json()
    g = GRANITE.replace("auth_required\n", "auth_required,umap_x,umap_y\n").replace("no\n", "no,0.5,-1.25\n")
    _bench(tell_dir, granite_features__csv=g)
    j = client.get("/api/galaxy").json()
    assert j["x"] == [0.5, None, None] and j["y"] == [-1.25, None, None]
    assert "emb_x" not in client.get("/api/cves/CVE-2026-0001").json()


def test_families_from_granite_joined_with_summary(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"))
    _bench(tell_dir, granite_features__csv=GRANITE, family_summary__csv=FAMS)
    c = client.get("/api/cves/CVE-2026-0001").json()
    assert c["family_id"] == "0" and c["family_name"] == "RCE" and c["remote_local"] == "remote"
    assert c["vulnerability_type"] is None and c["extraction_source"] is None
    assert client.get("/api/cves/CVE-2026-0002").json()["family_id"] is None
    f = client.get("/api/families").json()
    assert f[0]["family_name"] == "RCE" and f[0]["population_kev_rate"] is None and f[0]["representative_cves"] == []
    # old-style location (results/) still works when no benchmark files exist
    (tell_dir.parent / "gran" / "benchmark_2026" / "granite_features.csv").unlink()
    _drop(tell_dir, granite_features__csv=GRANITE)
    assert client.get("/api/cves/CVE-2026-0001").json()["family_id"] == "0"


def test_text_family_ids_still_work(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"))
    _bench(tell_dir, granite_features__csv=GRANITE.replace(",0,", ",FAM-01,"),
           family_summary__csv=FAMS.replace("0,RCE", "FAM-01,RCE"))
    assert client.get("/api/cves/CVE-2026-0001").json()["family_id"] == "FAM-01"
    assert client.get("/api/families/FAM-01").json()["family"]["family_name"] == "RCE"


def test_family_caveat_flag_only_for_8(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"))
    _bench(tell_dir, granite_features__csv=GRANITE.replace(",0,", ",8,"),
           family_summary__csv="family_id,family_name,family_size\n8,Mixed,1\n7,Other,1\n")
    f = {x["family_id"]: x for x in client.get("/api/families").json()}
    assert f["8"]["caveat"] and f["7"]["caveat"] is None


def test_derived_top500_and_status_files(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"), metrics__csv="model,hits_100\nx,1\n")
    _bench(tell_dir, granite_features__csv=GRANITE)
    s = client.get("/api/status").json()
    assert s["top500_source"] == "derived" and s["data_label"] == "demo"
    assert s["counts"]["top500"] == 3 and str(tell_dir.parent) not in str(s)
    by = {f["name"]: f for f in s["files"]}
    assert by["predictions.csv"]["present"] and by["predictions.csv"]["rows"] == 3
    assert by["predictions.csv"]["owner"] == "Member 1" and by["predictions.csv"]["modified"]
    assert by["metrics.csv"]["missing_required"] == ["hits_250", "hits_500"]
    assert by["benchmark_2026/family_summary.csv"]["present"] is False
    assert by["benchmark_2026/granite_features.csv"]["owner"] == "Member 2"
    assert client.get("/api/metrics").json() == []  # unavailable, API still up
    _drop(tell_dir, top500__csv="cve_id\nCVE-2026-0002\n")
    s = client.get("/api/status").json()
    assert s["top500_source"] == "file" and s["counts"]["top500"] == 1


def test_data_label_env(client, tell_dir, monkeypatch):
    monkeypatch.setenv("TELL_DATA_LABEL", "final")
    assert client.get("/api/status").json()["data_label"] == "final"
    monkeypatch.setenv("TELL_DATA_LABEL", "bogus")
    assert client.get("/api/status").json()["data_label"] == "demo"


def test_hot_reload_picks_up_new_file(client, tell_dir):
    assert client.get("/api/metrics").json() == []
    _drop(tell_dir, metrics__csv=METRICS)
    assert len(client.get("/api/metrics").json()) == 2
    time.sleep(0.02)
    _drop(tell_dir, metrics__csv=METRICS + "Third,0,0,0\n")
    assert len(client.get("/api/metrics").json()) == 3


def test_reload_failure_keeps_old_store(client, tell_dir, monkeypatch):
    _drop(tell_dir, metrics__csv=METRICS)
    assert len(client.get("/api/metrics").json()) == 2

    def boom(*a, **k):
        raise RuntimeError("bad")

    monkeypatch.setattr(store_mod, "Store", boom)
    _drop(tell_dir, metrics__csv=METRICS + "Third,0,0,0\n")
    assert len(client.get("/api/metrics").json()) == 2


def test_validate_exit_codes(tell_dir, capsys):
    ids = ["CVE-2026-%04d" % i for i in range(500)]
    _drop(tell_dir, predictions__csv="cve_id,rank,epss\n" + "".join(
        "%s,%d,0.1\n" % (c, i + 1) for i, c in enumerate(ids)), model_metrics__csv=METRICS,
        top500__csv="cve_id\n" + "\n".join(ids) + "\n")
    gf = "cve_id,family_id,remote_local,auth_required\n" + "".join("%s,0,remote,no\n" % c for c in ids)
    _bench(tell_dir, family_summary__csv="family_id,family_name,family_size\n0,RCE,500\n", granite_features__csv=gf)
    gran = str(tell_dir.parent / "gran")
    assert validate_mod.main(["--dir", str(tell_dir), "--granite-dir", gran]) == 0
    _drop(tell_dir, top500__csv="cve_id\n" + "\n".join(ids[:499] + ["CVE-9999-0001"]) + "\n")
    assert validate_mod.main(["--dir", str(tell_dir), "--granite-dir", gran]) == 1
    assert "not in predictions" in capsys.readouterr().out
    _drop(tell_dir, top500__csv="cve_id\n" + "\n".join(ids[:10]) + "\n")
    assert validate_mod.main(["--dir", str(tell_dir), "--granite-dir", gran]) == 1  # not 500 rows
    _drop(tell_dir, top500__csv="cve_id\n" + "\n".join(ids) + "\n", model_metrics__csv="model,hits_100\nx,1\n")
    assert validate_mod.main(["--dir", str(tell_dir), "--granite-dir", gran]) == 1  # missing required column
    _drop(tell_dir, model_metrics__csv=METRICS)
    _bench(tell_dir, granite_features__csv=gf.replace("CVE-2026-0499,0", "CVE-2026-0499,5"))  # id 5 has no summary
    assert validate_mod.main(["--dir", str(tell_dir), "--granite-dir", gran]) == 1
    assert "without summary" in capsys.readouterr().out
