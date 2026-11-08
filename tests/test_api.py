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

TOP = "CVE-2025-14558"  # rank 1 in results/predictions.csv


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
    assert "api_key" not in str(j).lower()


def test_overview(client):
    j = client.get("/api/overview").json()
    assert j["total_cves"] == 72670 and j["top500_count"] == 500 and j["family_count"] == 10
    assert j["positives_2025"] == 61
    assert j["best_hits_500"]["hits_500"] == 19 and j["tell"]["hits_500"] == 14
    assert j["epss_hits_500"] == 8
    assert set(j["signal_counts"]) == {"all", "top500"}
    assert j["signal_counts"]["all"]["any"] + j["signal_counts"]["all"]["none"] == 72670


def test_metrics(client):
    j = client.get("/api/metrics").json()
    assert len(j) == 6 and "roc_auc" in j[0]


def test_distributions(client):
    j = client.get("/api/distributions").json()
    for k in ("score_hist", "epss_hist"):
        h = j[k]
        assert len(h["edges"]) == 31 and len(h["all"]) == 30 and len(h["top500"]) == 30
        assert sum(h["all"]) == 72670 and sum(h["top500"]) == 500
    assert j["epss_hist"]["edges"][1] / j["epss_hist"]["edges"][0] == pytest.approx(
        j["epss_hist"]["edges"][2] / j["epss_hist"]["edges"][1])  # log spaced
    p = j["published_by_month"]
    assert sum(p["all"]) == 72670 and len(p["months"]) == len(p["top500"])
    assert sum(x["count"] for x in j["remote_local"]) == 72670
    assert sum(x["count"] for x in j["auth_required"]) == 72670


def test_families(client):
    fams = client.get("/api/families").json()
    assert len(fams) == 10 and fams[0]["family_id"] == "FAM-01" and isinstance(fams[0]["high_risk"], bool)
    d = client.get("/api/families/FAM-01").json()
    assert d["family"]["family_id"] == "FAM-01" and len(d["top_cves"]) == 20
    assert all(c["family_id"] == "FAM-01" for c in d["top_cves"])
    ranks = [c["rank"] for c in d["top_cves"]]
    assert ranks == sorted(ranks)
    assert 0 <= d["in_top500"] <= 500 and "any" in d["signal_counts"]
    assert client.get("/api/families/FAM-99").status_code == 404


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
    fam = client.get("/api/cves?family_id=FAM-01&scope=all&limit=5").json()
    assert all(i["family_id"] == "FAM-01" for i in fam["items"])
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
              "auth_required", "attack_type", "description", "cvss3_score", "attack_vector", "cwe_ids"):
        assert k in j
    assert j["rank"] == 1 and j["in_top500"] is True
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

    j = _chat(client, "which model has the best precision?")
    assert {"type": "navigate", "page": "models"} in j["actions"]

    j = _chat(client, "show me metasploit ones")
    assert {"type": "filter_top500", "signals": ["metasploit"]} in j["actions"]
    assert j["cves"] and all(c["metasploit"] for c in j["cves"])

    j = _chat(client, "top 3 riskiest")
    assert len(j["cves"]) == 3 and j["cves"][0]["cve_id"] == TOP

    for q in ("How does Tell compare to EPSS?", "Tell vs EPSS", "is the heuristic better than the ensemble?"):
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
    j = client.post("/api/explain", json={"target": "chart-family-kev", "page": "families"}).json()
    assert "Remote Code Execution" not in j["text"] or "%" in j["text"]
    assert client.post("/api/explain", json={"target": "nope", "page": "x"}).status_code == 404


def test_explain_gemini_rephrase_guard(client, monkeypatch):
    from src.api import explain as ex
    ex._cache.clear()
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    monkeypatch.setattr(ex, "gemini_call", lambda p, timeout=12: {"candidates": [{"content": {"parts": [
        {"text": "Invented 98765 hits!"}]}}]})
    assert client.post("/api/explain", json={"target": "kpi-hits500", "page": "o"}).json()["source"] == "offline"
    ex._cache.clear()


def test_unknown_api_route(client):
    assert client.get("/api/nope").status_code == 404


# ---------------------------------------------------------------- integration / drop-in data
import time  # noqa: E402

from src.api import store as store_mod  # noqa: E402
from src.api import validate as validate_mod  # noqa: E402

PRED = "cve_id,rank,{score},epss\nCVE-2026-0001,1,9.5,0.5\nCVE-2026-0002,2,8.0,0.1\nCVE-2026-0003,3,1.0,0.01\n"
METRICS = "model,hits_100,hits_250,hits_500\nTell ensemble,1,2,3\nEPSS baseline,0,1,1\n"
FAMS = "family_id,family_name,family_size\nFAM-01,RCE,2\n"
GRANITE = "cve_id,family_id,remote_local,auth_required\nCVE-2026-0001,FAM-01,REMOTE,NONE\n"


def _drop(d, **files):
    for n, txt in files.items():
        (d / n.replace("__", ".")).write_text(txt)


@pytest.fixture
def tell_dir(tmp_path, monkeypatch):
    rd = tmp_path / "res"
    rd.mkdir()
    (tmp_path / "data").mkdir()
    monkeypatch.setenv("TELL_RESULTS_DIR", str(rd))
    monkeypatch.setenv("THREATRANK_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("TELL_DATA_LABEL", "demo")
    monkeypatch.setattr(store_mod, "RELOAD_INTERVAL", 0)
    return rd


def test_alias_predictions_2026_score_column(client, tell_dir):
    _drop(tell_dir, predictions_2026__csv=PRED.format(score="score"), model_comparison__csv=METRICS)
    j = client.get("/api/cves", params={"scope": "all"}).json()
    assert j["total"] == 3 and j["items"][0]["prediction_score"] == 9.5
    assert j["items"][0]["exploitdb"] is None and j["items"][0]["family_id"] is None  # optional -> null
    assert len(client.get("/api/metrics").json()) == 2
    o = client.get("/api/overview").json()
    assert o["tell"]["hits_500"] == 3 and o["epss_hits_500"] == 1
    assert o["positives_2025"] is None  # no recall columns -> not invented
    assert o["signal_counts"]["all"]["any"] is None


def test_missing_metrics_and_families_degrade(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"))
    assert client.get("/api/metrics").json() == []
    o = client.get("/api/overview").json()
    assert o["tell"] is None and o["best_hits_500"] is None and o["family_count"] is None and o["total_cves"] == 3
    assert client.get("/api/families").json() == []
    assert client.get("/api/families/FAM-01").status_code == 404
    assert client.get("/api/cves/CVE-2026-0001").json()["family_name"] is None
    e = client.post("/api/explain", json={"target": "kpi-hits500", "page": "o"}).json()
    assert "waiting on Member 1's metrics.csv" in e["text"]
    c = client.post("/api/chat", json={"messages": [{"role": "user", "content": "compare the models"}]}).json()
    assert "waiting on Member 1's metrics.csv" in c["reply"]


def test_missing_predictions_degrade(client, tell_dir):
    j = client.get("/api/cves").json()
    assert j == {"total": 0, "items": []}
    o = client.get("/api/overview").json()
    assert o["total_cves"] is None and o["top500_count"] is None
    assert client.get("/api/distributions").status_code == 200
    s = client.get("/api/status").json()
    assert s["top500_source"] is None and s["counts"]["cves"] is None
    e = client.post("/api/explain", json={"target": "kpi-candidates", "page": "o"}).json()
    assert "waiting on Member 1's predictions.csv" in e["text"]
    c = client.post("/api/chat", json={"messages": [{"role": "user", "content": "CVE-2026-0001"}]}).json()
    assert "waiting on Member 1's predictions.csv" in c["reply"]


def test_families_from_granite_joined_with_summary(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"), granite_features__csv=GRANITE,
          family_summary__csv=FAMS)
    c = client.get("/api/cves/CVE-2026-0001").json()
    assert c["family_name"] == "RCE" and c["remote_local"] == "REMOTE" and c["attack_type"] is None
    assert client.get("/api/cves/CVE-2026-0002").json()["family_id"] is None
    f = client.get("/api/families").json()
    assert f[0]["family_name"] == "RCE" and f[0]["hist_kev_rate"] is None


def test_derived_top500_and_status_files(client, tell_dir):
    _drop(tell_dir, predictions__csv=PRED.format(score="prediction_score"), metrics__csv="model,hits_100\nx,1\n")
    s = client.get("/api/status").json()
    assert s["top500_source"] == "derived" and s["data_label"] == "demo"
    assert s["counts"]["top500"] == 3 and str(tell_dir.parent) not in str(s)
    by = {f["name"]: f for f in s["files"]}
    assert by["predictions.csv"]["present"] and by["predictions.csv"]["rows"] == 3
    assert by["predictions.csv"]["owner"] == "Member 1" and by["predictions.csv"]["modified"]
    assert by["metrics.csv"]["missing_required"] == ["hits_250", "hits_500"]
    assert by["family_summary.csv"]["present"] is False
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
    _drop(tell_dir, predictions__csv="cve_id,rank,prediction_score,epss\n" + "".join(
        "%s,%d,1.0,0.1\n" % (c, i + 1) for i, c in enumerate(ids)), metrics__csv=METRICS,
        family_summary__csv=FAMS, granite_features__csv=GRANITE, top500__csv="cve_id\n" + "\n".join(ids) + "\n")
    assert validate_mod.main(["--dir", str(tell_dir)]) == 0
    _drop(tell_dir, top500__csv="cve_id\n" + "\n".join(ids[:499] + ["CVE-9999-0001"]) + "\n")
    assert validate_mod.main(["--dir", str(tell_dir)]) == 1
    assert "not in predictions" in capsys.readouterr().out
    _drop(tell_dir, top500__csv="cve_id\n" + "\n".join(ids[:10]) + "\n")
    assert validate_mod.main(["--dir", str(tell_dir)]) == 1  # not 500 rows
    _drop(tell_dir, top500__csv="cve_id\n" + "\n".join(ids) + "\n", metrics__csv="model,hits_100\nx,1\n")
    assert validate_mod.main(["--dir", str(tell_dir)]) == 1  # missing required column
