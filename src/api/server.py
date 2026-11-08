"""Tell FastAPI app. Run: uvicorn src.api.server:app --port 8000"""
import logging
import mimetypes
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Path as PathParam, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# Slim images lack /etc/mime.types; without this the pet sprite is served as
# application/octet-stream, which nosniff can block.
mimetypes.add_type("image/webp", ".webp")

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # allow `uvicorn src.api.server:app` from anywhere
    sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from src.ai import EvidenceGroundingEngine, GeminiBriefGenerator, SnowflakeCortexAssistant  # noqa: E402
from src.api import chat as chat_mod  # noqa: E402
from src.api.explain import explain as explain_target  # noqa: E402
from src.api.store import SIGNALS, get_store, waiting_text  # noqa: E402

logger = logging.getLogger("Tell.API")
CVE_PATTERN = r"^CVE-\d{4}-\d{4,7}$"
DIST = ROOT / "web" / "dist"

_engine = None  # type: Optional[EvidenceGroundingEngine]
_engine_for = None  # the Store the engine was built from; rebuilt after a hot reload


def engine() -> EvidenceGroundingEngine:
    global _engine, _engine_for
    s = get_store()
    if _engine is None or _engine_for is not s:
        _engine = EvidenceGroundingEngine(s.df[["cve_id", "rank", "epss", "metasploit", "nuclei"]])
        _engine_for = s
    return _engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_store()
    engine()
    yield


app = FastAPI(title="Tell API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1000)


# ------------------------------------------------------------------ models
class BriefReq(BaseModel):
    cve_id: str = Field(..., pattern=CVE_PATTERN)


class AskReq(BaseModel):
    cve_id: str = Field(..., pattern=CVE_PATTERN)
    question: str = Field(..., min_length=1, max_length=1000)


class Msg(BaseModel):
    role: str = Field(..., pattern="^(user|assistant)$")
    content: str = Field(..., min_length=1, max_length=2000)


class ChatReq(BaseModel):
    messages: List[Msg] = Field(..., min_length=1, max_length=20)
    page: str = Field("overview", max_length=40)
    selection: Optional[Any] = None


class ExplainReq(BaseModel):
    target: str = Field(..., max_length=60)
    page: str = Field("overview", max_length=40)


# ------------------------------------------------------------------ helpers
def _need_cve(cve_id: str) -> Dict[str, Any]:
    st = get_store()
    if not st.has_predictions:
        raise HTTPException(503, waiting_text("predictions"))
    c = st.get_cve(cve_id)
    if c is None:
        raise HTTPException(404, "CVE not found in the 2026 scored set")
    return c


def _ai_ctx(c: Dict[str, Any]) -> Dict[str, Any]:
    """The existing generators index strings directly, so give them non-null text fields."""
    ctx = dict(c)
    ctx["description"] = c.get("description") or "No description available."
    for k, d in (("family_name", "Unclassified"), ("remote_local", "UNKNOWN"), ("auth_required", "UNKNOWN")):
        ctx[k] = c.get(k) or d
    # prediction_score stays None when the ranking has no score; src/ai templates omit it.
    return ctx


def _jsonable(obj: Any) -> Any:
    import json
    return json.loads(json.dumps(obj, default=lambda o: o.item() if hasattr(o, "item") else str(o)))


def _grounding(text: str, cve_id: str) -> Dict[str, Any]:
    return _jsonable(engine().verify_response(text, cve_id))


# ------------------------------------------------------------------ routes
@app.get("/api/status")
def status():
    s = get_store()
    return {
        "gemini": bool(os.environ.get("GEMINI_API_KEY")),
        "snowflake": all(os.environ.get(k) for k in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD")),
        "descriptions": s.has_descriptions,
        "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
        "counts": {"cves": int(len(s.df)) if s.has_predictions else None,
                   "top500": int(len(s.top500_df)) if s.has_predictions else None,
                   "families": int(len(s.fam_summary)) if s.fam_summary is not None else None},
        "has_score": s.has_score,
        "metrics_source": s.metrics_source,
        "research": bool(s.research.get("available")),
        "ranking_method": s.ranking_method,
        "data_label": s.label,
        "results_dir": s.results_rel,
        "top500_source": s.top500_source,
        "files": s.status_files(),
    }


@app.get("/api/overview")
def overview():
    return get_store().overview()


@app.get("/api/metrics")
def metrics():
    return get_store().metrics_list


@app.get("/api/patch-budget")
def patch_budget():
    return get_store().patch_budget()


@app.get("/api/research")
def research():
    return get_store().research


@app.get("/api/distributions")
def distributions():
    return get_store().distributions


@app.get("/api/galaxy")
def galaxy():
    return get_store().galaxy()


@app.get("/api/families")
def families():
    return get_store().families()


@app.get("/api/families/{family_id}")
def family(family_id: str = PathParam(..., max_length=20)):
    d = get_store().family_detail(family_id)
    if d is None:
        raise HTTPException(404, "Unknown family")
    return d


@app.get("/api/cves")
def cves(q: Optional[str] = Query(None, max_length=200),
         family_id: Optional[str] = Query(None, max_length=20),
         min_epss: Optional[float] = Query(None, ge=0, le=1),
         signals: Optional[str] = Query(None, max_length=100),
         scope: str = Query("top500", pattern="^(top500|all)$"),
         sort: str = Query("rank", pattern="^(rank|epss|score)$"),
         limit: int = Query(50, ge=1, le=200),
         offset: int = Query(0, ge=0)):
    sig = [x.strip() for x in (signals or "").split(",") if x.strip()]
    bad = [x for x in sig if x not in SIGNALS]
    if bad:
        raise HTTPException(422, "Unknown signal(s): %s. Use: %s" % (", ".join(bad), ", ".join(SIGNALS)))
    total, items = get_store().search(q, family_id, min_epss, sig, scope, sort, limit, offset)
    return {"total": total, "items": items}


@app.get("/api/cves/{cve_id}")
def cve(cve_id: str = PathParam(..., pattern=CVE_PATTERN)):
    return _need_cve(cve_id.upper())


@app.post("/api/brief")
def brief(req: BriefReq):
    c = _need_cve(req.cve_id.upper())
    try:
        out = GeminiBriefGenerator().generate_cve_brief(_ai_ctx(c))
        content = out["content"]
    except Exception as e:
        logger.warning("brief generation failed (%s)", type(e).__name__)
        out = {"source": "Offline (provider error)", "model": "none",
               "content": "A brief is unavailable right now. See the CVE fields for the facts."}
        content = out["content"]
    return {"source": out["source"], "model": out["model"], "content": content,
            "grounding": _grounding(content, c["cve_id"])}


@app.post("/api/ask")
def ask(req: AskReq):
    c = _need_cve(req.cve_id.upper())
    try:
        out = SnowflakeCortexAssistant().query_cortex(req.question, _ai_ctx(c))
        text = out["response"]
    except Exception as e:
        logger.warning("ask failed (%s)", type(e).__name__)
        out = {"source": "Offline (provider error)", "model": "none",
               "response": "The analyst assistant is unavailable right now."}
        text = out["response"]
    return {"source": out["source"], "model": out["model"], "response": text,
            "grounding": _grounding(text, c["cve_id"])}


@app.post("/api/chat")
def chat(req: ChatReq):
    msgs = [m.model_dump() for m in req.messages]
    if msgs[-1]["role"] != "user":
        raise HTTPException(422, "Last message must be from the user")
    try:
        out = chat_mod.chat(get_store(), engine(), msgs, req.page, req.selection)
    except Exception as e:  # last-resort guard: never 500 on AI paths
        logger.warning("chat failed (%s)", type(e).__name__)
        out = chat_mod._offline_chat(get_store(), engine(), msgs, req.page, req.selection)
    return JSONResponse(_jsonable(out))


@app.post("/api/explain")
def explain(req: ExplainReq):
    out = explain_target(get_store(), req.target, req.page)
    if out is None:
        raise HTTPException(404, "Unknown highlight target")
    return out


@app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
def api_not_found(rest: str):
    raise HTTPException(404, "Not found")


# ------------------------------------------------------------------ static SPA (mounted last)
if DIST.is_dir():
    _dist = DIST.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = (_dist / path).resolve()
        if path and f.is_file() and _dist in f.parents:
            return FileResponse(str(f))
        return FileResponse(str(_dist / "index.html"))
