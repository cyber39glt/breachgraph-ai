"""HTTP API for the BreachGraph dashboard.

Run locally:  uvicorn breachgraph.api:app --host 127.0.0.1 --port 8000

Every request either sends a dataset or uses the built-in synthetic demo dataset.
Nothing is stored server-side apart from small in-memory caches, and nothing here
can change a real cloud environment.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .agent import MAX_ROUNDS, run_fix_agent
from .importers.aws import import_aws
from .ai import PROVIDER, AIError, AISettings, explain_finding
from .engine import analyze
from .model import DatasetError, load_dataset, validate_dataset
from .remediation import candidates
from .simulate import simulate

ROOT = Path(__file__).resolve().parents[2]  # the breachgraph/ project folder
DEMO_DATASET = ROOT / "data" / "sample_org.json"
AWS_SAMPLE = ROOT / "data" / "aws-sample"
FRONTEND_DIST = ROOT / "frontend" / "dist"

# A local .env (git-ignored) may hold MODEL_API_KEY. Real environment variables win.
load_dotenv(ROOT / ".env", override=False)

log = logging.getLogger("breachgraph.api")

MAX_BODY_BYTES = 5_000_000
IMPORT_MAX_BODY_BYTES = 20_000_000  # raw AWS exports include large AWS-managed policies
MAX_ENTITIES = {"users": 500, "groups": 500, "roles": 500, "policies": 3000, "resources": 3000}
MAX_STATEMENTS_PER_POLICY = 200
MAX_PATHS_RETURNED = 300
MAX_ACCESS_RETURNED = 5000
MAX_CHANGES = 20
EXPLAIN_LIMIT_PER_MINUTE = 6
AGENT_LIMIT_PER_MINUTE = 2  # each run makes up to MAX_ROUNDS model calls

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


# --- request models -------------------------------------------------------------

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DatasetRequest(_Strict):
    dataset: dict[str, Any] | None = Field(default=None, description="Omit to use the synthetic demo dataset.")


class SimulateRequest(DatasetRequest):
    changes: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_CHANGES)


class ExplainRequest(DatasetRequest):
    finding_id: str = Field(pattern=r"^PATH-[0-9A-F]{8}$")


class AgentRequest(ExplainRequest):
    max_rounds: int = Field(default=MAX_ROUNDS, ge=1, le=MAX_ROUNDS)


class AwsImportRequest(_Strict):
    authorization_details: dict[str, Any] = Field(description="Output of `aws iam get-account-authorization-details`.")
    credential_report_csv: str | None = Field(default=None, max_length=5_000_000)
    context: dict[str, Any] | None = Field(default=None, description="Resource sensitivity and external identities.")


# --- helpers ----------------------------------------------------------------------

class _LRU(OrderedDict):
    def __init__(self, size: int):
        super().__init__()
        self.size = size
        self.lock = threading.Lock()

    def get_or(self, key: str, make):
        with self.lock:
            if key in self:
                self.move_to_end(key)
                return self[key]
        value = make()
        with self.lock:
            self[key] = value
            while len(self) > self.size:
                self.popitem(last=False)
        return value


_analysis_cache = _LRU(16)
_explain_cache = _LRU(64)
_explain_calls: deque[float] = deque()
_agent_calls: deque[float] = deque()
_rate_lock = threading.Lock()
# Tests replace this with an httpx.MockTransport so they never reach the real API.
ai_transport = None


def _demo() -> dict[str, Any]:
    return load_dataset(DEMO_DATASET)


def _dataset(req: DatasetRequest) -> dict[str, Any]:
    if req.dataset is None:
        return _demo()
    data = req.dataset
    for section, limit in MAX_ENTITIES.items():
        if isinstance(data.get(section), list) and len(data[section]) > limit:
            raise DatasetError(f"too many {section}: {len(data[section])} (limit {limit})")
    if isinstance(data.get("policies"), list):
        for p in data["policies"]:
            if isinstance(p, dict) and len(p.get("statements") or []) > MAX_STATEMENTS_PER_POLICY:
                raise DatasetError(f"{p.get('id')} has more than {MAX_STATEMENTS_PER_POLICY} statements")
    validate_dataset(data)
    return data


def trim_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    """Cap what is sent to the browser for very large accounts. Totals stay exact."""
    paths = [f for f in analysis["findings"] if f["type"] == "attack_path"]
    if len(paths) <= MAX_PATHS_RETURNED and len(analysis["access"]) <= MAX_ACCESS_RETURNED:
        return analysis
    kept = {f["id"] for f in paths[:MAX_PATHS_RETURNED]}  # findings are already sorted by risk
    shown_keys = {f["key"] for f in paths if f["id"] in kept}
    access = [a for a in analysis["access"] if a["key"] in shown_keys]
    access += [a for a in analysis["access"] if a["key"] not in shown_keys][: max(0, MAX_ACCESS_RETURNED - len(access))]
    return {
        **analysis,
        "findings": [f for f in analysis["findings"] if f["type"] != "attack_path" or f["id"] in kept],
        "access": access,
        "truncated": {"attack_paths_total": len(paths), "attack_paths_shown": len(kept),
                      "access_total": len(analysis["access"]), "access_shown": len(access)},
    }


def _fingerprint(data: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _analysis(data: dict[str, Any]) -> dict[str, Any]:
    return _analysis_cache.get_or(_fingerprint(data), lambda: analyze(data))


def _path_finding(analysis: dict[str, Any], finding_id: str) -> dict[str, Any]:
    # Looked up from the engine's own result; clients cannot supply evidence.
    finding = next((f for f in analysis["findings"] if f["id"] == finding_id), None)
    if finding is None:
        raise HTTPException(404, "No attack-path finding with that id in this dataset.")
    return finding


def _take_slot(calls: deque[float], limit: int, what: str) -> None:
    """Protect API credits from accidental repeated calls."""
    with _rate_lock:
        now = time.monotonic()
        while calls and now - calls[0] > 60:
            calls.popleft()
        if len(calls) >= limit:
            raise AIError("local_rate_limited", f"At most {limit} {what} per minute. Try again shortly.",
                          429, retry_after="60")
        calls.append(now)


def _ai_status() -> dict[str, Any]:
    s = AISettings.from_env()
    return {"provider": PROVIDER, "configured": s.configured, "model": s.model}


# --- app --------------------------------------------------------------------------

app = FastAPI(title="BreachGraph AI", version=__version__, docs_url="/api/docs", redoc_url=None,
              openapi_url="/api/openapi.json")


@app.middleware("http")
async def limits_and_headers(request: Request, call_next):
    length = request.headers.get("content-length")
    if request.method == "POST":
        if length is None:
            return JSONResponse({"error": "length_required", "message": "Content-Length is required."}, 411)
        limit = IMPORT_MAX_BODY_BYTES if request.url.path == "/api/import/aws" else MAX_BODY_BYTES
        if not length.isdigit() or int(length) > limit:
            return JSONResponse({"error": "too_large",
                                 "message": f"Request body is larger than {limit // 1_000_000} MB."}, 413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith(("/api/docs", "/api/openapi.json")):
        response.headers["Content-Security-Policy"] = CSP
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(DatasetError)
async def dataset_error(_: Request, exc: DatasetError):
    return JSONResponse({"error": "invalid_dataset", "message": str(exc)}, 400)


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    problems = [f"{'.'.join(str(p) for p in e['loc'] if p != 'body')}: {e['msg']}" for e in exc.errors()[:5]]
    return JSONResponse({"error": "invalid_request", "message": "; ".join(problems)}, 422)


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    code = "not_found" if exc.status_code == 404 else "http_error"
    return JSONResponse({"error": code, "message": str(exc.detail)}, exc.status_code)


@app.exception_handler(AIError)
async def ai_error(_: Request, exc: AIError):
    headers = {"Retry-After": exc.retry_after} if exc.retry_after else None
    return JSONResponse({"error": exc.code, "message": exc.message, "ai_generated": False},
                        exc.http_status, headers=headers)


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "ai": _ai_status()}


@app.get("/api/demo/dataset")
def demo_dataset() -> dict[str, Any]:
    return _demo()


@app.get("/api/demo/aws-sample")
def demo_aws_sample() -> dict[str, Any]:
    """A synthetic AWS IAM export (AWS's real file formats) for trying the importer without an account."""
    return {
        "authorization_details": json.loads((AWS_SAMPLE / "authorization-details.json").read_text(encoding="utf-8")),
        "credential_report_csv": (AWS_SAMPLE / "credential-report.csv").read_text(encoding="utf-8"),
        "context": json.loads((AWS_SAMPLE / "context.json").read_text(encoding="utf-8")),
    }


@app.post("/api/analyze")
def analyze_endpoint(req: DatasetRequest) -> dict[str, Any]:
    data = _dataset(req)
    analysis = _analysis(data)
    return {**trim_analysis(analysis), "candidates": candidates(data, analysis), "ai": _ai_status()}


@app.post("/api/simulate")
def simulate_endpoint(req: SimulateRequest) -> dict[str, Any]:
    result = simulate(_dataset(req), req.changes)
    result["before"] = trim_analysis(result["before"])
    result["after"] = trim_analysis(result["after"])
    for key in ("broken_paths", "remaining_paths", "new_paths"):
        result["diff"][key] = result["diff"][key][:MAX_PATHS_RETURNED]
    for key in ("access_removed", "collateral_access_removed", "access_added"):
        result["diff"][key] = result["diff"][key][:MAX_ACCESS_RETURNED]
    result["note"] = "Simulation only. No real permissions were changed."
    return result


@app.post("/api/explain")
def explain_endpoint(req: ExplainRequest) -> dict[str, Any]:
    data = _dataset(req)
    analysis = _analysis(data)
    finding = _path_finding(analysis, req.finding_id)
    settings = AISettings.from_env()
    key = f"{_fingerprint(data)}:{finding['id']}:{settings.model}"
    if settings.configured and key in _explain_cache:
        return {**_explain_cache[key], "cached": True}

    if settings.configured:
        _take_slot(_explain_calls, EXPLAIN_LIMIT_PER_MINUTE, "AI explanations")

    result = explain_finding(data, analysis, finding, settings, transport=ai_transport)
    result = {**result, "ai_generated": True, "generated_at": int(time.time())}
    _explain_cache.get_or(key, lambda: result)
    log.info("AI explanation generated for %s with %s", finding["id"], settings.model)
    return {**result, "cached": False}


@app.post("/api/import/aws")
def import_aws_endpoint(req: AwsImportRequest) -> dict[str, Any]:
    """Convert an AWS IAM export into a dataset. Offline: nothing is sent to AWS or stored."""
    data, report = import_aws(req.authorization_details, req.credential_report_csv, req.context)
    _dataset(DatasetRequest(dataset=data))  # the same size limits as any uploaded dataset
    return {"dataset": data, "report": report}


@app.post("/api/agent/fix")
def agent_endpoint(req: AgentRequest):
    """Stream the Fix Agent's rounds as newline-delimited JSON, then a final result."""
    data = _dataset(req)
    analysis = _analysis(data)
    finding = _path_finding(analysis, req.finding_id)
    settings = AISettings.from_env()
    if not settings.configured:
        raise AIError("not_configured", "AI is off: MODEL_API_KEY is not set on the server.", 503)
    _take_slot(_agent_calls, AGENT_LIMIT_PER_MINUTE, "Fix Agent runs")

    def events():
        for event in run_fix_agent(data, analysis, finding, settings, transport=ai_transport,
                                   max_rounds=req.max_rounds):
            yield json.dumps(event) + "\n"
        log.info("Fix Agent run finished for %s with %s", finding["id"], settings.model)

    return StreamingResponse(events(), media_type="application/x-ndjson")


@app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
def api_not_found(rest: str):
    raise HTTPException(404, "Unknown API route.")


# --- the built dashboard ------------------------------------------------------------

@app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
def frontend(path: str):
    if not FRONTEND_DIST.is_dir():
        return JSONResponse({"message": "Dashboard not built. Run `npm run build` in breachgraph/frontend, "
                                        "or use the Vite dev server on port 5173."}, 404)
    target = (FRONTEND_DIST / path).resolve()
    if path and target.is_file() and FRONTEND_DIST.resolve() in target.parents:
        return FileResponse(target)
    return FileResponse(FRONTEND_DIST / "index.html")
