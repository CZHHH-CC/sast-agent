"""Local read-only web viewer for sast-agent baseline.db.

Design constraints:
    - bind only to localhost (enforced by CLI default, see main.py::ui)
    - no auth, no CSRF — this is a local dev tool
    - DB opened read-only (`mode=ro` URI) in queries.py
    - no build step: HTMX + Alpine + Chart.js via CDN
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import queries

UI_DIR = Path(__file__).parent
TEMPLATES_DIR = UI_DIR / "templates"
STATIC_DIR = UI_DIR / "static"


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def create_app(repo: Path) -> FastAPI:
    repo = Path(repo).resolve()
    db_path = repo / ".sast-agent" / "baseline.db"
    if not db_path.exists():
        raise FileNotFoundError(
            f"baseline not found: {db_path}. Run `sast-agent scan --repo {repo}` first."
        )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["fmt_ts"] = _fmt_ts

    app = FastAPI(title="sast-agent UI", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _common_ctx(request: Request) -> dict:
        return {
            "request": request,
            "repo": repo,
            "repo_name": repo.name,
            "sink_types": queries.distinct_sink_types(db_path),
        }

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True, "db_mtime": queries.db_mtime(db_path)})

    @app.get("/", response_class=HTMLResponse)
    async def index(
        request: Request,
        status: str | None = Query(default=None, pattern="^(confirmed|excluded)$"),
        severity: str | None = Query(default=None),
        sink_type: str | None = Query(default=None),
        q: str | None = Query(default=None),
    ) -> Response:
        findings = queries.list_findings(
            db_path, status=status, severity=severity, sink_type=sink_type, q=q,
        )
        # HTMX partial swap: if HX-Request header present, return only the rows
        is_htmx = request.headers.get("HX-Request") == "true"
        template = "_rows.html" if is_htmx else "list.html"
        ctx = _common_ctx(request)
        ctx.update({
            "findings": findings,
            "filters": {
                "status": status or "",
                "severity": severity or "",
                "sink_type": sink_type or "",
                "q": q or "",
            },
            "confirmed_count": sum(1 for f in findings if f.status == "confirmed"),
            "excluded_count": sum(1 for f in findings if f.status == "excluded"),
        })
        return templates.TemplateResponse(request, template, ctx)

    @app.get("/finding/{fingerprint}", response_class=HTMLResponse)
    async def finding_detail(request: Request, fingerprint: str) -> Response:
        f = queries.get_finding(db_path, fingerprint)
        if not f:
            raise HTTPException(status_code=404, detail="finding not found")
        ctx = _common_ctx(request)
        ctx["f"] = f
        return templates.TemplateResponse(request, "detail.html", ctx)

    @app.get("/trends", response_class=HTMLResponse)
    async def trends(request: Request) -> Response:
        sev = queries.severity_counts(db_path)
        breakdown = queries.sink_type_breakdown(db_path)
        weekly = queries.weekly_trend(db_path, weeks=12)
        ctx = _common_ctx(request)
        ctx.update({
            "severity_counts": sev,
            "sink_breakdown": breakdown,
            "weekly_trend": weekly,
        })
        return templates.TemplateResponse(request, "trends.html", ctx)

    @app.get("/api/findings")
    async def api_findings(
        status: str | None = None,
        severity: str | None = None,
        sink_type: str | None = None,
        q: str | None = None,
    ) -> JSONResponse:
        findings = queries.list_findings(
            db_path, status=status, severity=severity, sink_type=sink_type, q=q,
        )
        return JSONResponse({
            "count": len(findings),
            "findings": [
                {
                    "fingerprint": f.fingerprint,
                    "status": f.status,
                    "severity": f.severity,
                    "sink_type": f.sink_type,
                    "file": f.file,
                    "line": f.line,
                    "title": f.title,
                    "exclusion_category": f.exclusion_category,
                    "first_seen": f.first_seen,
                    "last_seen": f.last_seen,
                }
                for f in findings
            ],
        })

    return app
