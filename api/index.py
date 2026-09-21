"""Vercel entrypoint for the public LogHawk demo.

Three things differ from running LogHawk on a workstation, and each is a
deliberate adaptation rather than a workaround:

1. **The filesystem is read-only apart from /tmp**, and /tmp does not survive a
   cold start. So the alert database lives in /tmp and is seeded at import
   time — which on a serverless platform means exactly once per cold start.
   Triage changes are therefore real but ephemeral, and the dashboard says so.

2. **The API is public.** SECURITY.md in the main repository states that
   `/api/scan` reads server-side paths supplied by the caller and must not be
   exposed. This file deletes that route and the file-upload route, replacing
   them with a fixed-scope rescan that can only ever read the synthetic samples
   shipped with the deploy.

3. **The engine is not vendored here.** It installs from the main repository at
   build time, so this repo holds deployment configuration and nothing else.

If anything above fails during import, a minimal fallback app is served so the
platform returns a readable message instead of an opaque 500, and the traceback
goes to stderr where Vercel's function logs will show it.
"""

from __future__ import annotations

import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any

# Must be set before loghawk.api is imported: it reads LOGHAWK_DB at import time.
DB_PATH = str(Path(tempfile.gettempdir()) / "loghawk-demo.db")
os.environ["LOGHAWK_DB"] = DB_PATH

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
SAMPLE_YEAR = 2026  # the bundled logs are syslog, which omits the year
SOURCE_URL = "https://github.com/Cyb3r-Abdullah/loghawk"

BANNER = f"""
<div style="position:fixed;left:12px;bottom:12px;z-index:200;max-width:min(420px,calc(100vw - 24px));
            background:rgba(10,17,32,.94);border:1px solid #22314f;border-left:2px solid #22d3ee;
            border-radius:4px;padding:9px 13px;font:11.5px/1.55 ui-monospace,Menlo,Consolas,monospace;
            color:#93a7c4;backdrop-filter:blur(8px)">
  <b style="color:#22d3ee;font-weight:600">LIVE DEMO</b> &nbsp;synthetic sample logs &middot;
  triage is real but resets when the serverless instance recycles &middot;
  <a href="{SOURCE_URL}" target="_blank" rel="noopener"
     style="color:#22d3ee;text-decoration:none">source &rarr;</a>
</div>
"""


def _build_app():
    import loghawk.api as upstream

    upstream.DB_PATH = DB_PATH

    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    from loghawk.engine import Engine
    from loghawk.parsers import parse_paths

    application: FastAPI = upstream.app

    def run_demo_scan() -> dict[str, Any]:
        """Scan the bundled samples and persist the result. The only scan there is."""
        events, sources = parse_paths([str(SAMPLES_DIR)], year=SAMPLE_YEAR)
        result = Engine().analyze(events, sources)
        payload = result.to_dict()
        payload["scan_id"] = upstream.store().save_scan(result)
        return payload

    # ── hardening: drop the routes that have no business on a public URL ──
    removed = {"/api/scan", "/api/scan/upload", "/"}
    application.router.routes = [
        route for route in application.router.routes
        if getattr(route, "path", None) not in removed
    ]

    @application.post("/api/scan", tags=["scan"])
    def demo_scan() -> dict[str, Any]:
        """Re-run all ten detections over the bundled sample logs.

        Upstream this endpoint accepts a list of server-side paths to read.
        That is reasonable on a workstation and unacceptable on a public URL,
        so this version takes no input at all.
        """
        return run_demo_scan()

    @application.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> HTMLResponse:
        try:
            html = Path(upstream.DASHBOARD).read_text(encoding="utf-8")
        except OSError:
            return HTMLResponse(
                "<h1>LogHawk</h1><p>Dashboard asset missing from the deployment.</p>",
                status_code=500,
            )
        return HTMLResponse(html.replace("</body>", BANNER + "</body>"))

    # ── seed once per cold start ──
    # Import time is exactly the right moment on a serverless platform: it runs
    # once per instance, before any request is served.
    if upstream.store().stats()["total_alerts"] == 0:
        run_demo_scan()

    return application


def _fallback_app(error: BaseException):
    """Serve a readable message rather than an opaque platform 500.

    The traceback goes to stderr only — it belongs in the function logs, not in
    a response body on a public URL.
    """
    print("LogHawk demo failed to start:", file=sys.stderr)
    traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)

    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse

    broken = FastAPI(title="LogHawk demo (degraded)")

    @broken.get("/api/health")
    def health() -> JSONResponse:
        return JSONResponse(
            {"status": "error", "detail": f"{type(error).__name__}: {error}"},
            status_code=503,
        )

    @broken.get("/{path:path}", include_in_schema=False)
    def anything(path: str) -> HTMLResponse:
        return HTMLResponse(
            "<body style='background:#04070e;color:#e8f0fb;font:14px system-ui;padding:40px'>"
            "<h1 style='color:#22d3ee'>LogHawk demo is starting up incorrectly</h1>"
            f"<p><code>{type(error).__name__}</code> during import. "
            "The traceback is in the Vercel function logs.</p>"
            f"<p><a style='color:#22d3ee' href='{SOURCE_URL}'>Source repository &rarr;</a></p>"
            "</body>",
            status_code=503,
        )

    return broken


try:
    app = _build_app()
except Exception as exc:  # noqa: BLE001 - never let the platform swallow the reason
    app = _fallback_app(exc)
