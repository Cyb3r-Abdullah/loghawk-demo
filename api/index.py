"""Vercel entrypoint for the public LogHawk demo.

Vercel detects FastAPI by scanning this file for a module-level `app`, so that
assignment stays plain and unindented — no try/except around it, no factory
call. Everything below it mutates that instance.

Two things differ from running LogHawk on a workstation:

1. **The filesystem is read-only apart from /tmp**, and /tmp does not survive a
   cold start. The alert database lives there and is seeded at import time,
   which on serverless means once per instance. Triage changes are real but
   ephemeral, and the dashboard says so.

2. **The API is public.** SECURITY.md in the main repository states that
   `/api/scan` reads server-side paths supplied by the caller and must not be
   exposed. This file deletes that route and the file-upload route, replacing
   them with a fixed-scope rescan that can only ever read the synthetic samples
   shipped with the deploy.

   Note that `python-multipart` is still a dependency even though the upload
   route is deleted here: it is declared by a decorator in loghawk/api.py, and
   decorators run at import. FastAPI raises while *defining* the route, before
   this file gets control. A route cannot be removed if defining it crashes.

The engine is not vendored — it installs from the main repository at build
time, so this repo holds deployment configuration and nothing else.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

# Must be set before loghawk.api is imported: it reads LOGHAWK_DB at import time.
DB_PATH = str(Path(tempfile.gettempdir()) / "loghawk-demo.db")
os.environ["LOGHAWK_DB"] = DB_PATH

import loghawk.api as upstream  # noqa: E402

upstream.DB_PATH = DB_PATH

from fastapi.responses import HTMLResponse  # noqa: E402

from loghawk.engine import Engine  # noqa: E402
from loghawk.parsers import parse_paths  # noqa: E402

# ── the instance Vercel looks for: top level, plain assignment ──
app = upstream.app

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
SAMPLE_YEAR = 2026  # the bundled logs are syslog, which omits the year
SOURCE_URL = "https://github.com/Cyb3r-Abdullah/loghawk"


def run_demo_scan() -> dict[str, Any]:
    """Scan the bundled samples and persist the result. The only scan there is."""
    events, sources = parse_paths([str(SAMPLES_DIR)], year=SAMPLE_YEAR)
    result = Engine().analyze(events, sources)
    payload = result.to_dict()
    payload["scan_id"] = upstream.store().save_scan(result)
    return payload


# ── hardening: drop the routes that have no business on a public URL ──
REMOVED = {"/api/scan", "/api/scan/upload", "/"}
app.router.routes = [
    route for route in app.router.routes
    if getattr(route, "path", None) not in REMOVED
]


@app.post("/api/scan", tags=["scan"])
def demo_scan() -> dict[str, Any]:
    """Re-run all ten detections over the bundled sample logs.

    Upstream this endpoint accepts a list of server-side paths to read. That is
    reasonable on a workstation and unacceptable on a public URL, so this
    version takes no input at all.
    """
    return run_demo_scan()


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


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
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
# Import time is the right moment on serverless: it runs once per instance,
# before any request is served. A failure here must not take the app down —
# the dashboard renders an empty queue rather than a 500.
try:
    if upstream.store().stats()["total_alerts"] == 0:
        run_demo_scan()
except Exception as exc:  # noqa: BLE001
    import sys, traceback
    print(f"LogHawk demo: seeding failed ({type(exc).__name__})", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
