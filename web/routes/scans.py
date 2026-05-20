"""Scan trigger and status routes."""

import os
import threading

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user
from web.db import get_db
from web.scanner import run_scan, scan_state

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.post("/scan/trigger")
def trigger_scan(request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    if scan_state["is_running"]:
        return RedirectResponse("/dashboard?msg=Scan+already+in+progress", status_code=303)

    threading.Thread(
        target=run_scan,
        kwargs={"triggered_by": user["username"]},
        daemon=True,
    ).start()

    return RedirectResponse("/dashboard?msg=Scan+started", status_code=303)


@router.get("/api/scan/status")
def scan_status(request: Request):
    user = get_session_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    with get_db() as conn:
        recent = conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 5"
        ).fetchall()

    return JSONResponse({
        "is_running": scan_state["is_running"],
        "current_asset": scan_state["current_asset"],
        "progress": scan_state["progress"],
        "total": scan_state["total"],
        "recent_runs": [dict(r) for r in recent],
    })
