"""Check trigger and status routes."""

import os
import threading

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from web.auth import get_session_user
from web.db import get_db
from web.scanner import check_state, run_check

router = APIRouter()


@router.post("/check/trigger")
def trigger_check(request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    if check_state["is_running"]:
        return RedirectResponse("/dashboard?msg=Check+already+in+progress", status_code=303)

    threading.Thread(
        target=run_check,
        kwargs={"triggered_by": user["username"]},
        daemon=True,
    ).start()

    return RedirectResponse("/dashboard?msg=Check+started", status_code=303)


@router.get("/api/check/status")
def check_status(request: Request):
    user = get_session_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    with get_db() as conn:
        recent = conn.execute(
            "SELECT * FROM check_runs ORDER BY started_at DESC LIMIT 5"
        ).fetchall()

    return JSONResponse({
        "is_running": check_state["is_running"],
        "current_product": check_state["current_product"],
        "progress": check_state["progress"],
        "total": check_state["total"],
        "recent_runs": [dict(r) for r in recent],
    })
