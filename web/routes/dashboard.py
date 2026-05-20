"""Main dashboard route."""

import os

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user
from web.db import get_db
from web.scanner import scan_state

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db() as conn:
        total_cves = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        patch_now = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE recommended_action = 'PATCH NOW'"
        ).fetchone()[0]
        monitor = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE recommended_action = 'MONITOR'"
        ).fetchone()[0]
        low_pri = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE recommended_action = 'LOW PRIORITY'"
        ).fetchone()[0]
        total_assets = conn.execute("SELECT COUNT(*) FROM assets WHERE active = 1").fetchone()[0]

        # CVEs per asset
        asset_counts = conn.execute("""
            SELECT a.name, a.id,
                   COUNT(c.id) as total,
                   SUM(CASE WHEN c.recommended_action = 'PATCH NOW' THEN 1 ELSE 0 END) as critical
            FROM assets a
            LEFT JOIN cves c ON c.asset_id = a.id
            WHERE a.active = 1
            GROUP BY a.id
            ORDER BY critical DESC, total DESC
        """).fetchall()

        # Recent PATCH NOW CVEs
        recent_critical = conn.execute("""
            SELECT c.*, a.name as asset_name
            FROM cves c JOIN assets a ON a.id = c.asset_id
            WHERE c.recommended_action = 'PATCH NOW'
            ORDER BY c.scanned_at DESC
            LIMIT 10
        """).fetchall()

        # Last scan run
        last_scan = conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()

    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "active_page": "dashboard",
        "total_cves": total_cves,
        "patch_now": patch_now,
        "monitor": monitor,
        "low_pri": low_pri,
        "total_assets": total_assets,
        "asset_counts": [dict(r) for r in asset_counts],
        "recent_critical": [dict(r) for r in recent_critical],
        "last_scan": dict(last_scan) if last_scan else None,
        "scan_running": scan_state["is_running"],
    })
