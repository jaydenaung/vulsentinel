"""Main dashboard route."""

import os

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user
from web.db import get_db
from web.scanner import check_state

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
        total_products = conn.execute("SELECT COUNT(*) FROM products WHERE active = 1").fetchone()[0]

        product_counts = conn.execute("""
            SELECT p.name, p.id,
                   COUNT(c.id) as total,
                   SUM(CASE WHEN c.recommended_action = 'PATCH NOW' THEN 1 ELSE 0 END) as critical
            FROM products p
            LEFT JOIN cves c ON c.product_id = p.id
            WHERE p.active = 1
            GROUP BY p.id
            ORDER BY critical DESC, total DESC
        """).fetchall()

        recent_critical = conn.execute("""
            SELECT c.*, p.name as product_name
            FROM cves c JOIN products p ON p.id = c.product_id
            WHERE c.recommended_action = 'PATCH NOW'
            ORDER BY c.checked_at DESC
            LIMIT 10
        """).fetchall()

        last_check = conn.execute(
            "SELECT * FROM check_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()

    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "active_page": "dashboard",
        "total_cves": total_cves,
        "patch_now": patch_now,
        "monitor": monitor,
        "low_pri": low_pri,
        "total_products": total_products,
        "product_counts": [dict(r) for r in product_counts],
        "recent_critical": [dict(r) for r in recent_critical],
        "last_check": dict(last_check) if last_check else None,
        "check_running": check_state["is_running"],
    })
