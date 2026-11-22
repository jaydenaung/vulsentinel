"""Daily critical feed: list and manual run trigger."""

import json
import threading
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from critical import REASON_LABELS
from web.auth import get_session_user
from web.daily import daily_state, run_daily
from web.db import get_db
from web.forms import CriticalFilters
from web.templating import templates

router = APIRouter()
MAX_ROWS = 300


def _where(f: CriticalFilters) -> tuple[str, list[Any]]:
    """Literal SQL fragments only; values go through binds."""
    clauses = ["v.first_seen >= datetime('now', ?)"]
    bind: list[Any] = [f"-{f.days} days"]
    if f.reason:
        clauses.append("v.critical_reasons LIKE ?")
        bind.append(f'%"{f.reason}"%')
    if f.watched:
        clauses.append("EXISTS (SELECT 1 FROM vuln_products w WHERE w.cve_id = v.cve_id)")
    return "WHERE " + " AND ".join(clauses), bind


def _row(r: Any) -> dict[str, Any]:
    d = dict(r)
    d["reasons"] = json.loads(d.pop("critical_reasons") or "[]")
    d["breakdown"] = json.loads(d.pop("risk_breakdown") or "{}")
    d["affected"] = json.loads(d.get("affected") or "[]")
    return d


@router.get("/critical", response_class=HTMLResponse)
def critical_feed(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    filters = CriticalFilters.from_query(dict(request.query_params))
    where_sql, bind = _where(filters)
    # S608 false positive: where_sql is built only from literal fragments in _where().
    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT v.*, GROUP_CONCAT(p.name, ', ') AS watched_products
            FROM vulns v
            LEFT JOIN vuln_products vp ON vp.cve_id = v.cve_id
            LEFT JOIN products p ON p.id = vp.product_id
            {where_sql}
            GROUP BY v.cve_id
            ORDER BY v.risk_score DESC, v.first_seen DESC
            LIMIT ?
            """,  # noqa: S608
            bind + [MAX_ROWS],
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM vulns v {where_sql}", bind).fetchone()[0]  # noqa: S608
        last_run = conn.execute("SELECT * FROM daily_runs ORDER BY id DESC LIMIT 1").fetchone()
    return templates.TemplateResponse(request, "critical.html", {
        "user": user,
        "active_page": "critical",
        "vulns": [_row(r) for r in rows],
        "total": total,
        "filters": filters,
        "reason_labels": REASON_LABELS,
        "last_run": dict(last_run) if last_run else None,
        "running": daily_state["is_running"],
    })


@router.post("/critical/run")
def trigger_daily(request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/critical", status_code=303)
    if daily_state["is_running"]:
        return RedirectResponse("/critical?msg=Daily+run+already+in+progress", status_code=303)
    threading.Thread(target=run_daily, kwargs={"triggered_by": user["username"]}, daemon=True).start()
    return RedirectResponse("/critical?msg=Daily+run+started", status_code=303)
