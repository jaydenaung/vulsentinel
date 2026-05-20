"""CVE list and detail routes."""

import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user
from web.db import get_db

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))

VALID_STATUSES = {"open", "accepted", "in_remediation", "mitigated"}
PAGE_SIZE = 50


@router.get("/cves", response_class=HTMLResponse)
def cve_list(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    params = request.query_params
    product_id = params.get("product_id", "")
    action = params.get("action", "")
    status = params.get("status", "")
    search = params.get("search", "")
    page = max(1, int(params.get("page", "1")))
    offset = (page - 1) * PAGE_SIZE

    where_clauses = []
    bind: list = []

    if product_id:
        where_clauses.append("c.product_id = ?")
        bind.append(int(product_id))
    if action:
        where_clauses.append("c.recommended_action = ?")
        bind.append(action)
    if status:
        where_clauses.append("c.status = ?")
        bind.append(status)
    if search:
        where_clauses.append("(c.cve_id LIKE ? OR c.description LIKE ?)")
        bind += [f"%{search}%", f"%{search}%"]

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    with get_db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM cves c {where_sql}", bind
        ).fetchone()[0]

        rows = conn.execute(
            f"""
            SELECT c.*, p.name as product_name
            FROM cves c JOIN products p ON p.id = c.product_id
            {where_sql}
            ORDER BY
                CASE c.recommended_action
                    WHEN 'PATCH NOW' THEN 0
                    WHEN 'MONITOR' THEN 1
                    ELSE 2 END,
                c.cvss_score DESC NULLS LAST,
                c.checked_at DESC
            LIMIT ? OFFSET ?
            """,
            bind + [PAGE_SIZE, offset],
        ).fetchall()

        products = conn.execute("SELECT id, name FROM products ORDER BY name").fetchall()

    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    return templates.TemplateResponse(request, "cve_list.html", {
        "user": user,
        "active_page": "cves",
        "cves": [dict(r) for r in rows],
        "products": [dict(r) for r in products],
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "filters": {"product_id": product_id, "action": action, "status": status, "search": search},
    })


@router.get("/cves/{cve_db_id}", response_class=HTMLResponse)
def cve_detail(cve_db_id: int, request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db() as conn:
        row = conn.execute(
            "SELECT c.*, p.name as product_name FROM cves c JOIN products p ON p.id = c.product_id WHERE c.id = ?",
            (cve_db_id,),
        ).fetchone()

    if not row:
        return RedirectResponse("/cves", status_code=303)

    return templates.TemplateResponse(request, "cve_detail.html", {
        "user": user,
        "active_page": "cves",
        "cve": dict(row),
        "valid_statuses": list(VALID_STATUSES),
        "msg": request.query_params.get("msg"),
    })


@router.post("/cves/{cve_db_id}/update")
async def update_cve(
    cve_db_id: int,
    request: Request,
    status: str = Form(...),
    notes: str = Form(""),
):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse(f"/cves/{cve_db_id}", status_code=303)

    if status not in VALID_STATUSES:
        return RedirectResponse(f"/cves/{cve_db_id}?msg=Invalid+status", status_code=303)

    with get_db() as conn:
        conn.execute(
            "UPDATE cves SET status = ?, notes = ? WHERE id = ?",
            (status, notes.strip(), cve_db_id),
        )

    return RedirectResponse(f"/cves/{cve_db_id}?msg=Updated+successfully", status_code=303)
