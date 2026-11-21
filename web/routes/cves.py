"""CVE list and detail routes."""

from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from web.auth import get_session_user
from web.db import get_db
from web.forms import CveFilters, CveUpdateForm, Status
from web.templating import templates

router = APIRouter()

VALID_STATUSES: list[str] = list(Status.__args__)  # type: ignore[attr-defined]
PAGE_SIZE = 50


def _where(filters: CveFilters) -> tuple[str, list[Any]]:
    """Build a WHERE clause from fixed fragments. Values only ever go through binds."""
    clauses: list[str] = []
    bind: list[Any] = []
    if filters.product_id:
        clauses.append("c.product_id = ?")
        bind.append(filters.product_id)
    if filters.action:
        clauses.append("c.recommended_action = ?")
        bind.append(filters.action)
    if filters.status:
        clauses.append("c.status = ?")
        bind.append(filters.status)
    if filters.search:
        escaped = filters.search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("(c.cve_id LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\')")
        bind += [f"%{escaped}%", f"%{escaped}%"]
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", bind


@router.get("/cves", response_class=HTMLResponse)
def cve_list(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    filters = CveFilters.from_query(dict(request.query_params))
    where_sql, bind = _where(filters)
    offset = (filters.page - 1) * PAGE_SIZE

    # S608 is a false positive here: where_sql is built only from literal fragments in _where(),
    # and every user value is passed through `bind` placeholders.
    with get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM cves c {where_sql}", bind).fetchone()[0]  # noqa: S608
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
            """,  # noqa: S608
            bind + [PAGE_SIZE, offset],
        ).fetchall()
        products = conn.execute("SELECT id, name FROM products ORDER BY name").fetchall()

    return templates.TemplateResponse(request, "cve_list.html", {
        "user": user,
        "active_page": "cves",
        "cves": [dict(r) for r in rows],
        "products": [dict(r) for r in products],
        "total": total,
        "page": filters.page,
        "total_pages": max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
        "filters": {
            "product_id": str(filters.product_id or ""),
            "action": filters.action or "",
            "status": filters.status or "",
            "search": filters.search,
        },
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
        "valid_statuses": VALID_STATUSES,
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

    try:
        form = CveUpdateForm(status=status, notes=notes)
    except ValidationError:
        return RedirectResponse(f"/cves/{cve_db_id}?error=Invalid+status", status_code=303)

    with get_db() as conn:
        conn.execute(
            "UPDATE cves SET status = ?, notes = ? WHERE id = ?",
            (form.status, form.notes, cve_db_id),
        )

    return RedirectResponse(f"/cves/{cve_db_id}?msg=Updated+successfully", status_code=303)
