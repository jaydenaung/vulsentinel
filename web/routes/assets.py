"""Asset inventory routes."""

import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user
from web.db import get_db

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db() as conn:
        assets = conn.execute("""
            SELECT a.*,
                   COUNT(c.id) as cve_count,
                   SUM(CASE WHEN c.recommended_action = 'PATCH NOW' THEN 1 ELSE 0 END) as critical_count
            FROM assets a
            LEFT JOIN cves c ON c.asset_id = a.id
            GROUP BY a.id
            ORDER BY a.name
        """).fetchall()

    return templates.TemplateResponse(request, "assets.html", {
        "user": user,
        "active_page": "assets",
        "assets": [dict(r) for r in assets],
        "msg": request.query_params.get("msg"),
        "error": request.query_params.get("error"),
    })


@router.post("/assets/add")
async def add_asset(
    request: Request,
    name: str = Form(...),
    keyword: str = Form(...),
    description: str = Form(""),
):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/assets", status_code=303)

    name = name.strip()
    keyword = keyword.strip().lower()

    if not name or not keyword:
        return RedirectResponse("/assets?error=Name+and+keyword+are+required", status_code=303)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO assets (name, keyword, description) VALUES (?, ?, ?)",
                (name, keyword, description.strip()),
            )
    except Exception as exc:
        return RedirectResponse(f"/assets?error=Could+not+add+asset:+{str(exc)[:80]}", status_code=303)

    return RedirectResponse("/assets?msg=Asset+added+successfully", status_code=303)


@router.post("/assets/{asset_id}/toggle")
def toggle_asset(asset_id: int, request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/assets", status_code=303)

    with get_db() as conn:
        conn.execute(
            "UPDATE assets SET active = CASE WHEN active = 1 THEN 0 ELSE 1 END WHERE id = ?",
            (asset_id,),
        )
    return RedirectResponse("/assets", status_code=303)


@router.post("/assets/{asset_id}/delete")
def delete_asset(asset_id: int, request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/assets", status_code=303)

    with get_db() as conn:
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    return RedirectResponse("/assets?msg=Asset+deleted", status_code=303)
