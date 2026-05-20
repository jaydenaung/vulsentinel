"""Product inventory routes."""

import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user
from web.db import get_db

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.get("/products", response_class=HTMLResponse)
def products_page(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db() as conn:
        products = conn.execute("""
            SELECT p.*,
                   COUNT(c.id) as cve_count,
                   SUM(CASE WHEN c.recommended_action = 'PATCH NOW' THEN 1 ELSE 0 END) as critical_count
            FROM products p
            LEFT JOIN cves c ON c.product_id = p.id
            GROUP BY p.id
            ORDER BY p.name
        """).fetchall()

    return templates.TemplateResponse(request, "products.html", {
        "user": user,
        "active_page": "products",
        "products": [dict(r) for r in products],
        "msg": request.query_params.get("msg"),
        "error": request.query_params.get("error"),
    })


@router.post("/products/add")
async def add_product(
    request: Request,
    name: str = Form(...),
    keyword: str = Form(...),
    description: str = Form(""),
):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/products", status_code=303)

    name = name.strip()
    keyword = keyword.strip().lower()

    if not name or not keyword:
        return RedirectResponse("/products?error=Name+and+keyword+are+required", status_code=303)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO products (name, keyword, description) VALUES (?, ?, ?)",
                (name, keyword, description.strip()),
            )
    except Exception as exc:
        return RedirectResponse(f"/products?error=Could+not+add+product:+{str(exc)[:80]}", status_code=303)

    return RedirectResponse("/products?msg=Product+added+successfully", status_code=303)


@router.post("/products/{product_id}/toggle")
def toggle_product(product_id: int, request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/products", status_code=303)

    with get_db() as conn:
        conn.execute(
            "UPDATE products SET active = CASE WHEN active = 1 THEN 0 ELSE 1 END WHERE id = ?",
            (product_id,),
        )
    return RedirectResponse("/products", status_code=303)


@router.post("/products/{product_id}/delete")
def delete_product(product_id: int, request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/products", status_code=303)

    with get_db() as conn:
        conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
    return RedirectResponse("/products?msg=Product+deleted", status_code=303)
