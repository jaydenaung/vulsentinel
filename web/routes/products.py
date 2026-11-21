"""Product inventory routes."""

import logging
import sqlite3

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from web.auth import get_session_user
from web.db import get_db
from web.forms import ProductForm
from web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter()


def _admin(request: Request) -> dict | None:
    user = get_session_user(request)
    return user if user and user["role"] == "admin" else None


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
    })


@router.post("/products/add")
async def add_product(
    request: Request,
    name: str = Form(""),
    keyword: str = Form(""),
    description: str = Form(""),
):
    if not _admin(request):
        return RedirectResponse("/products", status_code=303)

    if not name.strip() or not keyword.strip():
        return RedirectResponse("/products?error=Name+and+keyword+are+required", status_code=303)
    try:
        form = ProductForm(name=name, keyword=keyword, description=description)
    except ValidationError:
        return RedirectResponse("/products?error=Invalid+product+details", status_code=303)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO products (name, keyword, description) VALUES (?, ?, ?)",
                (form.name, form.keyword, form.description),
            )
    except sqlite3.Error:
        log.exception("Could not add product %r", form.name)
        return RedirectResponse("/products?error=Could+not+add+product", status_code=303)

    return RedirectResponse("/products?msg=Product+added+successfully", status_code=303)


@router.post("/products/{product_id}/toggle")
def toggle_product(product_id: int, request: Request):
    if not _admin(request):
        return RedirectResponse("/products", status_code=303)

    with get_db() as conn:
        conn.execute(
            "UPDATE products SET active = CASE WHEN active = 1 THEN 0 ELSE 1 END WHERE id = ?",
            (product_id,),
        )
    return RedirectResponse("/products", status_code=303)


@router.post("/products/{product_id}/delete")
def delete_product(product_id: int, request: Request):
    if not _admin(request):
        return RedirectResponse("/products", status_code=303)

    with get_db() as conn:
        conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
    return RedirectResponse("/products?msg=Product+deleted", status_code=303)
