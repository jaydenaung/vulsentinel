"""User management routes (admin only)."""

import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user, hash_password
from web.db import get_db

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    with get_db() as conn:
        users = conn.execute(
            "SELECT id, username, email, role, created_at FROM users ORDER BY created_at"
        ).fetchall()

    return templates.TemplateResponse(request, "users.html", {
        "user": user,
        "active_page": "users",
        "users": [dict(r) for r in users],
        "msg": request.query_params.get("msg"),
        "error": request.query_params.get("error"),
    })


@router.post("/users/add")
async def add_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    if len(password) < 8:
        return RedirectResponse("/users?error=Password+must+be+at+least+8+characters", status_code=303)

    if role not in ("admin", "viewer"):
        role = "viewer"

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (username.strip(), email.strip(), hash_password(password), role),
            )
    except Exception as exc:
        return RedirectResponse(f"/users?error=Could+not+create+user:+{str(exc)[:80]}", status_code=303)

    return RedirectResponse("/users?msg=User+created+successfully", status_code=303)


@router.post("/users/{target_id}/delete")
def delete_user(target_id: int, request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    if user["id"] == target_id:
        return RedirectResponse("/users?error=Cannot+delete+your+own+account", status_code=303)

    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (target_id,))

    return RedirectResponse("/users?msg=User+deleted", status_code=303)


@router.post("/users/{target_id}/reset-password")
async def reset_password(
    target_id: int,
    request: Request,
    new_password: str = Form(...),
):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    if len(new_password) < 8:
        return RedirectResponse("/users?error=Password+must+be+at+least+8+characters", status_code=303)

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), target_id),
        )

    return RedirectResponse("/users?msg=Password+updated", status_code=303)
