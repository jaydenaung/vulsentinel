"""User management routes (admin only)."""

import logging
import sqlite3

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from web.auth import get_session_user, hash_password, password_problem
from web.db import get_db
from web.forms import UserForm
from web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter()


def _admin(request: Request) -> dict | None:
    user = get_session_user(request)
    return user if user and user["role"] == "admin" else None


def _flash(kind: str, text: str) -> RedirectResponse:
    return RedirectResponse(f"/users?{kind}={text.replace(' ', '+')}", status_code=303)


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/dashboard", status_code=303)

    with get_db() as conn:
        users = conn.execute(
            "SELECT id, username, email, role, created_at FROM users ORDER BY created_at"
        ).fetchall()

    return templates.TemplateResponse(request, "users.html", {
        "user": user,
        "active_page": "users",
        "users": [dict(r) for r in users],
    })


@router.post("/users/add")
async def add_user(
    request: Request,
    username: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    role: str = Form("viewer"),
):
    if not _admin(request):
        return RedirectResponse("/dashboard", status_code=303)

    problem = password_problem(password)
    if problem:
        return _flash("error", problem)
    try:
        form = UserForm(username=username, email=email, role=role)
    except ValidationError:
        return _flash("error", "Invalid user details")

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (form.username, form.email, hash_password(password), form.role),
            )
    except sqlite3.IntegrityError:
        return _flash("error", "Could not create user (username or email may already exist)")
    except sqlite3.Error:
        log.exception("Could not create user %r", form.username)
        return _flash("error", "Invalid user details")

    return _flash("msg", "User created successfully")


@router.post("/users/{target_id}/delete")
def delete_user(target_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/dashboard", status_code=303)
    if user["id"] == target_id:
        return _flash("error", "Cannot delete your own account")

    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
    return _flash("msg", "User deleted")


@router.post("/users/{target_id}/reset-password")
async def reset_password(target_id: int, request: Request, new_password: str = Form("")):
    if not _admin(request):
        return RedirectResponse("/dashboard", status_code=303)

    problem = password_problem(new_password)
    if problem:
        return _flash("error", problem)

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), target_id),
        )
    return _flash("msg", "Password updated")
