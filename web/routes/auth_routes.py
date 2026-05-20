"""Login and logout routes."""

import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import SESSION_COOKIE, authenticate_user, create_session
from web.db import user_count

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {
        "setup_done": request.query_params.get("setup") == "1",
    })


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = authenticate_user(username.strip(), password)
    if not user:
        return templates.TemplateResponse(request, "login.html", {
            "error": "Invalid username or password.",
        }, status_code=401)

    token = create_session(user["id"])
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=86400 * 7,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.get("/")
def root():
    return RedirectResponse("/dashboard", status_code=303)
