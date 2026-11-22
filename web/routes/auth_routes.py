"""Login and logout routes."""

import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from web import ratelimit
from web.auth import authenticate_user, clear_session_cookie, get_session_user, revoke_sessions, set_session_cookie
from web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {
        "setup_done": request.query_params.get("setup") == "1",
    })


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(..., max_length=64),
    password: str = Form(..., max_length=256),
):
    name = username.strip()
    ip = request.client.host if request.client else "unknown"
    if ratelimit.is_blocked(name, ip):
        log.warning("Login throttled for %s", ip)  # username not logged: it may be a mistyped password
        return templates.TemplateResponse(request, "login.html", {
            "error": "Too many failed attempts. Try again in 15 minutes.",
        }, status_code=429)

    user = authenticate_user(name, password)
    if not user:
        ratelimit.record_failure(name, ip)
        log.info("Failed login attempt from %s", ip)
        return templates.TemplateResponse(request, "login.html", {
            "error": "Invalid username or password.",
        }, status_code=401)

    ratelimit.record_success(name, ip)
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(request, response, user["id"], user["session_version"])
    return response


@router.post("/logout")
def logout(request: Request):
    user = get_session_user(request)
    if user:
        revoke_sessions(user["id"])  # a copied cookie stops working too
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(request, response)
    return response


@router.get("/")
def root():
    return RedirectResponse("/dashboard", status_code=303)
