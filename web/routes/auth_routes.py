"""Login and logout routes."""

import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from web.auth import authenticate_user, clear_session_cookie, set_session_cookie
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
    user = authenticate_user(username.strip(), password)
    if not user:
        log.info("Failed login attempt from %s", request.client.host if request.client else "unknown")
        return templates.TemplateResponse(request, "login.html", {
            "error": "Invalid username or password.",
        }, status_code=401)

    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(request, response, user["id"])
    return response


@router.post("/logout")
def logout(request: Request):
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(request, response)
    return response


@router.get("/")
def root():
    return RedirectResponse("/dashboard", status_code=303)
