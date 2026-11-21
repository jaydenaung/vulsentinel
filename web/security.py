# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""CSRF protection, security headers, and cookie flag helpers."""

import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request
from starlette.responses import Response

from settings import get_settings, require_secret_key

CSRF_COOKIE = "cve_csrf"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'",
    "font-src 'self' https://cdn.jsdelivr.net",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def cookie_is_secure(request: Request) -> bool:
    mode = get_settings().cookie_secure
    if mode == "auto":
        return request.url.scheme == "https"
    return mode == "true"


def _sign(value: str) -> str:
    key = require_secret_key().encode()
    return hmac.new(key, f"csrf:{value}".encode(), hashlib.sha256).hexdigest()


def csrf_seed(request: Request) -> str:
    """Per-browser random seed. Created on first request, stored in a cookie by the middleware."""
    seed = getattr(request.state, "csrf_seed", None)
    if seed is None:
        seed = request.cookies.get(CSRF_COOKIE) or ""
        if len(seed) < 32:
            seed = secrets.token_urlsafe(32)
            request.state.csrf_new = True
        request.state.csrf_seed = seed
    return seed


def csrf_token(request: Request) -> str:
    return _sign(csrf_seed(request))


async def csrf_protect(request: Request) -> None:
    """Router dependency: every state-changing request must carry a valid token."""
    if request.method in SAFE_METHODS:
        return
    seed = request.cookies.get(CSRF_COOKIE, "")
    sent = request.headers.get(CSRF_HEADER, "")
    if not sent:
        form = await request.form()
        sent = str(form.get(CSRF_FIELD, ""))
    if not seed or not sent or not hmac.compare_digest(sent, _sign(seed)):
        raise HTTPException(status_code=403, detail="CSRF check failed")


def apply_security(request: Request, response: Response) -> Response:
    """Set security headers and, if new, the CSRF seed cookie."""
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith(("/dashboard", "/cves", "/products", "/users", "/settings", "/api")):
        response.headers.setdefault("Cache-Control", "no-store")
    if getattr(request.state, "csrf_new", False):
        response.set_cookie(
            CSRF_COOKIE, request.state.csrf_seed,
            httponly=True, samesite="strict", secure=cookie_is_secure(request), path="/",
        )
    return response
