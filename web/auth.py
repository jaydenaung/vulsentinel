# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Session auth: password hashing and signed cookie sessions."""

from functools import lru_cache

import bcrypt
from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from starlette.responses import Response

from settings import get_settings, require_secret_key
from web.db import get_db
from web.security import cookie_is_secure

SESSION_COOKIE = "cve_session"
MAX_PASSWORD_BYTES = 72  # bcrypt limit; longer input is rejected, not silently truncated

# Hash compared against when the username does not exist, so login timing
# does not reveal which usernames are valid.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt()).decode()


@lru_cache(maxsize=1)
def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(require_secret_key(), salt="cve-session")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def password_problem(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        return "Invalid user details"
    return None


def create_session(user_id: int, session_version: int) -> str:
    """Signed [user_id, version]. Bumping the user's version revokes every older cookie."""
    return _serializer().dumps([user_id, session_version])


def revoke_sessions(user_id: int) -> None:
    """Invalidate all of a user's sessions (password change, logout everywhere)."""
    with get_db() as conn:
        conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (user_id,))


def set_session_cookie(request: Request, response: Response, user_id: int, session_version: int) -> None:
    response.set_cookie(
        SESSION_COOKIE, create_session(user_id, session_version),
        max_age=get_settings().session_max_age_seconds,
        httponly=True, samesite="lax", secure=cookie_is_secure(request), path="/",
    )


def clear_session_cookie(request: Request, response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax",
                           secure=cookie_is_secure(request))


def get_session_user(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        payload = _serializer().loads(token, max_age=get_settings().session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    # Old cookies held a bare user id; they no longer validate, so users log in once more.
    if not (isinstance(payload, list) and len(payload) == 2 and all(type(x) is int for x in payload)):
        return None
    user_id, version = payload
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, email, role, created_at, session_version FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if not row or row["session_version"] != version:
        return None
    user = dict(row)
    user.pop("session_version")
    return user


def authenticate_user(username: str, password: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        verify_password(password, _DUMMY_HASH)
        return None
    user = dict(row)
    if not verify_password(password, user.pop("password_hash")):
        return None
    return user
