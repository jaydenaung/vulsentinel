# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Session auth — password hashing and signed cookie sessions."""

import os
from typing import Optional

import bcrypt
from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from web.db import get_db

SECRET_KEY = os.environ.get("CVE_SECRET_KEY", "dev-secret-key-change-in-production")
SESSION_COOKIE = "cve_session"
SESSION_MAX_AGE = 86400 * 7  # 7 days

_serializer = URLSafeTimedSerializer(SECRET_KEY)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_session(user_id: int) -> str:
    return _serializer.dumps(user_id)


def get_session_user(request: Request) -> Optional[dict]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        user_id = _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def authenticate_user(username: str, password: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    if not row:
        return None
    user = dict(row)
    if not verify_password(password, user["password_hash"]):
        return None
    return user
