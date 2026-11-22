# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Shared Jinja2 templates with CSRF token and allowlisted flash messages."""

import os
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

from web.security import csrf_token

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Only these strings may be shown from ?msg= / ?error=. Anything else is dropped,
# so a crafted link cannot put attacker text into a trusted-looking banner.
FLASH_MESSAGES = frozenset({
    "Check started", "Check already in progress",
    "Daily run started", "Daily run already in progress",
    "Updated successfully", "Invalid status",
    "Product added successfully", "Product deleted", "Name and keyword are required",
    "Could not add product", "Invalid product details",
    "User created successfully", "User deleted", "Password updated",
    "Password must be at least 8 characters", "Cannot delete your own account",
    "Could not create user (username or email may already exist)", "Invalid user details",
    "Settings saved", "Invalid settings value",
})


def safe_flash(value: str | None) -> str | None:
    return value if value in FLASH_MESSAGES else None


def _context(request: Request) -> dict[str, Any]:
    return {
        "csrf_token": csrf_token(request),
        "flash_msg": safe_flash(request.query_params.get("msg")),
        "flash_err": safe_flash(request.query_params.get("error")),
    }


templates = Jinja2Templates(directory=TEMPLATE_DIR, context_processors=[_context])
