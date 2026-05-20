"""First-run setup wizard."""

import os

import yaml
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import hash_password
from web.db import get_db, get_setting, init_db, set_setting, user_count

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    if user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    config_assets = _load_config_assets()
    return templates.TemplateResponse(request, "setup.html", {
        "config_assets": config_assets,
        "config_env_context": _load_config_env_context(),
    })


@router.post("/setup")
async def setup_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    import_assets: bool = Form(False),
):
    if user_count() > 0:
        return RedirectResponse("/login", status_code=303)

    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if not username.strip():
        errors.append("Username is required.")

    if errors:
        return templates.TemplateResponse(request, "setup.html", {
            "errors": errors,
            "config_assets": _load_config_assets(),
            "config_env_context": _load_config_env_context(),
        }, status_code=400)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
            (username.strip(), email.strip(), hash_password(password)),
        )

    # Optionally import assets from config.yaml
    if import_assets:
        assets = _load_config_assets()
        if assets:
            with get_db() as conn:
                for kw in assets:
                    conn.execute(
                        "INSERT OR IGNORE INTO assets (name, keyword, description) VALUES (?, ?, ?)",
                        (kw.title(), kw, f"Imported from config.yaml"),
                    )

    # Import env_context from config.yaml if available
    env = _load_config_env_context()
    if env and not get_setting("env_context"):
        set_setting("env_context", env)

    return RedirectResponse("/login?setup=1", status_code=303)


def _load_config_assets() -> list[str]:
    try:
        with open("config.yaml", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
            return cfg.get("products", [])
    except FileNotFoundError:
        return []


def _load_config_env_context() -> str:
    try:
        with open("config.yaml", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
            return cfg.get("scoring", {}).get("environment_context", "")
    except FileNotFoundError:
        return ""
