"""First-run setup wizard."""

import sqlite3

import yaml
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from web.auth import hash_password, password_problem
from web.db import get_db, get_setting, set_setting, user_count
from web.forms import ProductForm, UserForm
from web.templating import templates

router = APIRouter()


def _render(request: Request, errors: list[str] | None = None, status_code: int = 200):
    return templates.TemplateResponse(request, "setup.html", {
        "errors": errors or [],
        "config_products": _load_config_products(),
        "config_env_context": _load_config_env_context(),
    }, status_code=status_code)


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    if user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    return _render(request)


@router.post("/setup")
async def setup_submit(
    request: Request,
    username: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    import_products: bool = Form(False),
):
    if user_count() > 0:
        return RedirectResponse("/login", status_code=303)

    errors: list[str] = []
    problem = password_problem(password)
    if problem:
        errors.append(problem + ".")
    try:
        form = UserForm(username=username, email=email, role="admin")
    except ValidationError:
        form = None
        errors.append("Username must be 3-64 letters, digits, dot, dash or underscore, with a valid email.")
    if errors or form is None:
        return _render(request, errors, status_code=400)

    try:
        with get_db() as conn:
            # Re-check inside the write so two concurrent setups cannot both create an admin.
            if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
                return RedirectResponse("/login", status_code=303)
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (form.username, form.email, hash_password(password)),
            )
    except sqlite3.IntegrityError:
        return _render(request, ["Could not create the admin account."], status_code=400)

    if import_products:
        _import_config_products()

    env = _load_config_env_context()
    if env and not get_setting("env_context"):
        set_setting("env_context", env[:8000])

    return RedirectResponse("/login?setup=1", status_code=303)


def _import_config_products() -> None:
    with get_db() as conn:
        for kw in _load_config_products():
            try:
                product = ProductForm(name=str(kw).title(), keyword=str(kw), description="Imported from config.yaml")
            except ValidationError:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO products (name, keyword, description) VALUES (?, ?, ?)",
                (product.name, product.keyword, product.description),
            )


def _load_config() -> dict:
    try:
        with open("config.yaml", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
    except (FileNotFoundError, yaml.YAMLError):
        return {}
    return cfg if isinstance(cfg, dict) else {}


def _load_config_products() -> list[str]:
    products = _load_config().get("products", [])
    return [str(p) for p in products] if isinstance(products, list) else []


def _load_config_env_context() -> str:
    scoring = _load_config().get("scoring", {})
    return str(scoring.get("environment_context", "")) if isinstance(scoring, dict) else ""
