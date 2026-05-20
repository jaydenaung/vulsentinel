"""Settings page (admin only)."""

import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.auth import get_session_user
from web.db import get_setting, set_setting
from web.scheduler import reschedule

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    cfg = {
        "check_interval_hours": get_setting("check_interval_hours", "24"),
        "check_days_lookback": get_setting("check_days_lookback", "7"),
        "max_cves_per_product": get_setting("max_cves_per_product", "50"),
        "nvd_rate_limit_delay": get_setting("nvd_rate_limit_delay", "6.5"),
        "env_context": get_setting("env_context", ""),
    }

    return templates.TemplateResponse(request, "settings.html", {
        "user": user,
        "active_page": "settings",
        "cfg": cfg,
        "msg": request.query_params.get("msg"),
    })


@router.post("/settings")
async def save_settings(
    request: Request,
    check_interval_hours: str = Form("24"),
    check_days_lookback: str = Form("7"),
    max_cves_per_product: str = Form("50"),
    nvd_rate_limit_delay: str = Form("6.5"),
    env_context: str = Form(""),
):
    user = get_session_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)

    try:
        hours = max(1, int(check_interval_hours))
        int(check_days_lookback)
        int(max_cves_per_product)
        float(nvd_rate_limit_delay)
    except ValueError:
        return RedirectResponse("/settings?msg=Invalid+numeric+value", status_code=303)

    set_setting("check_interval_hours", str(hours))
    set_setting("check_days_lookback", check_days_lookback)
    set_setting("max_cves_per_product", max_cves_per_product)
    set_setting("nvd_rate_limit_delay", nvd_rate_limit_delay)
    set_setting("env_context", env_context.strip())

    reschedule(hours)

    return RedirectResponse("/settings?msg=Settings+saved", status_code=303)
