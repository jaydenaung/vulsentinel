"""Settings page (admin only)."""

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from web.auth import get_session_user
from web.db import get_setting, set_setting
from web.forms import SettingsForm
from web.scheduler import reschedule
from web.templating import templates

router = APIRouter()

SETTING_DEFAULTS = {
    "check_interval_hours": "24",
    "check_days_lookback": "7",
    "max_cves_per_product": "50",
    "nvd_rate_limit_delay": "6.5",
    "env_context": "",
}


def _admin(request: Request) -> dict | None:
    user = get_session_user(request)
    return user if user and user["role"] == "admin" else None


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/dashboard", status_code=303)

    cfg = {key: get_setting(key, default) for key, default in SETTING_DEFAULTS.items()}
    return templates.TemplateResponse(request, "settings.html", {
        "user": user,
        "active_page": "settings",
        "cfg": cfg,
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
    if not _admin(request):
        return RedirectResponse("/dashboard", status_code=303)

    try:
        form = SettingsForm(
            check_interval_hours=check_interval_hours,
            check_days_lookback=check_days_lookback,
            max_cves_per_product=max_cves_per_product,
            nvd_rate_limit_delay=nvd_rate_limit_delay,
            env_context=env_context,
        )
    except ValidationError:
        return RedirectResponse("/settings?error=Invalid+settings+value", status_code=303)

    for key, value in form.model_dump().items():
        set_setting(key, str(value))
    reschedule(form.check_interval_hours)

    return RedirectResponse("/settings?msg=Settings+saved", status_code=303)
