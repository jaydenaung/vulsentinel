# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Single settings module. All runtime config comes from here, read from env once."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr

ENV_PREFIX_MAP = {
    "anthropic_model": "VULSENTINEL_MODEL",
    "anthropic_max_tokens": "VULSENTINEL_MAX_TOKENS",
    "max_agent_turns": "VULSENTINEL_MAX_AGENT_TURNS",
    "secret_key": "CVE_SECRET_KEY",
    "cookie_secure": "CVE_COOKIE_SECURE",
    "nvd_api_key": "NVD_API_KEY",
}


class Settings(BaseModel):
    # Claude
    anthropic_model: str = Field(default="claude-sonnet-4-6", min_length=1)
    anthropic_max_tokens: int = Field(default=4096, ge=256, le=64000)
    max_agent_turns: int = Field(default=6, ge=2, le=20)
    triage_prompt_version: str = "v3"

    # Deterministic triage rules (decide without AI)
    rule_low_cvss_below: float = Field(default=4.0, ge=0, le=10)  # CVSS under this ...
    rule_low_epss_below: float = Field(default=0.05, ge=0, le=1)  # ... and EPSS under this = LOW PRIORITY
    ai_batch_size: int = Field(default=10, ge=1, le=25)  # gray-zone CVEs per Claude request
    epss_bulk_size: int = Field(default=100, ge=1, le=100)  # CVEs per EPSS API request

    # Daily critical feed (no AI). A CVE is critical if ANY rule matches.
    critical_cvss_min: float = Field(default=9.0, ge=0, le=10)
    critical_epss_min: float = Field(default=0.5, ge=0, le=1)  # newly crossing this counts
    daily_lookback_days: int = Field(default=2, ge=1, le=30)  # overlap so late records are not missed
    daily_max_lookups: int = Field(default=500, ge=1, le=2000)  # cve.org lookups per run (known ones skipped)
    cve_org_api: str = "https://cveawg.mitre.org/api/cve/"
    cve_org_delay_seconds: float = Field(default=0.2, ge=0, le=5)

    # Risk score weights (0-100). Shown to the user as a breakdown, so keep them simple.
    risk_cvss_weight: float = 3.0  # x CVSS, max 30
    risk_kev_points: int = 35
    risk_ransomware_points: int = 10
    risk_epss_weight: float = 15.0  # x EPSS, max 15
    risk_watchlist_points: int = 10

    # Enrichment sources
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    kev_cache_ttl_seconds: float = Field(default=3600.0, ge=60)
    http_timeout_seconds: float = Field(default=15.0, gt=0, le=120)

    # NVD API v2
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: SecretStr | None = None
    nvd_page_size: int = Field(default=2000, ge=1, le=2000)  # NVD maximum per page
    nvd_max_window_days: int = Field(default=120, ge=1, le=120)  # NVD maximum date range
    nvd_keyed_delay_seconds: float = 0.6  # 50 requests / 30s with a key
    nvd_max_retries: int = Field(default=3, ge=0, le=6)

    # Web
    secret_key: SecretStr | None = None
    cookie_secure: Literal["auto", "true", "false"] = "auto"
    session_max_age_seconds: int = 86400 * 7


# USD per million tokens (input, output). Used only for the token meter estimate.
MODEL_PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-haiku-4-5": (1.00, 5.00),
}


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float | None:
    prices = MODEL_PRICES_PER_MTOK.get(model)
    if prices is None:
        return None
    return round((input_tokens * prices[0] + output_tokens * prices[1]) / 1_000_000, 6)


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or unsafe."""


MIN_SECRET_LENGTH = 32


def load_dotenv(path: str | Path = ".env") -> None:
    """Minimal .env loader (stdlib only). Never overrides variables already set."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    values = {field: os.environ[env] for field, env in ENV_PREFIX_MAP.items() if env in os.environ}
    if "cookie_secure" in values:
        values["cookie_secure"] = values["cookie_secure"].strip().lower()
    return Settings(**values)


def require_secret_key() -> str:
    """Return the session signing key, or fail loudly. Called at web startup."""
    secret = get_settings().secret_key
    value = secret.get_secret_value() if secret else ""
    if len(value) < MIN_SECRET_LENGTH:
        raise ConfigError(
            f"CVE_SECRET_KEY must be set and at least {MIN_SECRET_LENGTH} characters. "
            'Generate one: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    return value
