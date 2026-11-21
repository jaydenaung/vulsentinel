# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Pydantic models for every form and query input. Validate at the boundary."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Action = Literal["PATCH NOW", "MONITOR", "LOW PRIORITY"]
Status = Literal["open", "accepted", "in_remediation", "mitigated"]
Role = Literal["admin", "viewer"]

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")


class _Form(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")


class ProductForm(_Form):
    name: str = Field(min_length=1, max_length=100)
    keyword: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)

    @field_validator("keyword")
    @classmethod
    def lower_keyword(cls, v: str) -> str:
        return v.lower()


class UserForm(_Form):
    username: str
    email: str = Field(max_length=254)
    role: Role = "viewer"

    @field_validator("username")
    @classmethod
    def check_username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("3-64 chars: letters, digits, dot, dash, underscore")
        return v

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        if not EMAIL_RE.match(v):
            raise ValueError("invalid email")
        return v.lower()


class SettingsForm(_Form):
    check_interval_hours: int = Field(ge=1, le=720)
    check_days_lookback: int = Field(ge=1, le=120)  # NVD max publish-date range is 120 days
    max_cves_per_product: int = Field(ge=1, le=2000)
    nvd_rate_limit_delay: float = Field(ge=0.6, le=60)
    env_context: str = Field(default="", max_length=8000)


class CveUpdateForm(_Form):
    status: Status
    notes: str = Field(default="", max_length=4000)


class CveFilters(_Form):
    product_id: int | None = Field(default=None, ge=1)
    action: Action | None = None
    status: Status | None = None
    search: str = Field(default="", max_length=100)
    page: int = Field(default=1, ge=1, le=10000)

    @classmethod
    def from_query(cls, params: dict[str, str]) -> "CveFilters":
        """Drop empty and invalid values instead of failing the whole page."""
        clean: dict[str, str] = {}
        for key in cls.model_fields:
            value = params.get(key, "").strip()
            if not value:
                continue
            try:
                cls.model_validate({key: value})
            except ValueError:
                continue
            clean[key] = value
        return cls.model_validate(clean)
