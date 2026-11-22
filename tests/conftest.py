"""Test-wide setup. Runs before any project module reads settings."""

import os

os.environ["CVE_SECRET_KEY"] = "test-secret-key-0123456789-abcdefghijklmnop"
os.environ.setdefault("CVE_COOKIE_SECURE", "auto")

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    from web import ratelimit
    ratelimit.reset()
    yield
