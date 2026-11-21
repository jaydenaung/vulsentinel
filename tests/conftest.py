"""Test-wide setup. Runs before any project module reads settings."""

import os

os.environ["CVE_SECRET_KEY"] = "test-secret-key-0123456789-abcdefghijklmnop"
os.environ.setdefault("CVE_COOKIE_SECURE", "auto")
