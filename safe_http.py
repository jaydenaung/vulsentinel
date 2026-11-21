# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Outbound HTTP for admin-configured URLs (feeds). Guards against SSRF.

- https only
- every resolved IP must be public (no private, loopback, link-local, reserved)
- redirects are followed manually and each hop is re-validated
- response size is capped

Known limit: DNS is resolved for the check and again by requests, so a
rebinding attacker could race it. Acceptable for an internal lab tool.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests

USER_AGENT = "VulSentinel/0.2 (feed reader)"
MAX_REDIRECTS = 3


class UnsafeURLError(ValueError):
    """URL failed a safety check."""


class FetchError(RuntimeError):
    """Fetch failed (status, size, network)."""


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"cannot resolve host {host!r}") from exc
    return sorted({info[4][0] for info in infos})


def validate_url(url: str) -> str:
    """Return the URL if it is https and every address it resolves to is public."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsafeURLError("only https URLs are allowed")
    if not parts.hostname or parts.username or parts.password:
        raise UnsafeURLError("URL must have a host and no credentials")
    if parts.port not in (None, 443):
        raise UnsafeURLError("only port 443 is allowed")
    for addr in _resolve(parts.hostname):
        if not ipaddress.ip_address(addr).is_global:
            raise UnsafeURLError(f"host {parts.hostname!r} resolves to a non-public address")
    return url


def fetch_url(url: str, max_bytes: int = 2_000_000, timeout: float = 15.0) -> bytes:
    """GET a public https URL with a size cap. Raises UnsafeURLError or FetchError."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        validate_url(current)
        try:
            resp = requests.get(
                current, headers={"User-Agent": USER_AGENT}, timeout=timeout,
                allow_redirects=False, stream=True,
            )
        except requests.RequestException as exc:
            raise FetchError(f"network error: {type(exc).__name__}") from exc
        with resp:
            if resp.is_redirect:
                location = resp.headers.get("Location", "")
                if not location:
                    raise FetchError("redirect without Location")
                current = urljoin(current, location)
                continue
            if resp.status_code != 200:
                raise FetchError(f"HTTP {resp.status_code}")
            declared = resp.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise FetchError("response too large")
            body = bytearray()
            for chunk in resp.iter_content(chunk_size=65536):
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise FetchError("response too large")
            return bytes(body)
    raise FetchError("too many redirects")
