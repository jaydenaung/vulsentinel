# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""NVD API v2 client: fetches CVEs by product keyword, with paging and rate limiting."""

import logging
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import requests

from settings import get_settings

log = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RETRY_STATUSES = {429, 500, 502, 503, 504}
CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class NVDError(RuntimeError):
    """NVD request failed after retries, or returned an unexpected shape."""


def _effective_delay(requested: float) -> float:
    """With an API key NVD allows ~10x the rate, so the delay can drop."""
    cfg = get_settings()
    return min(requested, cfg.nvd_keyed_delay_seconds) if cfg.nvd_api_key else requested


def _headers() -> dict[str, str]:
    key = get_settings().nvd_api_key
    return {"apiKey": key.get_secret_value()} if key else {}


def _retry_wait(resp: requests.Response, attempt: int) -> float:
    header = resp.headers.get("Retry-After", "")
    if header.isdigit():
        return min(float(header), 120.0)
    return min(30.0 * (attempt + 1), 120.0)


def _nvd_request(session: requests.Session, params: dict[str, Any], delay: float) -> dict[str, Any]:
    """One NVD request: sleep for rate limiting, retry on 429/5xx with backoff."""
    cfg = get_settings()
    for attempt in range(cfg.nvd_max_retries + 1):
        time.sleep(delay)
        resp = session.get(cfg.nvd_api_base, params=params, headers=_headers(), timeout=30)
        if resp.status_code not in RETRY_STATUSES:
            break
        if attempt == cfg.nvd_max_retries:
            break
        wait = _retry_wait(resp, attempt)
        log.warning("NVD returned %s, retrying in %.0fs (attempt %d)", resp.status_code, wait, attempt + 1)
        time.sleep(wait)
    if resp.status_code != 200:
        raise NVDError(f"NVD request failed with HTTP {resp.status_code}")
    data = resp.json()
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities", []), list):
        raise NVDError("Unexpected NVD response shape")
    return data


def _windows(days: int, now: datetime) -> list[tuple[datetime, datetime]]:
    """Split the look-back into ranges NVD accepts (max 120 days each), newest first."""
    step = timedelta(days=get_settings().nvd_max_window_days)
    start_limit = now - timedelta(days=days)
    windows: list[tuple[datetime, datetime]] = []
    end = now
    while end > start_limit:
        start = max(end - step, start_limit)
        windows.append((start, end))
        end = start
    return windows


def _fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_cves(
    product: str,
    days: int,
    rate_limit_delay: float = 6.5,
    max_results: int = 50,
) -> list[dict[str, Any]]:
    """Fetch up to max_results CVEs for a keyword published in the last N days.

    Pages through results and splits long look-backs into 120-day windows.

    Raises:
        ValueError: on invalid arguments.
        NVDError: when NVD fails after retries.
        requests.RequestException: on network errors.
    """
    if not product.strip() or len(product) > 100:
        raise ValueError("product keyword must be 1-100 characters")
    if days < 1 or max_results < 1:
        raise ValueError("days and max_results must be positive")

    cfg = get_settings()
    delay = _effective_delay(rate_limit_delay)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    with requests.Session() as session:
        for start, end in _windows(days, datetime.now(tz=UTC)):
            need = max_results - len(results)
            index = 0
            first_page = True
            while len(results) < max_results:
                params: dict[str, Any] = {
                    "keywordSearch": product,
                    "pubStartDate": _fmt(start),
                    "pubEndDate": _fmt(end),
                    "resultsPerPage": min(cfg.nvd_page_size, max_results - len(results)),
                    "startIndex": index,
                }
                data = _nvd_request(session, params, delay)
                total = int(data.get("totalResults", 0) or 0)
                if first_page and total > need:
                    # NVD sorts oldest first. Skip to the tail so we keep the newest CVEs.
                    first_page = False
                    index = total - need
                    continue
                first_page = False
                page = [
                    v["cve"] for v in data["vulnerabilities"]
                    if isinstance(v, dict) and isinstance(v.get("cve"), dict)
                ]
                for cve in page:
                    cve_id = cve.get("id", "")
                    if CVE_ID_RE.match(str(cve_id)) and cve_id not in seen:
                        seen.add(cve_id)
                        results.append(cve)
                index += len(page)
                if not page or index >= total:
                    break
            if len(results) >= max_results:
                break

    results.sort(key=lambda c: str(c.get("published", "")), reverse=True)
    log.info("NVD: %d CVE(s) for %r over %d day(s)", len(results), product, days)
    return results[:max_results]


def extract_cvss_score(cve: dict[str, Any]) -> float | None:
    """Highest base score from the newest CVSS version present (v4.0, then v3.1, v3.0, v2)."""
    metrics = cve.get("metrics", {}) or {}
    for key in CVSS_KEYS:
        scores = []
        for entry in metrics.get(key, []) or []:
            score = (entry.get("cvssData") or {}).get("baseScore")
            if score is None:
                score = entry.get("baseScore")
            if isinstance(score, (int, float)):
                scores.append(float(score))
        if scores:
            return max(scores)
    return None


def extract_description(cve: dict[str, Any]) -> str:
    """Return the first English description of a CVE."""
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            return str(desc.get("value") or "No description available.")
    return "No description available."


def format_cve_summary(cve: dict[str, Any], product: str) -> dict[str, Any]:
    """Flatten a raw NVD CVE object into a concise summary dict."""
    cve_id = str(cve.get("id", "UNKNOWN"))
    return {
        "cve_id": cve_id,
        "product": product,
        "published": str(cve.get("published", ""))[:10],
        "cvss_score": extract_cvss_score(cve),
        "description": extract_description(cve),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
