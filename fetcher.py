# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""NVD API v2 client — fetches CVEs by product keyword."""

import time
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import requests


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_request(params: dict[str, Any], delay: float) -> dict[str, Any]:
    """Make a single request to NVD API with rate-limit delay."""
    time.sleep(delay)
    resp = requests.get(NVD_API_BASE, params=params, timeout=30)
    if resp.status_code == 429:
        print("  [rate-limited] waiting 30s...", file=sys.stderr)
        time.sleep(30)
        resp = requests.get(NVD_API_BASE, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_cves(
    product: str,
    days: int,
    rate_limit_delay: float = 6.5,
    max_results: int = 50,
) -> list[dict[str, Any]]:
    """Fetch CVEs for a product published within the last N days.

    Args:
        product: Keyword to search (e.g. "kubernetes", "nginx").
        days: Number of days to look back.
        rate_limit_delay: Seconds to sleep before each API call.
        max_results: Cap on results per product.

    Returns:
        List of CVE dicts (NVD v2 cve objects).

    Raises:
        requests.HTTPError: On non-2xx response after retry.
    """
    end = datetime.now(tz=timezone.utc)
    start = end - timedelta(days=days)

    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    params: dict[str, Any] = {
        "keywordSearch": product,
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": min(max_results, 50),
        "startIndex": 0,
    }

    data = _nvd_request(params, rate_limit_delay)
    vulns = data.get("vulnerabilities", [])
    return [v["cve"] for v in vulns if "cve" in v]


def extract_cvss_score(cve: dict[str, Any]) -> float | None:
    """Extract the highest available CVSS score from a CVE object."""
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        for entry in entries:
            score = (
                entry.get("cvssData", {}).get("baseScore")
                or entry.get("baseScore")
            )
            if score is not None:
                return float(score)
    return None


def extract_description(cve: dict[str, Any]) -> str:
    """Return the first English description of a CVE."""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "No description available.")
    return "No description available."


def format_cve_summary(cve: dict[str, Any], product: str) -> dict[str, Any]:
    """Flatten a raw NVD CVE object into a concise summary dict."""
    cve_id = cve.get("id", "UNKNOWN")
    published = cve.get("published", "")[:10]
    description = extract_description(cve)
    cvss = extract_cvss_score(cve)
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return {
        "cve_id": cve_id,
        "product": product,
        "published": published,
        "cvss_score": cvss,
        "description": description,
        "nvd_url": nvd_url,
    }
