# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Deterministic enrichment: CISA KEV (cached catalog) and EPSS (bulk API). No AI."""

import logging
import re
import time
from typing import Any

import requests
from pydantic import BaseModel, Field

from settings import get_settings

log = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_kev_cache: dict[str, Any] | None = None
_kev_fetched_at: float = 0.0


class Evidence(BaseModel):
    in_kev: bool | None = None  # None = KEV lookup failed
    kev_date_added: str | None = None
    kev_ransomware: bool = False
    epss_score: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)


def kev_catalog() -> dict[str, Any]:
    """cveID -> KEV entry. Cached for kev_cache_ttl_seconds."""
    global _kev_cache, _kev_fetched_at
    cfg = get_settings()
    now = time.monotonic()
    if _kev_cache is None or (now - _kev_fetched_at) > cfg.kev_cache_ttl_seconds:
        resp = requests.get(cfg.cisa_kev_url, timeout=cfg.http_timeout_seconds)
        resp.raise_for_status()
        _kev_cache = {v["cveID"]: v for v in resp.json().get("vulnerabilities", []) if "cveID" in v}
        _kev_fetched_at = now
        log.info("KEV catalog loaded: %d entries", len(_kev_cache))
    return _kev_cache


def _epss_bulk(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    cfg = get_settings()
    scores: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cve_ids), cfg.epss_bulk_size):
        chunk = cve_ids[i:i + cfg.epss_bulk_size]
        resp = requests.get(cfg.epss_api_url, params={"cve": ",".join(chunk)}, timeout=cfg.http_timeout_seconds)
        resp.raise_for_status()
        for item in resp.json().get("data", []):
            try:
                scores[str(item["cve"]).upper()] = (float(item["epss"]), float(item["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    return scores


def enrich(cve_ids: list[str]) -> dict[str, Evidence]:
    """KEV + EPSS for many CVEs at once. Failures degrade to unknown, never raise."""
    ids = sorted({c for c in cve_ids if CVE_ID_RE.match(c)})
    evidence = {c: Evidence() for c in ids}
    if not ids:
        return evidence

    try:
        catalog = kev_catalog()
        for c in ids:
            entry = catalog.get(c)
            evidence[c].in_kev = entry is not None
            if entry:
                evidence[c].kev_date_added = entry.get("dateAdded")
                evidence[c].kev_ransomware = entry.get("knownRansomwareCampaignUse") == "Known"
    except (requests.RequestException, ValueError) as exc:
        log.warning("KEV lookup failed: %s", type(exc).__name__)

    try:
        for c, (epss, pct) in _epss_bulk(ids).items():
            if c in evidence:
                evidence[c].epss_score, evidence[c].epss_percentile = epss, pct
    except (requests.RequestException, ValueError) as exc:
        log.warning("EPSS bulk lookup failed: %s", type(exc).__name__)

    return evidence


def epss_above(threshold: float) -> dict[str, float]:
    """Every CVE whose EPSS is above threshold, in one request (about 4,400 at 0.5)."""
    cfg = get_settings()
    resp = requests.get(cfg.epss_api_url, params={"epss-gt": str(threshold), "limit": 20000},
                        timeout=max(cfg.http_timeout_seconds, 60))
    resp.raise_for_status()
    scores: dict[str, float] = {}
    for item in resp.json().get("data", []):
        try:
            cve_id = str(item["cve"]).upper()
            if CVE_ID_RE.match(cve_id):
                scores[cve_id] = float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
    return scores
