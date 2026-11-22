# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Official CVE record (cve.org CVE Services API). Has the vendor's affected product list
and CNA score within hours of publication, while NVD analysis is often deferred."""

import logging
import re
from typing import Any

import requests
from pydantic import BaseModel, Field

from settings import get_settings

log = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
MAX_FIELD = 200


class CveRecord(BaseModel):
    cve_id: str
    published: str = ""
    description: str = ""
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    affected: list[tuple[str, str]] = []  # (vendor, product)


def _cvss(containers: list[dict[str, Any]]) -> float | None:
    """Highest base score from the newest CVSS version any container provides."""
    for key in _CVSS_KEYS:
        scores = [
            float(m[key]["baseScore"])
            for c in containers for m in c.get("metrics", []) or []
            if isinstance(m, dict) and isinstance(m.get(key), dict)
            and isinstance(m[key].get("baseScore"), (int, float))
        ]
        if scores:
            return max(scores)
    return None


def parse_record(cve_id: str, data: dict[str, Any]) -> CveRecord:
    meta = data.get("cveMetadata") or {}
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    all_containers = [cna, *(containers.get("adp") or [])]
    description = next(
        (str(d.get("value", "")) for d in cna.get("descriptions", []) or [] if str(d.get("lang", "")).startswith("en")),
        "",
    )
    affected = [
        (str(a.get("vendor", ""))[:MAX_FIELD], str(a.get("product", ""))[:MAX_FIELD])
        for a in cna.get("affected", []) or [] if isinstance(a, dict)
    ]
    return CveRecord(
        cve_id=cve_id,
        published=str(meta.get("datePublished", ""))[:10],
        description=description[:4000],
        cvss_score=_cvss(all_containers),
        affected=affected[:20],
    )


def fetch_record(session: requests.Session, cve_id: str) -> CveRecord | None:
    """One official record, or None on any failure (logged, never raised)."""
    if not CVE_ID_RE.match(cve_id):
        return None
    cfg = get_settings()
    try:
        resp = session.get(cfg.cve_org_api + cve_id, timeout=cfg.http_timeout_seconds)
        resp.raise_for_status()
        data = resp.json()
        return parse_record(cve_id, data) if isinstance(data, dict) else None
    except (requests.RequestException, ValueError) as exc:
        log.warning("cve.org lookup failed for %s: %s", cve_id, type(exc).__name__)
        return None
