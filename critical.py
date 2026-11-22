# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Pure rules for the daily critical feed: what counts as critical, risk score, watchlist match.

No network, no database, no AI. Every number here can be explained to the user.
"""

import re
from typing import Any, Literal

from settings import get_settings

Reason = Literal["cvss", "kev", "epss", "news"]
REASON_LABELS: dict[str, str] = {
    "cvss": "CVSS 9+", "kev": "New in KEV", "epss": "EPSS 0.5+", "news": "In the news",
}


def severity(cvss: float | None) -> str:
    if cvss is None:
        return "none"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    return "medium" if cvss >= 4.0 else "low"


def critical_reasons(
    cvss: float | None, kev_added_recently: bool, epss_crossed: bool,
) -> list[Reason]:
    cfg = get_settings()
    reasons: list[Reason] = []
    if cvss is not None and cvss >= cfg.critical_cvss_min:
        reasons.append("cvss")
    if kev_added_recently:
        reasons.append("kev")
    if epss_crossed:
        reasons.append("epss")
    return reasons


def risk_score(
    cvss: float | None, in_kev: bool, ransomware: bool, epss: float | None, watched: bool,
) -> tuple[int, dict[str, int]]:
    """0-100 score and the points each factor added."""
    cfg = get_settings()
    parts = {
        "cvss": round((cvss or 0.0) * cfg.risk_cvss_weight),
        "kev": cfg.risk_kev_points if in_kev else 0,
        "ransomware": cfg.risk_ransomware_points if in_kev and ransomware else 0,
        "epss": round((epss or 0.0) * cfg.risk_epss_weight),
        "watchlist": cfg.risk_watchlist_points if watched else 0,
    }
    parts = {k: v for k, v in parts.items() if v}
    return min(100, sum(parts.values())), parts


def _word(keyword: str) -> re.Pattern[str]:
    # Word match that does not treat "admin.php" or "nginx-ui" style tokens as the product itself.
    return re.compile(rf"(?<![\w.\-/]){re.escape(keyword.lower())}(?![\w\-/]|\.\w)")


def match_products(
    products: list[dict[str, Any]], affected: list[tuple[str, str]], description: str,
) -> dict[int, str]:
    """product_id -> how it matched ("affected" from the vendor record, else "keyword")."""
    matches: dict[int, str] = {}
    names = [f"{v} {p}".lower() for v, p in affected]
    text = description.lower()
    for prod in products:
        pattern = _word(prod["keyword"])
        if names and any(pattern.search(n) for n in names):
            matches[prod["id"]] = "affected"
        elif not names and pattern.search(text):
            matches[prod["id"]] = "keyword"
    return matches
