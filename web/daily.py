# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Daily critical feed collector. Deterministic, no AI.

Sources, in one run:
  NVD        every CVE published in the lookback window, kept if CVSS >= 9
  CISA KEV   entries added in the window
  EPSS       CVEs that newly crossed 0.5 (first run stores a baseline instead)
  cve.org    vendor's affected product list, for watchlist matching
"""

import json
import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import requests
from pydantic import BaseModel

import critical
from cve_org import CveRecord, fetch_record
from enrichment import Evidence, enrich, epss_above, kev_catalog
from fetcher import extract_cvss_score, extract_description, fetch_published
from settings import get_settings
from web.db import get_db, get_setting

log = logging.getLogger(__name__)
_lock = threading.Lock()
daily_state: dict[str, Any] = {"is_running": False, "run_id": None, "stage": None}


class Candidate(BaseModel):
    cve_id: str
    published: str = ""
    description: str = ""
    cvss_score: float | None = None
    affected: list[tuple[str, str]] = []
    kev_new: bool = False
    epss_crossed: bool = False


class DailyStats(BaseModel):
    nvd_fetched: int = 0
    critical_new: int = 0
    critical_updated: int = 0
    kev_new: int = 0
    epss_crossers: int = 0
    watchlist_hits: int = 0


def is_daily_running() -> bool:
    return bool(daily_state["is_running"])


def run_daily(triggered_by: str = "manual", days: int | None = None) -> int | None:
    """Collect today's criticals. Returns the daily_runs id, or None if a run is in progress."""
    if not _lock.acquire(blocking=False):
        return None
    run_id: int | None = None
    try:
        with get_db() as conn:
            run_id = conn.execute("INSERT INTO daily_runs (triggered_by) VALUES (?)", (triggered_by,)).lastrowid
        daily_state.update(is_running=True, run_id=run_id, stage="starting")
        stats = collect(days or get_settings().daily_lookback_days)
        _finish(run_id, "completed", stats)
        return run_id
    except Exception:
        log.exception("Daily run %s failed", run_id)
        if run_id:
            _finish(run_id, "failed", DailyStats(), error="Daily run failed, see server log")
        return run_id
    finally:
        daily_state.update(is_running=False, stage=None)
        _lock.release()


def collect(days: int) -> DailyStats:
    cfg = get_settings()
    stats = DailyStats()
    candidates: dict[str, Candidate] = {}

    daily_state["stage"] = "NVD"
    rate_delay = float(get_setting("nvd_rate_limit_delay", "6.5"))
    published = fetch_published(days, rate_limit_delay=rate_delay)
    stats.nvd_fetched = len(published)
    for cve in published:
        score = extract_cvss_score(cve)
        if score is not None and score >= cfg.critical_cvss_min:
            candidates[cve["id"]] = Candidate(
                cve_id=cve["id"], published=str(cve.get("published", ""))[:10],
                description=extract_description(cve), cvss_score=score)

    daily_state["stage"] = "KEV"
    since = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")
    for cve_id, entry in kev_catalog().items():
        if str(entry.get("dateAdded", "")) >= since:
            kev_text = str(entry.get("shortDescription", ""))
            c = candidates.setdefault(cve_id, Candidate(cve_id=cve_id, description=kev_text))
            c.kev_new = True
            stats.kev_new += 1

    daily_state["stage"] = "EPSS"
    for cve_id in _epss_crossers():
        candidates.setdefault(cve_id, Candidate(cve_id=cve_id)).epss_crossed = True
        stats.epss_crossers += 1

    daily_state["stage"] = "cve.org"
    _fill_from_cve_org(list(candidates.values()))

    daily_state["stage"] = "Scoring"
    evidence = enrich(list(candidates))
    with get_db() as conn:
        products = [dict(r) for r in conn.execute("SELECT id, keyword FROM products WHERE active = 1")]
    for c in candidates.values():
        is_new, watched = _upsert(c, evidence.get(c.cve_id, Evidence()), products)
        stats.critical_new += is_new
        stats.critical_updated += not is_new
        stats.watchlist_hits += watched
    log.info("Daily: %s", stats.model_dump())
    return stats


def _epss_crossers() -> list[str]:
    """CVEs above the EPSS threshold that were not above it before. First run = baseline only."""
    cfg = get_settings()
    try:
        high = epss_above(cfg.critical_epss_min)
    except (requests.RequestException, ValueError) as exc:
        log.warning("EPSS threshold lookup failed: %s", type(exc).__name__)
        return []
    with get_db() as conn:
        known = {r[0] for r in conn.execute("SELECT cve_id FROM epss_baseline")}
        conn.executemany("INSERT OR IGNORE INTO epss_baseline (cve_id, epss_score) VALUES (?, ?)", high.items())
    if not known:
        log.info("EPSS baseline stored: %d CVEs above %.2f (none flagged on first run)",
                 len(high), cfg.critical_epss_min)
        return []
    return sorted(set(high) - known)


def _known_affected(cve_ids: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Vendor product lists already stored, so re-runs do not look them up again."""
    with get_db() as conn:
        rows = conn.execute("SELECT cve_id, affected FROM vulns WHERE affected != '[]'").fetchall()
    wanted = set(cve_ids)
    return {r[0]: [tuple(x) for x in json.loads(r[1])] for r in rows if r[0] in wanted}  # type: ignore[misc]


def _fill_from_cve_org(candidates: list[Candidate]) -> None:
    """Affected products for all; description/score/date where NVD did not provide them."""
    cfg = get_settings()
    known = _known_affected([c.cve_id for c in candidates])
    for c in candidates:
        c.affected = known.get(c.cve_id, [])
    todo = [c for c in candidates if c.cve_id not in known]
    with requests.Session() as session:
        for c in todo[:cfg.daily_max_lookups]:
            record: CveRecord | None = fetch_record(session, c.cve_id)
            time.sleep(cfg.cve_org_delay_seconds)
            if record is None:
                continue
            c.affected = record.affected
            c.description = c.description or record.description
            c.published = c.published or record.published
            if c.cvss_score is None:
                c.cvss_score = record.cvss_score
    if len(todo) > cfg.daily_max_lookups:
        log.warning("cve.org lookups capped at %d of %d, the rest next run", cfg.daily_max_lookups, len(todo))


def _upsert(c: Candidate, ev: Evidence, products: list[dict[str, Any]]) -> tuple[bool, bool]:
    """Insert or refresh one critical. Analyst status, notes and first_seen are kept."""
    matches = critical.match_products(products, c.affected, c.description)
    reasons = critical.critical_reasons(c.cvss_score, c.kev_new, c.epss_crossed)
    score, breakdown = critical.risk_score(c.cvss_score, bool(ev.in_kev), ev.kev_ransomware, ev.epss_score,
                                           bool(matches))
    with get_db() as conn:
        row = conn.execute("SELECT critical_reasons FROM vulns WHERE cve_id = ?", (c.cve_id,)).fetchone()
        if row:
            reasons = sorted(set(json.loads(row[0])) | set(reasons))  # a reason, once earned, stays
        conn.execute(
            """
            INSERT INTO vulns (cve_id, published, cvss_score, severity, description, affected, in_kev,
                               kev_date_added, kev_ransomware, epss_score, critical_reasons, risk_score,
                               risk_breakdown)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                published = COALESCE(NULLIF(excluded.published, ''), vulns.published),
                cvss_score = COALESCE(excluded.cvss_score, vulns.cvss_score),
                severity = excluded.severity,
                description = COALESCE(NULLIF(excluded.description, ''), vulns.description),
                affected = excluded.affected,
                in_kev = excluded.in_kev,
                kev_date_added = excluded.kev_date_added,
                kev_ransomware = excluded.kev_ransomware,
                epss_score = excluded.epss_score,
                critical_reasons = excluded.critical_reasons,
                risk_score = excluded.risk_score,
                risk_breakdown = excluded.risk_breakdown,
                last_updated = datetime('now')
            """,
            (c.cve_id, c.published, c.cvss_score, critical.severity(c.cvss_score), c.description,
             json.dumps(c.affected), int(bool(ev.in_kev)), ev.kev_date_added, int(ev.kev_ransomware),
             ev.epss_score, json.dumps(reasons), score, json.dumps(breakdown)),
        )
        conn.execute("DELETE FROM vuln_products WHERE cve_id = ?", (c.cve_id,))
        conn.executemany("INSERT INTO vuln_products (cve_id, product_id, match_type) VALUES (?, ?, ?)",
                         [(c.cve_id, pid, how) for pid, how in matches.items()])
    return row is None, bool(matches)


def _finish(run_id: int, status: str, stats: DailyStats, error: str | None = None) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE daily_runs SET finished_at = datetime('now'), status = ?, nvd_fetched = ?, critical_new = ?, "
            "critical_updated = ?, kev_new = ?, epss_crossers = ?, watchlist_hits = ?, error = ? WHERE id = ?",
            (status, stats.nvd_fetched, stats.critical_new, stats.critical_updated, stats.kev_new,
             stats.epss_crossers, stats.watchlist_hits, error, run_id),
        )
