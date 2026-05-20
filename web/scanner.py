# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Check orchestrator — wraps fetcher + scorer and persists results to DB."""

import threading
from datetime import datetime
from typing import Any, Optional

from fetcher import fetch_cves, format_cve_summary
from scorer import build_client, score_cve
from web.db import get_db, get_setting

_lock = threading.Lock()

# In-memory check progress (read by /api/check/status)
check_state: dict[str, Any] = {
    "is_running": False,
    "triggered_by": None,
    "current_product": None,
    "progress": 0,
    "total": 0,
    "check_run_id": None,
    "started_at": None,
    "last_error": None,
}


def is_check_running() -> bool:
    return check_state["is_running"]


def run_check(triggered_by: str = "manual", dry_run: bool = False) -> Optional[int]:
    """Start a CVE check in the current thread (call from background thread).

    Returns the check_run_id on success, None if already running.
    """
    if not _lock.acquire(blocking=False):
        return None

    check_run_id: Optional[int] = None
    try:
        _update_state(is_running=True, triggered_by=triggered_by, progress=0, total=0,
                      current_product=None, last_error=None, started_at=datetime.utcnow().isoformat())

        days = int(get_setting("check_days_lookback", "7"))
        max_per_product = int(get_setting("max_cves_per_product", "50"))
        rate_delay = float(get_setting("nvd_rate_limit_delay", "6.5"))
        env_context = get_setting("env_context", "")

        # Create check_run record
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO check_runs (triggered_by, status) VALUES (?, 'running')",
                (triggered_by,),
            )
            check_run_id = cur.lastrowid

        _update_state(check_run_id=check_run_id)

        # Load active products
        with get_db() as conn:
            products = [dict(r) for r in conn.execute(
                "SELECT * FROM products WHERE active = 1 ORDER BY name"
            ).fetchall()]

        if not products:
            _finish_check(check_run_id, cves_found=0, status="completed")
            return check_run_id

        # Build Claude client (unless dry run)
        client = None
        if not dry_run:
            try:
                client = build_client()
            except EnvironmentError as exc:
                _finish_check(check_run_id, cves_found=0, status="failed", error=str(exc))
                return check_run_id

        _update_state(total=len(products))
        total_cves = 0

        for i, product in enumerate(products, 1):
            _update_state(current_product=product["name"], progress=i)

            try:
                raw_cves = fetch_cves(
                    product["keyword"],
                    days=days,
                    rate_limit_delay=rate_delay,
                    max_results=max_per_product,
                )
            except Exception as exc:
                _update_state(last_error=f"Fetch failed for {product['name']}: {exc}")
                continue

            summaries = [format_cve_summary(c, product["keyword"]) for c in raw_cves]
            total_cves += len(summaries)

            for summary in summaries:
                if client and not dry_run:
                    score = score_cve(client, summary, env_context)
                else:
                    score = {
                        "exposure_score": None,
                        "telco_cnf_relevance": "N/A",
                        "recommended_action": "MONITOR",
                        "reason": "(dry run — scoring skipped)",
                    }

                _upsert_cve(product["id"], summary, score)

        _finish_check(check_run_id, cves_found=total_cves, status="completed")
        return check_run_id

    except Exception as exc:
        if check_run_id:
            _finish_check(check_run_id, cves_found=0, status="failed", error=str(exc))
        _update_state(last_error=str(exc))
        return check_run_id
    finally:
        _update_state(is_running=False, current_product=None)
        _lock.release()


def _update_state(**kwargs: Any) -> None:
    check_state.update(kwargs)


def _finish_check(
    check_run_id: int,
    cves_found: int,
    status: str,
    error: Optional[str] = None,
) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE check_runs SET finished_at = datetime('now'), cves_found = ?, status = ?, error = ? "
            "WHERE id = ?",
            (cves_found, status, error, check_run_id),
        )


def _upsert_cve(product_id: int, summary: dict, score: dict) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO cves (
                cve_id, product_id, published, cvss_score, description, nvd_url,
                exposure_score, telco_cnf_relevance, recommended_action, reason,
                checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id, product_id) DO UPDATE SET
                published           = excluded.published,
                cvss_score          = excluded.cvss_score,
                description         = excluded.description,
                nvd_url             = excluded.nvd_url,
                exposure_score      = excluded.exposure_score,
                telco_cnf_relevance = excluded.telco_cnf_relevance,
                recommended_action  = excluded.recommended_action,
                reason              = excluded.reason,
                checked_at          = excluded.checked_at
            """,
            (
                summary["cve_id"],
                product_id,
                summary.get("published"),
                summary.get("cvss_score"),
                summary.get("description"),
                summary.get("nvd_url"),
                score.get("exposure_score"),
                score.get("telco_cnf_relevance"),
                score.get("recommended_action", "MONITOR"),
                score.get("reason"),
            ),
        )
