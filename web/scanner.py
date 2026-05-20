# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Scan orchestrator — wraps fetcher + scorer and persists results to DB."""

import threading
from datetime import datetime
from typing import Any, Optional

from fetcher import fetch_cves, format_cve_summary
from scorer import build_client, score_cve
from web.db import get_db, get_setting

_lock = threading.Lock()

# In-memory scan progress (read by /api/scan/status)
scan_state: dict[str, Any] = {
    "is_running": False,
    "triggered_by": None,
    "current_asset": None,
    "progress": 0,
    "total": 0,
    "scan_run_id": None,
    "started_at": None,
    "last_error": None,
}


def is_scan_running() -> bool:
    return scan_state["is_running"]


def run_scan(triggered_by: str = "manual", dry_run: bool = False) -> Optional[int]:
    """Start a scan in the current thread (call from background thread).

    Returns the scan_run_id on success, None if already running.
    """
    if not _lock.acquire(blocking=False):
        return None

    scan_run_id: Optional[int] = None
    try:
        _update_state(is_running=True, triggered_by=triggered_by, progress=0, total=0,
                      current_asset=None, last_error=None, started_at=datetime.utcnow().isoformat())

        days = int(get_setting("scan_days_lookback", "7"))
        max_per_asset = int(get_setting("max_cves_per_asset", "50"))
        rate_delay = float(get_setting("nvd_rate_limit_delay", "6.5"))
        env_context = get_setting("env_context", "")

        # Create scan_run record
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO scan_runs (triggered_by, status) VALUES (?, 'running')",
                (triggered_by,),
            )
            scan_run_id = cur.lastrowid

        _update_state(scan_run_id=scan_run_id)

        # Load active assets
        with get_db() as conn:
            assets = [dict(r) for r in conn.execute(
                "SELECT * FROM assets WHERE active = 1 ORDER BY name"
            ).fetchall()]

        if not assets:
            _finish_scan(scan_run_id, cves_found=0, status="completed")
            return scan_run_id

        # Build Claude client (unless dry run)
        client = None
        if not dry_run:
            try:
                client = build_client()
            except EnvironmentError as exc:
                _finish_scan(scan_run_id, cves_found=0, status="failed", error=str(exc))
                return scan_run_id

        _update_state(total=len(assets))
        total_cves = 0

        for i, asset in enumerate(assets, 1):
            _update_state(current_asset=asset["name"], progress=i)

            try:
                raw_cves = fetch_cves(
                    asset["keyword"],
                    days=days,
                    rate_limit_delay=rate_delay,
                    max_results=max_per_asset,
                )
            except Exception as exc:
                # Log but continue with other assets
                _update_state(last_error=f"Fetch failed for {asset['name']}: {exc}")
                continue

            summaries = [format_cve_summary(c, asset["keyword"]) for c in raw_cves]
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

                _upsert_cve(asset["id"], summary, score, scan_run_id)

        _finish_scan(scan_run_id, cves_found=total_cves, status="completed")
        return scan_run_id

    except Exception as exc:
        if scan_run_id:
            _finish_scan(scan_run_id, cves_found=0, status="failed", error=str(exc))
        _update_state(last_error=str(exc))
        return scan_run_id
    finally:
        _update_state(is_running=False, current_asset=None)
        _lock.release()


def _update_state(**kwargs: Any) -> None:
    scan_state.update(kwargs)


def _finish_scan(
    scan_run_id: int,
    cves_found: int,
    status: str,
    error: Optional[str] = None,
) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE scan_runs SET finished_at = datetime('now'), cves_found = ?, status = ?, error = ? "
            "WHERE id = ?",
            (cves_found, status, error, scan_run_id),
        )


def _upsert_cve(asset_id: int, summary: dict, score: dict, scan_run_id: int) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO cves (
                cve_id, asset_id, published, cvss_score, description, nvd_url,
                exposure_score, telco_cnf_relevance, recommended_action, reason,
                scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id, asset_id) DO UPDATE SET
                published       = excluded.published,
                cvss_score      = excluded.cvss_score,
                description     = excluded.description,
                nvd_url         = excluded.nvd_url,
                exposure_score  = excluded.exposure_score,
                telco_cnf_relevance = excluded.telco_cnf_relevance,
                recommended_action  = excluded.recommended_action,
                reason          = excluded.reason,
                scanned_at      = excluded.scanned_at
            """,
            (
                summary["cve_id"],
                asset_id,
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
