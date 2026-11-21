# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Check orchestrator: fetch from NVD, triage (rules first, AI for the gray zone), persist."""

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from enrichment import Evidence
from fetcher import fetch_cves, format_cve_summary
from scorer import build_client
from triage import Decision, TriageStats, triage
from web.db import get_db, get_setting

log = logging.getLogger(__name__)
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


def run_check(triggered_by: str = "manual", dry_run: bool = False) -> int | None:
    """Start a CVE check in the current thread (call from background thread).

    Returns the check_run_id on success, None if already running.
    """
    if not _lock.acquire(blocking=False):
        return None

    check_run_id: int | None = None
    try:
        _update_state(is_running=True, triggered_by=triggered_by, progress=0, total=0,
                      current_product=None, last_error=None, started_at=datetime.now(UTC).isoformat())

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
            except OSError:
                log.error("Check %s: Claude API key not configured", check_run_id)
                _finish_check(check_run_id, cves_found=0, status="failed", error="Claude API key not configured")
                return check_run_id

        _update_state(total=len(products))
        collected: list[tuple[int, dict]] = []  # (product_id, summary)

        for i, product in enumerate(products, 1):
            _update_state(current_product=product["name"], progress=i)
            try:
                raw_cves = fetch_cves(
                    product["keyword"],
                    days=days,
                    rate_limit_delay=rate_delay,
                    max_results=max_per_product,
                )
            except Exception:
                log.exception("Check %s: NVD fetch failed for %s", check_run_id, product["name"])
                _update_state(last_error=f"Fetch failed for {product['name']}")
                continue
            collected += [(product["id"], format_cve_summary(c, product["keyword"])) for c in raw_cves]

        # One triage pass over all products: enrich once, skip unchanged, rules, then AI batches.
        _update_state(current_product="Triage")
        decisions, evidence, stats = triage(
            [s for _, s in collected], env_context, client, known_hashes=_known_hashes(collected),
        )
        for product_id, summary in collected:
            decision = decisions.get(summary["cve_id"])
            if decision:
                _upsert_cve(product_id, summary, decision)
            else:
                _refresh_evidence(product_id, summary, evidence.get(summary["cve_id"]))

        _record_meter(check_run_id, stats)
        _finish_check(check_run_id, cves_found=len(collected), status="completed")
        return check_run_id

    except Exception:
        log.exception("Check %s failed", check_run_id)
        if check_run_id:
            _finish_check(check_run_id, cves_found=0, status="failed", error="Check failed, see server log")
        _update_state(last_error="Check failed, see server log")
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
    error: str | None = None,
) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE check_runs SET finished_at = datetime('now'), cves_found = ?, status = ?, error = ? "
            "WHERE id = ?",
            (cves_found, status, error, check_run_id),
        )


def _known_hashes(collected: list[tuple[int, dict]]) -> dict[str, str]:
    """cve_id -> stored input_hash, only when every (product, CVE) pair seen now already has that hash.

    A CVE newly matched by another product is not skipped, so it gets its own row.
    """
    with get_db() as conn:
        stored = {(r["cve_id"], r["product_id"]): r["input_hash"]
                  for r in conn.execute("SELECT cve_id, product_id, input_hash FROM cves")}
    pairs: dict[str, set[str | None]] = {}
    for product_id, summary in collected:
        pairs.setdefault(summary["cve_id"], set()).add(stored.get((summary["cve_id"], product_id)))
    return {cve_id: next(iter(h)) for cve_id, h in pairs.items() if len(h) == 1 and None not in h}  # type: ignore[misc]


def _record_meter(check_run_id: int, stats: TriageStats) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE check_runs SET ai_calls = ?, ai_input_tokens = ?, ai_output_tokens = ?, ai_cost_usd = ?, "
            "rule_decided = ?, ai_decided = ?, cached_skipped = ? WHERE id = ?",
            (stats.usage.calls, stats.usage.input_tokens, stats.usage.output_tokens, stats.cost_usd,
             stats.rule_decided, stats.ai_decided + stats.fallback, stats.cached, check_run_id),
        )


def _refresh_evidence(product_id: int, summary: dict, ev: Evidence | None) -> None:
    """Unchanged CVE: keep the decision, refresh EPSS (it moves daily within a level)."""
    if ev is None:
        return
    with get_db() as conn:
        conn.execute(
            "UPDATE cves SET epss_score = ?, checked_at = datetime('now') WHERE cve_id = ? AND product_id = ?",
            (ev.epss_score, summary["cve_id"], product_id),
        )


def _upsert_cve(product_id: int, summary: dict, d: Decision) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO cves (
                cve_id, product_id, published, cvss_score, description, nvd_url,
                exposure_score, telco_cnf_relevance, recommended_action, reason,
                in_kev, epss_score, decided_by, input_hash, checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id, product_id) DO UPDATE SET
                published           = excluded.published,
                cvss_score          = excluded.cvss_score,
                description         = excluded.description,
                nvd_url             = excluded.nvd_url,
                exposure_score      = excluded.exposure_score,
                telco_cnf_relevance = excluded.telco_cnf_relevance,
                recommended_action  = excluded.recommended_action,
                reason              = excluded.reason,
                in_kev              = excluded.in_kev,
                epss_score          = excluded.epss_score,
                decided_by          = excluded.decided_by,
                input_hash          = excluded.input_hash,
                checked_at          = excluded.checked_at
            """,
            (
                summary["cve_id"],
                product_id,
                summary.get("published"),
                summary.get("cvss_score"),
                summary.get("description"),
                summary.get("nvd_url"),
                d.exposure_score,
                d.telco_cnf_relevance,
                d.recommended_action,
                d.reason,
                1 if d.in_kev else 0,
                d.epss_score,
                d.decided_by,
                d.input_hash,
            ),
        )
