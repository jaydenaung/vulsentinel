# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""News sweep: fetch enabled feeds, store new articles. Re-runs are idempotent."""

import json
import logging
from typing import Any

from news import parse_feed
from safe_http import FetchError, UnsafeURLError, fetch_url
from web.db import get_db

log = logging.getLogger(__name__)


def _store(feed_id: int, articles: list[Any]) -> int:
    new = 0
    with get_db() as conn:
        for a in articles:
            cur = conn.execute(
                "INSERT OR IGNORE INTO articles (feed_id, guid, url, title, summary, published_at, cve_ids) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (feed_id, a.guid, a.url, a.title, a.summary, a.published_at, json.dumps(a.cve_ids)),
            )
            new += cur.rowcount
    return new


def _mark(feed_id: int, status: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE feeds SET last_fetched_at = datetime('now'), last_status = ? WHERE id = ?",
            (status[:200], feed_id),
        )


def sweep_feed(feed: dict[str, Any]) -> dict[str, Any]:
    try:
        articles = parse_feed(fetch_url(feed["url"]))
    except (UnsafeURLError, FetchError) as exc:
        log.warning("Feed %s (%s) failed: %s", feed["name"], feed["url"], exc)
        _mark(feed["id"], f"error: {exc}")
        return {"feed": feed["name"], "ok": False, "parsed": 0, "new": 0, "error": str(exc)}
    new = _store(feed["id"], articles)
    _mark(feed["id"], f"ok: {len(articles)} parsed, {new} new")
    log.info("Feed %s: %d parsed, %d new", feed["name"], len(articles), new)
    return {"feed": feed["name"], "ok": True, "parsed": len(articles), "new": new}


def run_news_sweep() -> list[dict[str, Any]]:
    with get_db() as conn:
        feeds = [dict(r) for r in conn.execute("SELECT * FROM feeds WHERE enabled = 1 ORDER BY name")]
    return [sweep_feed(f) for f in feeds]


def latest_articles(limit: int = 10) -> list[dict[str, Any]]:
    """Newest articles with their CVEs, each CVE flagged if it is on the watchlist (in cves)."""
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT a.*, f.name AS feed_name FROM articles a JOIN feeds f ON f.id = a.feed_id "
            # published_at is ISO with 'T'; fetched_at is SQLite 'YYYY-MM-DD HH:MM:SS'. Same format for sorting.
            "ORDER BY COALESCE(a.published_at, strftime('%Y-%m-%dT%H:%M:%S+00:00', a.fetched_at)) DESC LIMIT ?",
            (limit,),
        )]
        all_ids = sorted({cid for r in rows for cid in json.loads(r["cve_ids"])})
        watched: set[str] = set()
        if all_ids:
            marks = ",".join("?" * len(all_ids))
            watched = {r[0] for r in conn.execute(
                f"SELECT DISTINCT cve_id FROM cves WHERE cve_id IN ({marks})", all_ids  # noqa: S608 (placeholders only)
            )}
    for r in rows:
        r["cves"] = [{"id": cid, "watched": cid in watched} for cid in json.loads(r["cve_ids"])]
    return rows
