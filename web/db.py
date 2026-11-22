# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""SQLite database layer — schema, migrations, and query helpers."""

import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager

DB_PATH = os.environ.get("CVE_DB_PATH", "cve_triage.db")


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                keyword TEXT NOT NULL,
                description TEXT DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                published TEXT,
                cvss_score REAL,
                description TEXT,
                nvd_url TEXT,
                exposure_score INTEGER,
                telco_cnf_relevance TEXT,
                recommended_action TEXT DEFAULT 'MONITOR',
                reason TEXT,
                in_kev INTEGER DEFAULT 0,
                epss_score REAL,
                status TEXT NOT NULL DEFAULT 'open',
                notes TEXT DEFAULT '',
                checked_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(cve_id, product_id)
            );

            CREATE TABLE IF NOT EXISTS check_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                triggered_by TEXT,
                started_at TEXT NOT NULL DEFAULT (datetime('now')),
                finished_at TEXT,
                cves_found INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running',
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO settings VALUES
                ('check_interval_hours', '24'),
                ('check_days_lookback', '7'),
                ('max_cves_per_product', '50'),
                ('nvd_rate_limit_delay', '6.5'),
                ('env_context', ''),
                ('daily_run_hour_utc', '6');

            CREATE TABLE IF NOT EXISTS feeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_fetched_at TEXT,
                last_status TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
                guid TEXT NOT NULL,
                url TEXT,
                title TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                published_at TEXT,
                cve_ids TEXT NOT NULL DEFAULT '[]',
                fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(feed_id, guid)
            );
            CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC);

            INSERT OR IGNORE INTO feeds (name, url) VALUES
                ('Wiz Research', 'https://www.wiz.io/feed/rss.xml');

            -- Daily critical feed: one row per CVE, any product.
            CREATE TABLE IF NOT EXISTS vulns (
                cve_id TEXT PRIMARY KEY,
                published TEXT,
                cvss_score REAL,
                severity TEXT NOT NULL DEFAULT 'none',
                description TEXT NOT NULL DEFAULT '',
                affected TEXT NOT NULL DEFAULT '[]',
                in_kev INTEGER NOT NULL DEFAULT 0,
                kev_date_added TEXT,
                kev_ransomware INTEGER NOT NULL DEFAULT 0,
                epss_score REAL,
                critical_reasons TEXT NOT NULL DEFAULT '[]',
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_breakdown TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'new',
                notes TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_updated TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_vulns_first_seen ON vulns(first_seen DESC);

            CREATE TABLE IF NOT EXISTS vuln_products (
                cve_id TEXT NOT NULL REFERENCES vulns(cve_id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                match_type TEXT NOT NULL,
                PRIMARY KEY (cve_id, product_id)
            );

            -- CVEs already above the EPSS threshold, so only new crossers are flagged.
            CREATE TABLE IF NOT EXISTS epss_baseline (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL NOT NULL,
                first_seen TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS daily_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                triggered_by TEXT,
                started_at TEXT NOT NULL DEFAULT (datetime('now')),
                finished_at TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                nvd_fetched INTEGER NOT NULL DEFAULT 0,
                critical_new INTEGER NOT NULL DEFAULT 0,
                critical_updated INTEGER NOT NULL DEFAULT 0,
                kev_new INTEGER NOT NULL DEFAULT 0,
                epss_crossers INTEGER NOT NULL DEFAULT 0,
                watchlist_hits INTEGER NOT NULL DEFAULT 0,
                error TEXT
            );
        """)
    _migrate_db()


# v3 columns: who decided each CVE (rule or AI), input hash for skip-if-unchanged, token meter.
# Names and types are literals from this module, never user input.
_ADD_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "cves": [("decided_by", "TEXT"), ("input_hash", "TEXT")],
    "users": [("session_version", "INTEGER NOT NULL DEFAULT 0")],
    "check_runs": [
        ("ai_calls", "INTEGER DEFAULT 0"),
        ("ai_input_tokens", "INTEGER DEFAULT 0"),
        ("ai_output_tokens", "INTEGER DEFAULT 0"),
        ("ai_cost_usd", "REAL"),
        ("rule_decided", "INTEGER DEFAULT 0"),
        ("ai_decided", "INTEGER DEFAULT 0"),
        ("cached_skipped", "INTEGER DEFAULT 0"),
    ],
}


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    for table, columns in _ADD_COLUMNS.items():
        existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, sql_type in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")


def _migrate_db() -> None:
    """Apply incremental schema migrations so existing DBs survive renames."""
    with get_db() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        # v2: assets → products, scan_runs → check_runs, cves gets product_id/checked_at
        if "assets" in tables:
            cve_cols = {r[1] for r in conn.execute("PRAGMA table_info(cves)")}
            needs_cve_rebuild = "asset_id" in cve_cols

            conn.executescript("PRAGMA foreign_keys = OFF;")

            conn.execute("""
                INSERT OR IGNORE INTO products (id, name, keyword, description, active, created_at)
                SELECT id, name, keyword, description, active, created_at FROM assets
            """)
            if "scan_runs" in tables:
                conn.execute("""
                    INSERT OR IGNORE INTO check_runs
                        (id, triggered_by, started_at, finished_at, cves_found, status, error)
                    SELECT id, triggered_by, started_at, finished_at, cves_found, status, error
                    FROM scan_runs
                """)

            if needs_cve_rebuild:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS cves_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cve_id TEXT NOT NULL,
                        product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                        published TEXT,
                        cvss_score REAL,
                        description TEXT,
                        nvd_url TEXT,
                        exposure_score INTEGER,
                        telco_cnf_relevance TEXT,
                        recommended_action TEXT DEFAULT 'MONITOR',
                        reason TEXT,
                        in_kev INTEGER DEFAULT 0,
                        epss_score REAL,
                        status TEXT NOT NULL DEFAULT 'open',
                        notes TEXT DEFAULT '',
                        checked_at TEXT NOT NULL DEFAULT (datetime('now')),
                        UNIQUE(cve_id, product_id)
                    );

                    INSERT OR IGNORE INTO cves_new
                        (id, cve_id, product_id, published, cvss_score, description, nvd_url,
                         exposure_score, telco_cnf_relevance, recommended_action, reason,
                         in_kev, epss_score, status, notes, checked_at)
                    SELECT id, cve_id, asset_id, published, cvss_score, description, nvd_url,
                           exposure_score, telco_cnf_relevance, recommended_action, reason,
                           in_kev, epss_score, status, notes, scanned_at
                    FROM cves;

                    DROP TABLE cves;
                    ALTER TABLE cves_new RENAME TO cves;
                """)

            conn.executescript("""
                DROP TABLE IF EXISTS assets;
                DROP TABLE IF EXISTS scan_runs;
                DROP TABLE IF EXISTS cves_migrated;
                PRAGMA foreign_keys = ON;
            """)

    # Last, so a legacy cves rebuild above cannot drop the new columns.
    with get_db() as conn:
        _add_missing_columns(conn)


def user_count() -> int:
    try:
        with get_db() as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        return 0


def get_setting(key: str, default: str = "") -> str:
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default


def set_setting(key: str, value: str) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
