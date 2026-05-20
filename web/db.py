# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""SQLite database layer — schema, migrations, and query helpers."""

import os
import sqlite3
from contextlib import contextmanager
from typing import Generator

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

            CREATE TABLE IF NOT EXISTS assets (
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
                asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
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
                scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(cve_id, asset_id)
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
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
                ('scan_interval_hours', '24'),
                ('scan_days_lookback', '7'),
                ('max_cves_per_asset', '50'),
                ('nvd_rate_limit_delay', '6.5'),
                ('env_context', '');
        """)


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
