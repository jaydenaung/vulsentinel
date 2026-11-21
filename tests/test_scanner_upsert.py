"""Scanner persistence: KEV/EPSS evidence is stored; triage status survives re-checks."""

import importlib
import sqlite3
from pathlib import Path

import pytest


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CVE_DB_PATH", str(tmp_path / "test.db"))
    import web.db as db_mod
    importlib.reload(db_mod)
    import web.scanner as scanner_mod
    importlib.reload(scanner_mod)
    db_mod.init_db()
    with db_mod.get_db() as conn:
        conn.execute("INSERT INTO products (id, name, keyword) VALUES (1, 'Nginx', 'nginx')")
    return db_mod, scanner_mod


SUMMARY = {"cve_id": "CVE-2026-1234", "published": "2026-11-01", "cvss_score": 9.8,
           "description": "d", "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"}


def _row(db_mod) -> sqlite3.Row:
    with db_mod.get_db() as conn:
        return conn.execute("SELECT * FROM cves WHERE cve_id = ?", (SUMMARY["cve_id"],)).fetchone()


def test_upsert_stores_kev_and_epss(db) -> None:
    db_mod, scanner_mod = db
    score = {"exposure_score": 9, "telco_cnf_relevance": "HIGH", "recommended_action": "PATCH NOW",
             "reason": "r", "in_kev": True, "epss_score": 0.91}
    scanner_mod._upsert_cve(1, SUMMARY, score)
    row = _row(db_mod)
    assert row["in_kev"] == 1
    assert row["epss_score"] == pytest.approx(0.91)


def test_recheck_preserves_status_and_notes(db) -> None:
    db_mod, scanner_mod = db
    score = {"exposure_score": 5, "telco_cnf_relevance": "LOW", "recommended_action": "MONITOR", "reason": "r"}
    scanner_mod._upsert_cve(1, SUMMARY, score)
    with db_mod.get_db() as conn:
        conn.execute("UPDATE cves SET status = 'mitigated', notes = 'patched'")
    scanner_mod._upsert_cve(1, SUMMARY, {**score, "recommended_action": "PATCH NOW", "in_kev": True})
    row = _row(db_mod)
    assert (row["status"], row["notes"], row["recommended_action"]) == ("mitigated", "patched", "PATCH NOW")
