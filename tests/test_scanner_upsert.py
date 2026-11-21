"""Scanner persistence: decisions, evidence, status survival, skip cache, token meter."""

import importlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from enrichment import Evidence
from scorer import TriageResult
from triage import Decision


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


def decision(**over: Any) -> Decision:
    base = {"cve_id": SUMMARY["cve_id"], "exposure_score": 9, "telco_cnf_relevance": "HIGH",
            "recommended_action": "PATCH NOW", "reason": "r", "decided_by": "ai",
            "in_kev": False, "epss_score": 0.91, "input_hash": "h1"}
    return Decision(**{**base, **over})


def _row(db_mod) -> sqlite3.Row:
    with db_mod.get_db() as conn:
        return conn.execute("SELECT * FROM cves WHERE cve_id = ?", (SUMMARY["cve_id"],)).fetchone()


def test_upsert_stores_evidence_and_decider(db) -> None:
    db_mod, scanner_mod = db
    scanner_mod._upsert_cve(1, SUMMARY, decision(in_kev=True, decided_by="rule:kev"))
    row = _row(db_mod)
    assert (row["in_kev"], row["decided_by"], row["input_hash"]) == (1, "rule:kev", "h1")
    assert row["epss_score"] == pytest.approx(0.91)


def test_recheck_preserves_status_and_notes(db) -> None:
    db_mod, scanner_mod = db
    scanner_mod._upsert_cve(1, SUMMARY, decision(recommended_action="MONITOR"))
    with db_mod.get_db() as conn:
        conn.execute("UPDATE cves SET status = 'mitigated', notes = 'patched'")
    scanner_mod._upsert_cve(1, SUMMARY, decision())
    row = _row(db_mod)
    assert (row["status"], row["notes"], row["recommended_action"]) == ("mitigated", "patched", "PATCH NOW")


def test_migration_adds_columns_to_old_db(db) -> None:
    db_mod, _ = db
    with db_mod.get_db() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(check_runs)")}
    assert {"ai_calls", "ai_input_tokens", "ai_cost_usd", "rule_decided", "cached_skipped"} <= cols


def test_known_hashes_skip_only_when_every_product_row_matches(db) -> None:
    db_mod, scanner_mod = db
    with db_mod.get_db() as conn:
        conn.execute("INSERT INTO products (id, name, keyword) VALUES (2, 'PHP', 'php')")
    scanner_mod._upsert_cve(1, SUMMARY, decision())
    assert scanner_mod._known_hashes([(1, SUMMARY)]) == {SUMMARY["cve_id"]: "h1"}
    # Same CVE newly matched by product 2: must not be skipped, it needs its own row.
    assert scanner_mod._known_hashes([(1, SUMMARY), (2, SUMMARY)]) == {}


def test_full_check_records_meter_and_skips_second_time(db, monkeypatch: pytest.MonkeyPatch) -> None:
    db_mod, scanner_mod = db
    import triage as triage_mod

    ai_calls: list[int] = []

    def fake_score_batch(client, items, env, usage) -> dict[str, TriageResult]:
        usage.calls += 1
        usage.input_tokens += 800
        usage.output_tokens += 100
        ai_calls.append(len(items))
        return {s["cve_id"]: TriageResult(exposure_score=5, telco_cnf_relevance="LOW",
                                          recommended_action="MONITOR", reason="r") for s, _ in items}

    raw = [{"id": "CVE-2026-0001", "cvss": 8.1}, {"id": "CVE-2026-0002", "cvss": 2.0}]
    monkeypatch.setattr(scanner_mod, "fetch_cves", lambda *a, **k: raw)
    monkeypatch.setattr(scanner_mod, "format_cve_summary", lambda c, kw: {
        "cve_id": c["id"], "product": kw, "cvss_score": c["cvss"], "description": "d", "published": "2026-11-01",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/" + c["id"]})
    monkeypatch.setattr(scanner_mod, "build_client", lambda: object())
    monkeypatch.setattr(triage_mod, "enrich", lambda ids: {i: Evidence(in_kev=False, epss_score=0.001) for i in ids})
    monkeypatch.setattr(triage_mod, "score_batch", fake_score_batch)

    first = scanner_mod.run_check("test")
    second = scanner_mod.run_check("test")

    with db_mod.get_db() as conn:
        runs = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM check_runs")}
        deciders = dict(conn.execute("SELECT cve_id, decided_by FROM cves").fetchall())
    assert deciders == {"CVE-2026-0001": "ai", "CVE-2026-0002": "rule:low"}
    assert (runs[first]["ai_calls"], runs[first]["ai_input_tokens"]) == (1, 800)
    assert (runs[first]["rule_decided"], runs[first]["ai_decided"]) == (1, 1)
    assert runs[first]["ai_cost_usd"] == pytest.approx((800 * 3 + 100 * 15) / 1_000_000)
    assert (runs[second]["ai_calls"], runs[second]["cached_skipped"]) == (0, 2)
    assert ai_calls == [1]
