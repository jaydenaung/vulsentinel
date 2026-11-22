"""Daily critical feed: pure rules, cve.org parsing, collector, and the web page. No network."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import critical
import web.daily as daily
import web.db as db_mod
from cve_org import parse_record
from enrichment import Evidence
from tests.test_web_security import add_viewer, login, setup_admin, token
from web.app import create_app

# ── pure rules ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("cvss", "kev", "epss", "expected"), [
    (9.0, False, False, ["cvss"]),
    (8.9, False, False, []),
    (None, True, False, ["kev"]),
    (5.0, False, True, ["epss"]),
    (9.8, True, True, ["cvss", "kev", "epss"]),
])
def test_critical_reasons(cvss, kev, epss, expected) -> None:
    assert critical.critical_reasons(cvss, kev, epss) == expected


def test_risk_score_breakdown_adds_up_and_caps() -> None:
    score, parts = critical.risk_score(9.8, in_kev=True, ransomware=True, epss=0.9, watched=True)
    assert parts == {"cvss": 29, "kev": 35, "ransomware": 10, "epss": 14, "watchlist": 10}
    assert score == min(100, sum(parts.values()))
    score, parts = critical.risk_score(9.1, in_kev=False, ransomware=True, epss=None, watched=False)
    assert parts == {"cvss": 27}  # ransomware only counts when in KEV


PRODUCTS = [{"id": 1, "keyword": "php"}, {"id": 2, "keyword": "nginx"}]


def test_watchlist_uses_vendor_record_when_present() -> None:
    assert critical.match_products(PRODUCTS, [("PHP Group", "PHP")], "") == {1: "affected"}
    # WordPress plugin: description mentions admin.php, vendor record says otherwise -> no match
    assert critical.match_products(PRODUCTS, [("acme", "Foo Gallery")], "XSS in admin.php") == {}
    # nginx-ui is a different product
    assert critical.match_products(PRODUCTS, [("0xJacky", "nginx-ui")], "") == {}


def test_watchlist_falls_back_to_description_keyword() -> None:
    assert critical.match_products(PRODUCTS, [], "A flaw in nginx allows request smuggling.") == {2: "keyword"}
    assert critical.match_products(PRODUCTS, [], "XSS in upload.php of the plugin.") == {}


def test_parse_cve_org_record() -> None:
    data = {
        "cveMetadata": {"datePublished": "2026-11-20T10:00:00Z"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Bug in pip."}],
                "affected": [{"vendor": "Pip maintainers", "product": "pip"}],
                "metrics": [{"cvssV3_1": {"baseScore": 9.3}}],
            },
            "adp": [{"metrics": [{"cvssV4_0": {"baseScore": 8.1}}]}],
        },
    }
    rec = parse_record("CVE-2026-0001", data)
    assert (rec.published, rec.description, rec.affected) == ("2026-11-20", "Bug in pip.", [("Pip maintainers", "pip")])
    assert rec.cvss_score == 8.1  # newest CVSS version wins, like the NVD extractor


# ── collector ────────────────────────────────────────────────────────────────


@pytest.fixture()
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "daily.db"))
    db_mod.init_db()
    with db_mod.get_db() as conn:
        conn.execute("INSERT INTO products (id, name, keyword) VALUES (1, 'PHP', 'php')")
    state: dict[str, Any] = {
        "nvd": [_nvd("CVE-2026-0001", 9.8), _nvd("CVE-2026-0002", 5.0)],
        "kev": {"CVE-2020-1111": {"dateAdded": "2999-01-01", "shortDescription": "Old bug, newly exploited"}},
        "epss": {"CVE-2019-0001": 0.7},
        "ev": {"CVE-2020-1111": Evidence(in_kev=True, kev_date_added="2999-01-01", kev_ransomware=True)},
    }
    monkeypatch.setattr(daily, "fetch_published", lambda days, rate_limit_delay: state["nvd"])
    monkeypatch.setattr(daily, "kev_catalog", lambda: state["kev"])
    monkeypatch.setattr(daily, "epss_above", lambda threshold: state["epss"])
    monkeypatch.setattr(daily, "enrich", lambda ids: {i: state["ev"].get(i, Evidence(in_kev=False)) for i in ids})
    monkeypatch.setattr(daily, "fetch_record", lambda session, cve_id: parse_record(cve_id, {
        "containers": {"cna": {"affected": [{"vendor": "PHP Group", "product": "PHP"}]
                               if cve_id == "CVE-2026-0001" else []}}}))
    monkeypatch.setattr(daily.get_settings(), "cve_org_delay_seconds", 0)
    return state


def _nvd(cve_id: str, score: float) -> dict[str, Any]:
    return {"id": cve_id, "published": "2026-11-21T00:00:00", "descriptions": [{"lang": "en", "value": "d"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}}


def _vulns() -> dict[str, dict[str, Any]]:
    with db_mod.get_db() as conn:
        return {r["cve_id"]: dict(r) for r in conn.execute("SELECT * FROM vulns")}


def test_first_run_collects_cvss_and_kev_and_sets_epss_baseline(world) -> None:
    run_id = daily.run_daily("test")
    vulns = _vulns()
    assert set(vulns) == {"CVE-2026-0001", "CVE-2020-1111"}  # 5.0 dropped, EPSS baseline only
    assert json.loads(vulns["CVE-2026-0001"]["critical_reasons"]) == ["cvss"]
    assert json.loads(vulns["CVE-2020-1111"]["critical_reasons"]) == ["kev"]
    assert vulns["CVE-2020-1111"]["kev_ransomware"] == 1
    with db_mod.get_db() as conn:
        run = dict(conn.execute("SELECT * FROM daily_runs WHERE id = ?", (run_id,)).fetchone())
        links = conn.execute("SELECT cve_id, match_type FROM vuln_products").fetchall()
    assert (run["status"], run["critical_new"], run["kev_new"], run["epss_crossers"]) == ("completed", 2, 1, 0)
    assert [tuple(r) for r in links] == [("CVE-2026-0001", "affected")]
    assert run["watchlist_hits"] == 1


def test_second_run_flags_only_new_epss_crossers_and_keeps_analyst_work(world) -> None:
    daily.run_daily("test")
    with db_mod.get_db() as conn:
        conn.execute("UPDATE vulns SET status = 'investigating', notes = 'on it' WHERE cve_id = 'CVE-2026-0001'")
    world["epss"] = {"CVE-2019-0001": 0.7, "CVE-2026-0001": 0.6}
    run_id = daily.run_daily("test")
    vulns = _vulns()
    assert "CVE-2019-0001" not in vulns  # was in the baseline
    v = vulns["CVE-2026-0001"]
    assert json.loads(v["critical_reasons"]) == ["cvss", "epss"]
    assert (v["status"], v["notes"]) == ("investigating", "on it")
    with db_mod.get_db() as conn:
        run = dict(conn.execute("SELECT * FROM daily_runs WHERE id = ?", (run_id,)).fetchone())
    assert (run["critical_new"], run["critical_updated"], run["epss_crossers"]) == (0, 2, 1)


def test_failed_run_is_recorded_with_generic_error(world, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(days, rate_limit_delay):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr(daily, "fetch_published", boom)
    run_id = daily.run_daily("test")
    with db_mod.get_db() as conn:
        run = dict(conn.execute("SELECT * FROM daily_runs WHERE id = ?", (run_id,)).fetchone())
    assert run["status"] == "failed" and "secret" not in run["error"]


# ── web page ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "web.db"))
    db_mod.init_db()
    return TestClient(create_app(start_background=False), follow_redirects=False)


def test_feed_page_escapes_untrusted_text_and_filters(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    with db_mod.get_db() as conn:
        conn.execute(
            "INSERT INTO vulns (cve_id, cvss_score, description, affected, critical_reasons, risk_score, "
            "risk_breakdown) VALUES (?, 9.8, ?, ?, '[\"cvss\"]', 29, '{\"cvss\": 29}')",
            ("CVE-2026-0001", "<script>alert(1)</script>", json.dumps([["<b>v</b>", "p"]])),
        )
        conn.execute("INSERT INTO vulns (cve_id, critical_reasons) VALUES ('CVE-2026-0002', '[\"kev\"]')")
    page = client.get("/critical").text
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page
    assert "<b>v</b>" not in page
    assert "CVE-2026-0002" in page
    assert "CVE-2026-0002" not in client.get("/critical?reason=cvss").text
    assert client.get("/critical?days=999&reason=drop").status_code == 200  # bad filters fall back


def test_only_admin_can_trigger_run(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[str] = []
    monkeypatch.setattr("web.routes.critical.run_daily", lambda triggered_by: started.append(triggered_by))
    setup_admin(client)
    add_viewer(client)
    login(client, "viewer", "viewer-pass-1")
    client.post("/critical/run", data={"csrf_token": token(client, "/critical")})
    assert started == []
    assert client.post("/critical/run").status_code == 403  # no CSRF token


def test_admin_can_trigger_run(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[str] = []
    monkeypatch.setattr("web.routes.critical.run_daily", lambda triggered_by: started.append(triggered_by))
    setup_admin(client)
    login(client)
    resp = client.post("/critical/run", data={"csrf_token": token(client, "/critical")})
    assert resp.status_code == 303 and "Daily+run+started" in resp.headers["location"]
    assert started == ["admin"]


def test_rerun_skips_cve_org_lookup_for_known_vendor_data(world, monkeypatch: pytest.MonkeyPatch) -> None:
    daily.run_daily("test")
    looked_up: list[str] = []
    monkeypatch.setattr(daily, "fetch_record", lambda session, cve_id: looked_up.append(cve_id))
    daily.run_daily("test")
    assert "CVE-2026-0001" not in looked_up  # vendor data stored on the first run
    with db_mod.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vuln_products").fetchone()[0] == 1  # match kept
