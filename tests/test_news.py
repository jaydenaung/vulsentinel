"""News slice tests: feed parsing, SSRF guard, sweep persistence, dashboard widget. Offline."""

import socket
from pathlib import Path
from typing import Any

import pytest

import news
import safe_http
import web.db as db_mod
from web import news_sweep

RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Test Research</title>
<item>
  <title>PHP2Shell: RCE in PHP (CVE-2026-109618, cve-2026-109619)</title>
  <link>https://research.example.com/php2shell</link>
  <guid>php2shell-1</guid>
  <pubDate>Wed, 21 Oct 2026 14:00:00 GMT</pubDate>
  <description><![CDATA[<p>Memory safety bug.</p><script>alert('x')</script>
    <b>Patch</b> now. Also CVE-2026-109618.]]></description>
</item>
<item>
  <title>Evil link post</title>
  <link>javascript:alert(document.cookie)</link>
  <guid>evil-1</guid>
  <description>No CVEs here</description>
</item>
<item>
  <title></title>
  <guid>empty-title</guid>
</item>
</channel></rss>"""


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_parse_feed_extracts_clean_articles() -> None:
    articles = news.parse_feed(RSS)
    assert [a.guid for a in articles] == ["php2shell-1", "evil-1"]  # empty title skipped
    first = articles[0]
    assert first.cve_ids == ["CVE-2026-109618", "CVE-2026-109619"]
    assert first.published_at == "2026-10-21T14:00:00+00:00"
    assert first.url == "https://research.example.com/php2shell"
    assert "<" not in first.summary and "alert" not in first.summary
    assert first.summary.startswith("Memory safety bug.")


def test_javascript_links_are_dropped() -> None:
    evil = news.parse_feed(RSS)[1]
    assert evil.url is None
    assert evil.cve_ids == []


@pytest.mark.parametrize("link,expected", [
    ("https://a.example/x", "https://a.example/x"),
    ("http://a.example/x", "http://a.example/x"),
    ("javascript:alert(1)", None),
    ("data:text/html,hi", None),
    ("/relative/path", None),
    (None, None),
])
def test_safe_link(link: Any, expected: str | None) -> None:
    assert news.safe_link(link) == expected


def test_garbage_input_does_not_crash() -> None:
    assert news.parse_feed(b"\x00\xffnot xml at all") == []


# ── SSRF guard ────────────────────────────────────────────────────────────────

def fake_dns(mapping: dict[str, str]):
    def resolve(host: str, *args: Any, **kwargs: Any):
        if host not in mapping:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 443))]
    return resolve


@pytest.mark.parametrize("url,reason", [
    ("http://feeds.example.com/rss", "only https"),
    ("https://internal.example.com/rss", "non-public"),
    ("https://metadata.example.com/latest", "non-public"),
    ("https://user:pw@feeds.example.com/rss", "credentials"),
    ("https://feeds.example.com:8443/rss", "port 443"),
    ("https://nope.example.com/rss", "cannot resolve"),
])
def test_validate_url_rejects_unsafe(monkeypatch: pytest.MonkeyPatch, url: str, reason: str) -> None:
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake_dns({
        "feeds.example.com": "93.184.216.34",
        "internal.example.com": "10.0.0.5",
        "metadata.example.com": "169.254.169.254",
    }))
    with pytest.raises(safe_http.UnsafeURLError, match=reason):
        safe_http.validate_url(url)


class FakeResp:
    def __init__(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self.is_redirect = status in (301, 302, 303, 307, 308)

    def iter_content(self, chunk_size: int):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def test_redirect_to_private_address_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake_dns({
        "feeds.example.com": "93.184.216.34", "internal.example.com": "10.0.0.5"}))
    monkeypatch.setattr(safe_http.requests, "get", lambda url, **kw: FakeResp(
        302, headers={"Location": "https://internal.example.com/admin"}))
    with pytest.raises(safe_http.UnsafeURLError):
        safe_http.fetch_url("https://feeds.example.com/rss")


def test_oversized_response_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake_dns({"feeds.example.com": "93.184.216.34"}))
    monkeypatch.setattr(safe_http.requests, "get", lambda url, **kw: FakeResp(200, b"x" * 5000))
    with pytest.raises(safe_http.FetchError, match="too large"):
        safe_http.fetch_url("https://feeds.example.com/rss", max_bytes=1000)


def test_fetch_sends_generic_user_agent_and_no_auto_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake_dns({"feeds.example.com": "93.184.216.34"}))

    def fake_get(url: str, **kw: Any) -> FakeResp:
        seen.update(kw)
        return FakeResp(200, RSS)

    monkeypatch.setattr(safe_http.requests, "get", fake_get)
    assert safe_http.fetch_url("https://feeds.example.com/rss") == RSS
    assert seen["allow_redirects"] is False
    assert seen["headers"]["User-Agent"] == safe_http.USER_AGENT


# ── Sweep + dashboard ─────────────────────────────────────────────────────────

@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "news.db"))
    db_mod.init_db()


def test_sweep_is_idempotent_and_records_status(db, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(news_sweep, "fetch_url", lambda url: RSS)
    first = news_sweep.run_news_sweep()
    second = news_sweep.run_news_sweep()
    assert (first[0]["new"], second[0]["new"]) == (2, 0)
    with db_mod.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0] == 2
        assert conn.execute("SELECT last_status FROM feeds").fetchone()[0] == "ok: 2 parsed, 0 new"


def test_sweep_failure_is_recorded_not_raised(db, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(url: str) -> bytes:
        raise safe_http.FetchError("HTTP 503")

    monkeypatch.setattr(news_sweep, "fetch_url", boom)
    result = news_sweep.run_news_sweep()
    assert result[0]["ok"] is False
    with db_mod.get_db() as conn:
        assert conn.execute("SELECT last_status FROM feeds").fetchone()[0] == "error: HTTP 503"


def test_latest_articles_flags_watchlist_cves(db, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(news_sweep, "fetch_url", lambda url: RSS)
    news_sweep.run_news_sweep()
    with db_mod.get_db() as conn:
        conn.execute("INSERT INTO products (id, name, keyword) VALUES (1, 'PHP', 'php')")
        conn.execute("INSERT INTO cves (cve_id, product_id) VALUES ('CVE-2026-109618', 1)")
    by_guid = {a["guid"]: a for a in news_sweep.latest_articles(10)}
    assert by_guid["php2shell-1"]["cves"] == [
        {"id": "CVE-2026-109618", "watched": True},
        {"id": "CVE-2026-109619", "watched": False},
    ]
    assert by_guid["evil-1"]["cves"] == []


def test_seeded_feed_is_wiz(db) -> None:
    with db_mod.get_db() as conn:
        assert [tuple(r) for r in conn.execute("SELECT name, url, enabled FROM feeds")] == [
            ("Wiz Research", "https://www.wiz.io/feed/rss.xml", 1)]
