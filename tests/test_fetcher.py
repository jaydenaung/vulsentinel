"""Fetcher tests. Fake NVD session and no-op sleep: no network, no waiting."""

from datetime import datetime
from typing import Any

import pytest
from pydantic import SecretStr

import fetcher
from settings import get_settings

FMT = "%Y-%m-%dT%H:%M:%S.000"


def cve(n: int, **extra: Any) -> dict[str, Any]:
    """Higher n = published later, matching NVD's oldest-first ordering when listed by n."""
    return {"cve": {"id": f"CVE-2026-{1000 + n}", "published": f"2026-11-{1 + n:02d}T00:00:00", **extra}}


class FakeResponse:
    def __init__(self, status: int, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}

    def json(self) -> dict[str, Any]:
        return self._body


class FakeSession:
    """Serves a fixed list of CVEs, honouring startIndex/resultsPerPage, after optional scripted errors."""

    def __init__(self, items: list[dict[str, Any]], errors: list[FakeResponse] | None = None):
        self.items = items
        self.errors = list(errors or [])
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, params: dict[str, Any], headers: dict[str, str], timeout: int) -> FakeResponse:
        self.calls.append({"params": dict(params), "headers": dict(headers)})
        if self.errors:
            return self.errors.pop(0)
        start, size = params["startIndex"], params["resultsPerPage"]
        page = self.items[start:start + size]
        return FakeResponse(200, {"totalResults": len(self.items), "vulnerabilities": page})

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


@pytest.fixture()
def nvd(monkeypatch: pytest.MonkeyPatch):
    sleeps: list[float] = []
    monkeypatch.setattr(fetcher.time, "sleep", lambda s: sleeps.append(s))
    cfg = get_settings()
    monkeypatch.setattr(cfg, "nvd_page_size", 2)
    monkeypatch.setattr(cfg, "nvd_api_key", None)

    def install(items: list[dict[str, Any]], errors: list[FakeResponse] | None = None) -> FakeSession:
        session = FakeSession(items, errors)
        monkeypatch.setattr(fetcher.requests, "Session", lambda: session)
        return session

    install.sleeps = sleeps  # type: ignore[attr-defined]
    return install


def test_pages_until_total_results_newest_first(nvd) -> None:
    session = nvd([cve(i) for i in range(5)])
    result = fetcher.fetch_cves("nginx", days=7, max_results=50)
    assert [c["id"] for c in result] == [f"CVE-2026-{1000 + i}" for i in reversed(range(5))]
    assert [c["params"]["startIndex"] for c in session.calls] == [0, 2, 4]


def test_truncation_keeps_newest_not_oldest(nvd) -> None:
    session = nvd([cve(i) for i in range(10)])
    result = fetcher.fetch_cves("nginx", days=7, max_results=3)
    assert [c["id"] for c in result] == ["CVE-2026-1009", "CVE-2026-1008", "CVE-2026-1007"]
    assert [c["params"]["startIndex"] for c in session.calls] == [0, 7, 9]


def test_long_lookback_split_into_nvd_windows(nvd) -> None:
    session = nvd([])
    fetcher.fetch_cves("nginx", days=200, max_results=50)
    assert len(session.calls) == 2
    for call in session.calls:
        start = datetime.strptime(call["params"]["pubStartDate"], FMT)
        end = datetime.strptime(call["params"]["pubEndDate"], FMT)
        assert (end - start).days <= 120


def test_retries_rate_limit_then_succeeds(nvd) -> None:
    nvd([cve(1)], errors=[FakeResponse(429, headers={"Retry-After": "7"})])
    result = fetcher.fetch_cves("nginx", days=7, rate_limit_delay=6.5)
    assert len(result) == 1
    assert 7.0 in nvd.sleeps


def test_gives_up_after_max_retries(nvd) -> None:
    retries = get_settings().nvd_max_retries
    nvd([cve(1)], errors=[FakeResponse(503)] * (retries + 1))
    with pytest.raises(fetcher.NVDError):
        fetcher.fetch_cves("nginx", days=7)


def test_non_retryable_error_raises_immediately(nvd) -> None:
    session = nvd([cve(1)], errors=[FakeResponse(403)])
    with pytest.raises(fetcher.NVDError):
        fetcher.fetch_cves("nginx", days=7)
    assert len(session.calls) == 1


def test_api_key_sent_as_header_and_delay_reduced(nvd, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "nvd_api_key", SecretStr("k" * 36))
    session = nvd([cve(1)])
    fetcher.fetch_cves("nginx", days=7, rate_limit_delay=6.5)
    assert session.calls[0]["headers"] == {"apiKey": "k" * 36}
    assert nvd.sleeps == [0.6]


def test_no_api_key_means_no_header_and_full_delay(nvd) -> None:
    session = nvd([cve(1)])
    fetcher.fetch_cves("nginx", days=7, rate_limit_delay=6.5)
    assert session.calls[0]["headers"] == {}
    assert nvd.sleeps == [6.5]


def test_malformed_and_duplicate_entries_dropped(nvd) -> None:
    items = [cve(1), cve(1), {"cve": {"id": "not-a-cve"}}, {"nope": 1}, cve(2)]
    nvd(items)
    result = fetcher.fetch_cves("nginx", days=7)
    assert [c["id"] for c in result] == ["CVE-2026-1002", "CVE-2026-1001"]


@pytest.mark.parametrize(
    "product,days,max_results",
    [("", 7, 10), ("x" * 101, 7, 10), ("nginx", 0, 10), ("nginx", 7, 0)],
)
def test_rejects_bad_arguments(nvd, product: str, days: int, max_results: int) -> None:
    with pytest.raises(ValueError):
        fetcher.fetch_cves(product, days=days, max_results=max_results)


def test_cvss_prefers_newest_version_and_takes_max() -> None:
    metrics = {
        "cvssMetricV40": [{"cvssData": {"baseScore": 6.9}}, {"cvssData": {"baseScore": 8.7}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
    }
    assert fetcher.extract_cvss_score({"metrics": metrics}) == 8.7


def test_cvss_zero_is_kept_not_dropped() -> None:
    assert fetcher.extract_cvss_score({"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 0.0}}]}}) == 0.0
    assert fetcher.extract_cvss_score({"metrics": {}}) is None
