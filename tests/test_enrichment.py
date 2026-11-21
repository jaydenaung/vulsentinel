"""Deterministic enrichment: KEV catalog + bulk EPSS. Network is stubbed."""

from typing import Any

import pytest
import requests

import enrichment


class Resp:
    def __init__(self, payload: dict[str, Any]):
        self._payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict[str, Any]:
        return self._payload


@pytest.fixture()
def calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    kev = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-02",
                                "knownRansomwareCampaignUse": "Known"}]}

    def fake_get(url: str, params: dict[str, str] | None = None, timeout: float = 0) -> Resp:
        seen.append({"url": url, "params": params})
        if params is None:
            return Resp(kev)
        ids = params["cve"].split(",")
        return Resp({"data": [{"cve": i, "epss": "0.5", "percentile": "0.9"} for i in ids]})

    monkeypatch.setattr(enrichment, "_kev_cache", None)
    monkeypatch.setattr(enrichment.requests, "get", fake_get)
    monkeypatch.setattr(enrichment.get_settings(), "epss_bulk_size", 2)
    return seen


def test_kev_and_epss_in_bulk(calls) -> None:
    ev = enrichment.enrich(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "not-a-cve"])
    assert set(ev) == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}
    assert ev["CVE-2026-0001"].in_kev and ev["CVE-2026-0001"].kev_ransomware
    assert ev["CVE-2026-0002"].in_kev is False
    assert ev["CVE-2026-0003"].epss_score == pytest.approx(0.5)
    epss_calls = [c for c in calls if c["params"]]
    assert len(epss_calls) == 2  # 3 IDs, chunk size 2


def test_kev_failure_degrades_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Resp:
        raise requests.ConnectionError("down")

    monkeypatch.setattr(enrichment, "_kev_cache", None)
    monkeypatch.setattr(enrichment.requests, "get", boom)
    ev = enrichment.enrich(["CVE-2026-0001"])
    assert ev["CVE-2026-0001"].in_kev is None
    assert ev["CVE-2026-0001"].epss_score is None
