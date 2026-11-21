"""Rules-first triage: which CVEs reach Claude, and which are skipped. No network."""

from typing import Any

import pytest

import triage
from enrichment import Evidence
from scorer import TriageResult


def cve(cve_id: str, cvss: float | None, description: str = "d") -> dict[str, Any]:
    return {"cve_id": cve_id, "product": "nginx", "cvss_score": cvss, "description": description}


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub enrichment and the AI scorer. state['ev'] sets evidence, state['ai_seen'] records AI inputs."""
    state: dict[str, Any] = {"ev": {}, "ai_seen": [], "ai_answer": True}

    def fake_enrich(ids: list[str]) -> dict[str, Evidence]:
        return {i: state["ev"].get(i, Evidence(in_kev=False, epss_score=0.2)) for i in ids}

    def fake_score_batch(client, items, env, usage) -> dict[str, TriageResult]:
        usage.calls += 1
        usage.input_tokens += 500
        state["ai_seen"].append([s["cve_id"] for s, _ in items])
        if not state["ai_answer"]:
            return {}
        return {s["cve_id"]: TriageResult(exposure_score=7, telco_cnf_relevance="HIGH",
                                          recommended_action="PATCH NOW", reason="r") for s, _ in items}

    monkeypatch.setattr(triage, "enrich", fake_enrich)
    monkeypatch.setattr(triage, "score_batch", fake_score_batch)
    return state


def test_rules_decide_kev_low_and_no_cvss_without_ai(world) -> None:
    world["ev"] = {
        "CVE-2026-0001": Evidence(in_kev=True, kev_date_added="2026-11-01"),
        "CVE-2026-0002": Evidence(in_kev=False, epss_score=0.001),
    }
    summaries = [cve("CVE-2026-0001", 9.8), cve("CVE-2026-0002", 3.1), cve("CVE-2026-0003", None)]
    decisions, _, stats = triage.triage(summaries, "", client=object())
    assert decisions["CVE-2026-0001"].decided_by == "rule:kev"
    assert decisions["CVE-2026-0001"].recommended_action == "PATCH NOW"
    assert decisions["CVE-2026-0002"].decided_by == "rule:low"
    assert decisions["CVE-2026-0003"].decided_by == "rule:no_cvss"
    assert world["ai_seen"] == []
    assert (stats.rule_decided, stats.ai_decided, stats.usage.calls) == (3, 0, 0)


def test_low_cvss_with_high_epss_goes_to_ai(world) -> None:
    world["ev"] = {"CVE-2026-0002": Evidence(in_kev=False, epss_score=0.6)}
    decisions, _, _ = triage.triage([cve("CVE-2026-0002", 3.1)], "", client=object())
    assert decisions["CVE-2026-0002"].decided_by == "ai"


def test_gray_zone_is_batched(world, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(triage.get_settings(), "ai_batch_size", 2)
    summaries = [cve(f"CVE-2026-000{i}", 7.5) for i in range(1, 6)]
    _, _, stats = triage.triage(summaries, "", client=object())
    assert [len(b) for b in world["ai_seen"]] == [2, 2, 1]
    assert stats.ai_decided == 5


def test_duplicate_cve_across_products_scored_once(world) -> None:
    triage.triage([cve("CVE-2026-0001", 7.5), cve("CVE-2026-0001", 7.5)], "", client=object())
    assert world["ai_seen"] == [["CVE-2026-0001"]]


def test_unchanged_inputs_are_skipped(world) -> None:
    s = cve("CVE-2026-0001", 7.5)
    first, _, _ = triage.triage([s], "env", client=object())
    known = {"CVE-2026-0001": first["CVE-2026-0001"].input_hash}
    second, _, stats = triage.triage([s], "env", client=object(), known_hashes=known)
    assert second == {} and stats.cached == 1
    assert len(world["ai_seen"]) == 1


@pytest.mark.parametrize("change", ["description", "cvss", "env", "epss_level", "kev"])
def test_changed_inputs_change_the_hash(change: str) -> None:
    s, ev, env = cve("CVE-2026-0001", 7.5), Evidence(in_kev=False, epss_score=0.02), "env"
    base = triage.input_hash(s, ev, env)
    if change == "description":
        s = {**s, "description": "new text"}
    elif change == "cvss":
        s = {**s, "cvss_score": 9.1}
    elif change == "env":
        env = "other env"
    elif change == "epss_level":
        ev = Evidence(in_kev=False, epss_score=0.5)
    else:
        ev = Evidence(in_kev=True, epss_score=0.02)
    assert triage.input_hash(s, ev, env) != base


def test_small_epss_drift_inside_level_keeps_hash() -> None:
    s = cve("CVE-2026-0001", 7.5)
    assert triage.input_hash(s, Evidence(epss_score=0.02), "") == triage.input_hash(s, Evidence(epss_score=0.08), "")


def test_ai_failure_falls_back_and_is_not_cached(world) -> None:
    world["ai_answer"] = False
    decisions, _, stats = triage.triage([cve("CVE-2026-0001", 7.5)], "", client=object())
    d = decisions["CVE-2026-0001"]
    assert (d.decided_by, d.recommended_action, d.input_hash) == ("fallback", "MONITOR", None)
    assert stats.fallback == 1


def test_dry_run_never_calls_ai(world) -> None:
    decisions, _, stats = triage.triage([cve("CVE-2026-0001", 7.5)], "", client=None)
    assert decisions["CVE-2026-0001"].decided_by == "dry_run"
    assert world["ai_seen"] == [] and stats.usage.calls == 0


def test_cost_estimate_uses_model_price(world) -> None:
    _, _, stats = triage.triage([cve("CVE-2026-0001", 7.5)], "", client=object())
    assert stats.cost_usd == pytest.approx(500 * 3.00 / 1_000_000)
