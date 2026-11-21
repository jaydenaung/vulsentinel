# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Triage pipeline: deterministic rules first, Claude only for the gray zone.

Order per CVE:
  1. unchanged inputs since last run  -> skip (no work, no tokens)
  2. in CISA KEV                      -> PATCH NOW          (rule:kev)
  3. no CVSS yet                      -> MONITOR, awaiting  (rule:no_cvss)
  4. CVSS and EPSS both low           -> LOW PRIORITY       (rule:low)
  5. everything else                  -> Claude, batched    (ai)
"""

import hashlib
import json
import logging
from typing import Any, Literal

import anthropic
from pydantic import BaseModel

from enrichment import Evidence, enrich
from scorer import FALLBACK_REASON, Usage, score_batch
from settings import estimate_cost_usd, get_settings

log = logging.getLogger(__name__)

DecidedBy = Literal["rule:kev", "rule:no_cvss", "rule:low", "ai", "fallback", "dry_run"]


class Decision(BaseModel):
    cve_id: str
    exposure_score: int | None
    telco_cnf_relevance: str
    recommended_action: str
    reason: str
    decided_by: DecidedBy
    in_kev: bool
    epss_score: float | None
    input_hash: str | None  # None = do not cache (retry next run)


class TriageStats(BaseModel):
    cached: int = 0
    rule_decided: int = 0
    ai_decided: int = 0
    fallback: int = 0
    usage: Usage = Usage()
    cost_usd: float | None = 0.0

    def finish(self, model: str) -> None:
        self.cost_usd = estimate_cost_usd(model, self.usage.input_tokens, self.usage.output_tokens)


def epss_level(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score < 0.01:
        return "negligible"
    if score < 0.1:
        return "low"
    return "medium" if score < 0.4 else "high"


def input_hash(summary: dict[str, Any], ev: Evidence, env_context: str) -> str:
    """Everything that could change the decision. Same hash = same answer, skip it."""
    cfg = get_settings()
    payload = {
        "description": summary.get("description", ""),
        "cvss": summary.get("cvss_score"),
        "in_kev": ev.in_kev,
        "epss_level": epss_level(ev.epss_score),
        "env": hashlib.sha256(env_context.encode()).hexdigest(),
        "prompt": cfg.triage_prompt_version,
        "model": cfg.anthropic_model,
        "rules": [cfg.rule_low_cvss_below, cfg.rule_low_epss_below],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _decision(cve_id: str, ev: Evidence, h: str | None, by: DecidedBy, action: str, reason: str,
              exposure: int | None = None, relevance: str = "N/A") -> Decision:
    return Decision(cve_id=cve_id, exposure_score=exposure, telco_cnf_relevance=relevance,
                    recommended_action=action, reason=reason, decided_by=by,
                    in_kev=bool(ev.in_kev), epss_score=ev.epss_score, input_hash=h)


def rule_decision(summary: dict[str, Any], ev: Evidence, h: str) -> Decision | None:
    cfg = get_settings()
    cve_id, cvss = summary["cve_id"], summary.get("cvss_score")
    if ev.in_kev:
        extra = ", known ransomware use" if ev.kev_ransomware else ""
        return _decision(cve_id, ev, h, "rule:kev", "PATCH NOW",
                         f"Listed in CISA KEV (added {ev.kev_date_added or 'unknown'}{extra}).")
    if cvss is None:
        return _decision(cve_id, ev, h, "rule:no_cvss", "MONITOR", "Awaiting NVD CVSS score.")
    epss_low = ev.epss_score is None or ev.epss_score < cfg.rule_low_epss_below
    if cvss < cfg.rule_low_cvss_below and epss_low:
        return _decision(cve_id, ev, h, "rule:low", "LOW PRIORITY",
                         f"Low severity (CVSS {cvss}), not in KEV, EPSS {epss_level(ev.epss_score)}.")
    return None


def triage(
    summaries: list[dict[str, Any]],
    env_context: str,
    client: anthropic.Anthropic | None,
    known_hashes: dict[str, str] | None = None,
) -> tuple[dict[str, Decision], dict[str, Evidence], TriageStats]:
    """Decide every CVE whose inputs changed. Returns (decisions, evidence for all, stats).

    known_hashes maps cve_id -> input_hash stored from a previous run. Matching CVEs are skipped.
    client=None means dry run: gray-zone CVEs are marked, not scored.
    """
    cfg = get_settings()
    known = known_hashes or {}
    unique = {s["cve_id"]: s for s in summaries}
    evidence = enrich(list(unique))
    stats = TriageStats()
    decisions: dict[str, Decision] = {}
    gray: list[tuple[dict[str, Any], Evidence, str]] = []

    for cve_id, summary in unique.items():
        ev = evidence.get(cve_id, Evidence())
        h = input_hash(summary, ev, env_context)
        if known.get(cve_id) == h:
            stats.cached += 1
            continue
        ruled = rule_decision(summary, ev, h)
        if ruled:
            decisions[cve_id] = ruled
            stats.rule_decided += 1
        else:
            gray.append((summary, ev, h))

    if client is None:
        for s, ev, _h in gray:
            decisions[s["cve_id"]] = _decision(s["cve_id"], ev, None, "dry_run", "MONITOR", "(dry run, AI skipped)")
        stats.finish(cfg.anthropic_model)
        return decisions, evidence, stats

    for i in range(0, len(gray), cfg.ai_batch_size):
        batch = gray[i:i + cfg.ai_batch_size]
        results = score_batch(client, [(s, ev) for s, ev, _ in batch], env_context, stats.usage)
        for s, ev, h in batch:
            r = results.get(s["cve_id"])
            if r:
                decisions[s["cve_id"]] = _decision(s["cve_id"], ev, h, "ai", r.recommended_action, r.reason,
                                                   r.exposure_score, r.telco_cnf_relevance)
                stats.ai_decided += 1
            else:
                decisions[s["cve_id"]] = _decision(s["cve_id"], ev, None, "fallback", "MONITOR", FALLBACK_REASON)
                stats.fallback += 1

    stats.finish(cfg.anthropic_model)
    log.info("Triage: %d cached, %d rule, %d ai, %d fallback, %d calls, %d in / %d out tokens, cost %s",
             stats.cached, stats.rule_decided, stats.ai_decided, stats.fallback, stats.usage.calls,
             stats.usage.input_tokens, stats.usage.output_tokens, stats.cost_usd)
    return decisions, evidence, stats
