# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""Claude AI scoring layer: agentic CVE analysis with tool use.

Claude may call check_cisa_kev / check_epss, then must finish by calling
submit_triage. The submitted input is untrusted model output, so it is
validated with Pydantic, and the KEV rule is enforced in code.
"""

import json
import logging
import os
import re
import time
from typing import Any, Literal

import anthropic
import requests
from pydantic import BaseModel, Field, ValidationError

from prompts import get_prompt
from settings import get_settings

log = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SUBMIT_TOOL = "submit_triage"
FALLBACK_REASON = "Scoring unavailable (see server log)"

Action = Literal["PATCH NOW", "MONITOR", "LOW PRIORITY"]
Relevance = Literal["HIGH", "MEDIUM", "LOW"]


class TriageResult(BaseModel):
    exposure_score: int = Field(ge=1, le=10)
    telco_cnf_relevance: Relevance
    recommended_action: Action
    reason: str = Field(min_length=1, max_length=600)


class Evidence(BaseModel):
    in_kev: bool | None = None
    epss_score: float | None = Field(default=None, ge=0, le=1)


_CVE_ID_SCHEMA = {
    "type": "object",
    "properties": {"cve_id": {"type": "string", "description": "CVE identifier, e.g. CVE-2024-1234"}},
    "required": ["cve_id"],
    "additionalProperties": False,
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "check_cisa_kev",
        "description": (
            "Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog. "
            "A hit means real-world exploitation is confirmed."
        ),
        "input_schema": _CVE_ID_SCHEMA,
    },
    {
        "name": "check_epss",
        "description": (
            "Get the EPSS score for a CVE: probability (0.0-1.0) of exploitation in the "
            "wild within 30 days. Above 0.4 indicates elevated risk."
        ),
        "input_schema": _CVE_ID_SCHEMA,
    },
    {
        "name": SUBMIT_TOOL,
        "description": "Submit the final triage assessment. Call exactly once, last.",
        "input_schema": {
            "type": "object",
            "properties": {
                "exposure_score": {"type": "integer", "description": "1-10, 10 = directly exploitable here"},
                "telco_cnf_relevance": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                "recommended_action": {"type": "string", "enum": ["PATCH NOW", "MONITOR", "LOW PRIORITY"]},
                "reason": {"type": "string", "description": "One concise sentence. Cite KEV/EPSS if they drove it."},
            },
            "required": ["exposure_score", "telco_cnf_relevance", "recommended_action", "reason"],
            "additionalProperties": False,
        },
    },
]


# ── Enrichment tools ──────────────────────────────────────────────────────────

_kev_cache: dict[str, Any] | None = None
_kev_fetched_at: float = 0.0


def _fetch_kev_catalog() -> dict[str, Any]:
    global _kev_cache, _kev_fetched_at
    cfg = get_settings()
    now = time.monotonic()
    if _kev_cache is None or (now - _kev_fetched_at) > cfg.kev_cache_ttl_seconds:
        resp = requests.get(cfg.cisa_kev_url, timeout=cfg.http_timeout_seconds)
        resp.raise_for_status()
        _kev_cache = {v["cveID"]: v for v in resp.json().get("vulnerabilities", []) if "cveID" in v}
        _kev_fetched_at = now
    return _kev_cache


def lookup_kev(cve_id: str) -> dict[str, Any]:
    entry = _fetch_kev_catalog().get(cve_id)
    if not entry:
        return {"in_kev": False}
    return {
        "in_kev": True,
        "vendor_project": entry.get("vendorProject"),
        "product": entry.get("product"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "date_added": entry.get("dateAdded"),
        "required_action": entry.get("requiredAction"),
        "due_date": entry.get("dueDate"),
    }


def lookup_epss(cve_id: str) -> dict[str, Any]:
    cfg = get_settings()
    resp = requests.get(cfg.epss_api_url, params={"cve": cve_id}, timeout=cfg.http_timeout_seconds)
    resp.raise_for_status()
    items = resp.json().get("data", [])
    if not items:
        return {"epss_score": None, "note": "No EPSS data for this CVE"}
    item = items[0]
    return {
        "epss_score": float(item.get("epss", 0)),
        "percentile": float(item.get("percentile", 0)),
        "date": item.get("date"),
    }


_LOOKUPS = {"check_cisa_kev": lookup_kev, "check_epss": lookup_epss}


def _run_lookup(name: str, tool_input: dict[str, Any], evidence: Evidence) -> tuple[dict[str, Any], bool]:
    """Run an enrichment tool. Returns (result, is_error). Records evidence."""
    cve_id = str(tool_input.get("cve_id", "")).strip().upper()
    if not CVE_ID_RE.match(cve_id):
        return {"error": "cve_id must look like CVE-YYYY-NNNN"}, True
    try:
        result = _LOOKUPS[name](cve_id)
    except (requests.RequestException, ValueError) as exc:
        log.warning("Tool %s failed for %s: %s", name, cve_id, exc)
        return {"error": "lookup failed, continue without this signal"}, True
    if name == "check_cisa_kev":
        evidence.in_kev = bool(result.get("in_kev"))
    elif result.get("epss_score") is not None:
        evidence.epss_score = result["epss_score"]
    return result, False


def _tool_result(block_id: str, content: dict[str, Any], is_error: bool) -> dict[str, Any]:
    return {"type": "tool_result", "tool_use_id": block_id, "content": json.dumps(content), "is_error": is_error}


# ── Agentic scoring loop ──────────────────────────────────────────────────────

def _build_prompt(cve_summary: dict[str, Any], env_context: str) -> str:
    return get_prompt("triage_user", get_settings().triage_prompt_version).format(
        env_context=env_context or "(none provided)",
        cve_id=cve_summary["cve_id"],
        product=cve_summary["product"],
        cvss_score=cve_summary.get("cvss_score") or "N/A",
        published=cve_summary.get("published", ""),
        description=str(cve_summary.get("description", ""))[:800],
    )


def _handle_tool_turn(content: list[Any], evidence: Evidence) -> tuple[TriageResult | None, list[dict[str, Any]]]:
    """Process tool_use blocks. Returns (validated result if submitted, tool_result blocks)."""
    results: list[dict[str, Any]] = []
    submitted: TriageResult | None = None
    for block in content:
        if getattr(block, "type", None) != "tool_use":
            continue
        tool_input = dict(block.input) if isinstance(block.input, dict) else {}
        if block.name == SUBMIT_TOOL:
            try:
                submitted = TriageResult.model_validate(tool_input)
                results.append(_tool_result(block.id, {"ok": True}, False))
            except ValidationError as exc:
                errors = [{"field": ".".join(map(str, e["loc"])), "msg": e["msg"]} for e in exc.errors()]
                results.append(_tool_result(block.id, {"error": "invalid assessment", "details": errors}, True))
        elif block.name in _LOOKUPS:
            output, is_error = _run_lookup(block.name, tool_input, evidence)
            results.append(_tool_result(block.id, output, is_error))
        else:
            results.append(_tool_result(block.id, {"error": f"unknown tool {block.name}"}, True))
    return submitted, results


def _enforce_kev_rule(cve_id: str, result: TriageResult, evidence: Evidence) -> TriageResult:
    """KEV hit always means PATCH NOW. Checked in code, not trusted to the model."""
    if evidence.in_kev is None:
        try:
            evidence.in_kev = bool(lookup_kev(cve_id).get("in_kev"))
        except (requests.RequestException, ValueError) as exc:
            log.warning("KEV check failed for %s: %s", cve_id, exc)
    if evidence.in_kev and result.recommended_action != "PATCH NOW":
        log.info("%s is in CISA KEV; escalating %s to PATCH NOW", cve_id, result.recommended_action)
        return result.model_copy(update={
            "recommended_action": "PATCH NOW",
            "reason": f"Listed in CISA KEV (escalated). {result.reason}"[:600],
        })
    return result


def _fallback(evidence: Evidence) -> dict[str, Any]:
    return {
        "exposure_score": None,
        "telco_cnf_relevance": "MEDIUM",
        "recommended_action": "PATCH NOW" if evidence.in_kev else "MONITOR",
        "reason": FALLBACK_REASON,
        **evidence.model_dump(),
    }


def score_cve(client: anthropic.Anthropic, cve_summary: dict[str, Any], env_context: str) -> dict[str, Any]:
    """Score one CVE. Returns TriageResult fields plus in_kev and epss_score."""
    cfg = get_settings()
    cve_id = cve_summary["cve_id"]
    system = get_prompt("triage_system", cfg.triage_prompt_version)
    nudge = get_prompt("triage_nudge", cfg.triage_prompt_version)
    messages: list[dict[str, Any]] = [{"role": "user", "content": _build_prompt(cve_summary, env_context)}]
    evidence = Evidence()

    try:
        for _turn in range(cfg.max_agent_turns):
            response = client.messages.create(
                model=cfg.anthropic_model,
                max_tokens=cfg.anthropic_max_tokens,
                system=system,
                tools=TOOLS,  # type: ignore[arg-type]
                tool_choice={"type": "auto"},
                messages=messages,  # type: ignore[arg-type]
            )
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "tool_use":
                submitted, tool_results = _handle_tool_turn(response.content, evidence)
                if submitted is not None:
                    final = _enforce_kev_rule(cve_id, submitted, evidence)
                    return {**final.model_dump(), **evidence.model_dump()}
                messages.append({"role": "user", "content": tool_results})
            elif response.stop_reason == "end_turn":
                messages.append({"role": "user", "content": nudge})
            else:
                log.warning("Scoring %s stopped early: stop_reason=%s", cve_id, response.stop_reason)
                return _fallback(evidence)

        log.warning("Scoring %s gave no valid submit_triage within %d turns", cve_id, cfg.max_agent_turns)
    except anthropic.APIError as exc:
        log.error("Claude API error while scoring %s: %s", cve_id, type(exc).__name__)
    return _fallback(evidence)


def build_client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDEAPI")
    if not api_key:
        raise OSError("ANTHROPIC_API_KEY environment variable not set.")
    return anthropic.Anthropic(api_key=api_key)
