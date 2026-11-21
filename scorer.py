# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""Claude scoring for gray-zone CVEs only: one batched request, validated output.

KEV/EPSS are looked up in code (enrichment.py) and passed in as evidence, so
there are no tool round trips. Claude returns all assessments through one
submit_triage_batch call; each item is validated with Pydantic. Model output
is untrusted: unknown CVE IDs are dropped, missing ones fall back.
"""

import html
import logging
import os
from typing import Any, Literal

import anthropic
from pydantic import BaseModel, Field, ValidationError

from enrichment import Evidence
from prompt_guard import clean_description
from prompts import get_prompt
from settings import get_settings

log = logging.getLogger(__name__)

SUBMIT_TOOL = "submit_triage_batch"
FALLBACK_REASON = "Scoring unavailable (see server log)"

Action = Literal["PATCH NOW", "MONITOR", "LOW PRIORITY"]
Relevance = Literal["HIGH", "MEDIUM", "LOW"]


class TriageResult(BaseModel):
    exposure_score: int = Field(ge=1, le=10)
    telco_cnf_relevance: Relevance
    recommended_action: Action
    reason: str = Field(min_length=1, max_length=600)


class _Assessment(TriageResult):
    cve_id: str


class Usage(BaseModel):
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, response: Any) -> None:
        self.calls += 1
        usage = getattr(response, "usage", None)
        self.input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
        self.output_tokens += int(getattr(usage, "output_tokens", 0) or 0)


TOOLS: list[dict[str, Any]] = [{
    "name": SUBMIT_TOOL,
    "description": "Submit the triage assessment for every CVE in the request. Call exactly once.",
    "input_schema": {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string"},
                        "exposure_score": {"type": "integer", "description": "1-10, 10 = directly exploitable here"},
                        "telco_cnf_relevance": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                        "recommended_action": {"type": "string", "enum": ["PATCH NOW", "MONITOR", "LOW PRIORITY"]},
                        "reason": {"type": "string", "description": "One short sentence."},
                    },
                    "required": ["cve_id", "exposure_score", "telco_cnf_relevance", "recommended_action", "reason"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["assessments"],
        "additionalProperties": False,
    },
}]


def _fmt_epss(ev: Evidence) -> str:
    return "unknown" if ev.epss_score is None else f"{ev.epss_score:.3f}"


def build_batch_prompt(items: list[tuple[dict[str, Any], Evidence]], env_context: str) -> str:
    version = get_settings().triage_prompt_version
    item_tpl = get_prompt("triage_item", version)
    blocks = [
        item_tpl.format(
            cve_id=s["cve_id"],
            product=html.escape(str(s.get("product", "")), quote=True),
            cvss_score=s.get("cvss_score") if s.get("cvss_score") is not None else "N/A",
            epss=_fmt_epss(ev),
            # Strip hidden characters, then escape so a description cannot close its <cve> block.
            description=html.escape(clean_description(str(s.get("description", ""))), quote=False),
        )
        for s, ev in items
    ]
    return get_prompt("triage_user", version).format(
        env_context=env_context or "(none provided)", count=len(items), items="\n".join(blocks),
    )


def _parse_submission(content: list[Any], wanted: set[str]) -> dict[str, TriageResult] | None:
    """Return validated results from a submit call, or None if no submit call was made."""
    for block in content:
        if getattr(block, "type", None) != "tool_use" or block.name != SUBMIT_TOOL:
            continue
        raw = block.input.get("assessments", []) if isinstance(block.input, dict) else []
        results: dict[str, TriageResult] = {}
        for item in raw if isinstance(raw, list) else []:
            try:
                a = _Assessment.model_validate(item)
            except ValidationError:
                log.warning("Dropped invalid assessment from model")
                continue
            cve_id = a.cve_id.strip().upper()
            if cve_id in wanted and cve_id not in results:
                results[cve_id] = TriageResult(**a.model_dump(exclude={"cve_id"}))
        return results
    return None


def score_batch(
    client: anthropic.Anthropic,
    items: list[tuple[dict[str, Any], Evidence]],
    env_context: str,
    usage: Usage,
) -> dict[str, TriageResult]:
    """Score up to ai_batch_size CVEs in one request (plus at most one nudge). Missing IDs are absent."""
    if not items:
        return {}
    cfg = get_settings()
    wanted = {s["cve_id"] for s, _ in items}
    messages: list[dict[str, Any]] = [{"role": "user", "content": build_batch_prompt(items, env_context)}]
    try:
        for attempt in range(2):
            response = client.messages.create(
                model=cfg.anthropic_model,
                max_tokens=cfg.anthropic_max_tokens,
                system=get_prompt("triage_system", cfg.triage_prompt_version),
                tools=TOOLS,  # type: ignore[arg-type]
                tool_choice={"type": "auto"},
                messages=messages,  # type: ignore[arg-type]
            )
            usage.add(response)
            results = _parse_submission(response.content, wanted)
            if results is not None:
                missing = wanted - results.keys()
                if missing:
                    log.warning("Model skipped %d of %d CVEs in batch", len(missing), len(wanted))
                return results
            if attempt == 0 and response.stop_reason == "end_turn":
                messages += [{"role": "assistant", "content": response.content},
                             {"role": "user", "content": get_prompt("triage_nudge", cfg.triage_prompt_version)}]
                continue
            log.warning("No %s call (stop_reason=%s)", SUBMIT_TOOL, response.stop_reason)
            break
    except anthropic.APIError as exc:
        log.error("Claude API error while scoring batch: %s", type(exc).__name__)
    return {}


def build_client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDEAPI")
    if not api_key:
        raise OSError("ANTHROPIC_API_KEY environment variable not set.")
    return anthropic.Anthropic(api_key=api_key)
