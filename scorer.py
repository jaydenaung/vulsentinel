# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""Claude AI scoring layer — agentic CVE analysis with tool use."""

import json
import os
import time
from typing import Any

import anthropic
import requests

MODEL = "claude-sonnet-4-6"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# In-process cache for the KEV catalog (refreshed every hour)
_kev_cache: dict[str, Any] | None = None
_kev_fetched_at: float = 0.0
_KEV_TTL = 3600.0

SYSTEM_PROMPT = """You are a senior security engineer specialising in cloud-native and
telco/5G security. You triage CVEs for a team running Kubernetes, CNFs, 5G core
(Nokia network functions), Istio service mesh, containerd, nginx, and OpenSSL on
Linux. Your job is to assess each CVE's real-world risk for that specific environment.

You have two tools available:
- check_cisa_kev: confirms whether a CVE is actively exploited in the wild (CISA catalog).
- check_epss: returns the probability (0–1) that a CVE will be exploited within 30 days.

Rules for tool use:
1. Always call check_cisa_kev for any CVE with CVSS >= 7.0 — a KEV hit immediately
   escalates to PATCH NOW regardless of other factors.
2. Call check_epss when CVSS is >= 6.0 and KEV status alone is ambiguous.
3. Skip tools for low CVSS (< 6.0) CVEs where additional data would not change LOW PRIORITY.

After gathering intelligence, respond with valid JSON only — no markdown, no extra text:
{
  "exposure_score": <integer 1-10, where 10 = directly exploitable in our environment>,
  "telco_cnf_relevance": "<HIGH|MEDIUM|LOW>",
  "recommended_action": "<PATCH NOW|MONITOR|LOW PRIORITY>",
  "reason": "<one concise sentence — cite KEV or EPSS findings if they drove the decision>"
}"""

SCORING_TEMPLATE = """Assess this CVE for our environment. Use your tools before making a recommendation.

Environment context:
{env_context}

CVE details:
- ID: {cve_id}
- Product: {product}
- CVSS Score: {cvss_score}
- Published: {published}
- Description: {description}"""

TOOLS: list[dict[str, Any]] = [
    {
        "name": "check_cisa_kev",
        "description": (
            "Check if a CVE is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog. "
            "A KEV hit means real-world exploitation is confirmed — the strongest possible signal "
            "to escalate to PATCH NOW regardless of CVSS score."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE identifier, e.g. CVE-2024-1234"}
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "check_epss",
        "description": (
            "Get the EPSS (Exploit Prediction Scoring System) score for a CVE — "
            "the probability (0.0–1.0) of exploitation in the wild within 30 days. "
            "Scores above 0.4 indicate elevated real-world exploitation risk."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE identifier, e.g. CVE-2024-1234"}
            },
            "required": ["cve_id"],
        },
    },
]


# ── Tool implementations ──────────────────────────────────────────────────────

def _fetch_kev_catalog() -> dict[str, Any]:
    global _kev_cache, _kev_fetched_at
    now = time.monotonic()
    if _kev_cache is None or (now - _kev_fetched_at) > _KEV_TTL:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        _kev_fetched_at = now
    return _kev_cache


def _tool_check_cisa_kev(cve_id: str) -> dict[str, Any]:
    try:
        entry = _fetch_kev_catalog().get(cve_id)
        if entry:
            return {
                "in_kev": True,
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "date_added": entry.get("dateAdded"),
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "due_date": entry.get("dueDate"),
            }
        return {"in_kev": False}
    except Exception as exc:
        return {"error": str(exc)}


def _tool_check_epss(cve_id: str) -> dict[str, Any]:
    try:
        resp = requests.get(EPSS_API_URL, params={"cve": cve_id}, timeout=10)
        resp.raise_for_status()
        items = resp.json().get("data", [])
        if items:
            item = items[0]
            return {
                "epss_score": float(item.get("epss", 0)),
                "percentile": float(item.get("percentile", 0)),
                "date": item.get("date"),
            }
        return {"epss_score": None, "note": "No EPSS data for this CVE"}
    except Exception as exc:
        return {"error": str(exc)}


def _execute_tool(name: str, tool_input: dict[str, Any]) -> Any:
    if name == "check_cisa_kev":
        return _tool_check_cisa_kev(tool_input["cve_id"])
    if name == "check_epss":
        return _tool_check_epss(tool_input["cve_id"])
    return {"error": f"Unknown tool: {name}"}


# ── Agentic scoring loop ──────────────────────────────────────────────────────

def score_cve(
    client: anthropic.Anthropic,
    cve_summary: dict[str, Any],
    env_context: str,
) -> dict[str, Any]:
    """Score a CVE using an agentic Claude loop with tool use.

    Claude autonomously calls check_cisa_kev and/or check_epss before
    arriving at its final JSON recommendation. Returns a dict with keys:
    exposure_score, telco_cnf_relevance, recommended_action, reason.
    """
    prompt = SCORING_TEMPLATE.format(
        env_context=env_context,
        cve_id=cve_summary["cve_id"],
        product=cve_summary["product"],
        cvss_score=cve_summary["cvss_score"] or "N/A",
        published=cve_summary["published"],
        description=cve_summary["description"][:800],
    )

    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]

    try:
        while True:
            response = client.messages.create(
                model=MODEL,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOLS,  # type: ignore[arg-type]
                messages=messages,  # type: ignore[arg-type]
            )

            if response.stop_reason == "end_turn":
                for block in response.content:
                    if isinstance(block, anthropic.types.TextBlock):
                        raw = block.text.strip()
                        if raw.startswith("```"):
                            raw = raw.split("```")[1]
                            if raw.startswith("json"):
                                raw = raw[4:]
                        result = json.loads(raw)
                        result["exposure_score"] = int(result.get("exposure_score", 5))
                        result["telco_cnf_relevance"] = str(result.get("telco_cnf_relevance", "MEDIUM")).upper()
                        result["recommended_action"] = str(result.get("recommended_action", "MONITOR")).upper()
                        result["reason"] = str(result.get("reason", ""))
                        return result
                raise ValueError("No text block in final response")

            if response.stop_reason == "tool_use":
                messages.append({"role": "assistant", "content": response.content})  # type: ignore[arg-type]
                tool_results: list[dict[str, Any]] = []
                for block in response.content:
                    if isinstance(block, anthropic.types.ToolUseBlock):
                        output = _execute_tool(block.name, dict(block.input))
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(output),
                        })
                messages.append({"role": "user", "content": tool_results})  # type: ignore[arg-type]
                continue

            raise ValueError(f"Unexpected stop_reason: {response.stop_reason}")

    except (json.JSONDecodeError, KeyError, IndexError, ValueError, anthropic.APIError) as exc:
        return {
            "exposure_score": 5,
            "telco_cnf_relevance": "MEDIUM",
            "recommended_action": "MONITOR",
            "reason": f"Scoring unavailable ({exc})",
        }


def build_client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDEAPI")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable not set.")
    return anthropic.Anthropic(api_key=api_key)
