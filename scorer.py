# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""Claude AI scoring layer — contextual risk analysis for CVEs."""

import json
import os
from typing import Any

import anthropic

MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a senior security engineer specialising in cloud-native and
telco/5G security. You triage CVEs for a team running Kubernetes, CNFs, 5G core
(Nokia network functions), Istio service mesh, containerd, nginx, and OpenSSL on
Linux. Your job is to assess each CVE's real-world risk for that specific environment
and recommend a concrete action.

Always respond with valid JSON only — no markdown, no extra text."""

SCORING_TEMPLATE = """Assess this CVE for our environment and respond with JSON only.

Environment context:
{env_context}

CVE details:
- ID: {cve_id}
- Product: {product}
- CVSS Score: {cvss_score}
- Published: {published}
- Description: {description}

Respond with exactly this JSON structure:
{{
  "exposure_score": <integer 1-10, where 10 = directly exploitable in our environment>,
  "telco_cnf_relevance": "<HIGH|MEDIUM|LOW>",
  "recommended_action": "<PATCH NOW|MONITOR|LOW PRIORITY>",
  "reason": "<one concise sentence explaining the risk and recommendation>"
}}"""


def score_cve(
    client: anthropic.Anthropic,
    cve_summary: dict[str, Any],
    env_context: str,
) -> dict[str, Any]:
    """Score a CVE using Claude AI and return a scoring dict.

    Args:
        client: Anthropic client instance.
        cve_summary: Dict from fetcher.format_cve_summary().
        env_context: Environment description from config.

    Returns:
        Dict with keys: exposure_score, telco_cnf_relevance,
        recommended_action, reason. Falls back to safe defaults on error.
    """
    prompt = SCORING_TEMPLATE.format(
        env_context=env_context,
        cve_id=cve_summary["cve_id"],
        product=cve_summary["product"],
        cvss_score=cve_summary["cvss_score"] or "N/A",
        published=cve_summary["published"],
        description=cve_summary["description"][:800],
    )

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        # Strip markdown code fences if Claude adds them anyway
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw)
        # Normalise types
        result["exposure_score"] = int(result.get("exposure_score", 5))
        result["telco_cnf_relevance"] = str(result.get("telco_cnf_relevance", "MEDIUM")).upper()
        result["recommended_action"] = str(result.get("recommended_action", "MONITOR")).upper()
        result["reason"] = str(result.get("reason", ""))
        return result
    except (json.JSONDecodeError, KeyError, IndexError, anthropic.APIError) as exc:
        return {
            "exposure_score": 5,
            "telco_cnf_relevance": "MEDIUM",
            "recommended_action": "MONITOR",
            "reason": f"Scoring unavailable ({exc})",
        }


def build_client() -> anthropic.Anthropic:
    """Create Anthropic client from ANTHROPIC_API_KEY env var."""
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDEAPI")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY environment variable not set."
        )
    return anthropic.Anthropic(api_key=api_key)
