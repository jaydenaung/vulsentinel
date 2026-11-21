# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Deterministic guard for untrusted CVE text before it reaches Claude. No AI.

clean_description: strips hidden characters used to smuggle instructions.
injection_signals: flags text that reads like orders to a model. Pattern matching can be
dodged by rewording, so it only decides isolation; the floors in triage.py are the backstop.
"""

import re
import unicodedata

MAX_DESCRIPTION_CHARS = 800

# Cc control, Cf format (zero-width, bidi overrides, tag chars), Co private use, Cs surrogates.
_HIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cs"}
_WHITESPACE = re.compile(r"\s+")
_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

_PATTERNS: dict[str, re.Pattern[str]] = {
    "override": re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|any|system|your)\b"
        r".{0,20}\b(instructions?|prompts?|rules|messages|guidelines)\b"),
    "new_instructions": re.compile(r"\b(new|updated|real|actual) instructions?\b"),
    "system_prompt": re.compile(r"\bsystem prompt\b"),
    "role_play": re.compile(r"\b(you are now|act as|as an ai|you are an? (ai|assistant|language model))\b"),
    "role_marker": re.compile(r"(^|[\n.!?]\s*)(system|assistant|human|user)\s*:"),
    "fake_tag": re.compile(
        r"</?\s*(system|assistant|user|human|instructions?|cve|environment_context|tool_use|function_calls?)\b"),
    "triage_vocab": re.compile(
        r"\b(low priority|patch now|recommended_action|exposure_score|telco_cnf_relevance|submit_triage\w*)\b"),
    "steer_others": re.compile(
        r"\b(mark|rate|score|classify|treat|consider)\b.{0,20}\b(all|every|other|these|the rest|remaining)\b"
        r".{0,20}\b(cves?|vulnerabilit\w+|entries|items)\b"),
}


def clean_description(text: str) -> str:
    """NFKC-normalise, drop hidden characters, collapse whitespace, cap length."""
    normalised = unicodedata.normalize("NFKC", text or "")
    visible = "".join(
        " " if ch in "\n\r\t" else ch
        for ch in normalised
        if ch in "\n\r\t" or unicodedata.category(ch) not in _HIDDEN_CATEGORIES
    )
    return _WHITESPACE.sub(" ", visible).strip()[:MAX_DESCRIPTION_CHARS]


def injection_signals(text: str, own_id: str, batch_ids: set[str]) -> list[str]:
    """Names of the patterns that fired. Empty list = looks like a normal CVE description."""
    raw = unicodedata.normalize("NFKC", text or "")
    hidden = any(unicodedata.category(ch) in _HIDDEN_CATEGORIES and ch not in "\n\r\t" for ch in raw)
    lowered = clean_description(raw).lower()
    signals = [name for name, pattern in _PATTERNS.items() if pattern.search(lowered)]
    if hidden:
        signals.append("hidden_chars")
    others = {m.upper() for m in _CVE_ID.findall(lowered)} & (batch_ids - {own_id})
    if others:
        signals.append("names_batch_cve")
    return signals
