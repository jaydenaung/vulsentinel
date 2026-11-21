# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""RSS/Atom parsing for security research feeds. No DB, no network.

Feed content is untrusted: HTML becomes plain text, links must be http(s),
and every field is length-capped before it leaves this module.
"""

import calendar
import hashlib
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

import feedparser
from pydantic import BaseModel, Field

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
MAX_ENTRIES = 200


class ArticleIn(BaseModel):
    guid: str = Field(min_length=1, max_length=500)
    url: str | None = Field(default=None, max_length=2000)
    title: str = Field(min_length=1, max_length=300)
    summary: str = Field(default="", max_length=1000)
    published_at: str | None = None  # ISO 8601 UTC
    cve_ids: list[str] = Field(default_factory=list)


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skipping = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skipping += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skipping:
            self._skipping -= 1

    def handle_data(self, data: str) -> None:
        if not self._skipping:
            self.parts.append(data)


def html_to_text(value: str, limit: int) -> str:
    parser = _TextExtractor()
    parser.feed(value or "")
    parser.close()
    text = re.sub(r"\s+", " ", "".join(parser.parts)).strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def safe_link(value: Any) -> str | None:
    """Only absolute http(s) links survive. Blocks javascript:, data:, relative junk."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc or len(url) > 2000:
        return None
    return url


def extract_cve_ids(*texts: str) -> list[str]:
    found = {f"CVE-{m.group(1)}-{m.group(2)}" for text in texts for m in CVE_RE.finditer(text or "")}
    return sorted(found)


def _published(entry: Any) -> str | None:
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                return datetime.fromtimestamp(calendar.timegm(parsed), tz=UTC).isoformat(timespec="seconds")
            except (OverflowError, ValueError, TypeError):
                continue
    return None


def _guid(entry: Any, link: str | None, title: str) -> str:
    raw = entry.get("id") or link
    if isinstance(raw, str) and raw.strip():
        return raw.strip()[:500]
    return "sha256:" + hashlib.sha256(title.encode()).hexdigest()


def parse_feed(content: bytes) -> list[ArticleIn]:
    """Parse feed bytes into validated articles. Invalid entries are skipped."""
    parsed = feedparser.parse(content)  # bytes in: feedparser never fetches anything itself
    articles: list[ArticleIn] = []
    for entry in parsed.entries[:MAX_ENTRIES]:
        title = html_to_text(str(entry.get("title", "")), 300)
        if not title:
            continue
        summary_html = str(entry.get("summary", "") or "")
        summary = html_to_text(summary_html, 1000)
        link = safe_link(entry.get("link"))
        articles.append(ArticleIn(
            guid=_guid(entry, link, title),
            url=link,
            title=title,
            summary=summary,
            published_at=_published(entry),
            cve_ids=extract_cve_ids(title, html_to_text(summary_html, 20000)),
        ))
    return articles
