"""Every external script and stylesheet must carry a Subresource Integrity hash."""

import re
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent.parent / "web" / "templates"
EXTERNAL_TAG = re.compile(r"<(?:script|link)\b[^>]*\b(?:src|href)=\"https?://[^\"]+\"[^>]*>", re.IGNORECASE)


def test_external_assets_have_integrity_and_crossorigin() -> None:
    tags = [(f.name, t) for f in TEMPLATES.glob("*.html") for t in EXTERNAL_TAG.findall(f.read_text())]
    tags = [(n, t) for n, t in tags if "<link" not in t or 'rel="stylesheet"' in t]
    assert tags, "expected some CDN assets"
    for name, tag in tags:
        assert re.search(r'integrity="sha384-[A-Za-z0-9+/=]{64}"', tag), f"{name}: missing SRI on {tag}"
        assert 'crossorigin="anonymous"' in tag, f"{name}: missing crossorigin on {tag}"
