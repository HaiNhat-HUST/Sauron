"""Content cleaning pipeline for collected text.

Produces the canonical "full content" stored in both PostgreSQL and the vector
database. Steps:

1. Strip HTML (drop script/style/nav and tags, unescape entities).
2. Remove common ad / boilerplate lines (newsletter, cookie, share prompts...).
3. Normalize Unicode (NFKC).
4. Expand defanged IOCs (hxxp→http, ``[.]``→``.``) so stored text is canonical.
5. Collapse duplicate whitespace.

Dependency-free (uses the stdlib ``html.parser``).
"""

from __future__ import annotations

import re
import unicodedata
from html.parser import HTMLParser

from .ioc_extractor import refang

_SKIP_TAGS = {"script", "style", "noscript", "iframe", "svg", "head"}
_BLOCK_TAGS = {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article"}


class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip:
            self._skip -= 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


# Lines (case-insensitive) that are almost always ads / navigation / boilerplate.
_AD_LINE = re.compile(
    r"\b(advertisement|sponsored|subscribe to our newsletter|sign up for|"
    r"share this article|follow us on|read more|cookie policy|accept cookies|"
    r"all rights reserved|©\s*\d{4}|back to top|related articles?)\b",
    re.I,
)
_HTML_HINT = re.compile(r"<[a-zA-Z/!]")
_MULTISPACE = re.compile(r"[^\S\n]+")     # runs of spaces/tabs (not newlines)
_MULTINEWLINE = re.compile(r"\n{3,}")     # 3+ newlines → 2


def strip_html(raw: str) -> str:
    parser = _HTMLStripper()
    try:
        parser.feed(raw)
        parser.close()
    except Exception:  # noqa: BLE001 — malformed HTML; fall back to raw
        return raw
    return parser.text()


def clean_text(raw: str | None) -> str | None:
    """Return the canonical cleaned form of ``raw`` (or None)."""
    if not raw:
        return None

    text = strip_html(raw) if _HTML_HINT.search(raw) else raw
    text = unicodedata.normalize("NFKC", text)
    text = refang(text)  # expand defanged IOCs to canonical form

    # Drop ad/boilerplate lines, trim each line, collapse intra-line spaces.
    kept: list[str] = []
    for line in text.splitlines():
        line = _MULTISPACE.sub(" ", line).strip()
        if not line or _AD_LINE.search(line):
            continue
        kept.append(line)

    cleaned = "\n".join(kept)
    cleaned = _MULTINEWLINE.sub("\n\n", cleaned).strip()
    return cleaned or None
