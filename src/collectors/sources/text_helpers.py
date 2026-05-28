"""Shared logic for free-text (unstructured) connectors: RSS / Reddit / X.

Turns one free-text document into an :class:`ArticleRecord` carrying the IOCs
and CVE ids the regex extractor found. The LLM stage can later fill
``summary_llm`` and add higher-precision tags.
"""

from __future__ import annotations

from datetime import datetime

from ...extraction import ioc_extractor
from ...extraction.cleaner import clean_text
from ..records import ArticleRecord, IOCRecord


def build_article(
    *,
    title: str,
    text: str,
    url: str | None,
    published: datetime | None,
    source_name: str,
) -> ArticleRecord:
    # Canonical cleaned content (HTML/ads stripped, unicode normalized,
    # defang expanded, whitespace collapsed) — stored in Postgres + vector DB.
    content = clean_text(text)
    iocs = ioc_extractor.extract(f"{title}\n{content or ''}")
    records: list[IOCRecord] = []

    def add(values, ioc_type):
        for v in values:
            records.append(IOCRecord(ioc_type=ioc_type, value=v, first_seen=published, last_seen=published))

    add(iocs.ipv4, "ip")
    add(iocs.domains, "domain")
    add(iocs.urls, "url")
    add(iocs.emails, "email")
    add(set(iocs.md5) | set(iocs.sha1) | set(iocs.sha256), "hash")

    return ArticleRecord(
        title=title or f"{source_name} post",
        url=url,
        content=content,
        published_date=published,
        source_name=source_name,
        iocs=records,
        cves=sorted(iocs.cves),
        tags=[],
    )
