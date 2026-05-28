"""RSS connector (unstructured) — security blogs/advisories as articles.

Each new feed entry becomes an :class:`ArticleRecord` with regex-extracted IOCs
and CVE ids. Configure feeds via ``RSS_FEEDS``.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import feedparser

from ..base import BaseConnector
from ..config import RSSConfig
from ..records import CollectionResult
from .text_helpers import build_article


class RSSConnector(BaseConnector):
    name = "rss"
    description = "RSS/Atom security blog and advisory feeds"

    config: RSSConfig

    async def collect(self) -> CollectionResult:
        feeds = self.config.feed_list
        if not feeds:
            self.log.warning("no feeds configured (RSS_FEEDS)")
            return CollectionResult()

        seen = set(self.state.get("seen_ids", []))
        result = CollectionResult()
        new_ids: list[str] = []

        for feed_url in feeds:
            try:
                raw = await self.get_text(feed_url)
            except Exception:  # noqa: BLE001 — skip a blocked/broken feed
                self.log.exception("failed to fetch feed %s", feed_url)
                continue

            parsed = await asyncio.to_thread(feedparser.parse, raw)
            source_name = parsed.feed.get("title") or urlparse(feed_url).netloc

            for entry in parsed.entries:
                eid = entry.get("id") or entry.get("link")
                if not eid or eid in seen:
                    continue
                new_ids.append(eid)
                result.articles.append(
                    build_article(
                        title=entry.get("title", ""),
                        text=_entry_text(entry),
                        url=entry.get("link"),
                        published=_entry_date(entry),
                        source_name=source_name,
                    )
                )

        self.state.set("seen_ids", (new_ids + list(seen))[:10000])
        self.log.info("RSS: %d new entries across %d feeds", len(new_ids), len(feeds))
        return result


def _entry_text(entry) -> str:
    if entry.get("content"):
        return " ".join(c.get("value", "") for c in entry["content"])
    return entry.get("summary", "") or entry.get("description", "")


def _entry_date(entry) -> datetime:
    for key in ("published_parsed", "updated_parsed"):
        if entry.get(key):
            return datetime.fromtimestamp(time.mktime(entry[key]), tz=timezone.utc)
    return datetime.now(timezone.utc)
