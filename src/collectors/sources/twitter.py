"""X / Twitter connector (unstructured) — recent-search tweets as articles.

DISABLED by default; needs a paid X API v2 bearer token (``TWITTER_BEARER_TOKEN``).
Each tweet becomes an :class:`ArticleRecord` with regex-extracted IOCs/CVEs.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..base import BaseConnector
from ..config import TwitterConfig
from ..records import CollectionResult
from .text_helpers import build_article

_SEARCH = "https://api.twitter.com/2/tweets/search/recent"


class TwitterConnector(BaseConnector):
    name = "twitter"
    description = "X/Twitter — recent-search monitor (requires paid API)"
    required_settings = ("bearer_token",)

    config: TwitterConfig

    async def collect(self) -> CollectionResult:
        params = {
            "query": self.config.query,
            "max_results": 100,
            "tweet.fields": "created_at,author_id,entities,lang",
        }
        since_id = self.state.get("since_id")
        if since_id:
            params["since_id"] = since_id

        data = await self.get_json(
            _SEARCH, params=params,
            headers={"Authorization": f"Bearer {self.config.bearer_token}"},
        )

        tweets = data.get("data", [])
        result = CollectionResult()
        newest = since_id

        for tw in tweets:
            tid = tw.get("id")
            text = tw.get("text", "")
            if newest is None or (tid and int(tid) > int(newest)):
                newest = tid
            result.articles.append(
                build_article(
                    title=text[:80],
                    text=text,
                    url=f"https://twitter.com/i/web/status/{tid}",
                    published=_parse(tw.get("created_at")),
                    source_name="X/Twitter",
                )
            )

        if newest:
            self.state.set("since_id", newest)
        self.log.info("Twitter: %d new tweets", len(tweets))
        return result


def _parse(value):
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
