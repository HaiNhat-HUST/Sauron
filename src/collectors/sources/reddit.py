"""Reddit connector (unstructured) — security subreddits as articles.

Each post becomes an :class:`ArticleRecord` with regex-extracted IOCs/CVEs.
Uses OAuth if ``REDDIT_CLIENT_ID``/``SECRET`` are set, else the public JSON
endpoints (rate-limited).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from ..base import BaseConnector
from ..config import RedditConfig
from ..records import CollectionResult
from .text_helpers import build_article

_TOKEN_URL = "https://www.reddit.com/api/v1/access_token"


class RedditConnector(BaseConnector):
    name = "reddit"
    description = "Reddit — security subreddit monitor"

    config: RedditConfig

    async def collect(self) -> CollectionResult:
        token = await self._get_token()
        base = "https://oauth.reddit.com" if token else "https://www.reddit.com"
        headers = {"User-Agent": self.config.user_agent}
        if token:
            headers["Authorization"] = f"bearer {token}"

        seen = set(self.state.get("seen_ids", []))
        result = CollectionResult()
        new_ids: list[str] = []

        for sub in self.config.subreddit_list:
            try:
                data = await self.get_json(
                    f"{base}/r/{sub}/new.json", params={"limit": 50}, headers=headers
                )
            except Exception:  # noqa: BLE001 — one bad sub shouldn't stop the rest
                self.log.exception("failed to fetch r/%s", sub)
                continue

            for child in data.get("data", {}).get("children", []):
                post = child.get("data", {})
                pid = post.get("id")
                if not pid or pid in seen:
                    continue
                new_ids.append(pid)
                published = datetime.fromtimestamp(
                    post.get("created_utc", time.time()), tz=timezone.utc
                )
                result.articles.append(
                    build_article(
                        title=post.get("title", ""),
                        text=post.get("selftext", "") or post.get("url", ""),
                        url=f"https://www.reddit.com{post.get('permalink', '')}",
                        published=published,
                        source_name=f"Reddit r/{sub}",
                    )
                )

        self.state.set("seen_ids", (new_ids + list(seen))[:5000])
        self.log.info("Reddit: %d new posts across %d subs", len(new_ids), len(self.config.subreddit_list))
        return result

    async def _get_token(self) -> str | None:
        if not (self.config.client_id and self.config.client_secret):
            return None
        cached = self.state.get("oauth_token")
        if cached and self.state.get("oauth_expiry", 0) > time.time() + 60:
            return cached
        try:
            resp = await self._request(
                "POST", _TOKEN_URL,
                data={"grant_type": "client_credentials"},
                auth=(self.config.client_id, self.config.client_secret),
                headers={"User-Agent": self.config.user_agent},
            )
            tok = resp.json()
            self.state.set("oauth_token", tok["access_token"])
            self.state.set("oauth_expiry", time.time() + tok.get("expires_in", 3600))
            return tok["access_token"]
        except Exception:  # noqa: BLE001
            self.log.warning("Reddit OAuth failed; falling back to public endpoint")
            return None
