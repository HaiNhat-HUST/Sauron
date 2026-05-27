"""Dashboard aggregation queries over the relational TI schema.

Read-only, async, returning plain dicts/lists for the web layer to serialise.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .database import get_sessionmaker
from .models import Article, ArticleTag, CVE, IOC, Tag


class DashboardQueries:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession] | None = None):
        self._sessionmaker = sessionmaker or get_sessionmaker()

    async def overview(self) -> dict:
        async with self._sessionmaker() as s:
            articles = await s.scalar(select(func.count()).select_from(Article))
            iocs = await s.scalar(select(func.count()).select_from(IOC))
            cves = await s.scalar(select(func.count()).select_from(CVE))
            tags = await s.scalar(select(func.count()).select_from(Tag))
            kev = await s.scalar(
                select(func.count()).select_from(CVE).where(CVE.known_exploited.is_(True))
            )
            last_article = await s.scalar(select(func.max(Article.created_at)))
            last_ioc = await s.scalar(select(func.max(IOC.last_seen)))
        last = max([t for t in (last_article, last_ioc) if t], default=None)
        return {
            "articles": articles or 0,
            "iocs": iocs or 0,
            "cves": cves or 0,
            "tags": tags or 0,
            "known_exploited": kev or 0,
            "last_ingest": last.isoformat() if last else None,
        }

    async def counts_by_source(self) -> list[dict]:
        """Objects contributed per connector (articles + iocs + cves)."""
        totals: dict[str, int] = defaultdict(int)
        async with self._sessionmaker() as s:
            for model, col in ((Article, Article.source_type), (IOC, IOC.source_type), (CVE, CVE.source_type)):
                rows = (await s.execute(select(col, func.count()).group_by(col))).all()
                for src, cnt in rows:
                    if src:
                        totals[src] += cnt
        return sorted(
            ({"source": k, "count": v} for k, v in totals.items()),
            key=lambda d: d["count"], reverse=True,
        )

    async def counts_by_ioc_type(self) -> list[dict]:
        async with self._sessionmaker() as s:
            rows = (await s.execute(
                select(IOC.ioc_type, func.count()).group_by(IOC.ioc_type).order_by(desc(func.count()))
            )).all()
        return [{"ioc_type": t, "count": c} for t, c in rows]

    async def cve_by_severity(self) -> list[dict]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        async with self._sessionmaker() as s:
            rows = (await s.execute(
                select(CVE.severity, func.count()).group_by(CVE.severity)
            )).all()
        out = [{"severity": sv or "unknown", "count": c} for sv, c in rows]
        return sorted(out, key=lambda d: order.get(d["severity"], 9))

    async def top_tags(self, limit: int = 10, tag_type: str | None = None) -> list[dict]:
        """Most-referenced tags (by article links)."""
        q = (
            select(Tag.name, Tag.type, func.count(ArticleTag.article_id))
            .join(ArticleTag, ArticleTag.tag_id == Tag.id)
            .group_by(Tag.id, Tag.name, Tag.type)
            .order_by(desc(func.count(ArticleTag.article_id)))
            .limit(limit)
        )
        if tag_type:
            q = q.where(Tag.type == tag_type)
        async with self._sessionmaker() as s:
            rows = (await s.execute(q)).all()
        return [{"name": n, "type": t, "count": c} for n, t, c in rows]

    async def ingestion_timeline(self, days: int = 14) -> list[dict]:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        a_day = func.date_trunc("day", Article.created_at)
        i_day = func.date_trunc("day", IOC.first_seen)
        per_day: dict[str, dict] = defaultdict(lambda: {"articles": 0, "iocs": 0})
        async with self._sessionmaker() as s:
            for rows, key in (
                ((await s.execute(
                    select(a_day, func.count()).where(Article.created_at >= since).group_by(a_day)
                )).all(), "articles"),
                ((await s.execute(
                    select(i_day, func.count()).where(IOC.first_seen >= since).group_by(i_day)
                )).all(), "iocs"),
            ):
                for day, cnt in rows:
                    if day:
                        per_day[day.date().isoformat()][key] += cnt
        return [{"day": d, **v} for d, v in sorted(per_day.items())]

    async def recent_articles(self, limit: int = 10) -> list[dict]:
        async with self._sessionmaker() as s:
            rows = (await s.execute(
                select(Article.id, Article.title, Article.url, Article.source_name,
                       Article.source_type, Article.published_date)
                .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                .limit(limit)
            )).all()
        return [
            {"id": i, "title": t, "url": u, "source_name": sn, "source_type": st,
             "published_date": pd.isoformat() if pd else None}
            for i, t, u, sn, st, pd in rows
        ]

    async def recent_iocs(self, limit: int = 12) -> list[dict]:
        async with self._sessionmaker() as s:
            rows = (await s.execute(
                select(IOC.ioc_type, IOC.value, IOC.tags, IOC.source_type, IOC.last_seen)
                .order_by(desc(IOC.last_seen))
                .limit(limit)
            )).all()
        return [
            {"ioc_type": t, "value": v, "tags": tags, "source_type": st,
             "last_seen": ls.isoformat() if ls else None}
            for t, v, tags, st, ls in rows
        ]

    async def recent_cves(self, limit: int = 8) -> list[dict]:
        async with self._sessionmaker() as s:
            rows = (await s.execute(
                select(CVE.cve_id, CVE.cvss_score, CVE.severity, CVE.known_exploited, CVE.published_date)
                .order_by(desc(func.coalesce(CVE.published_date, CVE.last_modified)))
                .limit(limit)
            )).all()
        return [
            {"cve_id": c, "cvss_score": sc, "severity": sv, "known_exploited": ke,
             "published_date": pd.isoformat() if pd else None}
            for c, sc, sv, ke, pd in rows
        ]
