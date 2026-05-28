"""Store — persist normalized connector output into the relational schema.

Ingests a :class:`~src.collectors.records.CollectionResult`, handling dedup:
articles by URL, IOCs by (type, value) with provenance/last_seen merge, CVEs by
id, tags by name. Works for both structured feeds and unstructured articles.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..collectors.records import (
    ArticleRecord,
    CollectionResult,
    CVERecord,
    IOCRecord,
    TagRecord,
)
from .config import StorageConfig, storage_config
from .database import get_sessionmaker
from .models import Article, ArticleCVE, ArticleTag, CVE, IOC, Tag
from .vector import VectorStore, get_vector_store

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Union two text[] arrays and de-dupe (existing row ⟂ incoming "excluded" row).
def _merge_tags(table: str) -> object:
    return text(
        f"(SELECT ARRAY(SELECT DISTINCT unnest("
        f"coalesce({table}.tags, '{{}}') || coalesce(excluded.tags, '{{}}'))))"
    )


class Store:
    def __init__(
        self,
        config: StorageConfig | None = None,
        sessionmaker: async_sessionmaker[AsyncSession] | None = None,
        vector_store: VectorStore | None = None,
    ):
        self.config = config or storage_config
        self._sessionmaker = sessionmaker or get_sessionmaker(self.config)
        self._vector = vector_store or get_vector_store(self.config)

    async def ingest(self, result: CollectionResult, source_type: str) -> dict[str, int]:
        stats = {"articles": 0, "iocs": 0, "cves": 0, "tags": 0, "embedded": 0}
        vector_items: list[dict] = []
        async with self._sessionmaker() as session:
            # Standalone structured records first (no article context).
            for cve in result.cves:
                await self._upsert_cve(session, cve, source_type)
                stats["cves"] += 1
            for tag in result.tags:
                await self._upsert_tag(session, tag)
                stats["tags"] += 1
            for ioc in result.iocs:
                await self._upsert_ioc(session, ioc, None, source_type)
                stats["iocs"] += 1

            # Articles + their extracted entities.
            for article in result.articles:
                article_id = await self._upsert_article(session, article, source_type)
                stats["articles"] += 1
                if article.content:
                    vector_items.append({
                        "id": article_id,
                        "document": article.content,
                        "metadata": {
                            "title": article.title,
                            "url": article.url,
                            "source_type": source_type,
                            "source_name": article.source_name,
                            "published_date": article.published_date.isoformat() if article.published_date else None,
                        },
                    })
                for ioc in article.iocs:
                    await self._upsert_ioc(session, ioc, article_id, source_type)
                    stats["iocs"] += 1
                for cve_id in article.cves:
                    await self._upsert_cve_stub(session, cve_id)
                    await self._link_article_cve(session, article_id, cve_id)
                for tag in article.tags:
                    tag_id = await self._upsert_tag(session, tag)
                    await self._link_article_tag(session, article_id, tag_id, tag.confidence)
                    stats["tags"] += 1

            await session.commit()

        # Embed article content into the vector DB (sync Chroma → thread).
        if vector_items:
            stats["embedded"] = await asyncio.to_thread(self._vector.upsert, vector_items)

        logger.info("ingested [%s]: %s", source_type, stats)
        return stats

    # -- articles ----------------------------------------------------------
    async def _upsert_article(self, session: AsyncSession, a: ArticleRecord, source_type: str) -> int:
        values = {
            "title": a.title or "(untitled)",
            "url": a.url,
            "content": a.content,
            "published_date": a.published_date,
            "source_type": source_type,
            "source_name": a.source_name,
        }
        if a.url:
            stmt = pg_insert(Article).values(**values)
            stmt = stmt.on_conflict_do_update(
                index_elements=[Article.url],
                set_={
                    "title": stmt.excluded.title,
                    "content": stmt.excluded.content,
                    "published_date": stmt.excluded.published_date,
                    "source_type": stmt.excluded.source_type,
                    "source_name": stmt.excluded.source_name,
                },
            ).returning(Article.id)
            return (await session.execute(stmt)).scalar_one()
        # No URL → can't dedup; plain insert.
        row = Article(**values)
        session.add(row)
        await session.flush()
        return row.id

    # -- iocs --------------------------------------------------------------
    async def _upsert_ioc(
        self, session: AsyncSession, ioc: IOCRecord, article_id: int | None, source_type: str
    ) -> None:
        value = (ioc.value or "").strip()
        if not value or ioc.ioc_type not in ("ip", "domain", "url", "email", "hash"):
            return
        now = _now()
        values = {
            "ioc_type": ioc.ioc_type,
            "value": value,
            "article_id": article_id,
            "source_type": source_type,
            "first_seen": ioc.first_seen or now,
            "last_seen": ioc.last_seen or now,
            "context": ioc.context,
            "tags": ioc.tags or None,
            "score": ioc.score or 0.0,
            "enrichment": ioc.enrichment,
        }
        stmt = pg_insert(IOC).values(**values)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_iocs_type_value",
            set_={
                # Keep the earliest first_seen, advance last_seen.
                "first_seen": func.least(IOC.first_seen, stmt.excluded.first_seen),
                "last_seen": func.greatest(IOC.last_seen, stmt.excluded.last_seen),
                # Don't lose an existing article link / context to a NULL.
                "article_id": func.coalesce(IOC.article_id, stmt.excluded.article_id),
                "source_type": func.coalesce(IOC.source_type, stmt.excluded.source_type),
                "context": func.coalesce(IOC.context, stmt.excluded.context),
                "score": func.greatest(IOC.score, stmt.excluded.score),
                "enrichment": func.coalesce(stmt.excluded.enrichment, IOC.enrichment),
                "tags": _merge_tags("iocs"),
            },
        )
        await session.execute(stmt)

    # -- cves --------------------------------------------------------------
    async def _upsert_cve(self, session: AsyncSession, cve: CVERecord, source_type: str) -> None:
        cve_id = (cve.cve_id or "").strip().upper()
        if not cve_id:
            return
        values = {
            "cve_id": cve_id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "severity": _severity_from_score(cve.cvss_score),
            "published_date": cve.published_date,
            "last_modified": cve.last_modified,
            "products": cve.products or None,
            "source_type": source_type,
            "known_exploited": source_type == "cisa_kev",
        }
        stmt = pg_insert(CVE).values(**values)
        # Only overwrite fields we actually have (don't null-out good data).
        stmt = stmt.on_conflict_do_update(
            index_elements=[CVE.cve_id],
            set_={
                "description": func.coalesce(stmt.excluded.description, CVE.description),
                "cvss_score": func.coalesce(stmt.excluded.cvss_score, CVE.cvss_score),
                "severity": func.coalesce(stmt.excluded.severity, CVE.severity),
                "published_date": func.coalesce(stmt.excluded.published_date, CVE.published_date),
                "last_modified": func.coalesce(stmt.excluded.last_modified, CVE.last_modified),
                "products": func.coalesce(stmt.excluded.products, CVE.products),
                # known_exploited is sticky once true.
                "known_exploited": CVE.known_exploited.op("OR")(stmt.excluded.known_exploited),
            },
        )
        await session.execute(stmt)

    async def _upsert_cve_stub(self, session: AsyncSession, cve_id: str) -> None:
        """Ensure a CVE row exists (for FK) when only the id is known."""
        cve_id = (cve_id or "").strip().upper()
        if not cve_id:
            return
        stmt = pg_insert(CVE).values(cve_id=cve_id).on_conflict_do_nothing(index_elements=[CVE.cve_id])
        await session.execute(stmt)

    async def _link_article_cve(self, session: AsyncSession, article_id: int, cve_id: str) -> None:
        cve_id = (cve_id or "").strip().upper()
        if not cve_id:
            return
        stmt = pg_insert(ArticleCVE).values(article_id=article_id, cve_id=cve_id)
        stmt = stmt.on_conflict_do_nothing(index_elements=[ArticleCVE.article_id, ArticleCVE.cve_id])
        await session.execute(stmt)

    # -- tags --------------------------------------------------------------
    async def _upsert_tag(self, session: AsyncSession, tag: TagRecord) -> int:
        name = (tag.name or "").strip()
        stmt = pg_insert(Tag).values(name=name, type=tag.type)
        stmt = stmt.on_conflict_do_update(
            index_elements=[Tag.name], set_={"type": stmt.excluded.type}
        ).returning(Tag.id)
        return (await session.execute(stmt)).scalar_one()

    async def _link_article_tag(
        self, session: AsyncSession, article_id: int, tag_id: int, confidence: float
    ) -> None:
        stmt = pg_insert(ArticleTag).values(
            article_id=article_id, tag_id=tag_id, confidence=confidence
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[ArticleTag.article_id, ArticleTag.tag_id],
            set_={"confidence": func.greatest(ArticleTag.confidence, stmt.excluded.confidence)},
        )
        await session.execute(stmt)


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"
