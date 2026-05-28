"""Lightweight search over the TI store (keyword/ILIKE) for the chat endpoint.

No vector index — the simplified schema relies on SQL search across articles,
IOCs and CVEs. The LLM layer can build richer RAG on top of these primitives.
"""

from __future__ import annotations

from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .database import get_sessionmaker
from .models import Article, CVE, IOC


class Retriever:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession] | None = None):
        self._sessionmaker = sessionmaker or get_sessionmaker()

    async def search(self, query: str, limit: int = 8) -> list[dict]:
        q = (query or "").strip()
        if not q:
            return []
        like = f"%{q}%"
        results: list[dict] = []
        async with self._sessionmaker() as s:
            # Articles
            arows = (await s.execute(
                select(Article.id, Article.title, Article.url, Article.source_name, Article.content)
                .where(or_(Article.title.ilike(like), Article.content.ilike(like)))
                .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                .limit(limit)
            )).all()
            for i, title, url, src, content in arows:
                results.append({
                    "kind": "article", "label": title, "url": url,
                    "source": src, "snippet": (content or "")[:200],
                })
            # CVEs
            crows = (await s.execute(
                select(CVE.cve_id, CVE.description, CVE.cvss_score, CVE.severity)
                .where(or_(CVE.cve_id.ilike(like), CVE.description.ilike(like)))
                .order_by(desc(CVE.cvss_score))
                .limit(limit)
            )).all()
            for cid, desc_, score, sev in crows:
                results.append({
                    "kind": "cve", "label": cid, "source": "cve",
                    "snippet": f"[{sev or '?'} {score or ''}] {(desc_ or '')[:180]}",
                })
            # IOCs
            irows = (await s.execute(
                select(IOC.ioc_type, IOC.value, IOC.tags, IOC.source_type)
                .where(IOC.value.ilike(like))
                .order_by(desc(IOC.last_seen))
                .limit(limit)
            )).all()
            for t, v, tags, src in irows:
                results.append({
                    "kind": "ioc", "label": f"{t}: {v}", "source": src,
                    "snippet": ", ".join(tags) if tags else "",
                })
        return results[: limit * 2]

    async def lookup_ioc(self, value: str) -> dict | None:
        value = (value or "").strip()
        if not value:
            return None
        async with self._sessionmaker() as s:
            row = (await s.execute(
                select(IOC).where(IOC.value == value).order_by(desc(IOC.last_seen)).limit(1)
            )).scalar_one_or_none()
            if not row:
                return None
            return {
                "ioc_type": row.ioc_type, "value": row.value, "tags": row.tags,
                "source_type": row.source_type, "context": row.context,
                "score": row.score, "enrichment": row.enrichment,
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
