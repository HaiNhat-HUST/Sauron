"""LangChain tools the TI agent uses to read the DB and vector store.

Each tool is the agent's only way to reach the data; they wrap the existing
async retrieval helpers (no new SQL here) and return JSON-serializable dicts
that an LLM can reason over. Add a new capability by writing a tool here and
adding it to :data:`TOOLS`.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from langchain_core.tools import tool
from sqlalchemy import desc, func, or_, select

from ..storage.database import get_sessionmaker
from ..storage.models import (
    Article,
    ArticleCVE,
    ArticleTag,
    CVE,
    IOC,
    Tag,
)
from ..storage.queries import DashboardQueries
from ..storage.retrieval import Retriever
from ..storage.vector import get_vector_store


# --- helpers --------------------------------------------------------------
def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _truncate(text: str | None, n: int) -> str:
    text = (text or "").replace("\n", " ").strip()
    return (text[: n - 1] + "…") if len(text) > n else text


# --- tools ----------------------------------------------------------------
@tool
async def search_articles(query: str, limit: int = 5) -> list[dict]:
    """Semantic (vector) search over the cleaned full content of articles.

    Use this whenever the user asks about a topic, threat actor, malware
    family, campaign, or vulnerability described in prose. Each hit returns
    the article id, title, url, source, a short snippet, and the vector
    distance (smaller is closer).
    """
    hits = await asyncio.to_thread(get_vector_store().search, query, limit)
    return [
        {
            "article_id": h.get("id"),
            "title": (h.get("metadata") or {}).get("title"),
            "url": (h.get("metadata") or {}).get("url"),
            "source": (h.get("metadata") or {}).get("source_name")
            or (h.get("metadata") or {}).get("source_type"),
            "published": (h.get("metadata") or {}).get("published_date"),
            "snippet": _truncate(h.get("document"), 280),
            "distance": h.get("distance"),
        }
        for h in hits
    ]


@tool
async def lookup_ioc(value: str) -> dict | None:
    """Look up a single IOC by exact value (IP, domain, URL, email, hash).

    Returns the IOC row including ``tags``, ``enrichment`` (GeoIP/ASN/etc.)
    and ``first_seen`` / ``last_seen``, plus the linked article title if any.
    """
    r = await Retriever().lookup_ioc(value)
    if not r:
        return None
    return r


@tool
async def lookup_cve(cve_id: str) -> dict | None:
    """Look up a CVE by id (case-insensitive, e.g. "CVE-2024-1234").

    Returns the CVE row (description, CVSS, severity, products,
    known_exploited) and the titles of articles that mention it.
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return None
    sm = get_sessionmaker()
    async with sm() as s:
        cve = (await s.execute(select(CVE).where(CVE.cve_id == cve_id))).scalar_one_or_none()
        if not cve:
            return None
        rows = (
            await s.execute(
                select(Article.id, Article.title, Article.url)
                .join(ArticleCVE, ArticleCVE.article_id == Article.id)
                .where(ArticleCVE.cve_id == cve_id)
                .order_by(desc(Article.created_at))
                .limit(10)
            )
        ).all()
    return {
        "cve_id": cve.cve_id,
        "description": cve.description,
        "cvss_score": cve.cvss_score,
        "severity": cve.severity,
        "published_date": _iso(cve.published_date),
        "products": cve.products,
        "known_exploited": cve.known_exploited,
        "source_type": cve.source_type,
        "articles": [{"id": aid, "title": title, "url": url} for aid, title, url in rows],
    }


@tool
async def find_by_tag(name: str, limit: int = 10) -> dict:
    """Find articles + IOCs linked to a named entity (threat actor, malware,
    technique, or campaign). Case-insensitive substring match on tag name.
    """
    name = (name or "").strip()
    if not name:
        return {"tags": [], "articles": [], "iocs": []}
    sm = get_sessionmaker()
    async with sm() as s:
        # Match the dedup name OR the human label, so "phishing" still finds
        # technique T1566 even though its name is now the bare code.
        like = f"%{name}%"
        tag_rows = (
            await s.execute(
                select(Tag.id, Tag.name, Tag.type, Tag.label)
                .where(or_(Tag.name.ilike(like), Tag.label.ilike(like)))
            )
        ).all()
        tag_ids = [tid for tid, _, _, _ in tag_rows]
        articles: list[dict] = []
        iocs: list[dict] = []
        if tag_ids:
            arows = (
                await s.execute(
                    select(
                        Article.id, Article.title, Article.url, Article.source_name,
                        Article.summary_llm, Article.published_date,
                    )
                    .join(ArticleTag, ArticleTag.article_id == Article.id)
                    .where(ArticleTag.tag_id.in_(tag_ids))
                    .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                    .limit(limit)
                )
            ).unique().all()
            articles = [
                {
                    "id": aid, "title": title, "url": url, "source": src,
                    "published": _iso(pub),
                    "summary": _truncate(summary, 240),
                }
                for aid, title, url, src, summary, pub in arows
            ]
            # IOCs that carry the same name in their free-tag list (best-effort).
            irows = (
                await s.execute(
                    select(IOC.ioc_type, IOC.value, IOC.tags, IOC.source_type, IOC.last_seen)
                    .where(IOC.tags.any(name))
                    .order_by(desc(IOC.last_seen))
                    .limit(limit)
                )
            ).all()
            iocs = [
                {"ioc_type": t, "value": v, "tags": tags, "source": src, "last_seen": _iso(seen)}
                for t, v, tags, src, seen in irows
            ]
    return {
        "tags": [{"name": n, "type": t, "label": lbl} for _, n, t, lbl in tag_rows],
        "articles": articles,
        "iocs": iocs,
    }


@tool
async def recent_intel(days: int = 7, limit: int = 10) -> dict:
    """Recent threat intelligence (articles + IOCs) from the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))
    sm = get_sessionmaker()
    async with sm() as s:
        arows = (
            await s.execute(
                select(
                    Article.id, Article.title, Article.url, Article.source_name,
                    Article.summary_llm, Article.published_date,
                )
                .where(func.coalesce(Article.published_date, Article.created_at) >= since)
                .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                .limit(limit)
            )
        ).all()
        irows = (
            await s.execute(
                select(IOC.ioc_type, IOC.value, IOC.tags, IOC.source_type, IOC.last_seen)
                .where(func.coalesce(IOC.last_seen, IOC.first_seen) >= since)
                .order_by(desc(func.coalesce(IOC.last_seen, IOC.first_seen)))
                .limit(limit)
            )
        ).all()
    return {
        "since": since.isoformat(),
        "articles": [
            {"id": aid, "title": title, "url": url, "source": src,
             "summary": _truncate(summary, 240), "published": _iso(pub)}
            for aid, title, url, src, summary, pub in arows
        ],
        "iocs": [
            {"ioc_type": t, "value": v, "tags": tags, "source": src, "last_seen": _iso(seen)}
            for t, v, tags, src, seen in irows
        ],
    }


@tool
async def get_stats() -> dict:
    """Dashboard-style overview counts: articles, IOCs, CVEs, tags, KEV, last ingest."""
    return await DashboardQueries().overview()


TOOLS = [
    search_articles,
    lookup_ioc,
    lookup_cve,
    find_by_tag,
    recent_intel,
    get_stats,
]

TOOLS_BY_NAME = {t.name: t for t in TOOLS}
