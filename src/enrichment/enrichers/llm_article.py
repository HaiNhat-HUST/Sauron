"""LLM article enricher — the AI-augmented half of the TI pipeline.

For one article it asks the configured LLM (see :mod:`src.llm.providers`) to
produce a short summary plus a structured set of extracted entities (threat
actors, malware families, ATT&CK techniques, CVEs, severity). LangChain's
``with_structured_output`` is used to coerce the response into a Pydantic
model — JSON parsing failures become job retries via the worker.

Writes back into:

* ``articles.summary_llm``
* ``tags`` + ``article_tags`` (one per named entity, type-tagged)
* ``article_cves`` (linked only when the CVE id parses; a stub CVE row is
  upserted to satisfy the FK, the NVD connector fills the details later).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ...llm.router import llm_for
from ...storage.database import get_sessionmaker
from ...storage.models import Article, ArticleCVE, ArticleTag, CVE, Tag
from ..base import BaseEnricher

logger = logging.getLogger(__name__)

_CONTENT_MAX_CHARS = int(os.getenv("ENRICHMENT_LLM_CONTENT_MAX", "8000"))
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_VALID_SEVERITY = {"low", "medium", "high", "critical"}
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. You read one threat-intelligence article "
    "and extract structured signals from it. Be precise; only include entities "
    "that are explicitly mentioned or strongly implied by the text. Use the "
    "exact format requested. If unsure, leave a field empty."
)


class _LLMArticleAnalysis(BaseModel):
    summary: str = Field(
        description="A neutral 2-3 sentence summary of the article. No marketing language."
    )
    threat_actors: list[str] = Field(
        default_factory=list,
        description='Named threat-actor groups, e.g. "Lazarus", "APT29", "Scattered Spider".',
    )
    malware_families: list[str] = Field(
        default_factory=list,
        description='Malware / ransomware / RAT family names, e.g. "LockBit", "Cobalt Strike".',
    )
    attack_techniques: list[str] = Field(
        default_factory=list,
        description='MITRE ATT&CK technique IDs only, e.g. "T1566", "T1059.001". Drop names; ids only.',
    )
    cves: list[str] = Field(
        default_factory=list,
        description='CVE ids explicitly mentioned, e.g. "CVE-2024-12345".',
    )
    severity: str = Field(
        default="medium",
        description='One of: low, medium, high, critical. Reflect article impact.',
    )


class LLMArticleEnricher(BaseEnricher):
    name = "llm_article"
    target_type = "article"

    def __init__(self) -> None:
        # Model is resolved per-call via :func:`llm_for` so admin UI changes
        # take effect immediately. Construction cost is negligible.
        pass

    async def enrich(self, target_id: str) -> dict[str, Any]:
        article_id = int(target_id)
        sm = get_sessionmaker()

        # 1. Load the article. Skip cleanly if it disappeared (e.g. retention).
        async with sm() as session:
            article = (
                await session.execute(
                    select(Article.id, Article.title, Article.content)
                    .where(Article.id == article_id)
                )
            ).one_or_none()
        if article is None:
            return {"skipped": "article gone"}
        _id, title, content = article
        if not (content or "").strip():
            return {"skipped": "empty content"}

        # 2. Ask the model. LangChain's structured output handles the JSON
        # parsing; we raise on validation errors so the worker can retry.
        base_llm = await llm_for("enrich_article")
        llm = base_llm.with_structured_output(_LLMArticleAnalysis)
        prompt = (
            f"{_SYSTEM_PROMPT}\n\n"
            f"Article title: {title}\n\n"
            f"Article content:\n{(content or '')[:_CONTENT_MAX_CHARS]}"
        )
        analysis: _LLMArticleAnalysis = await llm.ainvoke(prompt)

        # 3. Normalise the extracted fields before persisting.
        analysis.severity = (analysis.severity or "medium").lower().strip()
        if analysis.severity not in _VALID_SEVERITY:
            analysis.severity = "medium"
        techniques = [t.strip().upper() for t in analysis.attack_techniques if _TECHNIQUE_RE.match(t.strip().upper())]
        cves = sorted({m.group(0).upper() for m in (_CVE_RE.search(c) for c in analysis.cves) if m})
        actors = _dedup_titlecase(analysis.threat_actors)
        families = _dedup_titlecase(analysis.malware_families)

        # 4. Write everything back in one transaction.
        async with sm() as session, session.begin():
            await session.execute(
                update(Article)
                .where(Article.id == article_id)
                .values(summary_llm=analysis.summary.strip())
            )
            for name in actors:
                await _link_tag(session, article_id, name, "threat_actor", 0.7)
            for name in families:
                await _link_tag(session, article_id, name, "malware", 0.7)
            for tid in techniques:
                await _link_tag(session, article_id, tid, "attack_technique", 0.7)
            for cve_id in cves:
                await session.execute(
                    pg_insert(CVE).values(cve_id=cve_id)
                    .on_conflict_do_nothing(index_elements=[CVE.cve_id])
                )
                await session.execute(
                    pg_insert(ArticleCVE).values(article_id=article_id, cve_id=cve_id)
                    .on_conflict_do_nothing(
                        index_elements=[ArticleCVE.article_id, ArticleCVE.cve_id]
                    )
                )

        return {
            "summary_chars": len(analysis.summary),
            "threat_actors": len(actors),
            "malware_families": len(families),
            "techniques": len(techniques),
            "cves": len(cves),
            "severity": analysis.severity,
        }


def _dedup_titlecase(items: list[str]) -> list[str]:
    seen, out = set(), []
    for raw in items:
        name = (raw or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out


async def _link_tag(session, article_id: int, name: str, type_: str, confidence: float) -> None:
    stmt = (
        pg_insert(Tag).values(name=name, type=type_)
        .on_conflict_do_update(index_elements=[Tag.name], set_={"type": type_})
        .returning(Tag.id)
    )
    tag_id = (await session.execute(stmt)).scalar_one()
    await session.execute(
        pg_insert(ArticleTag)
        .values(article_id=article_id, tag_id=tag_id, confidence=confidence)
        .on_conflict_do_nothing(
            index_elements=[ArticleTag.article_id, ArticleTag.tag_id]
        )
    )
