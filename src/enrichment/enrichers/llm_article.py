"""LLM article enricher — the AI-augmented half of the TI pipeline.

For each article we run **two** LLM calls on the same configured model:

1. **Plain-text summary** — a free-form prompt asking for a 2-3 sentence
   neutral summary. Small open-source models (llama3.2:3b, etc.) handle this
   reliably; cramming the summary into a multi-field JSON schema makes them
   leave the field empty or copy the title in. See ``test_06_diagnose_summary``
   for the empirical evidence behind this split.

2. **Structured entity extraction** — ``with_structured_output`` against a
   schema *without* the summary field: threat actors, malware families,
   ATT&CK techniques, CVEs, severity. Models are much more reliable at
   filling list-of-string fields than free-text fields inside a schema.

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
# Match a T-code embedded anywhere in a string (the LLM often returns
# "Spear-phishing (T1566)" instead of bare "T1566").
_TECHNIQUE_SUBSTR_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


_SYSTEM_PROMPT_ENTITIES = (
    "You are a cybersecurity analyst. Read the article and extract every named "
    "entity that appears in the text:\n"
    "- threat_actors: APT groups, ransomware crews, named operators "
    "(e.g. 'Lazarus', 'APT29', 'Scattered Spider', 'LockBit affiliates',...).\n"
    "- malware_families: malware / ransomware / RAT / loader / stealer family "
    "names (e.g. 'BlackCat', 'Cobalt Strike', 'Emotet',...).\n"
    "- attack_techniques: MITRE ATT&CK ids ONLY in the form 'T####' or "
    "'T####.###' (e.g. 'T1566', 'T1059.001'). Drop technique names.\n"
    "- cves: CVE ids in the form 'CVE-YYYY-NNNN+' as they appear in the text.\n"
    "- severity: low | medium | high | critical (always set this).\n"
    "Do not invent entities. If a category truly has nothing in the article, "
    "leave that list empty — but search the text thoroughly first."
)

_SUMMARY_PROMPT = (
    "Write a concise 2-3 sentence neutral summary of the cybersecurity article "
    "below. Reply with ONLY the summary text — no preamble, no markdown, no "
    "bullet points, no labels like 'Summary:'. Do not just repeat the title; "
    "describe what happened.\n\n"
    "Title: {title}\n\nContent:\n{content}"
)

# Common preambles small models tack on even when told not to. Stripped post-hoc.
_PREAMBLE_RE = re.compile(
    r"^\s*(?:summary|here(?:'s| is)(?: a)?(?: short| brief| concise)?(?: summary)?)\s*:?\s*",
    re.IGNORECASE,
)


class _LLMArticleEntities(BaseModel):
    """Entity extraction only — summary is handled separately in plain text."""

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

        # 2. Two LLM passes on the same model. Small open-source models cannot
        # produce a real summary inside a multi-field JSON schema (they copy
        # the title or leave it blank), so we ask for the summary in plain
        # text first, then ask separately for the structured entities. Order
        # is summary→entities so a partial failure still gives us a summary.
        base_llm = await llm_for("enrich_article")
        body = (content or "")[:_CONTENT_MAX_CHARS]

        # 2a. Plain-text summary.
        summary_resp = await base_llm.ainvoke(
            _SUMMARY_PROMPT.format(title=title, content=body)
        )
        summary_text = _clean_summary(_extract_text(summary_resp), title=title)

        # 2b. Structured entity extraction (no summary field).
        entity_llm = base_llm.with_structured_output(_LLMArticleEntities)
        entities: _LLMArticleEntities = await entity_llm.ainvoke(
            f"{_SYSTEM_PROMPT_ENTITIES}\n\n"
            f"Article title: {title}\n\n"
            f"Article content:\n{body}"
        )

        # 3. Normalise + merge with regex fallbacks. CVEs and ATT&CK technique
        # ids have deterministic patterns — regex over the article body is the
        # floor, the LLM's extraction is the ceiling. Threat actors and
        # malware families have no such fallback and depend on the LLM.
        severity = (entities.severity or "medium").lower().strip()
        if severity not in _VALID_SEVERITY:
            severity = "medium"
        techniques = _merge_unique(
            _TECHNIQUE_SUBSTR_RE.findall("\n".join(entities.attack_techniques)),
            _TECHNIQUE_SUBSTR_RE.findall(body),
            transform=str.upper,
        )
        cves = _merge_unique(
            (m.group(0) for m in _CVE_RE.finditer("\n".join(entities.cves))),
            (m.group(0) for m in _CVE_RE.finditer(body)),
            transform=str.upper,
        )
        actors = _dedup_titlecase(entities.threat_actors)
        families = _dedup_titlecase(entities.malware_families)

        # 4. Write everything back in one transaction. Tags + CVE links land
        # even if the summary came back empty (partial enrichment is still
        # useful). We re-raise after committing if the summary is missing so
        # the worker schedules a retry — small models occasionally drop the
        # field on the first attempt.
        async with sm() as session, session.begin():
            if summary_text:
                await session.execute(
                    update(Article)
                    .where(Article.id == article_id)
                    .values(summary_llm=summary_text)
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

        if not summary_text:
            # Tags / CVEs persisted above; this raise reaches the worker which
            # schedules an exponential-backoff retry. A stronger model on the
            # next attempt usually fills the summary.
            raise RuntimeError("LLM returned empty summary — will retry")

        return {
            "summary_chars": len(summary_text),
            "threat_actors": len(actors),
            "malware_families": len(families),
            "techniques": len(techniques),
            "cves": len(cves),
            "severity": severity,
        }


def _merge_unique(*sources, transform=None) -> list[str]:
    """Concatenate iterables and dedupe in order, optionally transforming each item."""
    seen: set[str] = set()
    out: list[str] = []
    for src in sources:
        for item in src or []:
            if not item:
                continue
            value = transform(item) if transform else item
            if value in seen:
                continue
            seen.add(value)
            out.append(value)
    return out


def _extract_text(resp: Any) -> str:
    """Coerce a LangChain chat response to a plain string."""
    content = getattr(resp, "content", resp)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            (c.get("text", "") if isinstance(c, dict) else str(c)) for c in content
        )
    return str(content) if content is not None else ""


def _clean_summary(raw: str, *, title: str) -> str:
    """Trim LLM preambles and reject summaries that just echo the title."""
    text = (raw or "").strip().strip("\"'`")
    # Strip a "Summary:" / "Here is a summary:" preamble if the model added it.
    text = _PREAMBLE_RE.sub("", text).strip()
    # If the model returned just the title (or a tiny variant), treat as empty.
    if not text:
        return ""
    if len(text) < 40 and text.lower().strip(".") == (title or "").lower().strip("."):
        return ""
    return text


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
    # ``name`` is the dedup key: a bare T-code for techniques (so it merges with
    # the MITRE/OTX rows), the entity name otherwise. We deliberately don't set
    # ``label`` here — the enricher doesn't know the human name, and the conflict
    # update touches only ``type``, leaving any label set by MITRE/OTX intact.
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
