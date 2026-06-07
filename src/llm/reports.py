"""TI report generator — orchestrates several tools, then asks the LLM to
produce a structured threat-intelligence brief on a topic.

Compared with the chat path (which lets the LLM pick tools freely), the report
path:

1. **Gathers evidence deterministically** via three tools in parallel
   (vector search, tag pivot, recent intel), plus a follow-up pull of full
   article content for the top references.
2. **Builds the deterministic fields in code, not in the LLM**: indicators
   come from real IOCs in the evidence (not from the LLM, which we observed
   would copy article titles into the indicators field), and references
   come from real articles seen during retrieval.
3. **Asks the model in two narrow passes** — narrative (title, executive
   summary, key findings, recommendations) and entity extraction (threat
   actors, malware families, MITRE technique IDs, CVE ids) — because a
   single full-schema call overloads small open-source models, exactly the
   same failure mode we addressed in ``LLMArticleEnricher``.
4. **Falls back to regex on the evidence text** for CVEs and ATT&CK
   technique ids so those lists are guaranteed by code, not the LLM.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from pydantic import BaseModel, Field
from sqlalchemy import select

from ..storage.database import get_sessionmaker
from ..storage.models import Article, Tag
from .router import llm_for
from .tools import (
    find_by_tag as _t_find_by_tag,
    recent_intel as _t_recent_intel,
    search_articles as _t_search_articles,
)

logger = logging.getLogger(__name__)

_REPORT_LOOKBACK_DAYS = int(os.getenv("REPORT_LOOKBACK_DAYS", "30"))
_REPORT_RETRIEVAL_LIMIT = int(os.getenv("REPORT_RETRIEVAL_LIMIT", "12"))
_MAX_REFERENCES = int(os.getenv("REPORT_MAX_REFERENCES", "8"))
_ARTICLE_EXCERPT_CHARS = int(os.getenv("REPORT_ARTICLE_EXCERPT_CHARS", "900"))
_MAX_INDICATORS = int(os.getenv("REPORT_MAX_INDICATORS", "15"))

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# --- output schemas -------------------------------------------------------
class _Reference(BaseModel):
    title: str
    url: str | None = None
    source: str | None = None


class _TIReport(BaseModel):
    title: str = Field(description='Short, specific report title (e.g. "LockBit Ransomware — Activity Brief").')
    executive_summary: str = Field(description="3-5 sentence neutral summary fit for an exec briefing.")
    key_findings: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    references: list[_Reference] = Field(default_factory=list)


# Narrow schemas for the two LLM passes (kept private to this module).
class _Narrative(BaseModel):
    title: str = Field(description='Concrete title, e.g. "LockBit Ransomware — Activity Brief".')
    executive_summary: str = Field(
        description="3-5 sentences. Cite dated facts from the evidence; no boilerplate."
    )
    key_findings: list[str] = Field(
        default_factory=list,
        description="3-7 bullets, each grounded in a specific article from the evidence.",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="2-5 concrete defender actions tied to the findings.",
    )


class _Entities(BaseModel):
    threat_actors: list[str] = Field(
        default_factory=list,
        description='Named groups, e.g. "LockBit", "Scattered Spider", "APT29".',
    )
    malware_families: list[str] = Field(
        default_factory=list,
        description='Malware / ransomware / RAT family names.',
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description='MITRE ATT&CK technique IDs only, e.g. "T1566", "T1059.001".',
    )
    cves: list[str] = Field(
        default_factory=list,
        description='CVE ids in the form "CVE-YYYY-NNNN+".',
    )


# --- public API -----------------------------------------------------------
async def generate_report(topic: str) -> dict[str, Any]:
    """Build a structured TI report on ``topic`` and render it to Markdown.

    Returns ``{"topic", "generated_at", "report": <dict>, "markdown": <str>}``.
    """
    topic = (topic or "").strip()
    if not topic:
        raise ValueError("topic is required")

    # 1. Evidence: three retrieval angles in parallel. The first word of the
    # topic is used for the tag pivot ("LockBit ransomware" → tag "LockBit").
    primary_term = topic.split()[0] if topic else topic
    search_hits, tag_hits, recent = await asyncio.gather(
        _t_search_articles.ainvoke({"query": topic, "limit": _REPORT_RETRIEVAL_LIMIT}),
        _t_find_by_tag.ainvoke({"name": primary_term, "limit": _REPORT_RETRIEVAL_LIMIT}),
        _t_recent_intel.ainvoke({"days": _REPORT_LOOKBACK_DAYS, "limit": 6}),
    )

    # 2. Pick the top references (dedupe by url, cap at _MAX_REFERENCES) and
    # pull their full content from Postgres — recent_intel only returns short
    # summaries, but the model needs raw body to write a specific brief.
    top_refs = _select_top_references(search_hits, tag_hits, recent, _MAX_REFERENCES)
    contents = await _fetch_article_contents([r["id"] for r in top_refs if r.get("id") is not None])
    for ref in top_refs:
        ref["content"] = contents.get(ref.get("id"), "")

    # 3. Deterministic fields (no LLM):
    #    - references: real articles seen during retrieval
    #    - indicators: real IOC rows from tag/recent searches, formatted as "type: value"
    references = _build_references(top_refs)
    indicators = _build_indicators(tag_hits, recent, _MAX_INDICATORS)

    # 4. Build a single human-readable evidence text for both LLM passes.
    evidence_text = _format_evidence(topic, top_refs, tag_hits, recent)

    # 5. Regex fallback on the evidence text — guaranteed by code.
    cves_from_text = sorted({m.group(0).upper() for m in _CVE_RE.finditer(evidence_text)})
    techs_from_text = sorted({m.group(0).upper() for m in _TECHNIQUE_RE.finditer(evidence_text)})

    # 6. Two LLM passes on the same model. Pass 1: narrative. Pass 2: entities.
    base_llm = await llm_for("report")
    narrative, entities = await asyncio.gather(
        _run_narrative_pass(base_llm, topic, evidence_text),
        _run_entity_pass(base_llm, topic, evidence_text),
    )

    # 7. Merge LLM-extracted lists with regex floor.
    cves = _merge_unique(_normalise_cve_strings(entities.cves), cves_from_text)
    tech_codes = _merge_unique(
        (t for t in (s.upper() for s in entities.mitre_techniques) if _TECHNIQUE_RE.fullmatch(t)),
        techs_from_text,
    )
    # Decorate each code with its ATT&CK name (when the taxonomy knows it).
    techs = _format_techniques(tech_codes, await _technique_labels(tech_codes))

    # 8. Assemble final report.
    report = _TIReport(
        title=(narrative.title or "").strip() or _default_title(topic),
        executive_summary=(narrative.executive_summary or "").strip(),
        key_findings=[s.strip() for s in narrative.key_findings if s and s.strip()],
        threat_actors=_dedup_titlecase(entities.threat_actors),
        malware_families=_dedup_titlecase(entities.malware_families),
        mitre_techniques=techs,
        cves=cves,
        indicators=indicators,
        recommendations=[s.strip() for s in narrative.recommendations if s and s.strip()],
        references=references,
    )

    return {
        "topic": topic,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report": report.model_dump(),
        "markdown": _to_markdown(topic, report),
    }


# --- LLM passes -----------------------------------------------------------
_NARRATIVE_PROMPT = """\
You are writing a threat-intelligence brief for a security operations team on the topic: {topic}

Use ONLY the evidence below. Do not invent facts. Cite concrete dates and named
entities that appear in the articles. Avoid boilerplate phrases like "this brief
provides an overview".

EVIDENCE:
{evidence}

Produce a concrete, specific brief. The executive summary must reference the
actual events described above."""


_ENTITY_PROMPT = """\
Extract every named entity that appears in the article evidence below for the
topic: {topic}

Lists must contain values that actually appear in the evidence text. Use:
- threat_actors: named groups (APT, ransomware crew, operator)
- malware_families: malware / ransomware / RAT / loader names
- mitre_techniques: MITRE ATT&CK ids of the form "T####" or "T####.###"
- cves: CVE ids of the form "CVE-YYYY-NNNN+"

EVIDENCE:
{evidence}
"""


async def _run_narrative_pass(base_llm, topic: str, evidence: str) -> _Narrative:
    llm = base_llm.with_structured_output(_Narrative)
    try:
        return await llm.ainvoke(_NARRATIVE_PROMPT.format(topic=topic, evidence=evidence))
    except Exception as exc:  # noqa: BLE001
        logger.warning("narrative pass failed: %s", exc)
        return _Narrative(title="", executive_summary="", key_findings=[], recommendations=[])


async def _run_entity_pass(base_llm, topic: str, evidence: str) -> _Entities:
    llm = base_llm.with_structured_output(_Entities)
    try:
        return await llm.ainvoke(_ENTITY_PROMPT.format(topic=topic, evidence=evidence))
    except Exception as exc:  # noqa: BLE001
        logger.warning("entity pass failed: %s", exc)
        return _Entities()


# --- evidence assembly ----------------------------------------------------
def _select_top_references(
    search_hits: list[dict],
    tag_hits: dict,
    recent: dict,
    cap: int,
) -> list[dict]:
    seen: set = set()
    out: list[dict] = []
    sources: Iterable[Iterable[dict]] = (
        search_hits or [],
        tag_hits.get("articles", []) if isinstance(tag_hits, dict) else [],
        recent.get("articles", []) if isinstance(recent, dict) else [],
    )
    for group in sources:
        for hit in group:
            aid = hit.get("article_id") or hit.get("id")
            url = hit.get("url")
            key = aid if aid is not None else url
            if key is None or key in seen:
                continue
            seen.add(key)
            out.append({
                "id": aid,
                "title": hit.get("title") or "(untitled)",
                "url": url,
                "source": hit.get("source") or hit.get("source_name") or hit.get("source_type"),
                "summary": hit.get("summary") or hit.get("snippet"),
                "published": hit.get("published") or hit.get("published_date"),
            })
            if len(out) >= cap:
                return out
    return out


async def _fetch_article_contents(ids: list[Any]) -> dict[int, str]:
    if not ids:
        return {}
    int_ids = [int(i) for i in ids if i is not None]
    if not int_ids:
        return {}
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (await session.execute(
            select(Article.id, Article.content).where(Article.id.in_(int_ids))
        )).all()
    return {aid: (content or "") for aid, content in rows}


async def _technique_labels(codes: list[str]) -> dict[str, str]:
    """Map ATT&CK T-codes to their taxonomy names from the tags table."""
    if not codes:
        return {}
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (await session.execute(
            select(Tag.name, Tag.label)
            .where(Tag.type == "attack_technique", Tag.name.in_(codes))
        )).all()
    return {name: label for name, label in rows if label}


def _format_techniques(codes: list[str], labels: dict[str, str]) -> list[str]:
    """Render each technique as "T1059 — Command and Scripting Interpreter"."""
    out = []
    for code in codes:
        label = labels.get(code)
        out.append(f"{code} — {label}" if label else code)
    return out


def _format_evidence(
    topic: str,
    refs: list[dict],
    tag_hits: dict,
    recent: dict,
) -> str:
    lines: list[str] = [f"Topic: {topic}", ""]
    if not refs:
        lines.append("(No articles retrieved.)")
    else:
        lines.append(f"# Articles ({len(refs)})")
        for i, ref in enumerate(refs, 1):
            lines.append(f"\n## [{i}] {ref['title']}")
            if ref.get("url"):
                lines.append(f"URL: {ref['url']}")
            if ref.get("source"):
                lines.append(f"Source: {ref['source']}")
            if ref.get("published"):
                lines.append(f"Published: {ref['published']}")
            if ref.get("summary"):
                lines.append(f"Summary: {ref['summary']}")
            content = (ref.get("content") or "").strip()
            if content:
                lines.append("Excerpt:")
                lines.append(content[:_ARTICLE_EXCERPT_CHARS])

    tags_present = tag_hits.get("tags") if isinstance(tag_hits, dict) else []
    if tags_present:
        lines.append("\n# Tags matched")
        for t in tags_present[:10]:
            lines.append(f"- {t.get('name')} ({t.get('type')})")

    iocs = _collect_iocs(tag_hits, recent)
    if iocs:
        lines.append(f"\n# IOCs from evidence ({len(iocs)})")
        for i in iocs[:20]:
            tag_part = f" [tags: {', '.join(i['tags'])}]" if i.get("tags") else ""
            lines.append(f"- {i['ioc_type']}: {i['value']}{tag_part}")

    return "\n".join(lines)


# --- deterministic field builders ----------------------------------------
def _build_references(refs: list[dict]) -> list[_Reference]:
    return [
        _Reference(title=r["title"], url=r.get("url"), source=r.get("source"))
        for r in refs
    ]


def _collect_iocs(tag_hits: dict, recent: dict) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for group in (
        tag_hits.get("iocs", []) if isinstance(tag_hits, dict) else [],
        recent.get("iocs", []) if isinstance(recent, dict) else [],
    ):
        for ioc in group:
            key = (ioc.get("ioc_type"), ioc.get("value"))
            if not key[0] or not key[1] or key in seen:
                continue
            seen.add(key)
            out.append(ioc)
    return out


def _build_indicators(tag_hits: dict, recent: dict, cap: int) -> list[str]:
    iocs = _collect_iocs(tag_hits, recent)
    return [f"{i['ioc_type']}: {i['value']}" for i in iocs[:cap]]


# --- normalisation helpers -----------------------------------------------
def _merge_unique(*sources: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for src in sources:
        for item in src or []:
            v = (item or "").strip().upper() if item else ""
            if not v or v in seen:
                continue
            seen.add(v)
            out.append(v)
    return out


def _normalise_cve_strings(items: Iterable[str]) -> list[str]:
    """Pull valid CVE ids out of LLM-returned strings (often padded with prose)."""
    out: list[str] = []
    for item in items or []:
        for m in _CVE_RE.finditer(item or ""):
            out.append(m.group(0).upper())
    return out


def _dedup_titlecase(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in items or []:
        name = (raw or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out


def _default_title(topic: str) -> str:
    return f"{topic.strip()} — Threat-Intelligence Brief"


# --- rendering ------------------------------------------------------------
def _to_markdown(topic: str, r: _TIReport) -> str:
    lines: list[str] = [f"# {r.title or topic}", ""]
    lines.append("## Executive summary")
    lines.append(r.executive_summary.strip() or "_No summary available._")
    lines.append("")

    if r.key_findings:
        lines.append("## Key findings")
        lines.extend(f"- {bullet}" for bullet in r.key_findings)
        lines.append("")

    def _section(heading: str, items: list[str]) -> None:
        if items:
            lines.append(f"## {heading}")
            lines.extend(f"- {it}" for it in items)
            lines.append("")

    _section("Threat actors", r.threat_actors)
    _section("Malware / tools", r.malware_families)
    _section("MITRE ATT&CK techniques", r.mitre_techniques)
    _section("CVEs", r.cves)

    if r.indicators:
        lines.append("## Indicators")
        lines.append("```")
        lines.extend(r.indicators)
        lines.append("```")
        lines.append("")

    _section("Recommendations", r.recommendations)

    if r.references:
        lines.append("## References")
        for ref in r.references:
            label = ref.title or "(untitled)"
            if ref.url:
                lines.append(f"- [{label}]({ref.url})"
                             + (f" — _{ref.source}_" if ref.source else ""))
            else:
                lines.append(f"- {label}"
                             + (f" — _{ref.source}_" if ref.source else ""))
        lines.append("")

    return "\n".join(lines).strip() + "\n"
