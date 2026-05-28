"""TI report generator — orchestrates several tools, then asks the LLM to
produce a structured threat-intelligence brief on a topic.

Unlike the chat path which lets the LLM choose tools, the report path runs a
fixed retrieval sequence first (vector search, tag search, recent intel) and
then asks the model — with ``with_structured_output(_TIReport)`` — to fill a
Pydantic schema. The schema is rendered to Markdown for the SPA / API.

Why a separate path: report shape needs to be predictable (the SPA renders
specific sections, downstream pipelines may consume the JSON). Free-form
tool-driven chat can produce that too but with much more variance.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from .router import llm_for
from .tools import (
    find_by_tag as _t_find_by_tag,
    recent_intel as _t_recent_intel,
    search_articles as _t_search_articles,
)

logger = logging.getLogger(__name__)

_REPORT_LOOKBACK_DAYS = int(os.getenv("REPORT_LOOKBACK_DAYS", "30"))
_REPORT_RETRIEVAL_LIMIT = int(os.getenv("REPORT_RETRIEVAL_LIMIT", "12"))


# --- output schema --------------------------------------------------------
class _Reference(BaseModel):
    title: str
    url: str | None = None
    source: str | None = None


class _TIReport(BaseModel):
    title: str = Field(description='Short, specific report title (e.g. "LockBit Ransomware — Activity Brief").')
    executive_summary: str = Field(description="3-5 sentence neutral summary fit for an exec briefing.")
    key_findings: list[str] = Field(default_factory=list, description="3-7 bullet points of the most important findings.")
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list, description='MITRE ATT&CK technique IDs only, e.g. "T1566".')
    cves: list[str] = Field(default_factory=list, description='CVE ids referenced in the source material.')
    indicators: list[str] = Field(default_factory=list, description="A handful of high-signal IOCs (string form).")
    recommendations: list[str] = Field(default_factory=list, description="2-5 defender actions grounded in the findings.")
    references: list[_Reference] = Field(default_factory=list, description="Articles cited by the report.")


# --- public API -----------------------------------------------------------
async def generate_report(topic: str) -> dict[str, Any]:
    """Build a structured TI report on ``topic`` and render it to Markdown.

    Returns ``{"topic", "generated_at", "report": <dict>, "markdown": <str>}``.
    """
    topic = (topic or "").strip()
    if not topic:
        raise ValueError("topic is required")

    # 1. Retrieve evidence in parallel — three independent angles.
    search_hits, tag_hits, recent = await asyncio.gather(
        _t_search_articles.ainvoke({"query": topic, "limit": _REPORT_RETRIEVAL_LIMIT}),
        _t_find_by_tag.ainvoke({"name": topic, "limit": _REPORT_RETRIEVAL_LIMIT}),
        _t_recent_intel.ainvoke({"days": _REPORT_LOOKBACK_DAYS, "limit": 6}),
    )

    evidence = {
        "semantic_search_hits": search_hits,
        "tag_search": tag_hits,
        "recent_context": recent,
    }

    # 2. Ask the LLM to fill the report schema from the evidence.
    base_llm = await llm_for("report")
    llm = base_llm.with_structured_output(_TIReport)
    prompt = (
        "You are writing a threat-intelligence brief for a security operations team.\n"
        f"Topic: {topic}\n\n"
        "Use ONLY the evidence below. Do not invent indicators, CVEs, or threat actors.\n"
        "Prefer concrete, dated facts. Cite the article references with their title and URL.\n\n"
        f"EVIDENCE (JSON):\n{json.dumps(evidence, default=str)[:12000]}"
    )
    try:
        report: _TIReport = await llm.ainvoke(prompt)
    except Exception as exc:  # noqa: BLE001
        logger.exception("report synthesis failed: %s", exc)
        raise

    return {
        "topic": topic,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report": report.model_dump(),
        "markdown": _to_markdown(topic, report),
    }


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
