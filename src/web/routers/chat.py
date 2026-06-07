"""Chat + report routes — backed by the TIAgent (tool-calling LLM)."""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, func, or_, select

from ...llm import sessions as chat_sessions
from ...llm.agent import get_agent
from ...llm.reports import generate_report
from ...storage.database import get_sessionmaker
from ...storage.models import ArticleTag, CVE, IOC, Tag
from ..deps import get_current_user
from ..schemas import ChatRequest, ReportRequest

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chat"])


def _session_id(payload_sid: str | None, user: Dict[str, Any]) -> str:
    return (payload_sid or "").strip() or f"u{user['id']}-default"


@router.post("/chat/ask")
async def ask(payload: ChatRequest, user: Dict[str, Any] = Depends(get_current_user)) -> Any:
    message = (payload.message or "").strip()
    if not message:
        return {"answer": "Please enter a question.", "tool_calls": [], "sources": []}

    session_id = _session_id(payload.session_id, user)
    try:
        return await get_agent().chat(
            user_id=user["id"], session_id=session_id, message=message
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("agent chat failed: %s", exc)
        raise HTTPException(status_code=503, detail="Agent unavailable — check the LLM provider configuration.")


@router.post("/chat/report")
async def report(payload: ReportRequest, _: Dict[str, Any] = Depends(get_current_user)) -> Any:
    topic = (payload.topic or "").strip()
    if not topic:
        raise HTTPException(status_code=400, detail="Topic is required.")
    try:
        return await generate_report(topic)
    except Exception as exc:  # noqa: BLE001
        logger.exception("report generation failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"Report generation failed: {exc}")


@router.post("/chat/reset")
async def reset(payload: ChatRequest, user: Dict[str, Any] = Depends(get_current_user)) -> Any:
    """Clear the chat history for this user+session (does not delete TI data)."""
    chat_sessions.clear(user["id"], _session_id(payload.session_id, user))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Suggested prompts — derived from current TI data so the chips reflect
# what the analyst can actually ask about.
# ---------------------------------------------------------------------------
@router.get("/chat/suggestions")
async def suggestions(_: Dict[str, Any] = Depends(get_current_user)) -> Any:
    return {"items": await _build_suggestions()}


_TAG_TEMPLATES = {
    "threat_actor":     "What do we know about the {name} threat actor?",
    "malware":          "Summarize recent activity of {name}",
    "attack_technique": "Which articles reference MITRE {name}?",
    "campaign":         "What's happening with the {name} campaign?",
}

# Always-present prompts so the strip is never empty even on a cold DB.
_FALLBACK_PROMPTS = [
    {"prompt": "Show overall stats for the threat-intelligence store", "category": "stats"},
    {"prompt": "What are the most recent critical CVEs?", "category": "cve"},
    {"prompt": "Summarize the last 7 days of threat activity", "category": "recent"},
]


async def _build_suggestions(limit: int = 8) -> list[dict[str, str]]:
    """Mix tag / CVE / IOC / fallback prompts so the strip stays diverse.

    Per-category caps keep one strong category (e.g. lots of ATT&CK techniques
    after a big enrichment pass) from eating every chip slot.
    """
    sm = get_sessionmaker()
    cap_per_tag_type = 2          # max prompts per Tag.type value
    cap_cves = 2
    cap_iocs = 1
    items: list[dict[str, str]] = []
    seen: set[str] = set()
    tag_type_counts: dict[str, int] = {}

    def _push(prompt: str, category: str) -> None:
        if not prompt or prompt in seen:
            return
        seen.add(prompt)
        items.append({"prompt": prompt, "category": category})

    async with sm() as session:
        # 1. Top tags by article link count, capped per type.
        tag_rows = (await session.execute(
            select(Tag.name, Tag.type, Tag.label, func.count(ArticleTag.article_id).label("c"))
            .join(ArticleTag, ArticleTag.tag_id == Tag.id)
            .group_by(Tag.id)
            .order_by(desc("c"))
            .limit(20)
        )).all()
        for name, type_, label, _count in tag_rows:
            template = _TAG_TEMPLATES.get(type_)
            if not template:
                continue
            if tag_type_counts.get(type_, 0) >= cap_per_tag_type:
                continue
            # Techniques read better by name; fall back to the bare code.
            display = f"{name} {label}" if label and label != name else name
            _push(template.format(name=display), type_)
            tag_type_counts[type_] = tag_type_counts.get(type_, 0) + 1

        # 2. Recent critical or known-exploited CVEs.
        cve_rows = (await session.execute(
            select(CVE.cve_id)
            .where(or_(CVE.severity == "critical", CVE.known_exploited.is_(True)))
            .order_by(desc(func.coalesce(CVE.last_modified, CVE.published_date)))
            .limit(cap_cves)
        )).scalars().all()
        for cve_id in cve_rows:
            _push(f"What do we have on {cve_id}?", "cve")

        # 3. Top IOC source — orient the user toward the busiest feed.
        top_source = (await session.execute(
            select(IOC.source_type, func.count())
            .where(IOC.source_type.isnot(None))
            .group_by(IOC.source_type)
            .order_by(desc(func.count()))
            .limit(cap_iocs)
        )).all()
        for source_type, _count in top_source:
            _push(f"List recent IOCs from {source_type}", "ioc")

    # Always pad with static prompts so the strip is never sparse.
    for fallback in _FALLBACK_PROMPTS:
        _push(fallback["prompt"], fallback["category"])

    return items[:limit]
