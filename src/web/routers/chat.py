"""Chat + report routes — backed by the TIAgent (tool-calling LLM)."""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from ...llm import sessions as chat_sessions
from ...llm.agent import get_agent
from ...llm.reports import generate_report
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
