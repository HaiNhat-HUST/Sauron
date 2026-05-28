"""TIAgent — the threat-intelligence analyst chatbot.

A small ReAct-style tool-calling loop:

* the LLM is bound to the tools in :mod:`src.llm.tools` via
  ``ChatModel.bind_tools`` (works the same way for OpenAI / Gemini /
  tool-capable Ollama models);
* each turn the agent sends ``[system, …history, user]`` to the LLM and
  resolves any tool calls in the response, looping until the LLM returns a
  plain assistant message;
* every call into the DB / vector store goes through a tool, so the surface
  the model sees is exactly the helpers exposed in ``tools.py`` — no ad-hoc
  SQL, no hidden state.

The agent is also used by :mod:`src.llm.reports` to drive structured report
generation; that path bypasses the chat loop and asks the LLM to fill a
Pydantic schema after the tools have been run programmatically.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from . import sessions
from .router import llm_for
from .tools import TOOLS, TOOLS_BY_NAME

logger = logging.getLogger(__name__)

_MAX_TOOL_ITERATIONS = int(os.getenv("AGENT_MAX_TOOL_ITERATIONS", "6"))

_SYSTEM_PROMPT = """\
You are an experienced threat-intelligence analyst working inside an internal
TI platform. You answer questions from security analysts using only the data
returned by your tools — never invent IOCs, CVEs, threat actors, or article
references.

Tool selection
- Topic / theme questions ("what's happening with LockBit", "recent VPN
  vulnerabilities exploited") → call ``search_articles`` first, optionally
  ``find_by_tag`` to broaden coverage.
- Specific indicator (IP / domain / URL / email / hash) → ``lookup_ioc``.
- CVE id → ``lookup_cve``.
- "Recent" / "last N days" → ``recent_intel``.
- High-level "what do we have" questions → ``get_stats``.
Call several tools in parallel when they're clearly independent.

Answering
- Ground every claim in tool results. If the tools return nothing relevant,
  say so plainly — do not speculate.
- Cite sources inline as Markdown links to the article URL when available.
- Be concise. Use short paragraphs, bullet lists for IOC tables, and the
  fenced code block for raw indicators.
- Surface uncertainty: distinguish what the data confirms from what it only
  suggests.
"""


class TIAgent:
    """A tool-calling threat-intelligence analyst.

    Stateless across instances; per-user chat history lives in
    :mod:`src.llm.sessions`. Construct once and reuse — instantiating the
    LangChain model is the expensive bit.
    """

    def __init__(self) -> None:
        # Models are resolved per call via :func:`llm_for` so config changes
        # from the admin UI take effect without a restart.
        pass

    # -- public API --------------------------------------------------------
    async def chat(
        self,
        user_id: int,
        session_id: str,
        message: str,
    ) -> dict[str, Any]:
        """Run one user turn. Returns ``{answer, tool_calls, sources}``."""
        llm_with_tools = (await llm_for("agent_chat")).bind_tools(TOOLS)
        history = sessions.get_history(user_id, session_id)
        messages: list[BaseMessage] = [SystemMessage(content=_SYSTEM_PROMPT), *history,
                                       HumanMessage(content=message)]
        new_turn: list[BaseMessage] = [HumanMessage(content=message)]
        trace: list[dict[str, Any]] = []
        sources: list[str] = []

        for _ in range(_MAX_TOOL_ITERATIONS):
            ai: AIMessage = await llm_with_tools.ainvoke(messages)
            messages.append(ai)
            new_turn.append(ai)

            tool_calls = getattr(ai, "tool_calls", None) or []
            if not tool_calls:
                # LLM is done — final answer.
                answer = _stringify(ai.content)
                sessions.append(user_id, session_id, new_turn)
                return {"answer": answer, "tool_calls": trace, "sources": sources}

            # Run each tool call and feed the result back as a ToolMessage.
            for call in tool_calls:
                result, ok = await self._run_tool(call)
                trace.append({
                    "name": call.get("name"),
                    "args": call.get("args"),
                    "ok": ok,
                    "preview": _preview(result),
                })
                sources.extend(_extract_sources(result))
                tool_msg = ToolMessage(
                    content=json.dumps(result, default=str)[:8000],
                    tool_call_id=call.get("id") or call.get("name"),
                )
                messages.append(tool_msg)
                new_turn.append(tool_msg)

        # Loop budget exhausted — return whatever the last AI message had.
        answer = _stringify(messages[-1].content if messages else "")
        sessions.append(user_id, session_id, new_turn)
        return {
            "answer": answer or "I couldn't finish reasoning within the tool budget.",
            "tool_calls": trace,
            "sources": _dedup(sources),
        }

    async def _run_tool(self, call: dict[str, Any]) -> tuple[Any, bool]:
        name = call.get("name")
        args = call.get("args") or {}
        tool = TOOLS_BY_NAME.get(name)
        if tool is None:
            return {"error": f"unknown tool '{name}'"}, False
        try:
            return await tool.ainvoke(args), True
        except Exception as exc:  # noqa: BLE001 — tool failures must not crash the agent
            logger.exception("tool %s failed: %s", name, exc)
            return {"error": str(exc)[:300]}, False



# --- helpers --------------------------------------------------------------
def _stringify(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Some providers return a list of content blocks.
        return "\n".join(
            (c.get("text", "") if isinstance(c, dict) else str(c)) for c in content
        )
    return str(content) if content is not None else ""


def _preview(result: Any) -> str:
    """Compact, human-readable preview of a tool result for the UI trace."""
    if result is None:
        return "(no result)"
    if isinstance(result, dict):
        keys = list(result.keys())[:6]
        return "{" + ", ".join(keys) + ("…" if len(result) > 6 else "") + "}"
    if isinstance(result, list):
        return f"[{len(result)} item(s)]"
    return str(result)[:120]


def _extract_sources(result: Any) -> list[str]:
    """Pull plausible source names from a tool result for the UI sources strip."""
    out: list[str] = []
    if isinstance(result, dict):
        for key in ("articles",):
            for a in result.get(key, []) or []:
                src = a.get("source")
                if src:
                    out.append(src)
        if result.get("source"):
            out.append(result["source"])
    elif isinstance(result, list):
        for item in result:
            if isinstance(item, dict) and item.get("source"):
                out.append(item["source"])
    return out


def _dedup(items: list[str]) -> list[str]:
    seen, out = set(), []
    for it in items:
        if it and it not in seen:
            seen.add(it)
            out.append(it)
    return out


# --- singleton ------------------------------------------------------------
_agent: TIAgent | None = None


def get_agent() -> TIAgent:
    global _agent
    if _agent is None:
        _agent = TIAgent()
    return _agent
