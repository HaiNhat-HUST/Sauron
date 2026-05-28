"""In-memory chat history keyed by ``(user_id, session_id)``.

Kept deliberately simple: a dict with TTL eviction on read. The history is
just the last N LangChain ``BaseMessage`` objects, replayed into the agent
on each turn so it can answer follow-up questions in context.

Multi-process deployments would need to move this to Postgres/Redis. The
existing ``sessions`` table is for auth tokens, not chat history.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from langchain_core.messages import BaseMessage

_MAX_TURNS = int(os.getenv("AGENT_HISTORY_TURNS", "10"))      # user+assistant pairs to retain
_TTL_SECONDS = int(os.getenv("AGENT_HISTORY_TTL", "3600"))    # drop idle sessions after 1h


class _Entry:
    __slots__ = ("messages", "touched_at")

    def __init__(self) -> None:
        self.messages: list[BaseMessage] = []
        self.touched_at: float = time.time()


_store: dict[tuple[int, str], _Entry] = {}


def _evict_stale(now: float) -> None:
    dead = [k for k, e in _store.items() if now - e.touched_at > _TTL_SECONDS]
    for k in dead:
        _store.pop(k, None)


def get_history(user_id: int, session_id: str) -> list["BaseMessage"]:
    """Return a *copy* of the stored messages for this user+session."""
    now = time.time()
    _evict_stale(now)
    entry = _store.get((user_id, session_id))
    if entry is None:
        return []
    entry.touched_at = now
    return list(entry.messages)


def append(user_id: int, session_id: str, messages: list["BaseMessage"]) -> None:
    """Append new turn messages and trim to the rolling window."""
    if not messages:
        return
    entry = _store.setdefault((user_id, session_id), _Entry())
    entry.messages.extend(messages)
    # Keep at most _MAX_TURNS * ~3 messages (user + ai + tool). Cheap cap.
    cap = _MAX_TURNS * 4
    if len(entry.messages) > cap:
        entry.messages = entry.messages[-cap:]
    entry.touched_at = time.time()


def clear(user_id: int, session_id: str) -> None:
    _store.pop((user_id, session_id), None)
