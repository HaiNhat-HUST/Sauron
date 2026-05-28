"""LLM resolver — bridges admin DB config to the LangChain chat models.

Callers (the agent, the enricher, the report generator) ask for a chat model
by *function name* — ``agent_chat``, ``report``, ``enrich_article`` — and the
resolver looks up the per-function routing in ``llm_function_models`` plus the
provider credentials in ``llm_providers`` to construct a fresh LangChain
model.

Resolution happens per call (chat model construction is cheap — it's just a
config wrapper, no weights loaded) so config changes from the admin UI take
effect immediately without a process restart.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from langchain_core.language_models import BaseChatModel

from ..storage import app as appstore
from .providers import LLMConfig, get_provider

logger = logging.getLogger(__name__)

# Curated, opinionated model lists. Free-form override is always allowed by
# typing an arbitrary id into the admin UI's "model" field; this list just
# powers the dropdown / suggestions.
AVAILABLE_MODELS: dict[str, list[dict[str, str]]] = {
    "openai": [
        {"id": "gpt-4o-mini", "label": "gpt-4o-mini — cheap, fast, good tool calling"},
        {"id": "gpt-4o",      "label": "gpt-4o — flagship, best reasoning"},
        {"id": "gpt-4.1-mini","label": "gpt-4.1-mini — cheap, large context"},
        {"id": "o3-mini",     "label": "o3-mini — reasoning, slower"},
    ],
    "gemini": [
        {"id": "gemini-1.5-flash",  "label": "gemini-1.5-flash — cheap, generous free tier"},
        {"id": "gemini-1.5-pro",    "label": "gemini-1.5-pro — frontier, slower"},
        {"id": "gemini-2.0-flash",  "label": "gemini-2.0-flash — newer, fast"},
    ],
    "ollama": [
        {"id": "llama3.2",        "label": "llama3.2 (3B) — small, fast, good for batch"},
        {"id": "llama3.1:8b",     "label": "llama3.1:8b — solid all-rounder"},
        {"id": "qwen2.5:7b",      "label": "qwen2.5:7b — strong tool calling"},
        {"id": "mistral-nemo",    "label": "mistral-nemo (12B) — best local for agent"},
    ],
}

# Function metadata — the admin UI uses ``label`` for the row title.
FUNCTIONS: list[dict[str, str]] = [
    {
        "name": "agent_chat",
        "label": "Agent chat & tool selection",
        "hint": "Needs strong reasoning + reliable tool calling — favour frontier models.",
    },
    {
        "name": "report",
        "label": "TI report generation",
        "hint": "Structured Markdown brief — benefits from large context and good synthesis.",
    },
    {
        "name": "enrich_article",
        "label": "Article enrichment (summary + tagging)",
        "hint": "Bulk, batched, latency-tolerant — a local model is usually enough.",
    },
]

# Operator-facing presets. Returned by the admin endpoint so the UI can offer
# one-click application. Numbers are rough USD/MTok estimates (input) for the
# OpenAI tier; everything else is informational.
PRESETS: list[dict[str, Any]] = [
    {
        "id": "budget",
        "label": "Budget — all local (free)",
        "hint": "Runs everything through a local Ollama model. Free, slower; tool calling depends on the chosen model supporting it.",
        "assignments": {
            "agent_chat":     {"provider": "ollama", "model": "qwen2.5:7b"},
            "report":         {"provider": "ollama", "model": "llama3.1:8b"},
            "enrich_article": {"provider": "ollama", "model": "llama3.2"},
        },
    },
    {
        "id": "balanced",
        "label": "Balanced — paid where it matters",
        "hint": "Frontier model for the agent (tool calls + chat), cheap paid for reports, local for bulk article enrichment.",
        "assignments": {
            "agent_chat":     {"provider": "openai", "model": "gpt-4o-mini"},
            "report":         {"provider": "openai", "model": "gpt-4o-mini"},
            "enrich_article": {"provider": "ollama", "model": "llama3.2"},
        },
    },
    {
        "id": "premium",
        "label": "Premium — best quality",
        "hint": "Frontier across the board. Best answers, highest cost.",
        "assignments": {
            "agent_chat":     {"provider": "openai", "model": "gpt-4o"},
            "report":         {"provider": "openai", "model": "gpt-4o"},
            "enrich_article": {"provider": "openai", "model": "gpt-4o-mini"},
        },
    },
    {
        "id": "privacy",
        "label": "Privacy — never leaves the host",
        "hint": "All inference on local Ollama. Pick a bigger model for the agent if your GPU can run it.",
        "assignments": {
            "agent_chat":     {"provider": "ollama", "model": "mistral-nemo"},
            "report":         {"provider": "ollama", "model": "llama3.1:8b"},
            "enrich_article": {"provider": "ollama", "model": "llama3.2"},
        },
    },
]


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------
class LLMRouteError(RuntimeError):
    """Raised when no usable provider/model is configured for a function."""


async def llm_for(function: str) -> BaseChatModel:
    """Build a fresh LangChain chat model for the given function.

    Reads routing + credentials from the app store; raises :class:`LLMRouteError`
    if the picked provider is missing/disabled/lacks a key.
    """
    route = await appstore.get_llm_function(function)
    if route is None:
        raise LLMRouteError(f"no routing configured for function '{function}'")
    provider_name = route["provider"]
    provider = await appstore.get_llm_provider(provider_name, redact_key=False)
    if provider is None:
        raise LLMRouteError(f"provider '{provider_name}' not configured")
    if not provider["enabled"]:
        raise LLMRouteError(
            f"provider '{provider_name}' is disabled — enable it in admin → LLM"
        )
    model = route.get("model") or provider.get("default_model")
    if not model:
        raise LLMRouteError(f"no model set for provider '{provider_name}'")
    cfg = LLMConfig(
        provider=provider_name,
        model=model,
        api_key=provider.get("api_key") or None,
        base_url=provider.get("base_url") or None,
    )
    return get_provider(cfg).get_llm()


async def test_provider(name: str, *, prompt: str = "ping") -> dict[str, Any]:
    """Send a tiny prompt to ``name``'s configured default model. Used by the
    admin "Test" button; returns ``{ok, latency_ms, message}``."""
    provider = await appstore.get_llm_provider(name, redact_key=False)
    if provider is None:
        return {"ok": False, "message": f"unknown provider '{name}'"}
    if not provider.get("default_model"):
        return {"ok": False, "message": "no default model set"}
    cfg = LLMConfig(
        provider=name,
        model=provider["default_model"],
        api_key=provider.get("api_key") or None,
        base_url=provider.get("base_url") or None,
    )
    try:
        llm = get_provider(cfg).get_llm()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": f"init failed: {exc}"}

    start = time.monotonic()
    try:
        result = await asyncio.wait_for(llm.ainvoke(prompt), timeout=30)
    except asyncio.TimeoutError:
        return {"ok": False, "message": "timed out after 30s"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": str(exc)[:300]}
    latency_ms = int((time.monotonic() - start) * 1000)
    text = getattr(result, "content", "") or str(result)
    if isinstance(text, list):  # some providers return content blocks
        text = " ".join(c.get("text", str(c)) if isinstance(c, dict) else str(c) for c in text)
    return {
        "ok": True,
        "latency_ms": latency_ms,
        "message": (text[:200] or "(empty response)").strip(),
    }
