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
# powers the dropdown / suggestions. The first entry in each list is the
# recommended starting point and matches ``DEFAULT_MODELS`` in providers.py.
AVAILABLE_MODELS: dict[str, list[dict[str, str]]] = {
    "openai": [
        {"id": "gpt-5.4",      "label": "gpt-5.4 — default (custom endpoint compatible)"},
        {"id": "gpt-4o-mini",  "label": "gpt-4o-mini — cheap, fast, good tool calling"},
        {"id": "gpt-4o",       "label": "gpt-4o — flagship, best reasoning"},
        {"id": "gpt-4.1-mini", "label": "gpt-4.1-mini — cheap, large context"},
        {"id": "o3-mini",      "label": "o3-mini — reasoning, slower"},
    ],
    "gemini": [
        {"id": "gemini-1.5-flash",  "label": "gemini-1.5-flash — default, cheap, generous free tier"},
        {"id": "gemini-1.5-pro",    "label": "gemini-1.5-pro — frontier, slower"},
        {"id": "gemini-2.0-flash",  "label": "gemini-2.0-flash — newer, fast"},
    ],
    "ollama": [
        {"id": "qwen2.5-coder:3b", "label": "qwen2.5-coder:3b — default, code-aware (3B)"},
        {"id": "qwen3.5:2b",       "label": "qwen3.5:2b — newer, tiny"},
        {"id": "llama3.2:3b",      "label": "llama3.2:3b — small, fast, good for batch"},
        {"id": "codellama:7b",     "label": "codellama:7b — code-specialised"},
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

# Operator-facing presets — applied by the admin UI in one click. Models below
# match ``AVAILABLE_MODELS``; ``"model": None`` falls back to the provider's
# ``default_model`` stored in ``llm_providers``.
PRESETS: list[dict[str, Any]] = [
    {
        "id": "local",
        "label": "Local — all Ollama (free)",
        "hint": "Every function routed to the local Ollama default. Free and offline; quality depends on the picked model.",
        "assignments": {
            "agent_chat":     {"provider": "ollama", "model": None},
            "report":         {"provider": "ollama", "model": None},
            "enrich_article": {"provider": "ollama", "model": None},
        },
    },
    {
        "id": "balanced",
        "label": "Balanced — paid where it matters",
        "hint": "OpenAI for the interactive paths (agent + report), local Ollama for bulk article enrichment.",
        "assignments": {
            "agent_chat":     {"provider": "openai", "model": None},
            "report":         {"provider": "openai", "model": None},
            "enrich_article": {"provider": "ollama", "model": None},
        },
    },
    {
        "id": "cloud",
        "label": "Cloud — all OpenAI",
        "hint": "Frontier on every slot. Highest quality, highest cost.",
        "assignments": {
            "agent_chat":     {"provider": "openai", "model": None},
            "report":         {"provider": "openai", "model": None},
            "enrich_article": {"provider": "openai", "model": None},
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
