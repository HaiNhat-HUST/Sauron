"""LLM provider adapters — OpenAI, Google Gemini, Ollama.

Each provider wraps a LangChain ``BaseChatModel`` behind a single interface so
the rest of the system can treat them interchangeably. Runtime configuration
(provider, model, api_key, base_url) is supplied by :mod:`src.llm.router`,
which resolves it from the Postgres ``llm_providers`` and
``llm_function_models`` tables.

The :data:`DEFAULT_MODELS` map is the *single source of truth* for fallback
model identifiers. It is consumed by:

* :func:`src.storage.app.seed_defaults` — on first boot, when no env var
  overrides the model for a provider;
* the provider classes below — as a safety net if a caller constructs an
  ``LLMConfig`` without a model (production code never does this; the router
  always passes a model).

``.env.example`` documents the matching ``OPENAI_MODEL``, ``GEMINI_MODEL``
and ``OLLAMA_MODEL`` variables an operator can set to override the seed.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel


# ── Single source of truth for default model identifiers ─────────────────
DEFAULT_MODELS: dict[str, str] = {
    "openai": "gpt-5.4",
    "gemini": "gemini-1.5-flash",
    "ollama": "qwen2.5-coder:3b",
}

# Default endpoint for Ollama when no base_url is configured. The Docker
# compose stack overrides this to ``http://host.docker.internal:11434``.
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"


# ── Runtime config ────────────────────────────────────────────────────────
class LLMConfig(BaseModel):
    provider: str = "openai"          # openai | gemini | ollama
    model: str | None = None          # NULL → DEFAULT_MODELS[provider]
    temperature: float = 0.0
    max_tokens: int = 4096
    api_key: str | None = None
    base_url: str | None = None


# ── Abstract base ────────────────────────────────────────────────────────
class LLMProvider(ABC):
    name: str

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    @abstractmethod
    def get_llm(self) -> BaseChatModel: ...

    @property
    def _model(self) -> str:
        return self.config.model or DEFAULT_MODELS[self.name]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} model={self._model}>"


# ── Concrete providers ───────────────────────────────────────────────────
class OpenAIProvider(LLMProvider):
    name = "openai"

    def get_llm(self) -> BaseChatModel:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=self._model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            api_key=self.config.api_key,
            base_url=self.config.base_url,
        )


class GeminiProvider(LLMProvider):
    name = "gemini"

    def get_llm(self) -> BaseChatModel:
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model=self._model,
            temperature=self.config.temperature,
            max_output_tokens=self.config.max_tokens,
            google_api_key=self.config.api_key,
        )


class OllamaProvider(LLMProvider):
    name = "ollama"

    def get_llm(self) -> BaseChatModel:
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=self._model,
            temperature=self.config.temperature,
            base_url=self.config.base_url or DEFAULT_OLLAMA_BASE_URL,
            num_predict=self.config.max_tokens,
        )


# ── Factory ──────────────────────────────────────────────────────────────
_REGISTRY: dict[str, type[LLMProvider]] = {
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def get_provider(config: LLMConfig) -> LLMProvider:
    """Instantiate the correct provider for ``config.provider``."""
    cls = _REGISTRY.get(config.provider.lower())
    if cls is None:
        raise ValueError(
            f"Unknown provider '{config.provider}'. "
            f"Choose from: {sorted(_REGISTRY)}"
        )
    return cls(config)
