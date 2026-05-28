"""
LLM Provider Interface — supports OpenAI, Google Gemini, and Ollama.
Each provider wraps LangChain's chat model with a unified interface.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any

from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel


# ── Provider Config ───────────────────────────────────────────────────────────

class LLMConfig(BaseModel):
    provider: str = "openai"          # openai | gemini | ollama
    model: str | None = None          # override default model
    temperature: float = 0.0
    max_tokens: int = 4096
    # Provider-specific extras
    api_key: str | None = None
    base_url: str | None = None


# ── Abstract base ─────────────────────────────────────────────────────────────

class LLMProvider(ABC):
    name: str

    def __init__(self, config: LLMConfig):
        self.config = config

    @abstractmethod
    def get_llm(self) -> BaseChatModel:
        ...

    @property
    def display_name(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} model={self.config.model}>"


# ── OpenAI ────────────────────────────────────────────────────────────────────

class OpenAIProvider(LLMProvider):
    name = "openai"

    def get_llm(self) -> BaseChatModel:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise ImportError("Install langchain-openai: pip install langchain-openai")

        return ChatOpenAI(
            model=self.config.model or os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            api_key=self.config.api_key or os.getenv("OPENAI_API_KEY"),
            base_url=self.config.base_url or os.getenv("OPENAI_BASE_URL"),
        )


# ── Google Gemini ─────────────────────────────────────────────────────────────

class GeminiProvider(LLMProvider):
    name = "gemini"

    def get_llm(self) -> BaseChatModel:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError:
            raise ImportError("Install langchain-google-genai: pip install langchain-google-genai")

        return ChatGoogleGenerativeAI(
            model=self.config.model or os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
            temperature=self.config.temperature,
            max_output_tokens=self.config.max_tokens,
            google_api_key=self.config.api_key or os.getenv("GOOGLE_API_KEY"),
        )


# ── Ollama ────────────────────────────────────────────────────────────────────

class OllamaProvider(LLMProvider):
    name = "ollama"

    def get_llm(self) -> BaseChatModel:
        try:
            from langchain_ollama import ChatOllama
        except ImportError:
            raise ImportError("Install langchain-ollama: pip install langchain-ollama")

        return ChatOllama(
            model=self.config.model or os.getenv("OLLAMA_MODEL", "llama3.2"),
            temperature=self.config.temperature,
            base_url=self.config.base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            num_predict=self.config.max_tokens,
        )


# ── Factory ───────────────────────────────────────────────────────────────────

_REGISTRY: dict[str, type[LLMProvider]] = {
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def get_provider(config: LLMConfig) -> LLMProvider:
    """Instantiate the correct provider from config."""
    cls = _REGISTRY.get(config.provider.lower())
    if cls is None:
        raise ValueError(
            f"Unknown provider '{config.provider}'. "
            f"Choose from: {list(_REGISTRY.keys())}"
        )
    return cls(config)


def get_llm(config: LLMConfig | None = None) -> BaseChatModel:
    """Convenience: get a ready-to-use LangChain LLM from config or env defaults."""
    if config is None:
        config = LLMConfig(
            provider=os.getenv("DEFAULT_LLM_PROVIDER", "openai"),
        )
    return get_provider(config).get_llm()


def list_providers() -> list[dict[str, str]]:
    """Return available providers with display info."""
    return [
        {
            "id": "openai",
            "name": "OpenAI",
            "description": "GPT-4o, GPT-4o-mini — cloud API",
            "default_model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            "requires_api_key": True,
        },
        {
            "id": "gemini",
            "name": "Google Gemini",
            "description": "Gemini 1.5 Flash/Pro — cloud API",
            "default_model": os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
            "requires_api_key": True,
        },
        {
            "id": "ollama",
            "name": "Ollama (Local)",
            "description": "LLaMA, Mistral, Phi — runs on your machine",
            "default_model": os.getenv("OLLAMA_MODEL", "llama3.2"),
            "requires_api_key": False,
        },
    ]
