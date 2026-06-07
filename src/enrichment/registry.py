"""Enricher registry — one entry per concrete enricher.

Mirrors :mod:`src.collectors.registry`. Add a new enricher by importing its
class and adding one line to ``_REGISTRY``.
"""

from __future__ import annotations

from .base import BaseEnricher
from .enrichers.cve_epss import CVEEPSSEnricher
from .enrichers.ioc_basic import IOCBasicEnricher
from .enrichers.llm_article import LLMArticleEnricher

_REGISTRY: dict[str, type[BaseEnricher]] = {
    LLMArticleEnricher.name: LLMArticleEnricher,
    IOCBasicEnricher.name: IOCBasicEnricher,
    CVEEPSSEnricher.name: CVEEPSSEnricher,
}


def available() -> list[str]:
    return list(_REGISTRY)


def build_enricher(name: str) -> BaseEnricher:
    if name not in _REGISTRY:
        raise KeyError(f"unknown enricher '{name}'. Available: {', '.join(available())}")
    return _REGISTRY[name]()


def target_type_of(name: str) -> str:
    return _REGISTRY[name].target_type
