"""BaseEnricher — what every concrete enricher must implement.

An enricher is a small async unit that takes a *target id* (article id, IOC
id, CVE id) and writes derived data back into the target's row. It does NOT
touch the ``enrichment_jobs`` row; the worker handles status transitions.

Concrete enrichers should:

* set ``name`` (registry key) and ``target_type`` ('article' | 'ioc' | 'cve')
* implement :meth:`enrich`; return a small ``dict`` that the worker stores in
  ``enrichment_jobs.result`` for observability (do **not** return secrets).
* raise to signal a failure — the worker handles retry/backoff.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseEnricher(ABC):
    name: str = "base"
    target_type: str = "article"   # article | ioc | cve

    @abstractmethod
    async def enrich(self, target_id: str) -> dict[str, Any]:
        """Run the enrichment for one target. Persist results to the DB."""

    async def aclose(self) -> None:
        """Release any client resources held by the enricher. Override if needed."""
        return None
