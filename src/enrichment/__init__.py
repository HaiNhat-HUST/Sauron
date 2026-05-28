"""Post-ingest enrichment pipeline.

A background worker pool consumes jobs from the ``enrichment_jobs`` table and
runs one :class:`~src.enrichment.base.BaseEnricher` per job. Enrichers write
their output back into the target row (``articles.summary_llm``,
``iocs.enrichment``, etc.). A separate scanner coroutine periodically enqueues
new jobs for rows still missing their enrichment.

Public entry points:

* :func:`src.enrichment.worker.get_worker` — singleton pool, started/stopped
  by the FastAPI lifespan hook.
* :data:`src.enrichment.registry` — ``name → BaseEnricher class`` map.
"""

from .base import BaseEnricher
from .registry import available, build_enricher

__all__ = ["BaseEnricher", "available", "build_enricher"]
