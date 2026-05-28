"""Background worker pool + scanner for the enrichment pipeline.

Started from the FastAPI startup hook so workers share the uvicorn event loop
(same loop used by the async DB engine and the connector scheduler). On stop
every coroutine is cancelled and awaited.

Knobs (env):
* ``ENRICHMENT_ENABLED``         — set to false to skip the pool entirely
* ``ENRICHMENT_WORKERS``         — number of concurrent worker coroutines (default 2)
* ``ENRICHMENT_POLL_SECONDS``    — worker poll cadence when the queue is empty (default 5)
* ``ENRICHMENT_SCAN_SECONDS``    — scanner cadence for enqueuing new jobs (default 60)
* ``ENRICHMENT_MAX_ATTEMPTS``    — give-up threshold per job (default 3)
"""

from __future__ import annotations

import asyncio
import logging
import os

from . import jobs
from .registry import available, build_enricher

logger = logging.getLogger("enrichment.worker")

_WORKERS = int(os.getenv("ENRICHMENT_WORKERS", "2"))
_POLL_SECONDS = float(os.getenv("ENRICHMENT_POLL_SECONDS", "5"))
_SCAN_SECONDS = float(os.getenv("ENRICHMENT_SCAN_SECONDS", "60"))
_MAX_ATTEMPTS = int(os.getenv("ENRICHMENT_MAX_ATTEMPTS", "3"))


class EnrichmentWorker:
    def __init__(self) -> None:
        self._tasks: list[asyncio.Task] = []
        self._scanner: asyncio.Task | None = None
        self._stopped = False
        self._enricher_cache: dict[str, object] = {}

    async def start(self) -> None:
        if self._tasks or self._scanner:
            return
        self._stopped = False
        self._tasks = [
            asyncio.create_task(self._worker_loop(i)) for i in range(_WORKERS)
        ]
        self._scanner = asyncio.create_task(self._scanner_loop())
        logger.info(
            "enrichment workers started: pool=%d enrichers=%s",
            _WORKERS, available(),
        )

    async def stop(self) -> None:
        self._stopped = True
        for t in (*self._tasks, self._scanner):
            if t is not None:
                t.cancel()
        running = [t for t in (*self._tasks, self._scanner) if t is not None]
        if running:
            await asyncio.gather(*running, return_exceptions=True)
        for e in list(self._enricher_cache.values()):
            try:
                await e.aclose()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
        self._tasks.clear()
        self._scanner = None
        self._enricher_cache.clear()

    # -- scanner -----------------------------------------------------------
    async def _scanner_loop(self) -> None:
        while not self._stopped:
            try:
                for name in available():
                    # Only article enrichers known so far — extend when adding
                    # IOC/CVE scanners.
                    inserted = await jobs.enqueue_article_jobs(name, limit=500)
                    if inserted:
                        logger.info("enqueued %d %s jobs", inserted, name)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("enrichment scanner failed")
            try:
                await asyncio.sleep(_SCAN_SECONDS)
            except asyncio.CancelledError:
                break

    # -- worker ------------------------------------------------------------
    async def _worker_loop(self, idx: int) -> None:
        while not self._stopped:
            try:
                job = await jobs.claim_next()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("worker %d failed to claim", idx)
                await self._sleep_or_stop(_POLL_SECONDS)
                continue

            if job is None:
                await self._sleep_or_stop(_POLL_SECONDS)
                continue

            await self._run_job(idx, job)

    async def _run_job(self, idx: int, job: dict) -> None:
        name = job["enricher"]
        try:
            enricher = self._enricher_cache.get(name) or build_enricher(name)
            self._enricher_cache[name] = enricher
        except Exception as exc:  # noqa: BLE001 — unknown enricher
            await jobs.fail(job["id"], attempts=job["attempts"],
                            error=f"build failed: {exc}", max_attempts=_MAX_ATTEMPTS)
            return

        try:
            result = await enricher.enrich(job["target_id"])  # type: ignore[attr-defined]
        except asyncio.CancelledError:
            await jobs.fail(job["id"], attempts=job["attempts"],
                            error="cancelled", max_attempts=_MAX_ATTEMPTS)
            raise
        except Exception as exc:  # noqa: BLE001 — every enricher failure path
            logger.warning("worker %d %s(%s) failed: %s",
                           idx, name, job["target_id"], exc)
            await jobs.fail(job["id"], attempts=job["attempts"],
                            error=str(exc), max_attempts=_MAX_ATTEMPTS)
            return

        logger.info("worker %d %s(%s) ok", idx, name, job["target_id"])
        await jobs.complete(job["id"], result)

    async def _sleep_or_stop(self, seconds: float) -> None:
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            self._stopped = True
            raise


_worker: EnrichmentWorker | None = None


def get_worker() -> EnrichmentWorker:
    global _worker
    if _worker is None:
        _worker = EnrichmentWorker()
    return _worker
