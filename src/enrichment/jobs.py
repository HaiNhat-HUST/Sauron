"""Async helpers over the ``enrichment_jobs`` table.

The worker pool relies on Postgres' ``SELECT … FOR UPDATE SKIP LOCKED`` so any
number of worker coroutines can claim jobs concurrently without contention or
double-processing. Inserts are idempotent via the unique
(target_type, target_id, enricher) constraint.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..storage.database import get_sessionmaker
from ..storage.models import Article, CVE, EnrichmentJob, IOC

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Retry schedule: 1m, 5m, 30m (then status='error' after MAX_ATTEMPTS).
_BACKOFF_SECONDS = (60, 300, 1800)


# -- enqueue (idempotent) -------------------------------------------------
async def enqueue_article_jobs(enricher: str, limit: int = 500) -> int:
    """Add a pending job for every article missing ``summary_llm``.

    Idempotent: duplicate (target, enricher) pairs are skipped silently by the
    unique constraint. Returns the number of rows inserted.
    """
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        # Pick candidate article ids that have no row yet for this enricher
        # OR whose previous attempt ended in 'error' (allow manual replay by
        # deleting/resetting the error row, not by re-inserting).
        article_q = (
            select(Article.id)
            .where(Article.summary_llm.is_(None))
            .order_by(Article.created_at.desc())
            .limit(limit)
        )
        rows = (await session.execute(article_q)).scalars().all()
        if not rows:
            return 0

        stmt = (
            pg_insert(EnrichmentJob)
            .values([
                {"target_type": "article", "target_id": str(rid), "enricher": enricher}
                for rid in rows
            ])
            .on_conflict_do_nothing(
                constraint="uq_enrichment_target"
            )
        )
        result = await session.execute(stmt)
        # psycopg can report rowcount as -1 for INSERT … ON CONFLICT DO NOTHING
        # when it can't reliably count the skipped rows; clamp to 0 so callers
        # (and the scanner log) never see a negative "inserted" count.
        rowcount = result.rowcount
        return rowcount if isinstance(rowcount, int) and rowcount > 0 else 0


async def enqueue_ioc_jobs(enricher: str, limit: int = 500) -> int:
    """Add a pending job for every IOC still missing its ``enrichment`` payload.

    Mirrors :func:`enqueue_article_jobs`: idempotent via the unique
    (target_type, target_id, enricher) constraint. Returns rows inserted.
    """
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        # "Un-enriched" means SQL NULL *or* a JSONB ``null`` literal — connectors
        # persist the latter when an IOCRecord carries no enrichment, and it must
        # still count as a to-do or the scanner would never queue these rows.
        ioc_q = (
            select(IOC.id)
            .where(or_(IOC.enrichment.is_(None), IOC.enrichment == text("'null'::jsonb")))
            .order_by(IOC.id.desc())
            .limit(limit)
        )
        rows = (await session.execute(ioc_q)).scalars().all()
        if not rows:
            return 0

        stmt = (
            pg_insert(EnrichmentJob)
            .values([
                {"target_type": "ioc", "target_id": str(rid), "enricher": enricher}
                for rid in rows
            ])
            .on_conflict_do_nothing(constraint="uq_enrichment_target")
        )
        result = await session.execute(stmt)
        rowcount = result.rowcount
        return rowcount if isinstance(rowcount, int) and rowcount > 0 else 0


async def enqueue_cve_jobs(enricher: str, limit: int = 500) -> int:
    """Add a pending job for every CVE still missing its ``enrichment`` payload.

    Mirrors :func:`enqueue_ioc_jobs`: idempotent via the unique
    (target_type, target_id, enricher) constraint. Returns rows inserted.
    """
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        cve_q = (
            select(CVE.cve_id)
            .where(or_(CVE.enrichment.is_(None), CVE.enrichment == text("'null'::jsonb")))
            .order_by(CVE.published_date.desc().nulls_last())
            .limit(limit)
        )
        rows = (await session.execute(cve_q)).scalars().all()
        if not rows:
            return 0

        stmt = (
            pg_insert(EnrichmentJob)
            .values([
                {"target_type": "cve", "target_id": cid, "enricher": enricher}
                for cid in rows
            ])
            .on_conflict_do_nothing(constraint="uq_enrichment_target")
        )
        result = await session.execute(stmt)
        rowcount = result.rowcount
        return rowcount if isinstance(rowcount, int) and rowcount > 0 else 0


# -- claim / complete / fail ---------------------------------------------
async def claim_next() -> dict[str, Any] | None:
    """Atomically claim the next due pending job (or None).

    Uses ``SELECT … FOR UPDATE SKIP LOCKED`` so concurrent workers won't grab
    the same row. The transaction also flips status → 'running' and stamps the
    attempt counter.
    """
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        stmt = (
            select(EnrichmentJob)
            .where(EnrichmentJob.status == "pending",
                   EnrichmentJob.next_attempt_at <= func.now())
            .order_by(EnrichmentJob.next_attempt_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job = (await session.execute(stmt)).scalar_one_or_none()
        if job is None:
            return None
        job.status = "running"
        job.attempts += 1
        job.updated_at = _now()
        return {
            "id": job.id,
            "target_type": job.target_type,
            "target_id": job.target_id,
            "enricher": job.enricher,
            "attempts": job.attempts,
        }


async def complete(job_id: int, result: dict[str, Any] | None) -> None:
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        await session.execute(
            update(EnrichmentJob)
            .where(EnrichmentJob.id == job_id)
            .values(status="done", last_error=None, result=result, updated_at=_now())
        )


async def fail(job_id: int, *, attempts: int, error: str, max_attempts: int) -> None:
    """Mark a job failed. Re-queues with backoff while ``attempts < max_attempts``."""
    error = (error or "")[:1000]
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        if attempts >= max_attempts:
            await session.execute(
                update(EnrichmentJob)
                .where(EnrichmentJob.id == job_id)
                .values(status="error", last_error=error, updated_at=_now())
            )
            return
        backoff = _BACKOFF_SECONDS[min(attempts - 1, len(_BACKOFF_SECONDS) - 1)]
        await session.execute(
            update(EnrichmentJob)
            .where(EnrichmentJob.id == job_id)
            .values(
                status="pending",
                last_error=error,
                next_attempt_at=_now() + timedelta(seconds=backoff),
                updated_at=_now(),
            )
        )


# -- introspection (for the admin UI) -------------------------------------
async def stats() -> dict[str, dict[str, int]]:
    """Return ``{enricher_name: {status: count, ...}, ...}``."""
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (
            await session.execute(
                select(EnrichmentJob.enricher, EnrichmentJob.status, func.count())
                .group_by(EnrichmentJob.enricher, EnrichmentJob.status)
            )
        ).all()
    out: dict[str, dict[str, int]] = {}
    for enricher, status, count in rows:
        out.setdefault(enricher, {})[status] = count
    return out
