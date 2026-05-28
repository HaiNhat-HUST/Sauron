"""Dashboard data facade — async, called directly from FastAPI handlers.

Builds the consolidated payload the dashboard renders: headline counts, ingest
timeline and the most useful collected intelligence. Connector online/total
counts come from :mod:`src.storage.app`; everything else from the TI tables. If
the store is unreachable/empty the dashboard still renders with zeros and
``db_available: false``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from . import app as appstore
from .queries import DashboardQueries

logger = logging.getLogger(__name__)

_EMPTY: Dict[str, Any] = {
    "overview": {"articles": 0, "iocs": 0, "cves": 0, "tags": 0,
                 "known_exploited": 0, "last_ingest": None},
    "timeline": [], "by_source": [], "by_ioc_type": [], "cve_severity": [],
    "top_tags": [], "recent_articles": [], "recent_iocs": [], "recent_cves": [],
}


async def _gather_ti() -> Dict[str, Any]:
    q = DashboardQueries()
    (overview, timeline, by_source, by_ioc_type, cve_severity, top_tags,
     recent_articles, recent_iocs, recent_cves) = await asyncio.gather(
        q.overview(),
        q.ingestion_timeline(14),
        q.counts_by_source(),
        q.counts_by_ioc_type(),
        q.cve_by_severity(),
        q.top_tags(10),
        q.recent_articles(8),
        q.recent_iocs(12),
        q.recent_cves(8),
    )
    return {
        "overview": overview, "timeline": timeline, "by_source": by_source,
        "by_ioc_type": by_ioc_type, "cve_severity": cve_severity, "top_tags": top_tags,
        "recent_articles": recent_articles, "recent_iocs": recent_iocs,
        "recent_cves": recent_cves,
    }


async def get_overview() -> Dict[str, Any]:
    try:
        connectors = await appstore.list_connectors()
    except Exception as exc:  # noqa: BLE001
        logger.warning("dashboard: connector list unavailable (%s)", exc)
        connectors = []
    connectors_total = len(connectors)
    connectors_online = sum(1 for c in connectors if c.get("is_enabled"))
    connectors_running = sum(1 for c in connectors if c.get("status") in ("running", "queued"))

    try:
        ti = await _gather_ti()
        db_available = True
    except Exception as exc:  # noqa: BLE001 — dashboard must still render
        logger.warning("dashboard: TI store unavailable (%s)", exc)
        ti = {k: (dict(v) if isinstance(v, dict) else list(v)) for k, v in _EMPTY.items()}
        db_available = False

    try:
        from .vector import get_vector_store
        embeddings = await asyncio.to_thread(get_vector_store().count)
    except Exception:  # noqa: BLE001
        embeddings = 0

    summary = dict(ti["overview"])
    summary.update(
        connectors_online=connectors_online,
        connectors_total=connectors_total,
        connectors_running=connectors_running,
        embeddings=embeddings,
    )
    return {"db_available": db_available, "summary": summary,
            **{k: ti[k] for k in _EMPTY if k != "overview"}}
