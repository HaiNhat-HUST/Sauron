"""EPSS enricher for CVEs — exploit-prediction scoring (no API key).

EPSS (Exploit Prediction Scoring System, by FIRST.org) estimates the
probability a CVE will be exploited in the wild over the next 30 days. It is
the single most actionable prioritisation signal we can add for free: combined
with the CISA-KEV flag (already exploited) it tells an analyst what to patch
first.

The public API takes a comma-separated list of CVE ids and returns one row per
known CVE, so a single request enriches a whole batch — no per-CVE round trips.
Output is written to ``cves.enrichment`` (JSONB)::

    {"enricher": "cve_epss", "enriched_at": ..., "epss": 0.94358,
     "percentile": 0.99964, "score_date": "2026-06-06"}

A CVE EPSS doesn't know (too new / reserved) still gets a payload with
``epss: null`` so the scanner won't keep re-queuing it every sweep.

API: https://api.first.org/data/v1/epss
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select, update

from ...storage.database import get_sessionmaker
from ...storage.models import CVE
from ..base import BaseEnricher

logger = logging.getLogger(__name__)

_EPSS_API = "https://api.first.org/data/v1/epss"
_HTTP_TIMEOUT = 15.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class CVEEPSSEnricher(BaseEnricher):
    name = "cve_epss"
    target_type = "cve"

    def __init__(self) -> None:
        self._http: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(_HTTP_TIMEOUT), follow_redirects=True
            )
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def enrich(self, target_id: str) -> dict[str, Any]:
        cve_id = (target_id or "").strip().upper()
        sm = get_sessionmaker()

        # Skip cleanly if the CVE vanished (retention) between enqueue and run.
        async with sm() as session:
            exists = await session.scalar(select(CVE.cve_id).where(CVE.cve_id == cve_id))
        if not exists:
            return {"skipped": "cve gone"}

        epss = await self._fetch_epss(cve_id)

        enrichment = {
            "enricher": self.name,
            "enriched_at": _now_iso(),
            "epss": epss.get("epss") if epss else None,
            "percentile": epss.get("percentile") if epss else None,
            "score_date": epss.get("date") if epss else None,
        }

        async with sm() as session, session.begin():
            await session.execute(
                update(CVE).where(CVE.cve_id == cve_id).values(enrichment=enrichment)
            )

        return {
            "cve": cve_id,
            "epss": enrichment["epss"],
            "percentile": enrichment["percentile"],
            "found": epss is not None,
        }

    async def _fetch_epss(self, cve_id: str) -> dict[str, Any] | None:
        """Return {'epss', 'percentile', 'date'} for one CVE, or None.

        None means EPSS has no score for it (not an error) or the call failed —
        either way the caller stores a null-score payload so the row is marked
        done and won't be re-queued.
        """
        try:
            resp = await self._client().get(_EPSS_API, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("EPSS lookup failed for %s: %s", cve_id, exc)
            return None
        rows = (data or {}).get("data") or []
        if not rows:
            return None
        row = rows[0]
        return {
            "epss": _to_float(row.get("epss")),
            "percentile": _to_float(row.get("percentile")),
            "date": row.get("date"),
        }
