"""Key-free IOC enricher — pivots + internal cross-reference.

Implements the two pipeline recommendations without any external paid API:

1. **Pivots** (deterministic, derive structure from the indicator itself):
   * ``domain`` → forward-DNS A records (resolved IPs)
   * ``url``    → host / scheme / path
   * ``email``  → domain part
   * ``ip``     → reverse-DNS (PTR) hostname

2. **Internal cross-reference** (the "free, offline, no-rate-limit" signal): the
   indicator — and anything it pivots to — is checked against the IOCs we have
   already collected. The most useful hit is an IP that also appears on the
   abuse.ch Feodo C2 blocklist, which lets a benign-looking domain be flagged as
   resolving to known command-and-control infrastructure. We also surface how
   many articles reference the indicator (its blast radius) and the malware
   tags of those articles.

Output is written to ``iocs.enrichment`` (JSONB); nothing here creates new IOC
rows or edges — turning a resolved IP into a graph node is a follow-up that
needs an ioc↔ioc relation table. ``rdns`` / ``resolved_ips`` are stored so that
step can consume them later.

Connector sources treated as authoritative blocklists for the C2 check.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ...storage.database import get_sessionmaker
from ...storage.models import ArticleIOC, ArticleTag, IOC, IOCRelation, Tag
from ..base import BaseEnricher

logger = logging.getLogger(__name__)

# Connector source_types whose IPs/URLs are, by definition, malicious. An IOC
# (or a domain's resolved IP) matching one of these is a strong signal.
_C2_SOURCES = {"feodo"}
_BLOCKLIST_SOURCES = {"feodo", "urlhaus", "threatfox", "malwarebazaar"}

_DNS_TIMEOUT = 4.0  # seconds per lookup; DNS is rarely network-blocked

# --- external hash-lookup services ---------------------------------------
# MalwareBazaar shares the abuse.ch auth key; VirusTotal needs its own. Both
# are optional — when a key is missing or the host is unreachable the lookup is
# skipped gracefully and the rest of the enrichment still runs.
_MB_API = "https://mb-api.abuse.ch/api/v1/"
_MB_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
_VT_API = "https://www.virustotal.com/api/v3/files/"
_VT_API_KEY = os.getenv("VT_API_KEY", "")
_HTTP_TIMEOUT = 15.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _resolve_ips(host: str) -> list[str]:
    """Forward-resolve a host to its IPv4 addresses (best-effort)."""
    if not host:
        return []
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
            timeout=_DNS_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError, socket.gaierror):
        return []
    return sorted({info[4][0] for info in infos})


async def _reverse_dns(ip: str) -> str | None:
    """Reverse-resolve an IP to its PTR hostname (best-effort)."""
    if not ip:
        return None
    try:
        host, *_ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip), timeout=_DNS_TIMEOUT
        )
        return host
    except (asyncio.TimeoutError, OSError, socket.herror, socket.gaierror):
        return None


async def _malwarebazaar_lookup(client: httpx.AsyncClient, sha256: str) -> dict | None:
    """Look a hash up on MalwareBazaar (get_info). Needs ABUSECH_AUTH_KEY.

    Returns a compact dict (file_type, signature, family tags, mime, ...) or
    None when the key is missing, the sample is unknown, or the call fails.
    """
    if not _MB_AUTH_KEY:
        return None
    try:
        resp = await client.post(
            _MB_API,
            headers={"Auth-Key": _MB_AUTH_KEY},
            data={"query": "get_info", "hash": sha256},
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("query_status") != "ok":
        return None
    items = data.get("data") or []
    if not items:
        return None
    s = items[0]
    return {
        "file_type": s.get("file_type"),
        "file_name": s.get("file_name"),
        "signature": s.get("signature"),
        "mime_type": s.get("mime_type"),
        "tags": [t for t in (s.get("tags") or []) if t],
        "delivery": s.get("delivery_method"),
    }


async def _virustotal_lookup(client: httpx.AsyncClient, file_hash: str) -> dict | None:
    """Look a hash up on VirusTotal (file report). Needs VT_API_KEY.

    Returns detection stats + the most common threat label, or None when the
    key is missing, the file is unknown (404), rate-limited (429), or blocked.
    """
    if not _VT_API_KEY:
        return None
    try:
        resp = await client.get(
            f"{_VT_API}{file_hash}", headers={"x-apikey": _VT_API_KEY}
        )
        if resp.status_code in (404, 429):
            return None
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    attrs = ((data or {}).get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int)) or 0
    return {
        "malicious": malicious,
        "total": total,
        "ratio": f"{malicious}/{total}" if total else None,
        "threat_label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "type_description": attrs.get("type_description"),
        "names": (attrs.get("names") or [])[:3],
    }


async def _upsert_ioc(session, ioc_type: str, value: str, source_type: str) -> int | None:
    """Get-or-create an IOC by (type, value); return its id.

    Reuses the global (ioc_type, value) uniqueness so a resolved IP that already
    exists (e.g. from Feodo) is linked rather than duplicated. ``source_type`` is
    only set on first insert — an existing row keeps its original provenance.
    """
    value = (value or "").strip()
    if not value or ioc_type not in ("ip", "domain", "url", "email", "hash"):
        return None
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(IOC)
        .values(ioc_type=ioc_type, value=value, source_type=source_type,
                first_seen=now, last_seen=now)
        .on_conflict_do_update(
            constraint="uq_iocs_type_value",
            set_={"last_seen": func.greatest(IOC.last_seen, now)},
        )
        .returning(IOC.id)
    )
    return (await session.execute(stmt)).scalar_one()


async def _link_iocs(session, src_id: int, dst_id: int, relation: str) -> None:
    """Record a directed IOC→IOC edge (idempotent). Skips self-loops."""
    if src_id == dst_id:
        return
    stmt = (
        pg_insert(IOCRelation)
        .values(src_ioc_id=src_id, dst_ioc_id=dst_id, relation=relation)
        .on_conflict_do_nothing(
            index_elements=[IOCRelation.src_ioc_id, IOCRelation.dst_ioc_id, IOCRelation.relation]
        )
    )
    await session.execute(stmt)


class IOCBasicEnricher(BaseEnricher):
    name = "ioc_basic"
    target_type = "ioc"

    def __init__(self) -> None:
        self._http: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        # Lazily created on first hash lookup; reused across jobs, closed on stop.
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
        ioc_id = int(target_id)
        sm = get_sessionmaker()

        async with sm() as session:
            row = (await session.execute(
                select(IOC.id, IOC.ioc_type, IOC.value).where(IOC.id == ioc_id)
            )).first()
        if row is None:
            return {"skipped": "ioc gone"}
        _id, ioc_type, value = row
        value = (value or "").strip()

        pivot: dict[str, Any] = {}
        rdns: str | None = None

        # 1. Type-specific pivots.
        if ioc_type == "ip":
            rdns = await _reverse_dns(value)
        elif ioc_type == "domain":
            pivot["resolved_ips"] = await _resolve_ips(value)
        elif ioc_type == "url":
            parsed = urlparse(value)
            pivot["host"] = parsed.hostname
            pivot["scheme"] = parsed.scheme or None
            pivot["path"] = parsed.path or None
            if parsed.hostname:
                pivot["resolved_ips"] = await _resolve_ips(parsed.hostname)
        elif ioc_type == "email":
            pivot["domain"] = value.split("@", 1)[-1].lower() if "@" in value else None
        elif ioc_type == "hash":
            pivot["hash_intel"] = await self._lookup_hash(value)

        # 2. Internal cross-reference against already-collected intel.
        internal = await self._cross_reference(ioc_id, ioc_type, value, pivot)

        # 3. Materialise pivots as real IOC nodes + ioc↔ioc edges, so the graph
        # can pivot between indicators that share infrastructure.
        async with sm() as session, session.begin():
            edges = await self._materialise_pivots(session, ioc_id, ioc_type, pivot)
            enrichment = {
                "enricher": self.name,
                "enriched_at": _now_iso(),
                "rdns": rdns,
                "pivot": {k: v for k, v in pivot.items() if v},
                "internal": internal,
                "relations": edges,  # [{"relation": ..., "ioc_type": ..., "value": ...}]
            }
            await session.execute(
                update(IOC).where(IOC.id == ioc_id).values(enrichment=enrichment)
            )

        # Compact result for enrichment_jobs.result (observability only).
        hash_intel = pivot.get("hash_intel") or {}
        return {
            "ioc_type": ioc_type,
            "resolved_ips": len(pivot.get("resolved_ips", []) or []),
            "edges": len(edges),
            "rdns": bool(rdns),
            "known_c2": internal.get("known_c2", False),
            "article_refs": internal.get("article_refs", 0),
            "related_iocs": len(internal.get("related_ioc_ids", [])),
            "mb_hit": "malwarebazaar" in hash_intel,
            "vt_hit": "virustotal" in hash_intel,
        }

    async def _lookup_hash(self, value: str) -> dict[str, Any]:
        """Enrich a file hash via MalwareBazaar + VirusTotal (both optional).

        The two services are queried concurrently; whichever has a key and
        responds contributes its slice. Returns ``{}`` when neither is usable.
        """
        client = self._client()
        mb, vt = await asyncio.gather(
            _malwarebazaar_lookup(client, value),
            _virustotal_lookup(client, value),
            return_exceptions=True,
        )
        out: dict[str, Any] = {}
        if isinstance(mb, dict) and mb:
            out["malwarebazaar"] = mb
        if isinstance(vt, dict) and vt:
            out["virustotal"] = vt
        return out

    async def _materialise_pivots(
        self, session, ioc_id: int, ioc_type: str, pivot: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Turn this IOC's pivots into IOC nodes + directed edges.

        Edge map by source type:
          domain → ip      : ``resolves_to``
          url    → domain  : ``url_host``     (the URL's host)
          url    → ip      : ``resolves_to``  (host's resolved IPs)
          email  → domain  : ``email_domain``

        Returns a compact list of the edges created, for the JSONB payload.
        """
        edges: list[dict[str, str]] = []

        async def add(dst_type: str, dst_value: str, relation: str) -> None:
            dst_id = await _upsert_ioc(session, dst_type, dst_value, source_type="enrichment")
            if dst_id is None:
                return
            await _link_iocs(session, ioc_id, dst_id, relation)
            edges.append({"relation": relation, "ioc_type": dst_type, "value": dst_value})

        if ioc_type == "domain":
            for ip in pivot.get("resolved_ips", []) or []:
                await add("ip", ip, "resolves_to")
        elif ioc_type == "url":
            host = pivot.get("host")
            if host:
                await add("domain", host, "url_host")
            for ip in pivot.get("resolved_ips", []) or []:
                await add("ip", ip, "resolves_to")
        elif ioc_type == "email":
            domain = pivot.get("domain")
            if domain:
                await add("domain", domain, "email_domain")

        return edges

    async def _cross_reference(
        self, ioc_id: int, ioc_type: str, value: str, pivot: dict[str, Any]
    ) -> dict[str, Any]:
        """Match the indicator (and its pivots) against existing IOCs/articles."""
        sm = get_sessionmaker()
        notes: list[str] = []
        related_ids: list[int] = []
        known_c2 = False

        # Candidate IP/host values to look up in the iocs table: the indicator
        # itself plus anything it resolved/parsed to.
        lookup_values: set[str] = set()
        if ioc_type in ("ip", "domain", "url", "email"):
            lookup_values.update(pivot.get("resolved_ips", []) or [])
        if pivot.get("host"):
            lookup_values.add(pivot["host"])
        if pivot.get("domain"):
            lookup_values.add(pivot["domain"])
        # The IOC itself (an IP/hash may be its own blocklist hit).
        if ioc_type in ("ip", "hash"):
            lookup_values.add(value)

        async with sm() as session:
            # 2a. Articles that reference this indicator (its blast radius) and
            # the malware families those articles carry.
            article_refs = await session.scalar(
                select(func.count()).select_from(ArticleIOC)
                .where(ArticleIOC.ioc_id == ioc_id)
            ) or 0

            # Malware tags on the articles that reference this IOC.
            malware_rows = (await session.execute(
                select(func.coalesce(Tag.label, Tag.name))
                .select_from(ArticleIOC)
                .join(ArticleTag, ArticleTag.article_id == ArticleIOC.article_id)
                .join(Tag, Tag.id == ArticleTag.tag_id)
                .where(ArticleIOC.ioc_id == ioc_id, Tag.type == "malware")
                .distinct()
            )).scalars().all()
            malware = [m for m in malware_rows if m]

            # 2b. Look the candidate values up in the iocs table.
            if lookup_values:
                rows = (await session.execute(
                    select(IOC.id, IOC.ioc_type, IOC.value, IOC.source_type)
                    .where(IOC.value.in_(lookup_values), IOC.id != ioc_id)
                )).all()
                for rid, rtype, rval, rsource in rows:
                    related_ids.append(rid)
                    if rsource in _C2_SOURCES:
                        known_c2 = True
                        notes.append(f"{rval} is known C2 ({rsource})")
                    elif rsource in _BLOCKLIST_SOURCES:
                        notes.append(f"{rval} on {rsource} blocklist")

            # 2c. The indicator itself sitting on a blocklist source.
            self_source = await session.scalar(
                select(IOC.source_type).where(IOC.id == ioc_id)
            )
            if self_source in _C2_SOURCES:
                known_c2 = True
                notes.append(f"listed on {self_source} (C2)")

        return {
            "known_c2": known_c2,
            "article_refs": article_refs,
            "malware": malware,
            "related_ioc_ids": sorted(set(related_ids)),
            "notes": notes,
        }
