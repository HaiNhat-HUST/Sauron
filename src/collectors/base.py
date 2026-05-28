"""BaseConnector — the lifecycle every source connector inherits.

A scheduled loop that pulls from a source, normalizes it into a
:class:`~src.collectors.records.CollectionResult`, and ships it to the output
handler. Runs async and in-process.

A concrete connector only has to:

1. set ``name`` / ``description`` (and optionally ``required_settings``), and
2. implement :meth:`collect`, returning a :class:`CollectionResult`.

The base class handles scheduling, HTTP with retry, state persistence and output.
"""

from __future__ import annotations

import asyncio
import logging
import random
from abc import ABC, abstractmethod

import httpx

from .config import ConnectorConfig, GlobalConfig
from .handler.output import OutputHandler
from .records import CollectionResult
from .state import StateStore

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0  # seconds; exponential per retry


class BaseConnector(ABC):
    #: Stable connector id, used for state file names + author identity.
    name: str = "base"
    #: Human description, stamped on the author Identity.
    description: str = ""
    #: Config attribute names that must be truthy for the connector to run
    #: (e.g. ("auth_key",) for abuse.ch). Missing ones -> connector idles.
    required_settings: tuple[str, ...] = ()

    def __init__(
        self,
        config: ConnectorConfig,
        global_config: GlobalConfig,
        output: OutputHandler,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.config = config
        self.global_config = global_config
        self.output = output
        self.state = StateStore(self.name, global_config.state_dir)
        self._own_client = http_client is None
        # A browser-like UA: several OSINT feeds (CISA, some blogs/CDNs) reject
        # generic library user-agents with HTTP 403. Connectors that need their
        # own UA (e.g. Reddit) override it per-request.
        self.http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ai-threat-intel/0.1"
                )
            },
            follow_redirects=True,
        )
        self.log = logging.getLogger(f"connector.{self.name}")

    # -- lifecycle ---------------------------------------------------------
    @abstractmethod
    async def collect(self) -> CollectionResult:
        """Pull from the source and return a :class:`CollectionResult`.

        Implementations use :attr:`self.state` to track incremental cursors and
        the HTTP helpers to fetch. Both structured feeds and unstructured text
        documents map into the same result (articles / iocs / cves / tags).
        """

    def _missing_settings(self) -> list[str]:
        return [s for s in self.required_settings if not getattr(self.config, s, None)]

    async def run_once(self) -> int:
        """Run a single collection cycle. Returns the record count emitted."""
        missing = self._missing_settings()
        if missing:
            self.log.warning(
                "skipping run — missing required setting(s): %s", ", ".join(missing)
            )
            return 0

        self.log.info("collection started")
        result = await self.collect()
        if result is None or result.is_empty():
            self.log.info("collection finished — no new records")
            self.state.flush()
            return 0

        await self.output.send(result, self.name)
        self.state.flush()
        self.log.info("collection finished — emitted %d records", result.count())
        return result.count()

    async def aclose(self) -> None:
        if self._own_client:
            await self.http.aclose()

    # -- HTTP helpers with retry/backoff -----------------------------------
    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = await self.http.request(method, url, **kwargs)
                # Retry on transient server / rate-limit responses.
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise httpx.HTTPStatusError(
                        f"transient {resp.status_code}", request=resp.request, response=resp
                    )
                resp.raise_for_status()
                return resp
            except (httpx.HTTPError, httpx.TransportError) as exc:
                last_exc = exc
                if attempt == _MAX_RETRIES:
                    break
                delay = _BACKOFF_BASE ** attempt + random.uniform(0, 1)
                self.log.warning(
                    "request %s %s failed (%s); retry %d/%d in %.1fs",
                    method, url, exc, attempt, _MAX_RETRIES, delay,
                )
                await asyncio.sleep(delay)
        raise last_exc  # type: ignore[misc]

    async def get_json(self, url: str, **kwargs) -> dict | list:
        resp = await self._request("GET", url, **kwargs)
        return resp.json()

    async def post_json(self, url: str, **kwargs) -> dict | list:
        resp = await self._request("POST", url, **kwargs)
        return resp.json()

    async def get_text(self, url: str, **kwargs) -> str:
        resp = await self._request("GET", url, **kwargs)
        return resp.text
