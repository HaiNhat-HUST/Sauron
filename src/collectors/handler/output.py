"""Output handlers — where a connector's collected records go.

Connectors are decoupled from the rest of the system through this interface:

* :class:`FileOutputHandler`  — write each result to ``data/output`` as JSON.
* :class:`LoggingOutputHandler` — log a one-line summary (dry runs).
* :class:`CompositeOutputHandler` — fan out to several handlers.

The DB handler (:class:`~src.storage.output.DatabaseOutputHandler`) lives in the
storage package so the dependency points storage → collectors.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from ..records import CollectionResult

logger = logging.getLogger(__name__)


class OutputHandler(ABC):
    @abstractmethod
    async def send(self, result: CollectionResult, connector_name: str) -> None:
        ...


class FileOutputHandler(OutputHandler):
    def __init__(self, output_dir: str):
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    async def send(self, result: CollectionResult, connector_name: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = self._dir / f"{connector_name}_{ts}.json"
        payload = json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str)
        await asyncio.to_thread(path.write_text, payload, "utf-8")
        logger.info("[%s] wrote %d records -> %s", connector_name, result.count(), path.name)


class LoggingOutputHandler(OutputHandler):
    async def send(self, result: CollectionResult, connector_name: str) -> None:
        logger.info(
            "[%s] %d records (articles=%d iocs=%d cves=%d tags=%d)",
            connector_name, result.count(), len(result.articles),
            len(result.iocs), len(result.cves), len(result.tags),
        )


class CompositeOutputHandler(OutputHandler):
    def __init__(self, *handlers: OutputHandler):
        self._handlers = handlers

    async def send(self, result: CollectionResult, connector_name: str) -> None:
        await asyncio.gather(*(h.send(result, connector_name) for h in self._handlers))
