"""Bridge connectors -> storage: a DatabaseOutputHandler.

Implements the connector framework's :class:`~src.collectors.handler.output.OutputHandler`
so a connector can write its :class:`~src.collectors.records.CollectionResult`
straight into PostgreSQL.
"""

from __future__ import annotations

from ..collectors.handler.output import OutputHandler
from ..collectors.records import CollectionResult
from .store import Store


class DatabaseOutputHandler(OutputHandler):
    def __init__(self, store: Store | None = None):
        self.store = store or Store()

    async def send(self, result: CollectionResult, connector_name: str) -> None:
        await self.store.ingest(result, source_type=connector_name)
