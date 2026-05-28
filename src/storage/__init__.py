"""ai-threat-intel storage layer — PostgreSQL relational TI store.

Simple schema (articles / iocs / cves / tags) populated by the connectors,
queried by the dashboard and the chat search.

Entry points:
* :class:`~src.storage.store.Store`              — ingest CollectionResults.
* :class:`~src.storage.queries.DashboardQueries` — aggregations for dashboards.
* :class:`~src.storage.retrieval.Retriever`      — keyword search / IOC lookup.
* :class:`~src.storage.output.DatabaseOutputHandler` — connector → DB bridge.

CLI: ``python -m src.storage.cli --help``
"""

from .queries import DashboardQueries
from .retrieval import Retriever
from .store import Store

__all__ = ["Store", "DashboardQueries", "Retriever"]
