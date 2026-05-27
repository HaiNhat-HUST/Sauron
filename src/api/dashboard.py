"""Dashboard data facade — async, called directly from FastAPI handlers.

Builds the consolidated payload the dashboard renders: headline counts, ingest
timeline and the most useful collected intelligence. Connector online/total
counts come from the SQLite app-config store; everything else from PostgreSQL.
If the store is unreachable/empty the dashboard still renders with zeros and
``db_available: false``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from ..storage.queries import DashboardQueries
from . import storage as appdb