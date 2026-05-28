"""Per-connector coroutines, paced by the admin DB.

For every registered connector, :meth:`ConnectorScheduler.start` spawns a single
long-lived coroutine (``_run_loop``). Each loop reads its own config row from
the admin SQLite store on every iteration — that's where ``interval_minutes``
and ``is_enabled`` live (set by the admin UI) — and self-paces:

* if enabled and ``last_run + interval`` has elapsed → run once
* otherwise sleep until the next due time (or until a "Run now" event fires)

A per-connector :class:`asyncio.Event` is used as the manual-trigger; it wakes
the sleeper early and forces an immediate run on the next loop iteration.

A process-wide semaphore caps how many connectors can ingest at once.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from ..storage import app as appstore
from .config import GlobalConfig
from .handler.output import (
    CompositeOutputHandler,
    FileOutputHandler,
    LoggingOutputHandler,
    OutputHandler,
)

from .registry import available, build_connector

logger = logging.getLogger("connector.scheduler")

_MAX_CONCURRENT = int(os.getenv("SCHEDULER_MAX_CONCURRENT", "3"))
_RUN_TIMEOUT = int(os.getenv("SCHEDULER_RUN_TIMEOUT", "600"))
_DISABLED_RECHECK_SECONDS = 30.0  # how often a disabled connector checks back
_MIN_INTERVAL_SECONDS = 60.0

class ConnectorScheduler:
    def __init__(self) -> None:
        self._global = GlobalConfig()
        self._output: OutputHandler | None = None
        self._sem: asyncio.Semaphore | None = None
        self._tasks: dict[str, asyncio.Task] = {}
        self._triggers: dict[str, asyncio.Event] = {}
        self._stopped = False

    async def start(self) -> None:
        if self._tasks: 
            return 
        self._stopped = False
        self._sem = asyncio.Semaphore
        for name in available(): 
            event = asyncio.Semaphore()