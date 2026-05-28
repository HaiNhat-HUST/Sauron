"""Per-connector coroutines, paced by the admin DB.

For every registered connector, :meth:`ConnectorScheduler.start` spawns a single
long-lived coroutine (``_run_loop``). Each loop reads its own config row from
the Postgres app store on every iteration — that's where ``interval_minutes``
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

    # -- lifecycle (called from FastAPI startup/shutdown) ------------------
    async def start(self) -> None:
        if self._tasks:
            return
        self._stopped = False
        self._sem = asyncio.Semaphore(_MAX_CONCURRENT)
        for name in available():
            event = asyncio.Event()
            self._triggers[name] = event
            self._tasks[name] = asyncio.create_task(self._run_loop(name, event))
        logger.info(
            "scheduler started: %d connectors, max_concurrent=%d",
            len(self._tasks), _MAX_CONCURRENT,
        )

    async def stop(self) -> None:
        self._stopped = True
        for task in self._tasks.values():
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()
        self._triggers.clear()

    def trigger(self, name: str) -> bool:
        """Wake a connector's loop to run immediately. Returns False if unknown."""
        event = self._triggers.get(name)
        if event is None:
            return False
        event.set()
        return True

    # -- per-connector loop ------------------------------------------------
    async def _run_loop(self, name: str, trigger: asyncio.Event) -> None:
        """One coroutine per connector. Reads config, sleeps, runs, repeats."""
        while not self._stopped:
            try:
                wait_seconds = await self._step(name, trigger)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — never let one cycle kill the loop
                logger.exception("connector %s loop step crashed", name)
                wait_seconds = _DISABLED_RECHECK_SECONDS

            if wait_seconds <= 0:
                continue
            try:
                await asyncio.wait_for(trigger.wait(), timeout=wait_seconds)
            except asyncio.TimeoutError:
                pass  # natural wake — interval elapsed
            except asyncio.CancelledError:
                raise

    async def _step(self, name: str, trigger: asyncio.Event) -> float:
        """One iteration: decide whether to run, return seconds to sleep before next."""
        cfg = await appstore.get_connector_by_name(name) or {}
        interval = max(_MIN_INTERVAL_SECONDS, float(cfg.get("interval_minutes") or 60) * 60.0)
        enabled = bool(cfg.get("is_enabled"))
        last = _parse_ts(cfg.get("last_run"))

        if trigger.is_set():
            trigger.clear()
            await self._run_connector(name, manual=True)
            return 0.0  # re-evaluate immediately

        if not enabled:
            return _DISABLED_RECHECK_SECONDS

        elapsed = (datetime.now(timezone.utc) - last).total_seconds() if last else interval
        if elapsed >= interval:
            await self._run_connector(name, manual=False)
            return 0.0
        return max(1.0, interval - elapsed)

    async def _run_connector(self, name: str, *, manual: bool) -> None:
        await appstore.set_connector_status(name, "running")
        assert self._sem is not None
        async with self._sem:
            connector = build_connector(name, self._global, self._output_handler())
            missing = connector._missing_settings()  # noqa: SLF001 — same package
            if missing:
                await appstore.record_connector_run(
                    name, last_status="needs-key",
                    error="missing setting(s): " + ", ".join(missing),
                )
                logger.info("connector %s skipped — needs %s", name, missing)
                await connector.aclose()
                return
            try:
                count = await asyncio.wait_for(connector.run_once(), timeout=_RUN_TIMEOUT)
                await appstore.record_connector_run(name, last_status="ok", objects=count)
                logger.info("connector %s (%s) ok — %d records",
                            name, "manual" if manual else "scheduled", count)
            except asyncio.TimeoutError:
                await appstore.record_connector_run(
                    name, last_status="error", error=f"timed out after {_RUN_TIMEOUT}s"
                )
            except asyncio.CancelledError:
                await appstore.record_connector_run(name, last_status="error", error="cancelled")
                raise
            except Exception as exc:  # noqa: BLE001
                await appstore.record_connector_run(name, last_status="error", error=str(exc)[:300])
                logger.exception("connector %s failed", name)
            finally:
                await connector.aclose()

    def _output_handler(self) -> OutputHandler:
        if self._output is None:
            mode = os.getenv("SCHEDULER_OUTPUT", "file").lower()
            handlers: list[OutputHandler] = []
            if mode in ("file", "both"):
                handlers.append(FileOutputHandler(self._global.output_dir))
            if mode in ("db", "both"):
                from src.storage.output import DatabaseOutputHandler

                handlers.append(DatabaseOutputHandler())
            handlers.append(LoggingOutputHandler())
            self._output = CompositeOutputHandler(*handlers)
        return self._output


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


_scheduler: ConnectorScheduler | None = None


def get_scheduler() -> ConnectorScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ConnectorScheduler()
    return _scheduler

