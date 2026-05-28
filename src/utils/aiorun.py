"""Cross-platform ``asyncio.run`` wrapper.

On Windows the default event loop is the ProactorEventLoop, but psycopg's async
driver requires a SelectorEventLoop. Routing every CLI entry point through
:func:`run` makes the storage layer work on Windows without each caller having
to remember the quirk. On other platforms it's a plain ``asyncio.run``.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Coroutine


def run(coro: Coroutine):
    if sys.platform == "win32":
        # asyncio.run gained loop_factory in 3.12; SelectorEventLoop is the
        # psycopg-compatible loop.
        try:
            return asyncio.run(coro, loop_factory=asyncio.SelectorEventLoop)
        except TypeError:  # older Python without loop_factory
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            return asyncio.run(coro)
    return asyncio.run(coro)
