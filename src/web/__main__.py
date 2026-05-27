"""Entry point: ``python -m src.web``.

On Windows, force a SelectorEventLoop before uvicorn's server runs — psycopg's
async driver does not support the default ProactorEventLoop. We bypass
``uvicorn.run`` (which calls ``asyncio_setup`` that forces ProactorPolicy on
Windows) by driving the server via ``asyncio.run(Server.serve())`` directly.
"""

from __future__ import annotations

import asyncio
import os
import sys

import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def main() -> None:
    config = uvicorn.Config(
        "src.web.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
    server = uvicorn.Server(config)
    # asyncio.run respects the policy set above → SelectorEventLoop on Windows.
    asyncio.run(server.serve())


if __name__ == "__main__":
    main()
