"""FastAPI application — JSON API + single-page app (SPA) shell.

The frontend is a static SPA (``static/index.html`` + ES-module JS) using
client-side hash routing, so the server only serves the shell and the API.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..api import storage
# from ..collectors.scheduler import get_scheduler
from .routers import admin, auth, dashboard
from .routers import chat

logger = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
STATIC_DIR = HERE / "static"

app = FastAPI(title="ai-threat-intel", version="0.1.0")

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(dashboard.router)
app.include_router(chat.router)


@app.on_event("startup")
async def _startup() -> None:
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    storage.init_db()  # SQLite app store (users / connectors / retention)
    # Init the PostgreSQL TI schema up front so the scheduler's first tick
    # (which can run before any /dashboard/overview request) doesn't try to
    # write into missing tables. Tolerated if Postgres is down — the dashboard
    # still renders and the next scheduler tick will retry.
    try:
        from ..storage.database import init_db as init_ti_db

        await init_ti_db()
    except Exception as exc:  # noqa: BLE001
        logger.warning("TI store not reachable on startup (%s) — will retry lazily", exc)
    # if os.getenv("SCHEDULER_ENABLED", "true").lower() in ("1", "true", "yes"):
    #     await get_scheduler().start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    # await get_scheduler().stop()
    try:
        from ..storage.database import dispose

        await dispose()
    except Exception:  # noqa: BLE001
        pass


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# --- SPA shell + static assets -------------------------------------------
@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
