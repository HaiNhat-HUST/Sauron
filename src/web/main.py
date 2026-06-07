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

from ..collectors.scheduler import get_scheduler
from ..enrichment.worker import get_worker as get_enrichment_worker
from ..storage import app as appstore
from ..storage.database import dispose, init_db
from .routers import admin, articles, auth, chat, dashboard

logger = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
STATIC_DIR = HERE / "static"

app = FastAPI(title="ai-threat-intel", version="0.1.0")

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(dashboard.router)
app.include_router(articles.router)
app.include_router(chat.router)


@app.on_event("startup")
async def _startup() -> None:
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    # Single Postgres DB holds both TI data and app/admin state (users,
    # sessions, connector settings, retention). Failing here is fatal — every
    # request path depends on it.
    await init_db()
    await appstore.seed_defaults()
    if os.getenv("SCHEDULER_ENABLED", "true").lower() in ("1", "true", "yes"):
        await get_scheduler().start()
    if os.getenv("ENRICHMENT_ENABLED", "true").lower() in ("1", "true", "yes"):
        await get_enrichment_worker().start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    await get_scheduler().stop()
    await get_enrichment_worker().stop()
    try:
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
