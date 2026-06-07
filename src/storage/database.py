"""Async engine / session factory and one-shot schema initialisation."""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import StorageConfig, storage_config
from .models import Base

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine(config: StorageConfig | None = None) -> AsyncEngine:
    global _engine
    if _engine is None:
        cfg = config or storage_config
        _engine = create_async_engine(cfg.sqlalchemy_url, echo=cfg.db_echo, pool_pre_ping=True)
    return _engine


def get_sessionmaker(config: StorageConfig | None = None) -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            get_engine(config), expire_on_commit=False, class_=AsyncSession
        )
    return _sessionmaker


async def init_db(config: StorageConfig | None = None, *, reset: bool = False) -> None:
    """Create all tables (idempotent).

    ``reset=True`` drops every table first, so the schema is rebuilt from
    scratch — use it after a model change that ``create_all`` cannot apply to an
    existing table (it never alters or drops columns). This wipes all TI and app
    data; the caller is expected to re-seed defaults afterwards.
    """
    engine = get_engine(config)
    async with engine.begin() as conn:
        if reset:
            await conn.run_sync(Base.metadata.drop_all)
            logger.warning("schema dropped (reset=True) — all data wiped")
        await conn.run_sync(Base.metadata.create_all)
    logger.info("schema initialised")


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
