"""App/admin store — users, sessions, connector settings, retention.

Backed by the same async PostgreSQL database as the TI data (no second DB).
All public functions are async; password hashing is sync utility.

Call :func:`seed_defaults` once after :func:`src.storage.database.init_db` to
provision the default admin/analyst accounts, the connector rows the scheduler
will manage, and the singleton retention policy.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from .database import get_sessionmaker
from .models import (
    ConnectorSetting,
    LLMFunctionModel,
    LLMProvider,
    RetentionPolicy,
    Session,
    User,
)

logger = logging.getLogger(__name__)

PASSWORD_SALT = os.getenv("APP_PASSWORD_SALT", "ti-demo-salt")
SESSION_TTL_HOURS = int(os.getenv("APP_SESSION_TTL_HOURS", "24"))

# Seed rows used on first boot. ``name`` must match a connector in the registry.
# Functions that consume an LLM. Adding a new one = one row here + the
# function name passed to ``llm_for(...)`` in the new caller.
LLM_FUNCTIONS = ("agent_chat", "report", "enrich_article")

DEFAULT_CONNECTORS = [
    {"name": "threatfox",     "source": "abuse.ch",       "interval_minutes": 30,   "is_enabled": True},
    {"name": "malwarebazaar", "source": "abuse.ch",       "interval_minutes": 60,   "is_enabled": True},
    {"name": "urlhaus",       "source": "abuse.ch",       "interval_minutes": 45,   "is_enabled": True},
    {"name": "feodo",         "source": "abuse.ch",       "interval_minutes": 90,   "is_enabled": True},
    {"name": "nvd",           "source": "nist.gov",       "interval_minutes": 360,  "is_enabled": True},
    {"name": "mitre_attack",  "source": "mitre.org",      "interval_minutes": 1440, "is_enabled": True},
    {"name": "cisa_kev",      "source": "cisa.gov",       "interval_minutes": 720,  "is_enabled": True},
    {"name": "otx",           "source": "alienvault.com", "interval_minutes": 120,  "is_enabled": True},
    {"name": "reddit",        "source": "reddit.com",     "interval_minutes": 120,  "is_enabled": True},
    {"name": "rss",           "source": "security blogs", "interval_minutes": 60,   "is_enabled": True},
    {"name": "twitter",       "source": "x.com",          "interval_minutes": 180,  "is_enabled": False},
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return hashlib.sha256((PASSWORD_SALT + password).encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def _user_to_dict(u: User) -> Dict[str, Any]:
    return {
        "id": u.id,
        "username": u.username,
        "password_hash": u.password_hash,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def _connector_to_dict(c: ConnectorSetting) -> Dict[str, Any]:
    return {
        "id": c.id,
        "name": c.name,
        "source": c.source,
        "interval_minutes": c.interval_minutes,
        "is_enabled": c.is_enabled,
        "last_run": c.last_run.isoformat() if c.last_run else None,
        "status": c.status,
        "last_status": c.last_status,
        "last_error": c.last_error,
        "last_objects": c.last_objects,
    }


def _retention_to_dict(r: RetentionPolicy) -> Dict[str, Any]:
    return {
        "id": r.id,
        "raw_days": r.raw_days,
        "normalized_days": r.normalized_days,
        "archive_policy": r.archive_policy,
    }


def _provider_to_dict(p: LLMProvider, *, redact_key: bool = True) -> Dict[str, Any]:
    key = p.api_key or ""
    return {
        "name": p.name,
        "enabled": p.enabled,
        "has_key": bool(key),
        "key_hint": ("…" + key[-4:]) if redact_key and len(key) >= 4 else (key if not redact_key else None),
        # The actual key is *only* returned when ``redact_key=False`` (i.e. by
        # the internal LLM resolver, never by the admin API).
        "api_key": (None if redact_key else (key or None)),
        "base_url": p.base_url,
        "default_model": p.default_model,
    }


def _function_to_dict(f: LLMFunctionModel) -> Dict[str, Any]:
    return {"function": f.function, "provider": f.provider, "model": f.model}


# -- seed (idempotent) ----------------------------------------------------
async def seed_defaults() -> None:
    """Insert default users, connector rows and retention policy if missing."""
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        if not (await session.execute(select(User.id).limit(1))).first():
            now = _utc_now()
            session.add_all([
                User(username="admin", password_hash=hash_password("admin123"),
                     role="admin", is_active=True, created_at=now),
                User(username="analyst", password_hash=hash_password("analyst123"),
                     role="analyst", is_active=True, created_at=now),
            ])

        for cfg in DEFAULT_CONNECTORS:
            await session.execute(
                pg_insert(ConnectorSetting)
                .values(**cfg)
                .on_conflict_do_nothing(index_elements=["name"])
            )

        await session.execute(
            pg_insert(RetentionPolicy)
            .values(id=1, raw_days=30, normalized_days=180, archive_policy="cold-storage")
            .on_conflict_do_nothing(index_elements=["id"])
        )

        # Bootstrap LLM provider rows. Pre-populate from env vars if set so
        # existing deployments transition smoothly to DB-driven config. New
        # users start with everything disabled and configure via the admin UI.
        # Model defaults come from src.llm.providers.DEFAULT_MODELS — that's
        # the single source of truth. Env vars (OPENAI_MODEL / GEMINI_MODEL /
        # OLLAMA_MODEL) let an operator override per provider on first boot.
        from ..llm.providers import DEFAULT_MODELS, DEFAULT_OLLAMA_BASE_URL

        env_openai_key = os.getenv("OPENAI_API_KEY") or ""
        env_openai_base = os.getenv("OPENAI_BASE_URL") or None
        env_google_key = os.getenv("GOOGLE_API_KEY") or ""
        env_default_provider = (os.getenv("DEFAULT_LLM_PROVIDER") or "").lower()
        provider_seeds = [
            {
                "name": "openai",
                "enabled": bool(env_openai_key),
                "api_key": env_openai_key or None,
                "base_url": env_openai_base,
                "default_model": os.getenv("OPENAI_MODEL", DEFAULT_MODELS["openai"]),
            },
            {
                "name": "gemini",
                "enabled": bool(env_google_key),
                "api_key": env_google_key or None,
                "base_url": None,
                "default_model": os.getenv("GEMINI_MODEL", DEFAULT_MODELS["gemini"]),
            },
            {
                "name": "ollama",
                "enabled": env_default_provider == "ollama",
                "api_key": None,
                "base_url": os.getenv("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL),
                "default_model": os.getenv("OLLAMA_MODEL", DEFAULT_MODELS["ollama"]),
            },
        ]
        for row in provider_seeds:
            await session.execute(
                pg_insert(LLMProvider).values(**row).on_conflict_do_nothing(index_elements=["name"])
            )

        # Default function routing: any enabled provider, else ollama. We pick
        # whichever provider has a key as the starting point; the admin can
        # split routing later for cost/speed tuning.
        default_provider = next(
            (p["name"] for p in provider_seeds if p["enabled"]),
            "ollama",
        )
        for fn in LLM_FUNCTIONS:
            await session.execute(
                pg_insert(LLMFunctionModel)
                .values(function=fn, provider=default_provider, model=None)
                .on_conflict_do_nothing(index_elements=["function"])
            )


# -- sessions / auth ------------------------------------------------------
async def purge_expired_sessions() -> None:
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        await session.execute(delete(Session).where(Session.expires_at <= _utc_now()))


async def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = _utc_now() + timedelta(hours=SESSION_TTL_HOURS)
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        session.add(Session(token=token, user_id=user_id, expires_at=expires_at))
    return token


async def get_user_by_credentials(username: str) -> Optional[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        u = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
        return _user_to_dict(u) if u else None


async def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    await purge_expired_sessions()
    sm = get_sessionmaker()
    async with sm() as session:
        row = (
            await session.execute(
                select(User).join(Session, Session.user_id == User.id).where(Session.token == token)
            )
        ).scalar_one_or_none()
        return _user_to_dict(row) if row else None


# -- users ----------------------------------------------------------------
async def list_users() -> List[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (await session.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
        return [_user_to_dict(u) for u in rows]


async def create_user(username: str, password: str, role: str) -> Dict[str, Any]:
    sm = get_sessionmaker()
    try:
        async with sm() as session, session.begin():
            session.add(User(username=username, password_hash=hash_password(password),
                             role=role, is_active=True, created_at=_utc_now()))
    except IntegrityError as exc:
        raise ValueError("username_exists") from exc
    return await get_user_by_credentials(username) or {}


async def update_user(
    user_id: int,
    role: Optional[str],
    is_active: Optional[bool],
    password: Optional[str],
) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    if role is not None:
        values["role"] = role
    if is_active is not None:
        values["is_active"] = bool(is_active)
    if password:
        values["password_hash"] = hash_password(password)

    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        if values:
            await session.execute(update(User).where(User.id == user_id).values(**values))
        u = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        return _user_to_dict(u) if u else {}


# -- connector settings ---------------------------------------------------
async def list_connectors() -> List[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (
            await session.execute(select(ConnectorSetting).order_by(ConnectorSetting.name.asc()))
        ).scalars().all()
        return [_connector_to_dict(c) for c in rows]


async def get_connector(connector_id: int) -> Optional[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        c = (
            await session.execute(select(ConnectorSetting).where(ConnectorSetting.id == connector_id))
        ).scalar_one_or_none()
        return _connector_to_dict(c) if c else None


async def get_connector_by_name(name: str) -> Optional[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        c = (
            await session.execute(select(ConnectorSetting).where(ConnectorSetting.name == name))
        ).scalar_one_or_none()
        return _connector_to_dict(c) if c else None


async def update_connector(
    connector_id: int,
    interval_minutes: Optional[int],
    is_enabled: Optional[bool],
) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    if interval_minutes is not None:
        values["interval_minutes"] = int(interval_minutes)
    if is_enabled is not None:
        values["is_enabled"] = bool(is_enabled)

    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        if values:
            await session.execute(
                update(ConnectorSetting).where(ConnectorSetting.id == connector_id).values(**values)
            )
        c = (
            await session.execute(select(ConnectorSetting).where(ConnectorSetting.id == connector_id))
        ).scalar_one_or_none()
        return _connector_to_dict(c) if c else {}


async def set_connector_status(name: str, status: str) -> None:
    """Update the transient run state (idle | queued | running)."""
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        await session.execute(
            update(ConnectorSetting).where(ConnectorSetting.name == name).values(status=status)
        )


async def record_connector_run(
    name: str,
    *,
    last_status: str,
    objects: Optional[int] = None,
    error: Optional[str] = None,
    ran_at: Optional[datetime] = None,
) -> None:
    """Persist the outcome of a connector run and reset state to idle."""
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        await session.execute(
            update(ConnectorSetting)
            .where(ConnectorSetting.name == name)
            .values(
                status="idle",
                last_run=ran_at or _utc_now(),
                last_status=last_status,
                last_objects=objects,
                last_error=error,
            )
        )


# -- retention ------------------------------------------------------------
async def get_retention_policy() -> Dict[str, Any]:
    sm = get_sessionmaker()
    async with sm() as session:
        r = (await session.execute(select(RetentionPolicy).where(RetentionPolicy.id == 1))).scalar_one_or_none()
        return _retention_to_dict(r) if r else {}


# -- LLM providers + per-function routing ---------------------------------
async def list_llm_providers(*, redact_key: bool = True) -> List[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (
            await session.execute(select(LLMProvider).order_by(LLMProvider.name.asc()))
        ).scalars().all()
        return [_provider_to_dict(p, redact_key=redact_key) for p in rows]


async def get_llm_provider(name: str, *, redact_key: bool = True) -> Optional[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        p = (
            await session.execute(select(LLMProvider).where(LLMProvider.name == name))
        ).scalar_one_or_none()
        return _provider_to_dict(p, redact_key=redact_key) if p else None


async def update_llm_provider(
    name: str,
    *,
    enabled: Optional[bool] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    default_model: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    values: Dict[str, Any] = {"updated_at": _utc_now()}
    if enabled is not None:
        values["enabled"] = bool(enabled)
    # api_key sentinel: empty string clears, None means "leave as-is".
    if api_key is not None:
        values["api_key"] = api_key or None
    if base_url is not None:
        values["base_url"] = base_url or None
    if default_model is not None:
        values["default_model"] = default_model or None

    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        await session.execute(
            update(LLMProvider).where(LLMProvider.name == name).values(**values)
        )
    return await get_llm_provider(name)


async def list_llm_functions() -> List[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (
            await session.execute(select(LLMFunctionModel).order_by(LLMFunctionModel.function.asc()))
        ).scalars().all()
        return [_function_to_dict(f) for f in rows]


async def get_llm_function(function: str) -> Optional[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session:
        f = (
            await session.execute(select(LLMFunctionModel).where(LLMFunctionModel.function == function))
        ).scalar_one_or_none()
        return _function_to_dict(f) if f else None


async def update_llm_function(
    function: str, provider: str, model: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        await session.execute(
            update(LLMFunctionModel)
            .where(LLMFunctionModel.function == function)
            .values(provider=provider, model=(model or None), updated_at=_utc_now())
        )
    return await get_llm_function(function)


async def update_retention_policy(
    raw_days: int, normalized_days: int, archive_policy: str
) -> Dict[str, Any]:
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        await session.execute(
            pg_insert(RetentionPolicy)
            .values(id=1, raw_days=raw_days, normalized_days=normalized_days,
                    archive_policy=archive_policy)
            .on_conflict_do_update(
                index_elements=["id"],
                set_={"raw_days": raw_days, "normalized_days": normalized_days,
                      "archive_policy": archive_policy},
            )
        )
    return await get_retention_policy()
