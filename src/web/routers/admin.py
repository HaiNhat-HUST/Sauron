"""Admin routes: users, connectors (config + run-now), retention. Admin-only."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ...collectors.scheduler import get_scheduler
from ...enrichment import jobs as enrichment_jobs
from ...enrichment.registry import available as enrichment_available
from ...llm import router as llm_router
from ...storage import app as appstore
from ..deps import require_admin, user_out
from ..schemas import (
    ConnectorUpdate,
    LLMFunctionUpdate,
    LLMProviderUpdate,
    RetentionUpdate,
    UserCreate,
    UserUpdate,
)

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


# -- users -----------------------------------------------------------------
@router.get("/users")
async def list_users() -> Any:
    return [user_out(u) for u in await appstore.list_users()]


@router.post("/users")
async def create_user(payload: UserCreate) -> Any:
    if not payload.username.strip() or not payload.password.strip():
        raise HTTPException(status_code=400, detail="Invalid payload")
    try:
        user = await appstore.create_user(
            payload.username.strip(),
            payload.password.strip(),
            payload.role.strip() or "analyst",
        )
    except ValueError:
        raise HTTPException(status_code=409, detail="Username exists")
    return user_out(user)


@router.put("/users/{user_id}")
async def update_user(user_id: int, payload: UserUpdate) -> Any:
    user = await appstore.update_user(user_id, payload.role, payload.is_active, payload.password)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user_out(user)


# -- connectors ------------------------------------------------------------
@router.get("/connectors")
async def list_connectors() -> Any:
    return await appstore.list_connectors()


@router.put("/connectors/{connector_id}")
async def update_connector(connector_id: int, payload: ConnectorUpdate) -> Any:
    connector = await appstore.update_connector(connector_id, payload.interval_minutes, payload.is_enabled)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector


@router.post("/connectors/{connector_id}/run", status_code=202)
async def run_connector(connector_id: int) -> Any:
    """Trigger a connector to run immediately (does not wait for its cycle)."""
    connector = await appstore.get_connector(connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    if not get_scheduler().trigger(connector["name"]):
        raise HTTPException(status_code=400, detail="Connector is not runnable")
    await appstore.set_connector_status(connector["name"], "queued")
    return {"detail": "Run triggered", "name": connector["name"]}


# -- enrichment ------------------------------------------------------------
@router.get("/enrichment")
async def enrichment_status() -> Any:
    """Per-enricher job counts grouped by status (pending/running/done/error)."""
    stats = await enrichment_jobs.stats()
    return {
        "enrichers": enrichment_available(),
        "stats": stats,
    }


# -- LLM configuration -----------------------------------------------------
_PROVIDER_NAMES = {"openai", "gemini", "ollama"}


@router.get("/llm")
async def llm_config() -> Any:
    """Return everything the admin UI needs to render the LLM page."""
    providers = await appstore.list_llm_providers()
    functions = await appstore.list_llm_functions()
    return {
        "providers": providers,
        "functions": functions,
        "function_meta": llm_router.FUNCTIONS,
        "available_models": llm_router.AVAILABLE_MODELS,
        "presets": llm_router.PRESETS,
    }


@router.put("/llm/providers/{name}")
async def update_llm_provider(name: str, payload: LLMProviderUpdate) -> Any:
    if name not in _PROVIDER_NAMES:
        raise HTTPException(status_code=404, detail=f"Unknown provider '{name}'")
    updated = await appstore.update_llm_provider(
        name,
        enabled=payload.enabled,
        api_key=payload.api_key,
        base_url=payload.base_url,
        default_model=payload.default_model,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Provider not found")
    return updated


@router.put("/llm/functions/{function}")
async def update_llm_function(function: str, payload: LLMFunctionUpdate) -> Any:
    if function not in {f["name"] for f in llm_router.FUNCTIONS}:
        raise HTTPException(status_code=404, detail=f"Unknown function '{function}'")
    if payload.provider not in _PROVIDER_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown provider '{payload.provider}'")
    updated = await appstore.update_llm_function(function, payload.provider, payload.model)
    if not updated:
        raise HTTPException(status_code=404, detail="Routing not found")
    return updated


@router.post("/llm/providers/{name}/test")
async def test_llm_provider(name: str) -> Any:
    """Round-trip a tiny prompt to verify provider + model + credentials."""
    if name not in _PROVIDER_NAMES:
        raise HTTPException(status_code=404, detail=f"Unknown provider '{name}'")
    return await llm_router.test_provider(name)


# -- retention -------------------------------------------------------------
@router.get("/retention")
async def get_retention() -> Any:
    return await appstore.get_retention_policy()


@router.put("/retention")
async def update_retention(payload: RetentionUpdate) -> Any:
    if payload.raw_days <= 0 or payload.normalized_days <= 0 or not payload.archive_policy.strip():
        raise HTTPException(status_code=400, detail="Invalid retention payload")
    return await appstore.update_retention_policy(
        payload.raw_days, payload.normalized_days, payload.archive_policy.strip()
    )
