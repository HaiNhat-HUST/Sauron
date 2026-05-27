"""Admin routes: users, connectors (config + run-now), retention. Admin-only."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from ...api import storage
from ...collectors.scheduler import get_scheduler
from ..deps import require_admin, user_out
from ..schemas import ConnectorUpdate, RetentionUpdate, UserCreate, UserUpdate

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


# -- users -----------------------------------------------------------------
@router.get("/users")
async def list_users() -> Any:
    return [user_out(u) for u in storage.list_users()]


@router.post("/users")
async def create_user(payload: UserCreate) -> Any:
    if not payload.username.strip() or not payload.password.strip():
        raise HTTPException(status_code=400, detail="Invalid payload")
    try:
        user = storage.create_user(payload.username.strip(), payload.password.strip(),
                                   payload.role.strip() or "analyst")
    except ValueError:
        raise HTTPException(status_code=409, detail="Username exists")
    return user_out(user)


@router.put("/users/{user_id}")
async def update_user(user_id: int, payload: UserUpdate) -> Any:
    user = storage.update_user(user_id, payload.role, payload.is_active, payload.password)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user_out(user)


# -- connectors ------------------------------------------------------------
@router.get("/connectors")
async def list_connectors() -> Any:
    return storage.list_connectors()


@router.put("/connectors/{connector_id}")
async def update_connector(connector_id: int, payload: ConnectorUpdate) -> Any:
    connector = storage.update_connector(connector_id, payload.interval_minutes, payload.is_enabled)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector


@router.post("/connectors/{connector_id}/run", status_code=202)
async def run_connector(connector_id: int) -> Any:
    """Trigger a connector to run immediately (does not wait for its cycle)."""
    connector = storage.get_connector(connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    if not get_scheduler().trigger(connector["name"]):
        raise HTTPException(status_code=400, detail="Connector is not runnable")
    storage.set_connector_status(connector["name"], "queued")
    return {"detail": "Run triggered", "name": connector["name"]}


# -- retention -------------------------------------------------------------
@router.get("/retention")
async def get_retention() -> Any:
    return storage.get_retention_policy()


@router.put("/retention")
async def update_retention(payload: RetentionUpdate) -> Any:
    if payload.raw_days <= 0 or payload.normalized_days <= 0 or not payload.archive_policy.strip():
        raise HTTPException(status_code=400, detail="Invalid retention payload")
    return storage.update_retention_policy(
        payload.raw_days, payload.normalized_days, payload.archive_policy.strip()
    )
