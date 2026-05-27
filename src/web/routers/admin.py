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
