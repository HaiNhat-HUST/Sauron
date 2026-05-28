"""Dashboard data route (any authenticated user)."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends

from ...storage import dashboard as dashboard_api
from ..deps import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview")
async def overview(_: Dict[str, Any] = Depends(get_current_user)) -> Any:
    return await dashboard_api.get_overview()
