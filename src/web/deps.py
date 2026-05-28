"""Shared FastAPI dependencies — bearer-token auth backed by the Postgres app store."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import Depends, Header, HTTPException

from ..storage import app as appstore


def _parse_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    token = _parse_bearer(authorization)
    user = await appstore.get_user_by_token(token) if token else None
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


async def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def user_out(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "is_active": bool(user["is_active"]),
        "created_at": user["created_at"],
    }
