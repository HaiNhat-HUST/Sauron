"""Authentication routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from ...storage import app as appstore
from ..deps import user_out
from ..schemas import LoginRequest

router = APIRouter(tags=["auth"])


@router.post("/auth/login")
async def login(payload: LoginRequest) -> Any:
    username = payload.username.strip()
    password = payload.password.strip()

    user = await appstore.get_user_by_credentials(username)
    if not user or not appstore.verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active"):
        raise HTTPException(status_code=403, detail="User disabled")

    token = await appstore.create_session(user["id"])
    return {"token": token, "user": user_out(user)}
