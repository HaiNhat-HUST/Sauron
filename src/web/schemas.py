"""Pydantic request models for the API."""

from __future__ import annotations

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


class ConnectorUpdate(BaseModel):
    interval_minutes: int | None = None
    is_enabled: bool | None = None


class RetentionUpdate(BaseModel):
    raw_days: int
    normalized_days: int
    archive_policy: str


class ChatRequest(BaseModel):
    message: str
