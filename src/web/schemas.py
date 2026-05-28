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
    message: str = ""
    session_id: str | None = None   # client-supplied; keeps multi-turn history


class ReportRequest(BaseModel):
    topic: str


class LLMProviderUpdate(BaseModel):
    enabled: bool | None = None
    api_key: str | None = None       # None = leave as-is; "" = clear
    base_url: str | None = None
    default_model: str | None = None


class LLMFunctionUpdate(BaseModel):
    provider: str
    model: str | None = None
