"""SQLAlchemy models — TI schema + app/admin schema, single Postgres DB.

**TI schema** (the intelligence data the system collects):
* ``articles``      — unstructured documents (RSS/Reddit/Twitter posts, OTX pulses).
* ``iocs``          — indicators of compromise (globally unique by type+value).
* ``cves``          — vulnerabilities.
* ``article_cves``  — article ↔ CVE (many-to-many).
* ``tags``          — taxonomy (malware / attack_technique / threat_actor / campaign).
* ``article_tags``  — article ↔ tag (many-to-many) with a confidence score.

**App schema** (web/admin/scheduler runtime state):
* ``users``               — accounts for the SPA.
* ``sessions``            — bearer-token sessions.
* ``connector_settings``  — admin-controlled enable/interval + last-run status.
* ``retention_policy``    — singleton row driving data lifecycle (raw / archived).

``iocs.tags`` and ``cves.products`` use PostgreSQL ARRAY; ``iocs``/``cves``
carry ``source_type`` for provenance and dashboard aggregation.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _ts(**kw) -> Mapped[datetime]:  # helper for tz-aware timestamp columns
    return mapped_column(TIMESTAMP(timezone=True), **kw)


class Article(Base):
    __tablename__ = "articles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str | None] = mapped_column(Text, unique=True)
    content: Mapped[str | None] = mapped_column(Text)
    published_date: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    source_type: Mapped[str | None] = mapped_column(String(50))   # connector name
    source_name: Mapped[str | None] = mapped_column(String(200))  # 'The Hacker News'
    summary_llm: Mapped[str | None] = mapped_column(Text)          # filled later by LLM
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())

    iocs: Mapped[list["IOC"]] = relationship(back_populates="article")

    __table_args__ = (
        Index("idx_articles_date", "published_date"),
        Index("idx_articles_source", "source_type"),
    )


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    article_id: Mapped[int | None] = mapped_column(
        ForeignKey("articles.id", ondelete="SET NULL")
    )
    source_type: Mapped[str | None] = mapped_column(String(50))
    first_seen: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    context: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    score: Mapped[float] = mapped_column(Float, default=0.0)
    enrichment: Mapped[dict | None] = mapped_column(JSONB)

    article: Mapped["Article | None"] = relationship(back_populates="iocs")

    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_iocs_type_value"),
        CheckConstraint("ioc_type IN ('ip','domain','url','email','hash')", name="ck_iocs_type"),
        Index("idx_iocs_type", "ioc_type"),
        Index("idx_iocs_value", "value"),
        Index("idx_iocs_last_seen", "last_seen"),
    )


class CVE(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(20))     # critical/high/...
    published_date: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    last_modified: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    products: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    source_type: Mapped[str | None] = mapped_column(String(50))
    known_exploited: Mapped[bool] = mapped_column(default=False)  # from CISA KEV

    __table_args__ = (Index("idx_cves_published", "published_date"),)


class ArticleCVE(Base):
    __tablename__ = "article_cves"

    article_id: Mapped[int] = mapped_column(
        ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id", ondelete="CASCADE"), primary_key=True
    )


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)

    __table_args__ = (Index("idx_tags_type", "type"),)


class ArticleTag(Base):
    __tablename__ = "article_tags"

    article_id: Mapped[int] = mapped_column(
        ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[int] = mapped_column(
        ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.5)


# --- App / admin schema --------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


class Session(Base):
    __tablename__ = "sessions"

    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)


class ConnectorSetting(Base):
    __tablename__ = "connector_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # Transient run state set by the scheduler — idle | queued | running.
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="idle")
    last_status: Mapped[str | None] = mapped_column(String(20))   # ok | error | needs-key
    last_error: Mapped[str | None] = mapped_column(Text)
    last_objects: Mapped[int | None] = mapped_column(Integer)


class RetentionPolicy(Base):
    __tablename__ = "retention_policy"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # singleton: id = 1
    raw_days: Mapped[int] = mapped_column(Integer, nullable=False)
    normalized_days: Mapped[int] = mapped_column(Integer, nullable=False)
    archive_policy: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (CheckConstraint("id = 1", name="ck_retention_singleton"),)


class LLMProvider(Base):
    """One row per supported LLM provider — admin-controlled."""

    __tablename__ = "llm_providers"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)   # openai | gemini | ollama
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    api_key: Mapped[str | None] = mapped_column(Text)                # plaintext for v1 (single-tenant local DB)
    base_url: Mapped[str | None] = mapped_column(Text)               # Ollama or custom OpenAI-compatible host
    default_model: Mapped[str | None] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


class LLMFunctionModel(Base):
    """Per-function provider/model routing (e.g. cheap local for enrichment,
    paid frontier model for the chat agent)."""

    __tablename__ = "llm_function_models"

    function: Mapped[str] = mapped_column(String(32), primary_key=True)  # agent_chat | report | enrich_article
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str | None] = mapped_column(String(128))               # NULL → use the provider's default_model
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )


class EnrichmentJob(Base):
    """One unit of work for the enrichment workers.

    The unique (target_type, target_id, enricher) tuple makes the scanner
    idempotent: re-running ``INSERT … ON CONFLICT DO NOTHING`` against the
    table cannot create duplicate jobs. Workers claim ``status='pending'``
    rows whose ``next_attempt_at`` has elapsed via ``SELECT … FOR UPDATE
    SKIP LOCKED``.
    """

    __tablename__ = "enrichment_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)   # article | ioc | cve
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)     # str so IPs/CVE ids fit
    enricher: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict | None] = mapped_column(JSONB)
    next_attempt_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("target_type", "target_id", "enricher", name="uq_enrichment_target"),
        Index("idx_enrichment_pending", "status", "next_attempt_at"),
    )
