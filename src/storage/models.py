"""SQLAlchemy models — simple relational TI schema (no STIX).

Tables:
* ``articles``      — unstructured documents (RSS/Reddit/Twitter posts, OTX pulses).
* ``iocs``          — indicators of compromise (globally unique by type+value).
* ``cves``          — vulnerabilities.
* ``article_cves``  — article ↔ CVE (many-to-many).
* ``tags``          — taxonomy (malware / attack_technique / threat_actor / campaign).
* ``article_tags``  — article ↔ tag (many-to-many) with a confidence score.

Improvements over the base spec: ``iocs.tags`` and ``cves.products`` use
PostgreSQL ARRAY; ``iocs``/``cves`` carry ``source_type`` for provenance and
dashboard aggregation.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    ARRAY,
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
