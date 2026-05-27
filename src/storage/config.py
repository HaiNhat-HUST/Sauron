"""Storage layer configuration (PostgreSQL).

Read from environment / ``.env`` via pydantic-settings. The store is a plain
relational schema (articles / iocs / cves / tags) — no STIX, no vector columns.
"""

from __future__ import annotations

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False)

class StorageConfig(BaseSettings):
    model_config = _BASE

    database_url: str = Field("", validation_alias="DATABASE_URL")
    postgres_host: str = Field("localhost", validation_alias="POSTGRES_HOST")
    postgres_port: int = Field(5432, validation_alias="POSTGRES_PORT")
    postgres_db: str = Field("threatintel", validation_alias="POSTGRES_DB")
    postgres_user: str = Field("threatintel", validation_alias="POSTGRES_USER")
    postgres_password: str = Field("threatintel", validation_alias="POSTGRES_PASSWORD")
    db_echo: bool = Field(False, validation_alias="DB_ECHO")

    # --- vector database (ChromaDB) ---
    vector_enabled: bool = Field(True, validation_alias="VECTOR_ENABLED")
    chroma_host: str = Field("", validation_alias="CHROMA_HOST")          # set → HTTP client
    chroma_port: int = Field(8000, validation_alias="CHROMA_PORT")
    chroma_path: str = Field("./data/chroma", validation_alias="CHROMA_PATH")  # embedded client
    chroma_collection: str = Field("articles", validation_alias="CHROMA_COLLECTION")

    # Embedding backend for Chroma: default (local ONNX MiniLM) | openai
    embedding_provider: str = Field("default", validation_alias="EMBEDDING_PROVIDER")
    embedding_model: str = Field("text-embedding-3-small", validation_alias="EMBEDDING_MODEL")
    openai_api_key: str = Field("", validation_alias="OPENAI_API_KEY")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sqlalchemy_url(self) -> str:
        """Async SQLAlchemy URL, derived from discrete parts if not given."""
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


storage_config = StorageConfig()