"""Environment-driven configuration for the connector framework.

Per-connector secrets and tunables (API keys, subreddits, feeds, …) live here,
read from environment variables via ``pydantic-settings``. The scheduling knobs
that the admin UI controls — ``is_enabled`` and ``interval_minutes`` — are NOT
defined here; they live in the Postgres app store (``connector_settings``).

All variables are documented in ``.env.example``.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False)


class GlobalConfig(BaseSettings):
    """Process-wide defaults shared by every connector."""

    model_config = _BASE
    output_dir: str = Field("./data/output", validation_alias="CONNECTOR_OUTPUT_DIR")
    state_dir: str = Field("./data/state", validation_alias="CONNECTOR_STATE_DIR")
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")


class ConnectorConfig(BaseSettings):
    """Base for every per-connector settings model."""

    model_config = _BASE


# --- abuse.ch suite (shared ABUSECH_AUTH_KEY) ----------------------------
class URLhausConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="URLHAUS_")
    auth_key: str = Field("", validation_alias="ABUSECH_AUTH_KEY")


class MalwareBazaarConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="MALWAREBAZAAR_")
    auth_key: str = Field("", validation_alias="ABUSECH_AUTH_KEY")


class ThreatFoxConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="THREATFOX_")
    days: int = 1
    auth_key: str = Field("", validation_alias="ABUSECH_AUTH_KEY")


class FeodoConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="FEODO_")
    auth_key: str = Field("", validation_alias="ABUSECH_AUTH_KEY")


# --- vulnerability / TTP feeds -------------------------------------------
class NVDConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="NVD_")
    api_key: str = ""
    initial_lookback_hours: int = 24


class MitreAttackConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="MITRE_ATTACK_")
    domain: str = "enterprise-attack"


class CisaKevConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="CISA_KEV_")


class OTXConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="OTX_")
    api_key: str = ""


# --- text sources --------------------------------------------------------
class RedditConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="REDDIT_")
    client_id: str = ""
    client_secret: str = ""
    user_agent: str = "ai-threat-intel/0.1"
    subreddits: str = "netsec,Malware,blueteamsec,cybersecurity"

    @property
    def subreddit_list(self) -> list[str]:
        return [s.strip() for s in self.subreddits.split(",") if s.strip()]


class RSSConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="RSS_")
    feeds: str = (
        "https://www.bleepingcomputer.com/feed/,"
        "https://krebsonsecurity.com/feed/,"
        "https://thehackernews.com/feeds/posts/default,"
        "https://feeds.feedburner.com/eset/blog"
    )

    @property
    def feed_list(self) -> list[str]:
        return [f.strip() for f in self.feeds.split(",") if f.strip()]


class TwitterConfig(ConnectorConfig):
    model_config = SettingsConfigDict(**_BASE, env_prefix="TWITTER_")
    bearer_token: str = ""
    query: str = "(malware OR ransomware OR CVE) -is:retweet lang:en"
