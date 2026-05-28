"""Connector registry — the single place that knows every connector.

Maps a connector ``name`` to its (connector class, config class) pair. The
scheduler instantiates a connector on demand via :func:`build_connector` each
time it's due to run. Add a new connector by importing it and adding one line
to ``_REGISTRY``.
"""

from __future__ import annotations

from .base import BaseConnector
from .config import (
    CisaKevConfig,
    ConnectorConfig,
    FeodoConfig,
    GlobalConfig,
    MalwareBazaarConfig,
    MitreAttackConfig,
    NVDConfig,
    OTXConfig,
    RedditConfig,
    RSSConfig,
    ThreatFoxConfig,
    TwitterConfig,
    URLhausConfig,
)
from .handler.output import OutputHandler
from .sources.abusech_feodo import FeodoConnector
from .sources.abusech_malwarebazaar import MalwareBazaarConnector
from .sources.abusech_threatfox import ThreatFoxConnector
from .sources.abusech_urlhaus import URLhausConnector
from .sources.cisa_kev import CisaKevConnector
from .sources.mitre_attack import MitreAttackConnector
from .sources.nvd import NVDConnector
from .sources.otx import OTXConnector
from .sources.reddit import RedditConnector
from .sources.rss import RSSConnector
from .sources.twitter import TwitterConnector

# name -> (connector class, config class)
_REGISTRY: dict[str, tuple[type[BaseConnector], type[ConnectorConfig]]] = {
    URLhausConnector.name: (URLhausConnector, URLhausConfig),
    MalwareBazaarConnector.name: (MalwareBazaarConnector, MalwareBazaarConfig),
    ThreatFoxConnector.name: (ThreatFoxConnector, ThreatFoxConfig),
    FeodoConnector.name: (FeodoConnector, FeodoConfig),
    NVDConnector.name: (NVDConnector, NVDConfig),
    MitreAttackConnector.name: (MitreAttackConnector, MitreAttackConfig),
    CisaKevConnector.name: (CisaKevConnector, CisaKevConfig),
    OTXConnector.name: (OTXConnector, OTXConfig),
    RedditConnector.name: (RedditConnector, RedditConfig),
    RSSConnector.name: (RSSConnector, RSSConfig),
    TwitterConnector.name: (TwitterConnector, TwitterConfig),
}


def available() -> list[str]:
    return list(_REGISTRY)


def build_connector(
    name: str, global_config: GlobalConfig, output: OutputHandler
) -> BaseConnector:
    if name not in _REGISTRY:
        raise KeyError(f"unknown connector '{name}'. Available: {', '.join(available())}")
    connector_cls, config_cls = _REGISTRY[name]
    return connector_cls(config_cls(), global_config, output)
