"""ai-threat-intel connector framework.

Async, in-process connectors driven by per-connector coroutines in
:mod:`src.collectors.scheduler`. Schedule/enable state lives in the Postgres
app store (:mod:`src.storage.app`); everything else (secrets, source-specific
tunables) comes from env-driven config models in :mod:`src.collectors.config`.
"""

from .base import BaseConnector
from .registry import available, build_connector

__all__ = ["BaseConnector", "available", "build_connector"]
