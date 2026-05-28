"""Per-connector run state (cursors, last-run timestamps, dedup markers).

State is persisted as one JSON file per connector under the configured state
directory, e.g. ``data/state/urlhaus.json``. This lets connectors resume from
where they left off (incremental pulls) across process restarts without a
database. The pipeline/storage layer can later swap this for Redis/Postgres
by implementing the same tiny interface.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class StateStore:
    """File-backed key/value state scoped to a single connector."""

    def __init__(self, connector_name: str, state_dir: str):
        self._dir = Path(state_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / f"{connector_name}.json"
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read state %s (%s); starting fresh", self._path, exc)
            return {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def update(self, **kwargs: Any) -> None:
        self._data.update(kwargs)

    def flush(self) -> None:
        """Atomically write current state to disk."""
        fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, default=str)
            os.replace(tmp, self._path)
        except OSError as exc:
            logger.error("Failed to persist state %s: %s", self._path, exc)
            if os.path.exists(tmp):
                os.remove(tmp)
