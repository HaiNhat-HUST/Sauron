from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

DB_PATH = os.getenv("APP_DB_PATH", "data/app.db")
PASSWORD_SALT = os.getenv("APP_PASSWORD_SALT", "ti-demo-salt")
SESSION_TTL_HOURS = int(os.getenv("APP_SESSION_TTL_HOURS", "24"))

DEFAULT_CONNECTORS = [
    {"name": "threatfox", "source": "abuse.ch", "interval_minutes": 30, "is_enabled": 1},
    {"name": "malwarebazaar", "source": "abuse.ch", "interval_minutes": 60, "is_enabled": 1},
    {"name": "urlhaus", "source": "abuse.ch", "interval_minutes": 45, "is_enabled": 1},
    {"name": "feodo", "source": "abuse.ch", "interval_minutes": 90, "is_enabled": 1},
    {"name": "nvd", "source": "nist.gov", "interval_minutes": 360, "is_enabled": 1},
    {"name": "mitre_attack", "source": "mitre.org", "interval_minutes": 1440, "is_enabled": 1},
    {"name": "cisa_kev", "source": "cisa.gov", "interval_minutes": 720, "is_enabled": 1},
    {"name": "otx", "source": "alienvault.com", "interval_minutes": 120, "is_enabled": 1},
    {"name": "reddit", "source": "reddit.com", "interval_minutes": 120, "is_enabled": 1},
    {"name": "rss", "source": "security blogs", "interval_minutes": 60, "is_enabled": 1},
    {"name": "twitter", "source": "x.com", "interval_minutes": 180, "is_enabled": 0},
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    payload = (PASSWORD_SALT + password).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


# init sqlite3 database that store users information


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS connector_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL,
                interval_minutes INTEGER NOT NULL,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                last_run TEXT
            );

            CREATE TABLE IF NOT EXISTS retention_policy (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                raw_days INTEGER NOT NULL,
                normalized_days INTEGER NOT NULL,
                archive_policy TEXT NOT NULL
            );
            """
        )
        _migrate_connector_columns(conn)
        _seed_defaults(conn)


# Runtime/status columns added to connector_settings after the initial release.
# SQLite has no "ADD COLUMN IF NOT EXISTS", so we diff against PRAGMA table_info.
_CONNECTOR_RUNTIME_COLUMNS = (
    ("status", "TEXT NOT NULL DEFAULT 'idle'"),   # idle | queued | running
    ("last_status", "TEXT"),                       # ok | error | needs-key | skipped
    ("last_error", "TEXT"),
    ("last_objects", "INTEGER"),
)


def _migrate_connector_columns(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(connector_settings)")}
    for name, ddl in _CONNECTOR_RUNTIME_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE connector_settings ADD COLUMN {name} {ddl}")


def _seed_defaults(conn: sqlite3.Connection) -> None:
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        now = _utc_now().isoformat()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, 1, ?)",
            ("admin", hash_password("admin123"), "admin", now),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, 1, ?)",
            ("analyst", hash_password("analyst123"), "analyst", now),
        )

    connector_count = conn.execute("SELECT COUNT(*) FROM connector_settings").fetchone()[0]
    if connector_count == 0:
        for connector in DEFAULT_CONNECTORS:
            conn.execute(
                """
                INSERT INTO connector_settings (name, source, interval_minutes, is_enabled, last_run)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    connector["name"],
                    connector["source"],
                    connector["interval_minutes"],
                    connector["is_enabled"],
                    None,
                ),
            )

    conn.execute(
        """
        INSERT OR IGNORE INTO retention_policy (id, raw_days, normalized_days, archive_policy)
        VALUES (1, 30, 180, 'cold-storage')
        """
    )

    conn.commit()


def purge_expired_sessions() -> None:
    now = _utc_now().isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.commit()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (_utc_now() + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires_at),
        )
        conn.commit()
    return token


def get_user_by_credentials(username: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return _row_to_dict(row) if row else None


def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    purge_expired_sessions()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT users.*
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()
        if not row:
            return None
        return _row_to_dict(row)


def list_users() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        return [_row_to_dict(row) for row in rows]


def create_user(username: str, password: str, role: str) -> Dict[str, Any]:
    now = _utc_now().isoformat()
    password_hash = hash_password(password)
    with get_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (username, password_hash, role, now),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("username_exists") from exc
    return get_user_by_credentials(username) or {}


def update_user(user_id: int, role: Optional[str], is_active: Optional[bool], password: Optional[str]) -> Dict[str, Any]:
    fields: List[str] = []
    values: List[Any] = []

    if role is not None:
        fields.append("role = ?")
        values.append(role)
    if is_active is not None:
        fields.append("is_active = ?")
        values.append(1 if is_active else 0)
    if password:
        fields.append("password_hash = ?")
        values.append(hash_password(password))

    if fields:
        values.append(user_id)
        with get_conn() as conn:
            conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
            conn.commit()

    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_dict(row) if row else {}


def list_connectors() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM connector_settings ORDER BY name ASC").fetchall()
        return [_row_to_dict(row) for row in rows]


def update_connector(connector_id: int, interval_minutes: Optional[int], is_enabled: Optional[bool]) -> Dict[str, Any]:
    fields: List[str] = []
    values: List[Any] = []

    if interval_minutes is not None:
        fields.append("interval_minutes = ?")
        values.append(interval_minutes)
    if is_enabled is not None:
        fields.append("is_enabled = ?")
        values.append(1 if is_enabled else 0)

    if fields:
        values.append(connector_id)
        with get_conn() as conn:
            conn.execute(f"UPDATE connector_settings SET {', '.join(fields)} WHERE id = ?", values)
            conn.commit()

    with get_conn() as conn:
        row = conn.execute("SELECT * FROM connector_settings WHERE id = ?", (connector_id,)).fetchone()
        return _row_to_dict(row) if row else {}


def get_connector(connector_id: int) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM connector_settings WHERE id = ?", (connector_id,)).fetchone()
        return _row_to_dict(row) if row else None


def get_connector_by_name(name: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM connector_settings WHERE name = ?", (name,)).fetchone()
        return _row_to_dict(row) if row else None


def set_connector_status(name: str, status: str) -> None:
    """Update the transient run state (idle | queued | running)."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE connector_settings SET status = ? WHERE name = ?", (status, name)
        )
        conn.commit()


def record_connector_run(
    name: str,
    *,
    last_status: str,
    objects: Optional[int] = None,
    error: Optional[str] = None,
    ran_at: Optional[str] = None,
) -> None:
    """Persist the outcome of a connector run and reset state to idle."""
    timestamp = ran_at or _utc_now().isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE connector_settings
            SET status = 'idle', last_run = ?, last_status = ?, last_objects = ?, last_error = ?
            WHERE name = ?
            """,
            (timestamp, last_status, objects, error, name),
        )
        conn.commit()


def get_retention_policy() -> Dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM retention_policy WHERE id = 1").fetchone()
        return _row_to_dict(row) if row else {}


def update_retention_policy(raw_days: int, normalized_days: int, archive_policy: str) -> Dict[str, Any]:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO retention_policy (id, raw_days, normalized_days, archive_policy)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                raw_days = excluded.raw_days,
                normalized_days = excluded.normalized_days,
                archive_policy = excluded.archive_policy
            """,
            (raw_days, normalized_days, archive_policy),
        )
        conn.commit()
    return get_retention_policy()
