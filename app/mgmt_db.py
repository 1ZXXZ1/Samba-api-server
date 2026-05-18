"""
PostgreSQL-backed Management DB for API users, keys, roles, audit log, and AI chat.

v1.8.5-2: Replaced JSON-file-based storage with PostgreSQL.
Uses psycopg2 with ThreadedConnectionPool for thread-safe access.
All data survives server restarts.

Tables:
    mgmt_users       — API user accounts with bcrypt-hashed passwords
    mgmt_api_keys    — Long-lived bearer tokens tied to users
    mgmt_roles       — Named roles with assigned permission sets
    mgmt_audit_log   — Tamper-append log of every authenticated action
    ai_chat_sessions — AI chat session metadata
    ai_chat_messages — Individual chat messages with cost/usage tracking
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Module-level DB connection pool ──────────────────────────────────────

_pool: Optional[Any] = None  # psycopg2.pool.ThreadedConnectionPool
_pool_lock = threading.Lock()


def init_db(
    host: str = "localhost",
    port: int = 5432,
    dbname: str = "samba_api",
    user: str = "samba_api",
    password: str = "",
    dsn: Optional[str] = None,
    min_conn: int = 2,
    max_conn: int = 10,
) -> None:
    """Initialize the PostgreSQL connection pool and create tables if needed."""
    global _pool

    try:
        import psycopg2
        from psycopg2.pool import ThreadedConnectionPool
    except ImportError:
        raise ImportError(
            "psycopg2 is required for PostgreSQL management DB. "
            "Install with: apt-get install python3-psycopg2 (ALT Linux) "
            "or pip install psycopg2-binary"
        )

    _connect_kwargs: Dict[str, Any] = {}
    if dsn:
        _connect_kwargs = {"dsn": dsn}
    else:
        _connect_kwargs = {
            "host": host,
            "port": port,
            "dbname": dbname,
            "user": user,
            "password": password,
        }

    try:
        _pool = ThreadedConnectionPool(min_conn, max_conn, **_connect_kwargs)
        logger.info("[MGMT DB] PostgreSQL connection pool created (min=%d, max=%d)", min_conn, max_conn)
    except Exception as exc:
        logger.error("[MGMT DB] Failed to create PostgreSQL pool: %s", exc)
        raise

    # Create tables
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(_SCHEMA)
        conn.commit()
        logger.info("[MGMT DB] Tables verified/created in PostgreSQL")
    except Exception as exc:
        conn.rollback()
        logger.error("[MGMT DB] Failed to create tables: %s", exc)
        raise
    finally:
        _return_conn(conn)

    # Seed default admin user and roles if tables are empty
    _seed_defaults()


def _get_conn():
    """Get a connection from the pool."""
    if _pool is None:
        raise RuntimeError(
            "mgmt_db not initialized — call init_db() first. "
            "Set SAMBA_SHELL_PROJET_PG_* environment variables."
        )
    return _pool.getconn()


def _return_conn(conn) -> None:
    """Return a connection to the pool."""
    if _pool is not None and conn is not None:
        try:
            _pool.putconn(conn)
        except Exception:
            pass


def close_db() -> None:
    """Close all connections in the pool."""
    global _pool
    if _pool is not None:
        try:
            _pool.closeall()
        except Exception:
            pass
        _pool = None
        logger.info("[MGMT DB] PostgreSQL connection pool closed")


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ── Schema (PostgreSQL) ─────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mgmt_users (
    id              SERIAL PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    full_name       TEXT DEFAULT '',
    email           TEXT DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'operator',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TEXT,
    updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS mgmt_api_keys (
    id              SERIAL PRIMARY KEY,
    key_hash        TEXT NOT NULL,
    key_prefix      TEXT NOT NULL,
    user_id         INTEGER NOT NULL REFERENCES mgmt_users(id) ON DELETE CASCADE,
    name            TEXT DEFAULT '',
    description     TEXT DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'operator',
    is_active       BOOLEAN DEFAULT TRUE,
    expires_at      TEXT,
    created_at      TEXT,
    last_used_at    TEXT
);

CREATE TABLE IF NOT EXISTS mgmt_roles (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT DEFAULT '',
    permissions     JSONB DEFAULT '[]',
    is_builtin      BOOLEAN DEFAULT FALSE,
    created_at      TEXT,
    updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS mgmt_audit_log (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER,
    api_key_id      INTEGER,
    action          TEXT NOT NULL,
    endpoint        TEXT DEFAULT '',
    ip_address      TEXT DEFAULT '',
    timestamp       TEXT,
    details         TEXT
);

CREATE TABLE IF NOT EXISTS ai_chat_sessions (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL DEFAULT 'New Chat',
    owner_id        TEXT NOT NULL,
    owner_username  TEXT DEFAULT '',
    model           TEXT DEFAULT '',
    system_prompt   TEXT DEFAULT '',
    context         JSONB DEFAULT '{}',
    is_archived     BOOLEAN DEFAULT FALSE,
    created_at      TEXT,
    updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS ai_chat_messages (
    id              TEXT PRIMARY KEY,
    chat_id         TEXT NOT NULL REFERENCES ai_chat_sessions(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         TEXT DEFAULT '',
    model_used      TEXT,
    tokens_used     INTEGER,
    cost_rub        REAL,
    usage_info      JSONB,
    tool_steps      JSONB,
    timestamp       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mgmt_users_username ON mgmt_users(username);
CREATE INDEX IF NOT EXISTS idx_mgmt_api_keys_prefix ON mgmt_api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_mgmt_api_keys_user ON mgmt_api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_mgmt_audit_timestamp ON mgmt_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_ai_chat_sessions_owner ON ai_chat_sessions(owner_id);
CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_chat ON ai_chat_messages(chat_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_timestamp ON ai_chat_messages(timestamp);
"""


def _seed_defaults() -> None:
    """Seed default admin user and built-in roles if tables are empty."""
    import bcrypt

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Check if admin user exists
            cur.execute("SELECT COUNT(*) FROM mgmt_users WHERE username = 'admin'")
            if cur.fetchone()[0] == 0:
                hashed = bcrypt.hashpw("admin".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                now = _now_iso()
                cur.execute(
                    "INSERT INTO mgmt_users (username, password_hash, full_name, role, is_active, created_at, updated_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    ("admin", hashed, "Default Administrator", "admin", True, now, now),
                )
                logger.info("[MGMT DB] Created default admin user (password: admin)")

            # Seed built-in roles
            try:
                from app.permissions import DEFAULT_ROLE_PERMISSIONS
                default_perms = DEFAULT_ROLE_PERMISSIONS
            except ImportError:
                default_perms = {
                    "admin": set(),
                    "operator": set(),
                    "auditor": set(),
                }

            for rname, perms in default_perms.items():
                cur.execute("SELECT COUNT(*) FROM mgmt_roles WHERE name = %s", (rname,))
                if cur.fetchone()[0] == 0:
                    now = _now_iso()
                    cur.execute(
                        "INSERT INTO mgmt_roles (name, description, permissions, is_builtin, created_at, updated_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (rname, f"Built-in {rname} role", json.dumps(sorted(perms)), True, now, now),
                    )
                else:
                    # Update built-in role permissions
                    cur.execute(
                        "UPDATE mgmt_roles SET permissions = %s, updated_at = %s WHERE name = %s AND is_builtin = TRUE",
                        (json.dumps(sorted(perms)), _now_iso(), rname),
                    )

        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[MGMT DB] Seed defaults failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  User Management
# ═══════════════════════════════════════════════════════════════════════

def create_user(username: str, password: str, role: str = "operator",
                full_name: str = "", email: str = "") -> Dict[str, Any]:
    """Create a new API user. Returns user record without password_hash."""
    import bcrypt

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now = _now_iso()

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Check username uniqueness
            cur.execute("SELECT id FROM mgmt_users WHERE username = %s", (username,))
            if cur.fetchone():
                raise ValueError(f"Username '{username}' already exists")

            # Validate role
            cur.execute("SELECT name FROM mgmt_roles WHERE name = %s", (role,))
            if not cur.fetchone():
                raise ValueError(f"Invalid role '{role}'")

            cur.execute(
                "INSERT INTO mgmt_users (username, password_hash, full_name, email, role, is_active, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (username, hashed, full_name, email, role, True, now, now),
            )
            user_id = cur.fetchone()[0]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return get_user(user_id) or {"id": user_id, "username": username, "role": role}


def delete_user(user_id: int) -> bool:
    """Soft-delete user (set is_active=FALSE) and deactivate all API keys."""
    now = _now_iso()
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM mgmt_users WHERE id = %s AND is_active = TRUE", (user_id,))
            if not cur.fetchone():
                return False

            cur.execute("UPDATE mgmt_users SET is_active = FALSE, updated_at = %s WHERE id = %s", (now, user_id))
            cur.execute("UPDATE mgmt_api_keys SET is_active = FALSE WHERE user_id = %s", (user_id,))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        _return_conn(conn)


def update_user(user_id: int, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Update user fields. Returns updated user or None."""
    allowed = {"username", "full_name", "email", "role", "is_active"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}

    if "password" in kwargs:
        import bcrypt
        updates["password_hash"] = bcrypt.hashpw(
            kwargs["password"].encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    if not updates:
        return get_user(user_id)

    updates["updated_at"] = _now_iso()
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [user_id]

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE mgmt_users SET {set_clause} WHERE id = %s", values)
            if cur.rowcount == 0:
                return None
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    result = get_user(user_id)
    if result:
        result.pop("password_hash", None)
    return result


def get_user(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a user by ID."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password_hash, full_name, email, role, is_active, created_at, updated_at "
                "FROM mgmt_users WHERE id = %s", (user_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0], "username": row[1], "password_hash": row[2],
                "full_name": row[3], "email": row[4], "role": row[5],
                "is_active": 1 if row[6] else 0, "created_at": row[7], "updated_at": row[8],
            }
    finally:
        _return_conn(conn)


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve a user by username."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password_hash, full_name, email, role, is_active, created_at, updated_at "
                "FROM mgmt_users WHERE username = %s", (username,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0], "username": row[1], "password_hash": row[2],
                "full_name": row[3], "email": row[4], "role": row[5],
                "is_active": 1 if row[6] else 0, "created_at": row[7], "updated_at": row[8],
            }
    finally:
        _return_conn(conn)


def list_users(role: Optional[str] = None, is_active: Optional[bool] = None,
               offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """List users with optional filtering and pagination."""
    conditions = []
    params: list = []

    if role is not None:
        conditions.append("role = %s")
        params.append(role)
    if is_active is not None:
        conditions.append("is_active = %s")
        params.append(is_active)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.extend([offset, limit])

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id, username, full_name, email, role, is_active, created_at, updated_at "
                f"FROM mgmt_users {where} ORDER BY id OFFSET %s LIMIT %s",
                params,
            )
            rows = cur.fetchall()
            results = []
            for row in rows:
                d = {
                    "id": row[0], "username": row[1], "full_name": row[2],
                    "email": row[3], "role": row[4], "is_active": 1 if row[5] else 0,
                    "created_at": row[6], "updated_at": row[7],
                }
                results.append(d)
            return results
    finally:
        _return_conn(conn)


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify a username/password pair."""
    import bcrypt

    user = get_user_by_username(username)
    if user is None or not user.get("is_active"):
        return None

    try:
        if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            result = dict(user)
            result.pop("password_hash", None)
            return result
    except Exception:
        logger.warning("bcrypt check failed for user '%s'", username, exc_info=True)
    return None


# ═══════════════════════════════════════════════════════════════════════
#  API Key Management
# ═══════════════════════════════════════════════════════════════════════

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def create_api_key(user_id: int, name: str = "", role: str = "operator",
                   expires_days: Optional[int] = None, description: str = "") -> str:
    """Generate a new API key. Returns plaintext key ONCE."""
    user = get_user(user_id)
    if not user or not user.get("is_active"):
        raise ValueError(f"User {user_id} does not exist or is not active")

    plaintext_key = secrets.token_urlsafe(48)
    key_hash = _hash_key(plaintext_key)
    key_prefix = plaintext_key[:8]
    now = _now_iso()
    expires_at = None
    if expires_days is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Validate role
            cur.execute("SELECT name FROM mgmt_roles WHERE name = %s", (role,))
            if not cur.fetchone():
                raise ValueError(f"Invalid role '{role}'")

            cur.execute(
                "INSERT INTO mgmt_api_keys (key_hash, key_prefix, user_id, name, description, role, is_active, expires_at, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (key_hash, key_prefix, user_id, name, description, role, True, expires_at, now),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return plaintext_key


def delete_api_key(key_id: int) -> bool:
    """Deactivate an API key."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE mgmt_api_keys SET is_active = FALSE WHERE id = %s AND is_active = TRUE", (key_id,))
            found = cur.rowcount > 0
        conn.commit()
        return found
    except Exception:
        conn.rollback()
        return False
    finally:
        _return_conn(conn)


def update_api_key(key_id: int, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Update API key fields."""
    allowed = {"name", "description", "role", "is_active", "expires_at"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}

    if not updates:
        return get_api_key(key_id)

    set_clause = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [key_id]

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE mgmt_api_keys SET {set_clause} WHERE id = %s", values)
            if cur.rowcount == 0:
                return None
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return get_api_key(key_id)


def get_api_key(key_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve an API key record by ID."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, key_hash, key_prefix, user_id, name, description, role, is_active, expires_at, created_at, last_used_at "
                "FROM mgmt_api_keys WHERE id = %s", (key_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0], "key_hash": row[1], "key_prefix": row[2],
                "user_id": row[3], "name": row[4], "description": row[5],
                "role": row[6], "is_active": 1 if row[7] else 0,
                "expires_at": row[8], "created_at": row[9], "last_used_at": row[10],
            }
    finally:
        _return_conn(conn)


def validate_api_key(key_plaintext: str) -> Optional[Dict[str, Any]]:
    """Validate a plaintext API key. Returns enriched info or None."""
    key_hash = _hash_key(key_plaintext)
    key_prefix = key_plaintext[:8]

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, key_hash, user_id, role, key_prefix, expires_at, is_active "
                "FROM mgmt_api_keys WHERE key_prefix = %s AND is_active = TRUE",
                (key_prefix,),
            )
            row = cur.fetchone()
            if not row:
                return None

            db_id, db_hash, db_user_id, db_role, db_prefix, db_expires, db_active = row

            if not secrets.compare_digest(db_hash, key_hash):
                return None

            # Check expiry
            if db_expires:
                try:
                    exp = datetime.fromisoformat(db_expires)
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > exp:
                        return None
                except (ValueError, TypeError):
                    pass

            # Update last_used_at
            now = _now_iso()
            try:
                cur.execute("UPDATE mgmt_api_keys SET last_used_at = %s WHERE id = %s", (now, db_id))
                conn.commit()
            except Exception:
                conn.rollback()

            # Get username
            cur.execute("SELECT username FROM mgmt_users WHERE id = %s", (db_user_id,))
            user_row = cur.fetchone()
            username = user_row[0] if user_row else None

        return {
            "key_id": db_id,
            "user_id": db_user_id,
            "username": username,
            "role": db_role,
            "key_prefix": db_prefix,
            "expires_at": db_expires,
        }
    finally:
        _return_conn(conn)


def list_api_keys(user_id: Optional[int] = None, is_active: Optional[bool] = None,
                  offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """List API keys with optional filtering."""
    conditions = []
    params: list = []

    if user_id is not None:
        conditions.append("user_id = %s")
        params.append(user_id)
    if is_active is not None:
        conditions.append("is_active = %s")
        params.append(is_active)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.extend([offset, limit])

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id, key_prefix, user_id, name, description, role, is_active, expires_at, created_at, last_used_at "
                f"FROM mgmt_api_keys {where} ORDER BY id OFFSET %s LIMIT %s",
                params,
            )
            rows = cur.fetchall()
            return [
                {
                    "id": r[0], "key_prefix": r[1], "user_id": r[2], "name": r[3],
                    "description": r[4], "role": r[5], "is_active": 1 if r[6] else 0,
                    "expires_at": r[7], "created_at": r[8], "last_used_at": r[9],
                }
                for r in rows
            ]
    finally:
        _return_conn(conn)


def rotate_api_key(key_id: int) -> Optional[str]:
    """Deactivate old key and create new one with same settings."""
    old_key = get_api_key(key_id)
    if old_key is None:
        return None

    delete_api_key(key_id)

    expires_days = None
    if old_key.get("expires_at"):
        try:
            exp = datetime.fromisoformat(old_key["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            remaining = exp - datetime.now(timezone.utc)
            if remaining.total_seconds() > 0:
                expires_days = max(1, int(remaining.total_seconds() / 86400))
        except (ValueError, TypeError):
            pass

    return create_api_key(
        user_id=old_key["user_id"], name=old_key["name"], role=old_key["role"],
        expires_days=expires_days, description=old_key.get("description", ""),
    )


# ═══════════════════════════════════════════════════════════════════════
#  Role Management
# ═══════════════════════════════════════════════════════════════════════

def list_roles() -> List[Dict[str, Any]]:
    """List all defined roles with their permissions."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT name, description, permissions, is_builtin, created_at, updated_at FROM mgmt_roles ORDER BY name")
            rows = cur.fetchall()
            results = []
            for r in rows:
                perms = r[2]
                if isinstance(perms, str):
                    try:
                        perms = json.loads(perms)
                    except json.JSONDecodeError:
                        perms = []
                results.append({
                    "name": r[0], "description": r[1], "permissions": perms or [],
                    "is_builtin": r[3], "created_at": r[4], "updated_at": r[5],
                })
            return results
    finally:
        _return_conn(conn)


def get_role(name: str) -> Optional[Dict[str, Any]]:
    """Retrieve a role by name."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT name, description, permissions, is_builtin, created_at, updated_at FROM mgmt_roles WHERE name = %s", (name,))
            row = cur.fetchone()
            if not row:
                return None
            perms = row[2]
            if isinstance(perms, str):
                try:
                    perms = json.loads(perms)
                except json.JSONDecodeError:
                    perms = []
            return {
                "name": row[0], "description": row[1], "permissions": perms or [],
                "is_builtin": row[3], "created_at": row[4], "updated_at": row[5],
            }
    finally:
        _return_conn(conn)


def create_role(name: str, permissions: List[str], description: str = "") -> Dict[str, Any]:
    """Create a new custom role."""
    try:
        from app.permissions import ALL_PERMISSIONS
        invalid = set(permissions) - ALL_PERMISSIONS
        if invalid:
            raise ValueError(f"Invalid permissions: {sorted(invalid)}")
    except ImportError:
        pass

    now = _now_iso()
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT name FROM mgmt_roles WHERE name = %s", (name,))
            if cur.fetchone():
                raise ValueError(f"Role '{name}' already exists")

            cur.execute(
                "INSERT INTO mgmt_roles (name, description, permissions, is_builtin, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (name, description, json.dumps(sorted(set(permissions))), False, now, now),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return get_role(name) or {"name": name, "permissions": permissions}


def update_role(role_name: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Update a role's attributes.

    Parameters:
        role_name: Current name of the role to update.
        **kwargs: Fields to update — 'name' (rename), 'description', 'permissions'.

    The first positional parameter is ``role_name`` (not ``name``) so that
    callers can safely pass ``name=...`` in kwargs for rename operations
    without triggering ``TypeError: got multiple values for argument 'name'``.
    """
    updates: Dict[str, Any] = {}

    if "permissions" in kwargs:
        try:
            from app.permissions import ALL_PERMISSIONS
            invalid = set(kwargs["permissions"]) - ALL_PERMISSIONS
            if invalid:
                raise ValueError(f"Invalid permissions: {sorted(invalid)}")
        except ImportError:
            pass
        updates["permissions"] = json.dumps(sorted(set(kwargs["permissions"])))

    if "description" in kwargs:
        updates["description"] = kwargs["description"]

    if not updates:
        return get_role(role_name)

    updates["updated_at"] = _now_iso()

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            set_clause = ", ".join(f"{k} = %s" for k in updates)
            values = list(updates.values()) + [role_name]
            cur.execute(f"UPDATE mgmt_roles SET {set_clause} WHERE name = %s", values)
            if cur.rowcount == 0:
                return None

            # Handle rename
            new_name = kwargs.get("name")
            if new_name and new_name != role_name:
                cur.execute("SELECT name FROM mgmt_roles WHERE name = %s", (new_name,))
                if cur.fetchone():
                    raise ValueError(f"Role '{new_name}' already exists")
                cur.execute("UPDATE mgmt_roles SET name = %s, updated_at = %s WHERE name = %s", (new_name, _now_iso(), role_name))
                cur.execute("UPDATE mgmt_users SET role = %s WHERE role = %s", (new_name, role_name))
                cur.execute("UPDATE mgmt_api_keys SET role = %s WHERE role = %s", (new_name, role_name))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return get_role(kwargs.get("name") or role_name)


def delete_role(name: str) -> bool:
    """Delete a custom (non-built-in) role."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT is_builtin FROM mgmt_roles WHERE name = %s", (name,))
            row = cur.fetchone()
            if not row:
                return False
            if row[0]:  # is_builtin
                return False

            cur.execute("DELETE FROM mgmt_roles WHERE name = %s AND is_builtin = FALSE", (name,))
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        return False
    finally:
        _return_conn(conn)


def get_role_permissions(role_name: str) -> set:
    """Return the set of permission strings for a role."""
    role = get_role(role_name)
    if role:
        return set(role.get("permissions", []))

    # Fallback to default permissions from permissions module
    try:
        from app.permissions import DEFAULT_ROLE_PERMISSIONS
        if role_name in DEFAULT_ROLE_PERMISSIONS:
            return set(DEFAULT_ROLE_PERMISSIONS[role_name])
    except ImportError:
        pass

    return set()


def has_permission(role: str, method: str, endpoint: str) -> bool:
    """Check if a role is allowed to call method on endpoint."""
    try:
        from app.permissions import resolve_permission
        required_perm = resolve_permission(method, endpoint)
    except (ImportError, Exception):
        required_perm = None

    if required_perm is None:
        return True

    role_perms = get_role_permissions(role)
    if required_perm in role_perms:
        return True

    if role == "admin":
        return True

    return False


def has_specific_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific named permission."""
    return permission in get_role_permissions(role)


# ═══════════════════════════════════════════════════════════════════════
#  Audit Log
# ═══════════════════════════════════════════════════════════════════════

def log_action(user_id: Optional[int], api_key_id: Optional[int], action: str,
               endpoint: str = "", ip_address: str = "", details: Optional[str] = None) -> None:
    """Append an entry to the audit log."""
    now = _now_iso()
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO mgmt_audit_log (user_id, api_key_id, action, endpoint, ip_address, timestamp, details) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (user_id, api_key_id, action, endpoint, ip_address, now, details),
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.debug("Audit log write failed (non-fatal): %s", exc)
    finally:
        _return_conn(conn)


def list_audit_log(user_id: Optional[int] = None, action: Optional[str] = None,
                   endpoint: Optional[str] = None, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """List audit log entries with filtering and pagination."""
    conditions = []
    params: list = []

    if user_id is not None:
        conditions.append("user_id = %s")
        params.append(user_id)
    if action is not None:
        conditions.append("action = %s")
        params.append(action)
    if endpoint is not None:
        conditions.append("endpoint LIKE %s")
        params.append(f"{endpoint}%")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.extend([offset, limit])

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id, user_id, api_key_id, action, endpoint, ip_address, timestamp, details "
                f"FROM mgmt_audit_log {where} ORDER BY id DESC OFFSET %s LIMIT %s",
                params,
            )
            rows = cur.fetchall()
            return [
                {"id": r[0], "user_id": r[1], "api_key_id": r[2], "action": r[3],
                 "endpoint": r[4], "ip_address": r[5], "timestamp": r[6], "details": r[7]}
                for r in rows
            ]
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  AI Chat Sessions & Messages
# ═══════════════════════════════════════════════════════════════════════

def chat_create_session(session_id: str, title: str, owner_id: str, owner_username: str,
                        model: str, system_prompt: str, context: str,
                        created_at: str, updated_at: str) -> Dict[str, Any]:
    """Insert a new AI chat session record."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ai_chat_sessions (id, title, owner_id, owner_username, model, system_prompt, context, is_archived, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (session_id, title, owner_id, owner_username, model, system_prompt, context, False, created_at, updated_at),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return {"id": session_id, "title": title, "owner_id": owner_id}


def chat_list_sessions(owner_id: Optional[str] = None, include_archived: bool = False) -> List[Dict[str, Any]]:
    """List chat sessions, optionally filtered by owner."""
    conditions = []
    params: list = []

    if owner_id is not None:
        conditions.append("owner_id = %s")
        params.append(owner_id)
    if not include_archived:
        conditions.append("is_archived = FALSE")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id, title, owner_id, owner_username, model, system_prompt, context, is_archived, created_at, updated_at "
                f"FROM ai_chat_sessions {where} ORDER BY updated_at DESC",
                params,
            )
            rows = cur.fetchall()
            return [
                {"id": r[0], "title": r[1], "owner_id": r[2], "owner_username": r[3],
                 "model": r[4], "system_prompt": r[5], "context": r[6],
                 "is_archived": 1 if r[7] else 0, "created_at": r[8], "updated_at": r[9]}
                for r in rows
            ]
    finally:
        _return_conn(conn)


def chat_get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single chat session by ID."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, owner_id, owner_username, model, system_prompt, context, is_archived, created_at, updated_at "
                "FROM ai_chat_sessions WHERE id = %s", (session_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0], "title": row[1], "owner_id": row[2], "owner_username": row[3],
                "model": row[4], "system_prompt": row[5], "context": row[6],
                "is_archived": 1 if row[7] else 0, "created_at": row[8], "updated_at": row[9],
            }
    finally:
        _return_conn(conn)


def chat_update_session(session_id: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Update fields on a chat session."""
    allowed = {"title", "system_prompt", "context", "is_archived", "model", "updated_at"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}

    if not updates:
        return chat_get_session(session_id)

    # v1.8-2 fix: JSONB columns (context) must be wrapped with
    # psycopg2.extras.Json() to avoid "can't adapt type 'dict'" errors.
    try:
        from psycopg2.extras import Json as Psycopg2Json
    except ImportError:
        Psycopg2Json = None

    jsonb_columns = {"context"}
    final_values = []
    for k, v in updates.items():
        if k in jsonb_columns and v is not None:
            if Psycopg2Json is not None:
                # Wrap dict/list with psycopg2 adapter
                if isinstance(v, (dict, list)):
                    final_values.append(Psycopg2Json(v))
                elif isinstance(v, str):
                    # Parse string to object, then wrap
                    try:
                        final_values.append(Psycopg2Json(json.loads(v)))
                    except json.JSONDecodeError:
                        final_values.append(v)
                else:
                    final_values.append(v)
            else:
                # Fallback: serialize to JSON string (PostgreSQL auto-casts)
                if isinstance(v, (dict, list)):
                    final_values.append(json.dumps(v))
                else:
                    final_values.append(v)
        else:
            final_values.append(v)

    set_clause = ", ".join(f"{k} = %s" for k in updates)
    values = final_values + [session_id]

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE ai_chat_sessions SET {set_clause} WHERE id = %s", values)
            if cur.rowcount == 0:
                return None
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return chat_get_session(session_id)


def chat_delete_session(session_id: str) -> bool:
    """Delete a chat session and all its messages."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM ai_chat_messages WHERE chat_id = %s", (session_id,))
            cur.execute("DELETE FROM ai_chat_sessions WHERE id = %s", (session_id,))
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        return False
    finally:
        _return_conn(conn)


def chat_count_sessions(owner_id: str) -> int:
    """Count active chat sessions for a user."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM ai_chat_sessions WHERE owner_id = %s AND is_archived = FALSE",
                (owner_id,),
            )
            return cur.fetchone()[0]
    finally:
        _return_conn(conn)


def chat_add_message(msg_id: str, chat_id: str, role: str, content: str,
                     model_used: Optional[str], tokens_used: Optional[int],
                     cost_rub: Optional[float], usage_info: Optional[str],
                     tool_steps: Optional[str], timestamp: str) -> Dict[str, Any]:
    """Insert a new chat message record."""
    # v1.8-2 fix: psycopg2 cannot adapt Python dicts for JSONB parameters,
    # causing "can't adapt type 'dict'" errors. Use psycopg2.extras.Json()
    # wrapper for JSONB column values. PostgreSQL then receives proper JSONB.
    try:
        from psycopg2.extras import Json as Psycopg2Json
        _json_wrapper = Psycopg2Json
    except ImportError:
        # Fallback: pass as string (PostgreSQL auto-casts string → JSONB)
        _json_wrapper = lambda x: json.dumps(x) if not isinstance(x, str) else x

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Wrap JSONB values with psycopg2.extras.Json adapter
            ui_val = None
            if usage_info:
                try:
                    parsed = json.loads(usage_info) if isinstance(usage_info, str) else usage_info
                    ui_val = _json_wrapper(parsed)
                except json.JSONDecodeError:
                    ui_val = _json_wrapper(usage_info)

            ts_val = None
            if tool_steps:
                try:
                    parsed = json.loads(tool_steps) if isinstance(tool_steps, str) else tool_steps
                    ts_val = _json_wrapper(parsed)
                except json.JSONDecodeError:
                    ts_val = _json_wrapper(tool_steps)

            cur.execute(
                "INSERT INTO ai_chat_messages (id, chat_id, role, content, model_used, tokens_used, cost_rub, usage_info, tool_steps, timestamp) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (msg_id, chat_id, role, content, model_used, tokens_used, cost_rub, ui_val, ts_val, timestamp),
            )
            # Update session updated_at
            cur.execute("UPDATE ai_chat_sessions SET updated_at = %s WHERE id = %s", (timestamp, chat_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)

    return {"id": msg_id, "chat_id": chat_id, "role": role}


def chat_get_messages(chat_id: str, limit: int = 50, before: Optional[str] = None) -> Tuple[List[Dict[str, Any]], bool]:
    """Get chat messages. Returns (messages, has_more) in chronological order."""
    conditions = ["chat_id = %s"]
    params: list = [chat_id]

    if before:
        conditions.append("timestamp < %s")
        params.append(before)

    where = f"WHERE {' AND '.join(conditions)}"

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Get total count for has_more
            cur.execute(f"SELECT COUNT(*) FROM ai_chat_messages {where}", params[:])
            total = cur.fetchone()[0]

            cur.execute(
                f"SELECT id, chat_id, role, content, model_used, tokens_used, cost_rub, usage_info, tool_steps, timestamp "
                f"FROM ai_chat_messages {where} ORDER BY timestamp ASC LIMIT %s",
                params + [limit + 1],
            )
            rows = cur.fetchall()

            has_more = len(rows) > limit
            rows = rows[:limit]

            messages = []
            for r in rows:
                ui = r[7]
                if isinstance(ui, str):
                    try:
                        ui = json.loads(ui)
                    except json.JSONDecodeError:
                        ui = None

                ts = r[8]
                if isinstance(ts, str):
                    try:
                        ts = json.loads(ts)
                    except json.JSONDecodeError:
                        ts = None

                messages.append({
                    "id": r[0], "chat_id": r[1], "role": r[2], "content": r[3],
                    "model_used": r[4], "tokens_used": r[5], "cost_rub": r[6],
                    "usage_info": ui, "tool_steps": ts, "timestamp": r[9],
                })

            return messages, has_more
    finally:
        _return_conn(conn)


def chat_get_messages_for_agent(chat_id: str) -> List[Dict[str, Any]]:
    """Get all messages in OpenAI-compatible format for the agent loop."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT role, content FROM ai_chat_messages WHERE chat_id = %s ORDER BY timestamp ASC",
                (chat_id,),
            )
            rows = cur.fetchall()
            return [{"role": r[0], "content": r[1]} for r in rows]
    finally:
        _return_conn(conn)


def chat_count_messages(chat_id: str) -> int:
    """Count messages in a chat session."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ai_chat_messages WHERE chat_id = %s", (chat_id,))
            return cur.fetchone()[0]
    finally:
        _return_conn(conn)


def chat_get_cost_summary(chat_id: str) -> Dict[str, Any]:
    """Get cost and usage summary for a chat session."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, model_used, tokens_used, cost_rub, usage_info, timestamp, role "
                "FROM ai_chat_messages WHERE chat_id = %s ORDER BY timestamp ASC",
                (chat_id,),
            )
            rows = cur.fetchall()

        total_cost = 0.0
        total_tokens = 0
        total_prompt = 0
        total_completion = 0
        total_reasoning = 0
        assistant_count = 0
        message_breakdown = []

        for r in rows:
            msg_id, model_used, tokens_used, cost_rub, usage_info, timestamp, role = r

            msg_cost = 0.0
            if cost_rub is not None:
                try:
                    msg_cost = float(cost_rub)
                except (ValueError, TypeError):
                    pass

            if role == "assistant":
                assistant_count += 1
                total_cost += msg_cost
                total_tokens += (tokens_used or 0)

                if usage_info:
                    ui = usage_info if isinstance(usage_info, dict) else None
                    if isinstance(usage_info, str):
                        try:
                            ui = json.loads(usage_info)
                        except json.JSONDecodeError:
                            ui = None
                    if ui:
                        total_prompt += (ui.get("prompt_tokens") or 0)
                        total_completion += (ui.get("completion_tokens") or 0)
                        total_reasoning += (ui.get("reasoning_tokens") or 0)

                if msg_cost > 0 or tokens_used:
                    message_breakdown.append({
                        "id": msg_id, "timestamp": timestamp,
                        "model_used": model_used, "tokens_used": tokens_used,
                        "cost_rub": round(msg_cost, 8),
                    })

        return {
            "total_cost_rub": round(total_cost, 8),
            "total_tokens": total_tokens,
            "total_prompt_tokens": total_prompt,
            "total_completion_tokens": total_completion,
            "total_reasoning_tokens": total_reasoning,
            "assistant_message_count": assistant_count,
            "messages": message_breakdown,
        }
    finally:
        _return_conn(conn)


def chat_get_all_cost_summary() -> Dict[str, Any]:
    """Get cost summary across ALL chat sessions."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title FROM ai_chat_sessions ORDER BY updated_at DESC")
            sessions = cur.fetchall()
    finally:
        _return_conn(conn)

    grand_total_cost = 0.0
    grand_total_tokens = 0
    chat_costs = []

    for session in sessions:
        chat_id, title = session
        summary = chat_get_cost_summary(chat_id)
        cost = summary["total_cost_rub"]
        tokens = summary["total_tokens"]
        grand_total_cost += cost
        grand_total_tokens += tokens
        chat_costs.append({
            "chat_id": chat_id, "title": title,
            "message_count": summary["assistant_message_count"],
            "total_cost_rub": cost, "total_tokens": tokens,
        })

    return {
        "total_cost_rub": round(grand_total_cost, 8),
        "total_tokens": grand_total_tokens,
        "total_chats": len(sessions),
        "chat_costs": chat_costs,
    }


def chat_prune_old_messages(chat_id: str, max_history: int) -> None:
    """Remove oldest messages when a chat exceeds the max history limit."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ai_chat_messages WHERE chat_id = %s", (chat_id,))
            count = cur.fetchone()[0]

            if count > max_history:
                cur.execute(
                    "DELETE FROM ai_chat_messages WHERE chat_id = %s AND id IN ("
                    "  SELECT id FROM ai_chat_messages WHERE chat_id = %s ORDER BY timestamp ASC LIMIT %s"
                    ")",
                    (chat_id, chat_id, count - max_history),
                )
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  General-purpose PostgreSQL query helper (for AI tools)
# ═══════════════════════════════════════════════════════════════════════

def execute_query(query: str, params: Optional[tuple] = None, fetch: bool = True) -> Any:
    """Execute a SQL query and optionally return results.

    WARNING: This is a low-level function. Use with caution.
    Only SELECT queries should use fetch=True.
    """
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if fetch:
                columns = [desc[0] for desc in cur.description] if cur.description else []
                rows = cur.fetchall()
                return [dict(zip(columns, row)) for row in rows]
            else:
                conn.commit()
                return {"rows_affected": cur.rowcount}
    except Exception as exc:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)


def execute_select(table: str, columns: str = "*", where: Optional[str] = None,
                   order_by: Optional[str] = None, limit: int = 100,
                   offset: int = 0) -> List[Dict[str, Any]]:
    """Safe SELECT query builder. Only allows read operations."""
    # Validate table name (prevent SQL injection)
    allowed_tables = {
        "mgmt_users", "mgmt_api_keys", "mgmt_roles", "mgmt_audit_log",
        "ai_chat_sessions", "ai_chat_messages",
        "projects", "history", "audit_log", "schedules", "snapshots", "templates",
        "information_schema.tables", "information_schema.columns",
    }
    if table.lower() not in {t.lower() for t in allowed_tables}:
        raise ValueError(f"Table '{table}' is not allowed for SELECT queries. Allowed: {sorted(allowed_tables)}")

    query = f"SELECT {columns} FROM {table}"
    params: list = []

    if where:
        query += f" WHERE {where}"

    if order_by:
        # Validate order_by doesn't contain injection
        if ";" in order_by or "--" in order_by:
            raise ValueError("Invalid order_by clause")
        query += f" ORDER BY {order_by}"

    query += " LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            columns_list = [desc[0] for desc in cur.description] if cur.description else []
            rows = cur.fetchall()
            return [dict(zip(columns_list, row)) for row in rows]
    finally:
        _return_conn(conn)


def execute_insert(table: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Safe INSERT query builder."""
    allowed_tables = {
        "mgmt_audit_log", "ai_chat_sessions", "ai_chat_messages",
    }
    if table.lower() not in {t.lower() for t in allowed_tables}:
        raise ValueError(f"INSERT not allowed on table '{table}'")

    cols = ", ".join(data.keys())
    placeholders = ", ".join(["%s"] * len(data))
    values = list(data.values())

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})", values)
        conn.commit()
        return {"status": "ok", "rows_affected": 1}
    except Exception as exc:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)


def execute_update(table: str, data: Dict[str, Any], where: str, where_params: Optional[tuple] = None) -> Dict[str, Any]:
    """Safe UPDATE query builder."""
    allowed_tables = {
        "mgmt_users", "mgmt_api_keys", "mgmt_roles",
        "ai_chat_sessions", "ai_chat_messages",
    }
    if table.lower() not in {t.lower() for t in allowed_tables}:
        raise ValueError(f"UPDATE not allowed on table '{table}'")

    set_clause = ", ".join(f"{k} = %s" for k in data.keys())
    values = list(data.values())

    query = f"UPDATE {table} SET {set_clause} WHERE {where}"

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            if where_params:
                cur.execute(query, values + list(where_params))
            else:
                cur.execute(query, values)
            rows_affected = cur.rowcount
        conn.commit()
        return {"status": "ok", "rows_affected": rows_affected}
    except Exception as exc:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)


def execute_delete(table: str, where: str, where_params: Optional[tuple] = None) -> Dict[str, Any]:
    """Safe DELETE query builder."""
    allowed_tables = {
        "ai_chat_sessions", "ai_chat_messages",
    }
    if table.lower() not in {t.lower() for t in allowed_tables}:
        raise ValueError(f"DELETE not allowed on table '{table}'")

    query = f"DELETE FROM {table} WHERE {where}"

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            if where_params:
                cur.execute(query, where_params)
            else:
                cur.execute(query)
            rows_affected = cur.rowcount
        conn.commit()
        return {"status": "ok", "rows_affected": rows_affected}
    except Exception as exc:
        conn.rollback()
        raise
    finally:
        _return_conn(conn)


def list_tables() -> List[Dict[str, Any]]:
    """List all tables in the database with row counts."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)
            tables = cur.fetchall()

            result = []
            for (table_name,) in tables:
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {table_name}")
                    count = cur.fetchone()[0]
                    result.append({"table": table_name, "row_count": count})
                except Exception:
                    result.append({"table": table_name, "row_count": -1})

            return result
    finally:
        _return_conn(conn)


def describe_table(table_name: str) -> List[Dict[str, Any]]:
    """Describe columns of a table."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_name = %s AND table_schema = 'public'
                ORDER BY ordinal_position
            """, (table_name,))
            rows = cur.fetchall()
            return [
                {"column": r[0], "type": r[1], "nullable": r[2] == "YES", "default": r[3]}
                for r in rows
            ]
    finally:
        _return_conn(conn)
