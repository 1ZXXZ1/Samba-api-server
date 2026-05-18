"""
PostgreSQL persistence for Shell Project registry.

v1.6.7-7: Fixed ForeignKeyViolation on audit_log after project deletion.
    - audit_log(projet_id) is now called BEFORE delete_project() in all
      4 call sites, so the parent row still exists during INSERT.
    - Added ALTER TABLE migration to fix existing tables that may have
      audit_log_projet_id_fkey without ON DELETE SET NULL.
    - audit_log.projet_id is now correctly set to NULL when the parent
      project row is deleted (ON DELETE SET NULL).

v1.6.7-6: Fixed DSN construction — replaced string-based DSN with keyword
    arguments to ThreadedConnectionPool. This fixes the "invalid dsn:
    missing = after #" error caused by special characters (#, @, etc.)
    in passwords being misinterpreted by libpq's connection string parser.
    Also password is no longer logged in the DSN string (security fix).

v1.6.7-5: Migrated from SQLite to PostgreSQL for ALT Linux compatibility.
Uses psycopg2 with ThreadedConnectionPool for thread-safe access.
All project records survive server restarts. Orphan workspaces are
detected and re-linked on startup.

Tables:
    projects      — core project metadata
    history       — execution history entries
    audit_log     — audit trail for all project actions
    schedules     — cron schedules for project execution
    snapshots     — workspace snapshot metadata
    templates     — project templates
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Module-level DB connection pool ──────────────────────────────────────

_pool: Optional[Any] = None  # psycopg2.pool.ThreadedConnectionPool

# PostgreSQL connection parameters (set via init_db)
_PG_DSN: Optional[str] = None


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
    """Initialize the PostgreSQL connection pool and create tables if needed.

    Parameters
    ----------
    host : str
        PostgreSQL server hostname.
    port : int
        PostgreSQL server port.
    dbname : str
        Database name.
    user : str
        Database user.
    password : str
        Database password.
    dsn : str, optional
        If provided, used as the connection string instead of individual params.
        Example: ``postgresql://samba_api:secret@localhost:5432/samba_api``
    min_conn : int
        Minimum connections in the pool.
    max_conn : int
        Maximum connections in the pool.
    """
    global _pool, _PG_DSN

    try:
        import psycopg2
        from psycopg2.pool import ThreadedConnectionPool
    except ImportError:
        raise ImportError(
            "psycopg2 is required for PostgreSQL persistence. "
            "Install with: apt-get install python3-psycopg2  (ALT Linux)  "
            "or  pip install psycopg2-binary"
        )

    # v1.6.7-6 fix: Use keyword arguments instead of DSN string to avoid
    # libpq parsing issues with special characters (#, @, etc.) in passwords.
    # This also avoids the "invalid dsn: missing = after #" error.
    _connect_kwargs: Dict[str, Any] = {}
    if dsn:
        # User provided a full DSN/URI — use it directly
        _PG_DSN = dsn
        _connect_kwargs = {"dsn": dsn}
    else:
        # Use individual keyword arguments — psycopg2.connect() handles
        # special characters in password properly this way.
        _PG_DSN = (
            f"host={host} port={port} dbname={dbname} "
            f"user={user} password=***"
        )
        _connect_kwargs = {
            "host": host,
            "port": port,
            "dbname": dbname,
            "user": user,
            "password": password,
        }

    try:
        _pool = ThreadedConnectionPool(min_conn, max_conn, **_connect_kwargs)
        logger.info("[PROJET DB] PostgreSQL connection pool created "
                     "(min=%d, max=%d, dsn=%s)", min_conn, max_conn, _PG_DSN)
    except Exception as exc:
        logger.error("[PROJET DB] Failed to create PostgreSQL pool: %s", exc)
        raise

    # Create tables
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(_SCHEMA)
        conn.commit()
        logger.info("[PROJET DB] Tables verified/created in PostgreSQL")
    finally:
        _return_conn(conn)

    # v1.6.7-7: Migrate existing audit_log FK to ON DELETE SET NULL.
    # Older tables may have been created with the default ON DELETE NO ACTION,
    # which prevents inserting audit_log rows after the parent project is deleted.
    # We drop and recreate the constraint with the correct ON DELETE SET NULL.
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Check if the FK constraint exists and has the wrong ON DELETE action
            cur.execute("""
                SELECT conname, confdeltype
                FROM pg_constraint
                WHERE conrelid = 'audit_log'::regclass
                  AND contype = 'f'
            """)
            fk_rows = cur.fetchall()
            for fk_name, del_type in fk_rows:
                # confdeltype: 'a' = NO ACTION, 'c' = CASCADE, 'n' = SET NULL, 'd' = SET DEFAULT
                # We want SET NULL ('n'). If it's anything else, drop and recreate.
                if del_type != 'n':
                    try:
                        cur.execute(
                            f"ALTER TABLE audit_log DROP CONSTRAINT {fk_name}"
                        )
                        cur.execute("""
                            ALTER TABLE audit_log
                            ADD CONSTRAINT audit_log_projet_id_fkey
                            FOREIGN KEY (projet_id) REFERENCES projects(projet_id)
                            ON DELETE SET NULL
                        """)
                        conn.commit()
                        logger.info("[PROJET DB] Migrated audit_log FK to ON DELETE SET NULL")
                    except Exception as mig_exc:
                        conn.rollback()
                        logger.warning("[PROJET DB] FK migration failed (non-fatal): %s", mig_exc)
                else:
                    logger.info("[PROJET DB] audit_log FK already has ON DELETE SET NULL")
        # Final commit for the check queries
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.warning("[PROJET DB] FK migration check failed (non-fatal): %s", exc)
    finally:
        _return_conn(conn)


def _get_conn():
    """Get a connection from the pool."""
    if _pool is None:
        raise RuntimeError(
            "projet_db not initialized — call init_db() first. "
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
        logger.info("[PROJET DB] PostgreSQL connection pool closed")


# ── Schema (PostgreSQL) ─────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    projet_id       TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    workspace_path  TEXT NOT NULL,
    owner           TEXT DEFAULT '',
    status          TEXT DEFAULT 'creating',
    created_at      TEXT,
    completed_at    TEXT,
    auto_delete     BOOLEAN DEFAULT TRUE,
    archive         TEXT,
    last_command    TEXT,
    last_returncode INTEGER,
    sudo            BOOLEAN DEFAULT FALSE,
    env             JSONB DEFAULT '{}',
    permissions     TEXT,
    tags            JSONB DEFAULT '[]',
    labels          JSONB DEFAULT '{}',
    ttl_seconds     INTEGER,
    ttl_expires_at  TEXT,
    callback_url    TEXT,
    schedule_cron   TEXT,
    volumes         JSONB DEFAULT '[]',
    resource_limits JSONB DEFAULT '{}',
    encrypted_env   JSONB DEFAULT '{}',
    depends_on      JSONB DEFAULT '[]',
    template_id     TEXT
);

CREATE TABLE IF NOT EXISTS history (
    id          SERIAL PRIMARY KEY,
    projet_id   TEXT NOT NULL REFERENCES projects(projet_id) ON DELETE CASCADE,
    command     TEXT NOT NULL,
    rc          INTEGER,
    elapsed     REAL,
    timed_out   BOOLEAN DEFAULT FALSE,
    executed_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    projet_id   TEXT REFERENCES projects(projet_id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    actor       TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    ip_address  TEXT DEFAULT '',
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS schedules (
    id          SERIAL PRIMARY KEY,
    projet_id   TEXT NOT NULL REFERENCES projects(projet_id) ON DELETE CASCADE,
    cron_expr   TEXT NOT NULL,
    run_command TEXT NOT NULL,
    enabled     BOOLEAN DEFAULT TRUE,
    last_run_at TEXT,
    next_run_at TEXT,
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id            SERIAL PRIMARY KEY,
    projet_id     TEXT NOT NULL REFERENCES projects(projet_id) ON DELETE CASCADE,
    snapshot_id   TEXT NOT NULL,
    archive_path  TEXT,
    created_at    TEXT
);

CREATE TABLE IF NOT EXISTS templates (
    template_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    archive_path    TEXT,
    run_command     TEXT,
    env             JSONB DEFAULT '{}',
    tags            JSONB DEFAULT '[]',
    labels          JSONB DEFAULT '{}',
    pre_commands    JSONB DEFAULT '[]',
    post_commands   JSONB DEFAULT '[]',
    resource_limits JSONB DEFAULT '{}',
    volumes         JSONB DEFAULT '[]',
    created_at      TEXT,
    updated_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner);
CREATE INDEX IF NOT EXISTS idx_projects_name ON projects(name);
CREATE INDEX IF NOT EXISTS idx_history_projet ON history(projet_id);
CREATE INDEX IF NOT EXISTS idx_audit_projet ON audit_log(projet_id);
CREATE INDEX IF NOT EXISTS idx_schedules_projet ON schedules(projet_id);
CREATE INDEX IF NOT EXISTS idx_schedules_next ON schedules(next_run_at);
CREATE INDEX IF NOT EXISTS idx_snapshots_projet ON snapshots(projet_id);
"""


# ═══════════════════════════════════════════════════════════════════════
#  Project CRUD
# ═══════════════════════════════════════════════════════════════════════


def save_project(record: Dict[str, Any]) -> None:
    """Insert or update a project record (upsert via ON CONFLICT)."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO projects (
                    projet_id, name, workspace_path, owner, status,
                    created_at, completed_at, auto_delete, archive,
                    last_command, last_returncode, sudo, env, permissions,
                    tags, labels, ttl_seconds, ttl_expires_at, callback_url,
                    schedule_cron, volumes, resource_limits, encrypted_env,
                    depends_on, template_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (projet_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    workspace_path = EXCLUDED.workspace_path,
                    owner = EXCLUDED.owner,
                    status = EXCLUDED.status,
                    created_at = EXCLUDED.created_at,
                    completed_at = EXCLUDED.completed_at,
                    auto_delete = EXCLUDED.auto_delete,
                    archive = EXCLUDED.archive,
                    last_command = EXCLUDED.last_command,
                    last_returncode = EXCLUDED.last_returncode,
                    sudo = EXCLUDED.sudo,
                    env = EXCLUDED.env,
                    permissions = EXCLUDED.permissions,
                    tags = EXCLUDED.tags,
                    labels = EXCLUDED.labels,
                    ttl_seconds = EXCLUDED.ttl_seconds,
                    ttl_expires_at = EXCLUDED.ttl_expires_at,
                    callback_url = EXCLUDED.callback_url,
                    schedule_cron = EXCLUDED.schedule_cron,
                    volumes = EXCLUDED.volumes,
                    resource_limits = EXCLUDED.resource_limits,
                    encrypted_env = EXCLUDED.encrypted_env,
                    depends_on = EXCLUDED.depends_on,
                    template_id = EXCLUDED.template_id
            """, (
                record["projet_id"],
                record["name"],
                record["workspace_path"],
                record.get("owner", ""),
                record.get("status", "creating"),
                record.get("created_at"),
                record.get("completed_at"),
                record.get("auto_delete", True),
                record.get("archive"),
                record.get("last_command"),
                record.get("last_returncode"),
                record.get("sudo", False),
                json.dumps(record.get("env") or {}, ensure_ascii=False),
                record.get("permissions"),
                json.dumps(record.get("tags") or [], ensure_ascii=False),
                json.dumps(record.get("labels") or {}, ensure_ascii=False),
                record.get("ttl_seconds"),
                record.get("ttl_expires_at"),
                record.get("callback_url"),
                record.get("schedule_cron"),
                json.dumps(record.get("volumes") or [], ensure_ascii=False),
                json.dumps(record.get("resource_limits") or {}, ensure_ascii=False),
                json.dumps(record.get("encrypted_env") or {}, ensure_ascii=False),
                json.dumps(record.get("depends_on") or [], ensure_ascii=False),
                record.get("template_id"),
            ))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] save_project failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def load_project(projet_id: str) -> Optional[Dict[str, Any]]:
    """Load a single project record by ID."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM projects WHERE projet_id = %s", (projet_id,)
            )
            row = cur.fetchone()
            if row is None:
                return None
            columns = [desc[0] for desc in cur.description]
            return _row_to_dict(dict(zip(columns, row)))
    finally:
        _return_conn(conn)


def load_all_projects() -> Dict[str, Dict[str, Any]]:
    """Load all project records as a dict of projet_id → record."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM projects")
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            result = {}
            for row in rows:
                d = _row_to_dict(dict(zip(columns, row)))
                result[d["projet_id"]] = d
            return result
    finally:
        _return_conn(conn)


def delete_project(projet_id: str) -> bool:
    """Delete a project record from the database."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM projects WHERE projet_id = %s", (projet_id,)
            )
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] delete_project failed: %s", exc)
        return False
    finally:
        _return_conn(conn)


def update_project_status(projet_id: str, new_status: str, completed_at: Optional[str] = None) -> None:
    """Update just the status (and optionally completed_at) of a project."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            if completed_at:
                cur.execute(
                    "UPDATE projects SET status = %s, completed_at = %s WHERE projet_id = %s",
                    (new_status, completed_at, projet_id),
                )
            else:
                cur.execute(
                    "UPDATE projects SET status = %s WHERE projet_id = %s",
                    (new_status, projet_id),
                )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] update_project_status failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def update_project_field(projet_id: str, field: str, value: Any) -> None:
    """Update a single field of a project record."""
    if field not in {
        "owner", "tags", "labels", "callback_url", "last_command",
        "last_returncode", "ttl_seconds", "ttl_expires_at",
        "schedule_cron", "volumes", "resource_limits", "encrypted_env",
        "depends_on", "archive",
    }:
        raise ValueError(f"Field '{field}' is not updatable via update_project_field")

    # Serialize JSON fields
    json_fields = {"tags", "labels", "volumes", "resource_limits", "encrypted_env", "depends_on"}
    if field in json_fields:
        value = json.dumps(value, ensure_ascii=False)

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # field is validated above — safe from injection
            cur.execute(
                f"UPDATE projects SET {field} = %s WHERE projet_id = %s",
                (value, projet_id),
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] update_project_field failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def count_projects() -> int:
    """Return total number of registered projects."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM projects")
            row = cur.fetchone()
            return row[0] if row else 0
    finally:
        _return_conn(conn)


def _row_to_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a database row to a Python dict with deserialized JSON fields."""
    # Deserialize JSON fields (psycopg2 may return them as strings or dicts)
    for key in ("env", "tags", "labels", "volumes", "resource_limits", "encrypted_env", "depends_on"):
        val = d.get(key)
        if isinstance(val, str):
            try:
                d[key] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                d[key] = {} if key in ("env", "labels", "resource_limits", "encrypted_env") else []
        elif val is None:
            d[key] = {} if key in ("env", "labels", "resource_limits", "encrypted_env") else []
    # Convert booleans (PostgreSQL may return True/False already)
    if "auto_delete" in d and not isinstance(d["auto_delete"], bool):
        d["auto_delete"] = bool(d.get("auto_delete", True))
    if "sudo" in d and not isinstance(d["sudo"], bool):
        d["sudo"] = bool(d.get("sudo", False))
    return d


# ═══════════════════════════════════════════════════════════════════════
#  Execution History
# ═══════════════════════════════════════════════════════════════════════


def append_history(projet_id: str, command: str, rc: int, elapsed: float,
                   timed_out: bool = False) -> None:
    """Append an execution history entry."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO history (projet_id, command, rc, elapsed, timed_out, executed_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                projet_id,
                command,
                rc,
                round(elapsed, 3),
                timed_out,
                datetime.now(timezone.utc).isoformat(),
            ))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] append_history failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def load_history(projet_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Load execution history for a project."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM history WHERE projet_id = %s ORDER BY id DESC LIMIT %s",
                (projet_id, limit),
            )
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            results = []
            for row in rows:
                d = dict(zip(columns, row))
                results.append({
                    "command": d["command"],
                    "rc": d["rc"],
                    "elapsed": d["elapsed"],
                    "timed_out": bool(d.get("timed_out", False)),
                    "at": d["executed_at"],
                })
            results.reverse()  # chronological order
            return results
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  Audit Log
# ═══════════════════════════════════════════════════════════════════════


def audit_log(projet_id: Optional[str], action: str, actor: str = "",
              detail: str = "", ip_address: str = "") -> None:
    """Write an audit log entry.

    projet_id may be None for actions not tied to a specific project
    (e.g. batch_operation, create_template, delete_template).
    """
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (projet_id, action, actor, detail, ip_address, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                projet_id,
                action,
                actor,
                detail,
                ip_address,
                datetime.now(timezone.utc).isoformat(),
            ))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] audit_log failed: %s", exc)
        # v1.6.7-7: Don't re-raise — audit log failures should not crash
        # the main operation. The error is already logged above.
    finally:
        _return_conn(conn)


def load_audit_log(projet_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Load audit log entries, optionally filtered by project."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            if projet_id:
                cur.execute(
                    "SELECT * FROM audit_log WHERE projet_id = %s ORDER BY id DESC LIMIT %s",
                    (projet_id, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT %s",
                    (limit,),
                )
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            results = []
            for row in rows:
                d = dict(zip(columns, row))
                # Convert boolean fields
                d["timed_out"] = bool(d.get("timed_out", False))
                d["auto_delete"] = bool(d.get("auto_delete", True))
                d["sudo"] = bool(d.get("sudo", False))
                d["enabled"] = bool(d.get("enabled", True))
                results.append(d)
            return results
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  Schedules
# ═══════════════════════════════════════════════════════════════════════


def save_schedule(projet_id: str, cron_expr: str, run_command: str) -> int:
    """Create a schedule entry. Returns the schedule ID."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO schedules (projet_id, cron_expr, run_command, created_at)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (
                projet_id,
                cron_expr,
                run_command,
                datetime.now(timezone.utc).isoformat(),
            ))
            schedule_id = cur.fetchone()[0]
        conn.commit()
        return schedule_id
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] save_schedule failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def load_schedules(projet_id: Optional[str] = None, enabled_only: bool = False) -> List[Dict[str, Any]]:
    """Load schedule entries."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            if projet_id:
                cur.execute(
                    "SELECT * FROM schedules WHERE projet_id = %s ORDER BY id",
                    (projet_id,),
                )
            elif enabled_only:
                cur.execute(
                    "SELECT * FROM schedules WHERE enabled = TRUE ORDER BY next_run_at",
                )
            else:
                cur.execute("SELECT * FROM schedules ORDER BY id")
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            results = []
            for row in rows:
                d = dict(zip(columns, row))
                d["enabled"] = bool(d.get("enabled", True))
                results.append(d)
            return results
    finally:
        _return_conn(conn)


def delete_schedule(schedule_id: int) -> bool:
    """Delete a schedule entry."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM schedules WHERE id = %s", (schedule_id,))
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] delete_schedule failed: %s", exc)
        return False
    finally:
        _return_conn(conn)


def update_schedule_run(schedule_id: int, last_run_at: str, next_run_at: str) -> None:
    """Update schedule run timestamps."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE schedules SET last_run_at = %s, next_run_at = %s WHERE id = %s",
                (last_run_at, next_run_at, schedule_id),
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] update_schedule_run failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def toggle_schedule(schedule_id: int, enabled: bool) -> None:
    """Enable or disable a schedule."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE schedules SET enabled = %s WHERE id = %s",
                (enabled, schedule_id),
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] toggle_schedule failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  Snapshots
# ═══════════════════════════════════════════════════════════════════════


def save_snapshot(projet_id: str, snapshot_id: str, archive_path: str) -> None:
    """Record a snapshot."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO snapshots (projet_id, snapshot_id, archive_path, created_at)
                VALUES (%s, %s, %s, %s)
            """, (
                projet_id,
                snapshot_id,
                archive_path,
                datetime.now(timezone.utc).isoformat(),
            ))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] save_snapshot failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def load_snapshots(projet_id: str) -> List[Dict[str, Any]]:
    """Load snapshots for a project."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM snapshots WHERE projet_id = %s ORDER BY id DESC",
                (projet_id,),
            )
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            return [dict(zip(columns, row)) for row in rows]
    finally:
        _return_conn(conn)


def delete_snapshot(snapshot_id: str) -> bool:
    """Delete a snapshot record."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM snapshots WHERE snapshot_id = %s", (snapshot_id,))
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] delete_snapshot failed: %s", exc)
        return False
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  Templates
# ═══════════════════════════════════════════════════════════════════════


def save_template(template: Dict[str, Any]) -> None:
    """Insert or update a template (upsert via ON CONFLICT)."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO templates (
                    template_id, name, description, archive_path, run_command,
                    env, tags, labels, pre_commands, post_commands,
                    resource_limits, volumes, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (template_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    archive_path = EXCLUDED.archive_path,
                    run_command = EXCLUDED.run_command,
                    env = EXCLUDED.env,
                    tags = EXCLUDED.tags,
                    labels = EXCLUDED.labels,
                    pre_commands = EXCLUDED.pre_commands,
                    post_commands = EXCLUDED.post_commands,
                    resource_limits = EXCLUDED.resource_limits,
                    volumes = EXCLUDED.volumes,
                    updated_at = EXCLUDED.updated_at
            """, (
                template["template_id"],
                template["name"],
                template.get("description", ""),
                template.get("archive_path"),
                template.get("run_command"),
                json.dumps(template.get("env") or {}, ensure_ascii=False),
                json.dumps(template.get("tags") or [], ensure_ascii=False),
                json.dumps(template.get("labels") or {}, ensure_ascii=False),
                json.dumps(template.get("pre_commands") or [], ensure_ascii=False),
                json.dumps(template.get("post_commands") or [], ensure_ascii=False),
                json.dumps(template.get("resource_limits") or {}, ensure_ascii=False),
                json.dumps(template.get("volumes") or [], ensure_ascii=False),
                template.get("created_at", datetime.now(timezone.utc).isoformat()),
                datetime.now(timezone.utc).isoformat(),
            ))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] save_template failed: %s", exc)
        raise
    finally:
        _return_conn(conn)


def load_template(template_id: str) -> Optional[Dict[str, Any]]:
    """Load a template by ID."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM templates WHERE template_id = %s", (template_id,)
            )
            row = cur.fetchone()
            if row is None:
                return None
            columns = [desc[0] for desc in cur.description]
            d = dict(zip(columns, row))
            for key in ("env", "tags", "labels", "pre_commands", "post_commands", "resource_limits", "volumes"):
                val = d.get(key)
                if isinstance(val, str):
                    try:
                        d[key] = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        d[key] = {} if key in ("env", "labels", "resource_limits") else []
                elif val is None:
                    d[key] = {} if key in ("env", "labels", "resource_limits") else []
            return d
    finally:
        _return_conn(conn)


def load_all_templates() -> List[Dict[str, Any]]:
    """Load all templates."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM templates ORDER BY name")
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            results = []
            for row in rows:
                d = dict(zip(columns, row))
                for key in ("env", "tags", "labels", "pre_commands", "post_commands", "resource_limits", "volumes"):
                    val = d.get(key)
                    if isinstance(val, str):
                        try:
                            d[key] = json.loads(val)
                        except (json.JSONDecodeError, TypeError):
                            d[key] = {} if key in ("env", "labels", "resource_limits") else []
                    elif val is None:
                        d[key] = {} if key in ("env", "labels", "resource_limits") else []
                results.append(d)
            return results
    finally:
        _return_conn(conn)


def delete_template(template_id: str) -> bool:
    """Delete a template."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM templates WHERE template_id = %s", (template_id,))
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception as exc:
        conn.rollback()
        logger.error("[PROJET DB] delete_template failed: %s", exc)
        return False
    finally:
        _return_conn(conn)


# ═══════════════════════════════════════════════════════════════════════
#  Orphan Recovery
# ═══════════════════════════════════════════════════════════════════════


def find_orphan_workspaces(base_dir: str) -> List[Dict[str, str]]:
    """Find workspace directories on disk that are not in the DB.

    Scans /home/AD-API-USER/{name}/{id}/ directories and checks
    if projet_id exists in the projects table.

    Returns a list of {projet_id, name, workspace_path}.
    """
    conn = _get_conn()
    try:
        base = Path(base_dir)
        if not base.is_dir():
            return []

        orphans = []
        for name_dir in sorted(base.iterdir()):
            if not name_dir.is_dir() or name_dir.name.startswith("."):
                continue
            for id_dir in sorted(name_dir.iterdir()):
                if not id_dir.is_dir() or id_dir.name.startswith("."):
                    continue
                projet_id = id_dir.name
                # Check if in DB
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM projects WHERE projet_id = %s", (projet_id,)
                    )
                    if cur.fetchone() is None:
                        orphans.append({
                            "projet_id": projet_id,
                            "name": name_dir.name,
                            "workspace_path": str(id_dir),
                        })
        return orphans
    finally:
        _return_conn(conn)


def recover_orphan(projet_id: str, name: str, workspace_path: str,
                   owner: str = "recovered") -> None:
    """Re-link an orphan workspace into the DB."""
    record = {
        "projet_id": projet_id,
        "name": name,
        "workspace_path": workspace_path,
        "owner": owner,
        "status": "ready",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "auto_delete": False,
    }
    save_project(record)
    audit_log(projet_id, "recover_orphan", detail=f"Recovered from {workspace_path}")
