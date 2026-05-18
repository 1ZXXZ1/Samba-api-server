"""
API User & Key Management Module for the Samba AD DC Management API.

v1.8.5-2: Replaced JSON-file-based storage with PostgreSQL via app.mgmt_db.
All data (users, keys, roles, audit log, AI chat) is now stored in
PostgreSQL using the same connection pool as Shell Projects.

This module is **standalone** — it has no FastAPI dependency and can be
used from any Python context (CLI tools, background workers, tests, etc.).

All functions delegate to app.mgmt_db which uses psycopg2 with
ThreadedConnectionPool for thread-safe PostgreSQL access.

Quick start::

    from app.api_ma import init_db, create_user, create_api_key

    init_db()                         # creates tables + default admin
    key = create_api_key(             # returns plaintext ONCE
        user_id=1, name="ci-token", role="operator", expires_days=90,
    )
    print(key)                        # store this securely!
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

# Import everything from mgmt_db — this module is now a thin wrapper
from app.mgmt_db import (  # noqa: F401
    chat_add_message,
    chat_count_messages,
    chat_count_sessions,
    chat_create_session,
    chat_delete_session,
    chat_get_all_cost_summary,
    chat_get_cost_summary,
    chat_get_messages,
    chat_get_messages_for_agent,
    chat_get_session,
    chat_list_sessions,
    chat_prune_old_messages,
    chat_update_session,
    close_db,
    create_api_key,
    create_role,
    create_user,
    delete_api_key,
    delete_role,
    delete_user,
    describe_table,
    execute_delete,
    execute_insert,
    execute_query,
    execute_select,
    execute_update,
    get_api_key,
    get_role,
    get_role_permissions,
    get_user,
    get_user_by_username,
    has_permission,
    has_specific_permission,
    list_api_keys,
    list_audit_log,
    list_roles,
    list_tables,
    list_users,
    log_action,
    rotate_api_key,
    update_api_key,
    update_role,
    update_user,
    validate_api_key,
)

# Re-export authenticate_user which has the same signature
from app.mgmt_db import authenticate_user  # noqa: F401

logger = logging.getLogger(__name__)

# Valid roles (kept for backward compatibility)
VALID_ROLES = {"admin", "operator", "auditor"}


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize the PostgreSQL management database.

    Creates tables if they don't exist and seeds default admin user.

    The db_path parameter is ignored — it's kept for backward
    compatibility with the old JSON-based init_db() signature.
    All connection settings come from SAMBA_SHELL_PROJET_PG_*
    environment variables via app.config.
    """
    from app.config import get_settings
    settings = get_settings()

    from app.mgmt_db import init_db as _init_db
    _init_db(
        host=settings.SHELL_PROJET_PG_HOST,
        port=settings.SHELL_PROJET_PG_PORT,
        dbname=settings.SHELL_PROJET_PG_DBNAME,
        user=settings.SHELL_PROJET_PG_USER,
        password=settings.SHELL_PROJET_PG_PASSWORD,
        dsn=settings.SHELL_PROJET_PG_DSN or None,
        min_conn=settings.SHELL_PROJET_PG_POOL_MIN,
        max_conn=settings.SHELL_PROJET_PG_POOL_MAX,
    )

    logger.info("Management database initialized (PostgreSQL)")
