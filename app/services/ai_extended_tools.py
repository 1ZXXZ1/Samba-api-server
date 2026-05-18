"""
Extended AI Agent Tools for Samba AD Administration (v2.3).

Adds the following tools to the AI agent:
    - manage_samba_share  — Create, edit, delete Samba file shares
    - manage_samba_config — Read/modify smb.conf configuration
    - system_admin        — System administration (services, logs, processes, backups)
    - network_admin       — Network diagnostics and configuration
    - ai_skill_execute    — Execute a skill from the SKILL directory
    - request_api_access  — Request specific API endpoints based on permissions
    - manage_postgresql   — Manage PostgreSQL databases: list databases/tables, read/write/update/delete records, execute SQL queries
    - ldbsearch_ad        — Query Samba AD using ldbsearch (count, search, list, show, groups_of, members_of, disabled, locked, export)
                            v2.3: Auto-save snapshot (always, no need to call twice), dynamic preview (all rows when ≤30),
                            'dn' removed from preview (kept in snapshot), optimized for 1-step completion
    - data_import         — Auto-import data from API, files, JSON with field detection
    - data_export         — Export to multi-sheet XLSX (with charts!), CSV, JSON, TSV. Supports 'columns' param for column filtering.
    - data_transform      — Filter, sort, aggregate, pivot, merge, deduplicate, select (alias for select_columns), derive (alias for add_column)
    - data_diagram        — Create bar, line, pie, scatter, histogram, table diagrams

These tools are added to the existing AGENT_TOOLS list and dispatched
through the same _dispatch_tool_call mechanism.

v2.3: Optimize for 1-step completion — auto-save snapshot, dynamic preview, remove 'dn' from preview
v2.2: Fix group_count 0 bug — add group_count column to include_groups results;
      Fix _get_groups_bulk_map — use efficient memberOf query (1 step) instead of N+1 samba-tool calls;
      Fix _transform_enrich_with_groups — auto-find __groups_bulk_map__ snapshot + add group_count;
      Fix exclude filter — apply at LDAP query level + post-processing;
      Fix _safe_parse_tool_args — handle JSON true/false/null in tool arguments
v2.0: ldbsearch_ad one-step export — snapshot_name, include_groups, exclude, export_xlsx params
      reduce data export tasks from 10 steps to 1-2 steps (~0.10₽ instead of ~1.27₽)
v1.8.9: data_export 'columns' parameter, data_transform 'derive' alias, optimized system prompt
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Extended Tool Definitions (OpenAI-compatible function calling format)
# ═══════════════════════════════════════════════════════════════════════

EXTENDED_AGENT_TOOLS = [
    # ── Samba Share Management ────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "manage_samba_share",
            "description": (
                "Manage Samba file shares. Actions: "
                "'list' — list all shares from smb.conf, "
                "'create' — create a new share with specified path and options, "
                "'edit' — modify share configuration, "
                "'delete' — remove a share from smb.conf. "
                "Also creates the share directory and sets permissions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "create", "edit", "delete"],
                        "description": "Action to perform on the share.",
                    },
                    "name": {
                        "type": "string",
                        "description": "Share name (e.g. 'public', 'homes', 'data').",
                    },
                    "path": {
                        "type": "string",
                        "description": "Filesystem path for the share (for create/edit).",
                    },
                    "options": {
                        "type": "object",
                        "description": (
                            "Share options as key-value pairs. Common options: "
                            "comment, browseable, read only, writable, guest ok, "
                            "valid users, write list, create mask, directory mask, "
                            "force user, force group, vfs objects, etc."
                        ),
                        "additionalProperties": {"type": "string"},
                    },
                    "create_dir": {
                        "type": "boolean",
                        "description": "Create the share directory if it doesn't exist (default: true).",
                        "default": True,
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── Samba Configuration Management ────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "manage_samba_config",
            "description": (
                "Read and modify Samba configuration (smb.conf). Actions: "
                "'read' — read the full config or a specific section, "
                "'set_global' — set a global parameter, "
                "'get_global' — get a global parameter value, "
                "'test' — validate config with testparm, "
                "'reload' — reload Samba configuration (smbcontrol or systemctl)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "set_global", "get_global", "test", "reload"],
                        "description": "Action to perform.",
                    },
                    "section": {
                        "type": "string",
                        "description": "Section name (e.g. 'global', 'homes', or a share name).",
                    },
                    "parameter": {
                        "type": "string",
                        "description": "Parameter name (for set_global/get_global).",
                    },
                    "value": {
                        "type": "string",
                        "description": "Parameter value (for set_global).",
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── System Administration ─────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "system_admin",
            "description": (
                "System administration tool. Actions: "
                "'service_status' — check service status, "
                "'service_restart' — restart a service, "
                "'service_start' / 'service_stop' — start/stop a service, "
                "'journalctl' — read system logs, "
                "'df' — disk space usage, "
                "'free' — memory usage, "
                "'top' — process overview, "
                "'backup' — create a backup of specified paths, "
                "'restore' — restore from backup, "
                "'uptime' — system uptime info."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "service_status", "service_restart", "service_start", "service_stop",
                            "journalctl", "df", "free", "top", "backup", "restore", "uptime",
                        ],
                        "description": "System administration action.",
                    },
                    "service_name": {
                        "type": "string",
                        "description": "Service name (e.g. 'smbd', 'nmbd', 'samba', 'sshd').",
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of lines for journalctl/top output (default: 50).",
                        "default": 50,
                    },
                    "paths": {
                        "type": "string",
                        "description": "Comma-separated paths to backup.",
                    },
                    "backup_name": {
                        "type": "string",
                        "description": "Backup name/identifier (for restore).",
                    },
                    "unit": {
                        "type": "string",
                        "description": "Systemd unit for journalctl (e.g. 'smbd.service').",
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── Network Administration ────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "network_admin",
            "description": (
                "Network diagnostics and administration. Actions: "
                "'ping' — ping a host, "
                "'dns_lookup' — DNS lookup (dig/host), "
                "'netstat' — network connections, "
                "'ip_addr' — IP address info, "
                "'traceroute' — trace route to host, "
                "'smb_status' — Samba connection status, "
                "'firewall_status' — check firewall rules."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "ping", "dns_lookup", "netstat", "ip_addr",
                            "traceroute", "smb_status", "firewall_status",
                        ],
                        "description": "Network action.",
                    },
                    "host": {
                        "type": "string",
                        "description": "Target hostname or IP (for ping/dns_lookup/traceroute).",
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type (A, AAAA, MX, CNAME, SRV, etc.).",
                        "default": "A",
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── AI Skill Execution ────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "ai_skill_execute",
            "description": (
                "Execute an AI skill from the SKILL directory. Skills contain "
                "specialized knowledge about samba-tool, ldbsearch, smbclient, "
                "rpcclient, and other Samba administration tools. Use 'list' to "
                "see available skills, 'read' to get a skill's documentation, "
                "or 'apply' to execute a skill's recommended commands."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "read", "apply"],
                        "description": "Skill action: list skills, read skill docs, or apply skill.",
                    },
                    "skill_name": {
                        "type": "string",
                        "description": "Name of the skill (e.g. 'samba-tool-alt-linux-cli').",
                    },
                    "command": {
                        "type": "string",
                        "description": "Specific command to execute from the skill (for 'apply').",
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── PostgreSQL Database Management (v1.8.5-2 fix: direct psycopg2) ─
    {
        "type": "function",
        "function": {
            "name": "manage_postgresql",
            "description": (
                "Manage PostgreSQL databases. Full CRUD operations for database management. "
                "Actions: "
                "'list_databases' — list all databases on the server, "
                "'list_tables' — list tables in a database (current DB by default), "
                "'describe_table' — show table structure (columns, types, constraints), "
                "'select' — read/query records from a table with optional WHERE, ORDER BY, LIMIT, "
                "'count' — count records in a table with optional WHERE, "
                "'insert' — insert a new record into a table, "
                "'update' — update records in a table with WHERE condition, "
                "'delete' — delete records from a table with WHERE condition, "
                "'execute_query' — execute a raw SQL query (SELECT only for safety), "
                "'create_table' — create a new table with specified columns, "
                "'drop_table' — drop a table (DANGEROUS, requires confirmation). "
                "The database connection uses the same PostgreSQL instance as the management DB."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "list_databases", "list_tables", "describe_table",
                            "select", "count", "insert", "update", "delete",
                            "execute_query", "create_table", "drop_table",
                        ],
                        "description": "PostgreSQL management action.",
                    },
                    "database": {
                        "type": "string",
                        "description": "Database name (default: current management DB).",
                    },
                    "table": {
                        "type": "string",
                        "description": "Table name (for select/insert/update/delete/describe_table/count/create_table/drop_table).",
                    },
                    "columns": {
                        "type": "string",
                        "description": "Comma-separated column names for SELECT (default: '*' for all columns).",
                    },
                    "where": {
                        "type": "string",
                        "description": "WHERE condition for select/update/delete (e.g. \"id = 5\" or \"name LIKE '%test%'\").",
                    },
                    "order_by": {
                        "type": "string",
                        "description": "ORDER BY clause for select (e.g. 'created_at DESC').",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of rows to return (default: 100, max: 1000).",
                        "default": 100,
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Number of rows to skip (for pagination).",
                        "default": 0,
                    },
                    "data": {
                        "type": "object",
                        "description": "Data for insert/update as key-value pairs. For insert, all column values. For update, columns to change.",
                        "additionalProperties": True,
                    },
                    "query": {
                        "type": "string",
                        "description": "Raw SQL query for execute_query action (SELECT statements only).",
                    },
                    "table_definition": {
                        "type": "string",
                        "description": "SQL column definitions for create_table (e.g. 'id SERIAL PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW()').",
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation flag for destructive operations (drop_table, delete without where). Must be true to proceed.",
                        "default": False,
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── LDBSearch AD Query (v2.0: one-step data export) ──────────────
    {
        "type": "function",
        "function": {
            "name": "ldbsearch_ad",
            "description": (
                "Query Samba Active Directory database directly using ldbsearch. "
                "MUCH FASTER than execute_shell_command for AD queries — returns results in ONE step. "
                "v2.3: Auto-saves snapshot (no need to call twice). Dynamic preview (all rows when ≤30). "
                "'dn' column removed from preview (kept in snapshot for XLSX). "
                "Results include VALIDATION (approved/rejected) and are FILTERED by schema weights. "
                "Only W5+W3 attributes are shown in preview. Full data saved in snapshot for XLSX export. "
                "Actions: "
                "'count' — count objects by type (user, group, computer, ou, gpo, etc.), "
                "'search' — search for objects matching a filter, "
                "'list' — list objects of a given type with specified attributes, "
                "'show' — show details of a specific object by sAMAccountName, "
                "'groups_of' — list groups a user belongs to, "
                "'groups_bulk' — get groups for ALL users in ONE step! Returns dict {username: [groups]}. "
                "'members_of' — list members of a group, "
                "'disabled' — list disabled accounts, "
                "'locked' — list locked accounts. "
                "ONE-STEP EXPORT: set export_xlsx='filename.xlsx' to auto-export to XLSX without separate data_export call! "
                "Use include_groups=true to add 'groups' column automatically. "
                "Use exclude='Administrator,Guest,krbtgt' to filter out system accounts. "
                "computer (SUP user): inherits user attrs + dNSHostName, operatingSystem, userAccountControl, servicePrincipalName, etc. "
                "Uses /var/lib/samba/private/sam.ldb on the server."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["count", "search", "list", "show", "groups_of", "groups_bulk", "members_of", "disabled", "locked", "export"],
                        "description": (
                            "LDBSearch action. 'groups_bulk' gets ALL user groups in ONE step instead of calling groups_of N times. "
                            "'export' is alias for 'list' with auto-export (requires export_xlsx param)."
                        ),
                    },
                    "object_type": {
                        "type": "string",
                        "enum": ["user", "group", "computer", "ou", "gpo", "dns_zone", "trust", "site", "contact", "service_account"],
                        "description": "Type of AD object (for count, list, disabled actions).",
                    },
                    "name": {
                        "type": "string",
                        "description": "Object name/sAMAccountName (for show, groups_of, members_of).",
                    },
                    "filter": {
                        "type": "string",
                        "description": "Custom LDAP filter for search action (e.g. '(sAMAccountName=ivanov)').",
                    },
                    "attributes": {
                        "type": "string",
                        "description": "Comma-separated attributes to return (default: key attributes for the object type).",
                    },
                    "base_dn": {
                        "type": "string",
                        "description": "Base DN for search (default: domain root).",
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["sub", "one", "base"],
                        "description": "Search scope (default: sub).",
                        "default": "sub",
                    },
                    "snapshot_name": {
                        "type": "string",
                        "description": "Optional custom name for the snapshot. If omitted, auto-saved as '__ldb_auto__'. Data is ALWAYS saved — no need to call ldbsearch_ad twice!",
                    },
                    "include_groups": {
                        "type": "boolean",
                        "description": "When true, automatically fetch groups for all users and add 'groups' column. Works with list/search/disabled/locked actions.",
                        "default": False,
                    },
                    "exclude": {
                        "type": "string",
                        "description": "Comma-separated sAMAccountNames to exclude from results. E.g. 'Administrator,Guest,krbtgt,default'.",
                    },
                    "export_xlsx": {
                        "type": "string",
                        "description": "When set to a filename (e.g. 'users_report.xlsx'), auto-export to XLSX after query. One-step data export!",
                    },
                    "export_columns": {
                        "type": "string",
                        "description": "Comma-separated columns to include in XLSX export (used with export_xlsx). E.g. 'sAMAccountName,cn,department,groups'.",
                    },
                    "chart_type": {
                        "type": "string",
                        "enum": ["bar", "line", "pie", "scatter", "histogram"],
                        "description": "Type of chart to embed on 2nd sheet of XLSX (used with export_xlsx).",
                    },
                    "chart_x": {
                        "type": "string",
                        "description": "Column for chart X axis / categories (used with export_xlsx + chart_type).",
                    },
                    "chart_y": {
                        "type": "string",
                        "description": "Column for chart Y axis / values (used with export_xlsx + chart_type).",
                    },
                    "chart_title": {
                        "type": "string",
                        "description": "Title for embedded chart (used with export_xlsx + chart_type).",
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── Dispenser Execute (v1.9.1) ──────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "dispenser_execute",
            "description": (
                "Execute a validated command via the dispenser proxy. "
                "The dispenser acts as a validator between AI and the actual "
                "command execution. AI sees only key fields (like sAMAccountName, "
                "displayName), while the user can access the full data through the "
                "dispenser. Actions: "
                "'ldb_query' — execute an ldbsearch query and return validated results, "
                "'shell_query' — execute a shell command and return validated results, "
                "'validate' — validate previously fetched data against criteria."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["ldb_query", "shell_query", "validate"],
                        "description": "Dispenser action to execute.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command or query to execute (e.g. ldbsearch parameters, shell command).",
                    },
                    "object_type": {
                        "type": "string",
                        "description": "Type of AD object for ldb_query (e.g. 'user', 'group').",
                    },
                    "attributes": {
                        "type": "string",
                        "description": "Comma-separated attributes to return as keys (partial data for AI).",
                    },
                    "filter": {
                        "type": "string",
                        "description": "LDAP filter for ldb_query.",
                    },
                    "validate_criteria": {
                        "type": "string",
                        "description": "Criteria for validate action (e.g. 'must_have:mail', 'count_lt:100').",
                    },
                    "snapshot_name": {
                        "type": "string",
                        "description": "Name to save the full data as a snapshot for later access.",
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── Execute API as specific user (v1.9.6-4) ─────────────────────────
    {
        "type": "function",
        "function": {
            "name": "execute_samba_api_as",
            "description": (
                "Call a Samba AD Management API endpoint on behalf of a specific user. "
                "The tool looks up the user by username or user ID, creates a temporary "
                "JWT access token with their role and permissions, and makes the API call "
                "using that identity. This allows testing RBAC permissions — for example, "
                "calling DELETE /api/v1/users/testuser as 'junior_admin' to verify that "
                "role does NOT have delete permission. "
                "Use this when you need to test or verify what a specific user/role can do. "
                "For regular API calls (as admin), use execute_samba_api instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                        "description": "HTTP method",
                    },
                    "path": {
                        "type": "string",
                        "description": "API endpoint path, e.g. /api/v1/users/",
                    },
                    "as_user": {
                        "type": "string",
                        "description": (
                            "Username or user ID to execute as. "
                            "Examples: 'junior_admin', '4', 'operator1'. "
                            "If numeric, treated as user_id; otherwise as username."
                        ),
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Query string parameters (key-value pairs)",
                        "additionalProperties": {"type": "string"},
                    },
                    "body_params": {
                        "type": "object",
                        "description": "JSON body for POST/PUT/PATCH requests",
                        "additionalProperties": True,
                    },
                },
                "required": ["method", "path", "as_user"],
            },
        },
    },

    # ── Permission-based API Access ───────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "request_api_access",
            "description": (
                "Request access to specific API endpoints based on the user's "
                "permissions. Instead of receiving the full API schema, the AI "
                "uses this tool to discover what endpoints are available for the "
                "current user and request specific endpoint details. "
                "Actions: "
                "'list_permissions' — list all permissions the current user has, "
                "'list_endpoints' — list available API endpoints for given permissions, "
                "'get_endpoint_detail' — get full details of a specific endpoint."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list_permissions", "list_endpoints", "get_endpoint_detail"],
                        "description": "API access discovery action.",
                    },
                    "permission_filter": {
                        "type": "string",
                        "description": "Filter permissions by category (e.g. 'user', 'group', 'dns').",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method for endpoint detail.",
                    },
                    "path": {
                        "type": "string",
                        "description": "API path for endpoint detail (e.g. '/api/v1/users/').",
                    },
                },
                "required": ["action"],
            },
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════
#  Data Tools — lazy-loaded from ai_data_tools module (v1.8.7)
# ═══════════════════════════════════════════════════════════════════════

def _get_data_tools():
    """Lazy-load DATA_AGENT_TOOLS to avoid import at module level."""
    from app.services.ai_data_tools import DATA_AGENT_TOOLS
    return DATA_AGENT_TOOLS


def get_all_extended_tools():
    """Return the combined list of all extended tools including data tools."""
    return EXTENDED_AGENT_TOOLS + _get_data_tools()


# ═══════════════════════════════════════════════════════════════════════
#  Samba Share Management Implementation
# ═══════════════════════════════════════════════════════════════════════


def _manage_samba_share(args: Dict[str, Any]) -> str:
    """Manage Samba file shares via smb.conf manipulation."""
    settings = get_settings()
    action = args.get("action", "list")
    name = args.get("name", "")
    path = args.get("path", "")
    options = args.get("options", {})
    create_dir = args.get("create_dir", True)

    smb_conf = getattr(settings, "SAMBA_SHARES_CONF", settings.SMB_CONF)
    shares_dir = getattr(settings, "SAMBA_SHARES_DIR", "/srv/samba/shares")

    try:
        if action == "list":
            return _list_shares(smb_conf)

        elif action == "create":
            if not name:
                return json.dumps({"error": "Share name is required for create action"})
            if not path:
                path = os.path.join(shares_dir, name)

            # Create directory if needed
            if create_dir and not os.path.exists(path):
                try:
                    os.makedirs(path, exist_ok=True)
                    # Set permissions for Samba share
                    os.chmod(path, 0o2775)  # SGID + rwxrwxr-x
                    logger.info("[AI-TOOL] Created share directory: %s", path)
                except OSError as exc:
                    return json.dumps({"error": f"Failed to create directory {path}: {exc}"})

            # Build share config
            default_options = {
                "comment": f"Samba share {name}",
                "path": path,
                "browseable": "yes",
                "writable": "yes",
                "valid users": f"@{name}",
                "create mask": "0660",
                "directory mask": "0770",
            }
            share_opts = {**default_options, **options}

            return _add_share_to_conf(smb_conf, name, share_opts)

        elif action == "edit":
            if not name:
                return json.dumps({"error": "Share name is required for edit action"})
            return _edit_share_in_conf(smb_conf, name, options, path)

        elif action == "delete":
            if not name:
                return json.dumps({"error": "Share name is required for delete action"})
            return _delete_share_from_conf(smb_conf, name)

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        logger.error("[AI-TOOL] manage_samba_share failed: %s", exc)
        return json.dumps({"error": f"Share management failed: {exc}"})


def _list_shares(smb_conf: str) -> str:
    """List all shares from smb.conf."""
    if not os.path.exists(smb_conf):
        return json.dumps({"error": f"smb.conf not found at {smb_conf}"})

    try:
        with open(smb_conf, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as exc:
        return json.dumps({"error": f"Failed to read smb.conf: {exc}"})

    shares = []
    current_section = None
    current_opts: Dict[str, str] = {}

    for line in content.splitlines():
        stripped = line.strip()
        # Skip comments and empty lines
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        # Section header [name]
        section_match = re.match(r"^\[(.+)\]$", stripped)
        if section_match:
            if current_section and current_section != "global":
                shares.append({"name": current_section, **current_opts})
            current_section = section_match.group(1).lower()
            current_opts = {}
            continue

        # Key = value
        kv_match = re.match(r"^(\S+)\s*=\s*(.+)$", stripped)
        if kv_match and current_section and current_section != "global":
            current_opts[kv_match.group(1).strip()] = kv_match.group(2).strip()

    # Don't forget the last section
    if current_section and current_section != "global":
        shares.append({"name": current_section, **current_opts})

    return json.dumps({"shares": shares, "total": len(shares)}, ensure_ascii=False)


def _add_share_to_conf(smb_conf: str, name: str, options: Dict[str, str]) -> str:
    """Add a new share section to smb.conf."""
    # Check if share already exists
    try:
        with open(smb_conf, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        if re.search(rf"^\[{re.escape(name)}\]", content, re.MULTILINE | re.IGNORECASE):
            return json.dumps({"error": f"Share '{name}' already exists in {smb_conf}. Use 'edit' action instead."})
    except Exception as exc:
        return json.dumps({"error": f"Failed to read smb.conf: {exc}"})

    # Build share section
    lines = [f"\n[{name}]"]
    for key, value in options.items():
        lines.append(f"    {key} = {value}")

    share_block = "\n".join(lines) + "\n"

    # Backup and write
    try:
        _backup_file(smb_conf)
        with open(smb_conf, "a", encoding="utf-8") as f:
            f.write(share_block)

        logger.info("[AI-TOOL] Added share '%s' to %s", name, smb_conf)
        return json.dumps({
            "success": True,
            "share": name,
            "message": f"Share '{name}' added to {smb_conf}. Run 'manage_samba_config' with action='reload' to apply.",
        })
    except Exception as exc:
        return json.dumps({"error": f"Failed to write smb.conf: {exc}"})


def _edit_share_in_conf(smb_conf: str, name: str, options: Dict[str, str], new_path: str = "") -> str:
    """Edit an existing share in smb.conf."""
    try:
        with open(smb_conf, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as exc:
        return json.dumps({"error": f"Failed to read smb.conf: {exc}"})

    # Find the share section
    in_section = False
    section_start = -1
    section_end = -1

    for i, line in enumerate(lines):
        stripped = line.strip()
        section_match = re.match(r"^\[(.+)\]$", stripped)
        if section_match:
            if in_section:
                section_end = i
                break
            if section_match.group(1).lower() == name.lower():
                in_section = True
                section_start = i

    if not in_section:
        return json.dumps({"error": f"Share '{name}' not found in {smb_conf}"})

    if section_end == -1:
        section_end = len(lines)

    # Modify options within the section
    _backup_file(smb_conf)

    new_lines = lines[:section_start + 1]
    existing_keys = set()

    for i in range(section_start + 1, section_end):
        line = lines[i]
        stripped = line.strip()

        # Check if this is another section
        if re.match(r"^\[(.+)\]$", stripped):
            break

        # Parse key = value
        kv_match = re.match(r"^(\S+)\s*=\s*(.+)$", stripped)
        if kv_match:
            key = kv_match.group(1).strip()
            existing_keys.add(key.lower())
            if key.lower() in {k.lower() for k in options}:
                # Replace with new value
                for opt_key, opt_val in options.items():
                    if opt_key.lower() == key.lower():
                        indent = line[:len(line) - len(line.lstrip())]
                        new_lines.append(f"{indent}{opt_key} = {opt_val}\n")
                        break
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    # Add new options that don't exist yet
    for opt_key, opt_val in options.items():
        if opt_key.lower() not in existing_keys:
            new_lines.append(f"    {opt_key} = {opt_val}\n")

    # Update path if specified
    if new_path:
        path_found = False
        for i, line in enumerate(new_lines):
            if re.match(r"^\s*path\s*=", line, re.IGNORECASE):
                new_lines[i] = f"    path = {new_path}\n"
                path_found = True
                break
        if not path_found:
            new_lines.append(f"    path = {new_path}\n")

    new_lines.extend(lines[section_end:])

    try:
        with open(smb_conf, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        logger.info("[AI-TOOL] Edited share '%s' in %s", name, smb_conf)
        return json.dumps({
            "success": True,
            "share": name,
            "message": f"Share '{name}' updated in {smb_conf}. Run 'manage_samba_config' with action='reload' to apply.",
        })
    except Exception as exc:
        return json.dumps({"error": f"Failed to write smb.conf: {exc}"})


def _delete_share_from_conf(smb_conf: str, name: str) -> str:
    """Delete a share section from smb.conf."""
    try:
        with open(smb_conf, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as exc:
        return json.dumps({"error": f"Failed to read smb.conf: {exc}"})

    _backup_file(smb_conf)

    new_lines = []
    skip = False
    found = False

    for line in lines:
        stripped = line.strip()
        section_match = re.match(r"^\[(.+)\]$", stripped)
        if section_match:
            if section_match.group(1).lower() == name.lower():
                skip = True
                found = True
                continue
            else:
                skip = False

        if not skip:
            new_lines.append(line)

    if not found:
        return json.dumps({"error": f"Share '{name}' not found in {smb_conf}"})

    try:
        with open(smb_conf, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        logger.info("[AI-TOOL] Deleted share '%s' from %s", name, smb_conf)
        return json.dumps({
            "success": True,
            "share": name,
            "message": f"Share '{name}' removed from {smb_conf}. Run 'manage_samba_config' with action='reload' to apply.",
        })
    except Exception as exc:
        return json.dumps({"error": f"Failed to write smb.conf: {exc}"})


# ═══════════════════════════════════════════════════════════════════════
#  Samba Configuration Management Implementation
# ═══════════════════════════════════════════════════════════════════════


def _manage_samba_config(args: Dict[str, Any]) -> str:
    """Manage Samba configuration (smb.conf)."""
    settings = get_settings()
    action = args.get("action", "read")
    section = args.get("section", "")
    parameter = args.get("parameter", "")
    value = args.get("value", "")

    smb_conf = getattr(settings, "SAMBA_SHARES_CONF", settings.SMB_CONF)

    try:
        if action == "read":
            return _read_smb_conf(smb_conf, section)

        elif action == "get_global":
            return _get_global_param(smb_conf, parameter)

        elif action == "set_global":
            if not parameter:
                return json.dumps({"error": "Parameter name is required for set_global"})
            return _set_global_param(smb_conf, parameter, value)

        elif action == "test":
            return _testparm(smb_conf)

        elif action == "reload":
            return _reload_samba()

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        logger.error("[AI-TOOL] manage_samba_config failed: %s", exc)
        return json.dumps({"error": f"Config management failed: {exc}"})


def _read_smb_conf(smb_conf: str, section: str = "") -> str:
    """Read smb.conf content."""
    if not os.path.exists(smb_conf):
        return json.dumps({"error": f"smb.conf not found at {smb_conf}"})

    try:
        with open(smb_conf, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        if section:
            # Extract specific section
            pattern = rf"^\[{re.escape(section)}\]\s*\n(.*?)(?=^\[|\Z)"
            match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE | re.DOTALL)
            if match:
                return json.dumps({
                    "section": section,
                    "content": match.group(0).strip(),
                    "file": smb_conf,
                })
            return json.dumps({"error": f"Section [{section}] not found"})

        return json.dumps({"content": content, "file": smb_conf})

    except Exception as exc:
        return json.dumps({"error": f"Failed to read smb.conf: {exc}"})


def _get_global_param(smb_conf: str, parameter: str) -> str:
    """Get a global parameter value from smb.conf."""
    try:
        result = subprocess.run(
            ["testparm", "--parameter-name", parameter, f"--configfile={smb_conf}", "--suppress-prompt"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return json.dumps({"parameter": parameter, "value": result.stdout.strip()})
        return json.dumps({"error": f"Parameter '{parameter}' not found: {result.stderr.strip()}"})
    except Exception as exc:
        return json.dumps({"error": f"Failed to get parameter: {exc}"})


def _set_global_param(smb_conf: str, parameter: str, value: str) -> str:
    """Set a global parameter in smb.conf."""
    try:
        with open(smb_conf, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as exc:
        return json.dumps({"error": f"Failed to read smb.conf: {exc}"})

    _backup_file(smb_conf)

    in_global = False
    param_found = False
    new_lines = []

    for line in lines:
        stripped = line.strip()
        section_match = re.match(r"^\[(.+)\]$", stripped)

        if section_match:
            if section_match.group(1).lower() == "global":
                in_global = True
            else:
                # If we were in global and didn't find the param, add it before leaving
                if in_global and not param_found:
                    new_lines.append(f"    {parameter} = {value}\n")
                    param_found = True
                in_global = False

        if in_global and not param_found:
            kv_match = re.match(r"^(\s*)(\S+)\s*=\s*(.+)$", stripped)
            if kv_match and kv_match.group(2).lower() == parameter.lower():
                indent = kv_match.group(1)
                new_lines.append(f"{indent}{parameter} = {value}\n")
                param_found = True
                continue

        new_lines.append(line)

    # If global section exists but param was at the end
    if in_global and not param_found:
        new_lines.append(f"    {parameter} = {value}\n")

    try:
        with open(smb_conf, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        return json.dumps({
            "success": True,
            "parameter": parameter,
            "value": value,
            "message": f"Parameter '{parameter}' set to '{value}'. Run 'manage_samba_config' with action='reload' to apply.",
        })
    except Exception as exc:
        return json.dumps({"error": f"Failed to write smb.conf: {exc}"})


def _testparm(smb_conf: str) -> str:
    """Validate smb.conf with testparm."""
    try:
        result = subprocess.run(
            ["testparm", f"--configfile={smb_conf}", "--suppress-prompt"],
            capture_output=True, text=True, timeout=15,
        )
        return json.dumps({
            "valid": result.returncode == 0,
            "output": result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout,
            "errors": result.stderr[-1000:] if result.stderr else "",
        })
    except Exception as exc:
        return json.dumps({"error": f"testparm failed: {exc}"})


def _reload_samba() -> str:
    """Reload Samba configuration."""
    # Try smbcontrol first (Samba AD DC)
    for cmd in [
        ["smbcontrol", "smbd", "reload-config"],
        ["systemctl", "reload", "smbd"],
        ["systemctl", "reload", "samba"],
        ["systemctl", "reload", "samba-ad-dc"],
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                return json.dumps({
                    "success": True,
                    "command": " ".join(cmd),
                    "message": "Samba configuration reloaded successfully.",
                })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return json.dumps({
        "error": "Could not reload Samba. Try manually: sudo smbcontrol smbd reload-config",
    })


# ═══════════════════════════════════════════════════════════════════════
#  System Administration Implementation
# ═══════════════════════════════════════════════════════════════════════


def _system_admin(args: Dict[str, Any]) -> str:
    """System administration tool."""
    action = args.get("action", "")
    service_name = args.get("service_name", "")
    lines = args.get("lines", 50)
    paths = args.get("paths", "")
    backup_name = args.get("backup_name", "")
    unit = args.get("unit", "")

    try:
        if action == "service_status":
            if not service_name:
                return json.dumps({"error": "service_name is required"})
            result = subprocess.run(
                ["systemctl", "status", service_name],
                capture_output=True, text=True, timeout=10,
            )
            return json.dumps({
                "service": service_name,
                "active": "active" in result.stdout,
                "output": result.stdout[-2000:] if result.stdout else result.stderr,
            })

        elif action in ("service_restart", "service_start", "service_stop"):
            if not service_name:
                return json.dumps({"error": "service_name is required"})
            svc_action = action.replace("service_", "")
            result = subprocess.run(
                ["systemctl", svc_action, service_name],
                capture_output=True, text=True, timeout=30,
            )
            return json.dumps({
                "success": result.returncode == 0,
                "service": service_name,
                "action": svc_action,
                "output": result.stdout + result.stderr,
            })

        elif action == "journalctl":
            cmd = ["journalctl", "-n", str(lines), "--no-pager"]
            if unit:
                cmd.extend(["-u", unit])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return json.dumps({"logs": result.stdout[-3000:], "unit": unit or "all"})

        elif action == "df":
            result = subprocess.run(["df", "-h"], capture_output=True, text=True, timeout=10)
            return json.dumps({"output": result.stdout})

        elif action == "free":
            result = subprocess.run(["free", "-h"], capture_output=True, text=True, timeout=10)
            return json.dumps({"output": result.stdout})

        elif action == "top":
            result = subprocess.run(
                ["ps", "aux", "--sort=-%mem"], capture_output=True, text=True, timeout=10,
            )
            lines_out = result.stdout.splitlines()[:lines]
            return json.dumps({"processes": lines_out})

        elif action == "backup":
            if not paths:
                return json.dumps({"error": "paths is required for backup action"})
            settings = get_settings()
            backup_dir = os.path.join(
                getattr(settings, "AI_AGENT_EXPORT_DIR", "/home/AD-API-USER/ai-exports"),
                "backups",
            )
            os.makedirs(backup_dir, exist_ok=True)

            ts = _now_compact()
            bname = backup_name or f"backup_{ts}"
            backup_path = os.path.join(backup_dir, f"{bname}.tar.gz")

            path_list = [p.strip() for p in paths.split(",") if p.strip()]
            existing_paths = [p for p in path_list if os.path.exists(p)]

            if not existing_paths:
                return json.dumps({"error": f"None of the specified paths exist: {paths}"})

            result = subprocess.run(
                ["tar", "czf", backup_path] + existing_paths,
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                size = os.path.getsize(backup_path)
                return json.dumps({
                    "success": True,
                    "backup_path": backup_path,
                    "size_bytes": size,
                    "sources": existing_paths,
                })
            return json.dumps({"error": f"Backup failed: {result.stderr}"})

        elif action == "uptime":
            result = subprocess.run(["uptime"], capture_output=True, text=True, timeout=5)
            return json.dumps({"output": result.stdout.strip()})

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        return json.dumps({"error": f"System admin failed: {exc}"})


# ═══════════════════════════════════════════════════════════════════════
#  Network Administration Implementation
# ═══════════════════════════════════════════════════════════════════════


def _network_admin(args: Dict[str, Any]) -> str:
    """Network diagnostics and administration."""
    action = args.get("action", "")
    host = args.get("host", "")
    record_type = args.get("record_type", "A")

    try:
        if action == "ping":
            if not host:
                return json.dumps({"error": "host is required for ping"})
            result = subprocess.run(
                ["ping", "-c", "4", "-W", "5", host],
                capture_output=True, text=True, timeout=15,
            )
            return json.dumps({"host": host, "output": result.stdout, "success": result.returncode == 0})

        elif action == "dns_lookup":
            if not host:
                return json.dumps({"error": "host is required for dns_lookup"})
            result = subprocess.run(
                ["dig", "+short", host, record_type],
                capture_output=True, text=True, timeout=10,
            )
            return json.dumps({
                "host": host,
                "type": record_type,
                "results": result.stdout.strip().splitlines(),
            })

        elif action == "netstat":
            result = subprocess.run(
                ["ss", "-tulnp"],
                capture_output=True, text=True, timeout=10,
            )
            return json.dumps({"output": result.stdout[-3000:]})

        elif action == "ip_addr":
            result = subprocess.run(
                ["ip", "addr", "show"],
                capture_output=True, text=True, timeout=10,
            )
            return json.dumps({"output": result.stdout[-3000:]})

        elif action == "traceroute":
            if not host:
                return json.dumps({"error": "host is required for traceroute"})
            result = subprocess.run(
                ["traceroute", "-m", "15", host],
                capture_output=True, text=True, timeout=30,
            )
            return json.dumps({"host": host, "output": result.stdout})

        elif action == "smb_status":
            result = subprocess.run(
                ["smbstatus"],
                capture_output=True, text=True, timeout=10,
            )
            return json.dumps({"output": result.stdout[-3000:]})

        elif action == "firewall_status":
            for cmd in [["iptables", "-L", "-n"], ["nft", "list", "ruleset"]]:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        return json.dumps({"tool": cmd[0], "output": result.stdout[-3000:]})
                except FileNotFoundError:
                    continue
            return json.dumps({"error": "No firewall tool found (iptables/nft)"})

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        return json.dumps({"error": f"Network admin failed: {exc}"})


# ═══════════════════════════════════════════════════════════════════════
#  AI Skill Execution Implementation
# ═══════════════════════════════════════════════════════════════════════


def _ai_skill_execute(args: Dict[str, Any]) -> str:
    """Execute an AI skill from the SKILL directory."""
    settings = get_settings()
    action = args.get("action", "list")
    skill_name = args.get("skill_name", "")
    command = args.get("command", "")

    if not getattr(settings, "AI_SKILLS_ENABLED", True):
        return json.dumps({"error": "AI skills are disabled by administrator"})

    skills_dir = getattr(settings, "AI_SKILLS_DIR", "")
    if not skills_dir:
        # Default to app/models/ai/SKILL/
        skills_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "ai", "SKILL")

    if not os.path.isdir(skills_dir):
        return json.dumps({"error": f"Skills directory not found: {skills_dir}"})

    try:
        if action == "list":
            skills = []
            for item in sorted(os.listdir(skills_dir)):
                skill_path = os.path.join(skills_dir, item)
                if os.path.isdir(skill_path):
                    skill_md = os.path.join(skill_path, "SKILL.md")
                    has_doc = os.path.exists(skill_md)
                    skills.append({
                        "name": item,
                        "has_documentation": has_doc,
                    })
            return json.dumps({"skills": skills, "total": len(skills), "directory": skills_dir})

        elif action == "read":
            if not skill_name:
                return json.dumps({"error": "skill_name is required for read action"})

            skill_path = os.path.join(skills_dir, skill_name, "SKILL.md")
            if not os.path.exists(skill_path):
                return json.dumps({"error": f"Skill '{skill_name}' not found (no SKILL.md)"})

            with open(skill_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Also read references if they exist
            refs_dir = os.path.join(skills_dir, skill_name, "references")
            references = {}
            if os.path.isdir(refs_dir):
                for ref_file in os.listdir(refs_dir):
                    if ref_file.endswith(".md"):
                        try:
                            with open(os.path.join(refs_dir, ref_file), "r", encoding="utf-8", errors="replace") as f:
                                references[ref_file] = f.read()[:3000]
                        except Exception:
                            pass

            return json.dumps({
                "skill": skill_name,
                "documentation": content[:8000],
                "references": {k: v[:2000] for k, v in references.items()} if references else {},
            })

        elif action == "apply":
            if not skill_name:
                return json.dumps({"error": "skill_name is required for apply action"})
            if not command:
                return json.dumps({"error": "command is required for apply action"})

            # Build command with Samba environment variables
            env_vars = _get_samba_env_for_skill()

            # Execute command with environment
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, **env_vars},
            )

            output = result.stdout or ""
            if result.stderr:
                output += f"\n[STDERR]: {result.stderr}"
            if result.returncode != 0:
                output += f"\n[EXIT CODE]: {result.returncode}"

            return json.dumps({
                "skill": skill_name,
                "command": command,
                "output": output[:3000],
                "exit_code": result.returncode,
            })

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        return json.dumps({"error": f"Skill execution failed: {exc}"})


def _get_samba_env_for_skill() -> Dict[str, str]:
    """Get Samba-related environment variables for skill execution.

    These variables are sourced from .env and passed to skill commands
    so that skills can use SAMBA_TDB_URL, SAMBA_CREDENTIALS_USER, etc.
    """
    settings = get_settings()
    env = {}

    # Map settings fields to environment variables for skills
    env_mappings = {
        "TDB_URL": "SAMBA_TDB_URL",
        "TDB_SAM_LDB_PATH": "SAMBA_TDB_SAM_LDB_PATH",
        "CREDENTIALS_USER": "SAMBA_CREDENTIALS_USER",
        "CREDENTIALS_PASSWORD": "SAMBA_CREDENTIALS_PASSWORD",
        "USE_KERBEROS": "SAMBA_USE_KERBEROS",
        "SMB_CONF": "SAMBA_SMB_CONF",
        "TOOL_PATH": "SAMBA_TOOL_PATH",
        "LDBSEARCH_PATH": "SAMBA_LDBSEARCH_PATH",
        "SERVER": "SAMBA_SERVER",
        "DC_HOSTNAME": "SAMBA_DC_HOSTNAME",
        "REALM": "SAMBA_REALM",
        "DOMAIN_DN": "SAMBA_DOMAIN_DN",
        "LDAP_URL": "SAMBA_LDAP_URL",
        "LDAPI_URL": "SAMBA_LDAPI_URL",
        "JSON_MODE": "SAMBA_JSON_MODE",
    }

    for settings_attr, env_var in env_mappings.items():
        value = getattr(settings, settings_attr, "")
        if value:
            env[env_var] = str(value)

    return env


# ═══════════════════════════════════════════════════════════════════════
#  Permission-based API Access Implementation
# ═══════════════════════════════════════════════════════════════════════


def _request_api_access(args: Dict[str, Any], user_permissions: Optional[set] = None) -> str:
    """Request API access based on user permissions.

    Instead of sending the full API schema, the AI uses this tool to
    discover what endpoints are available for the current user.
    """
    action = args.get("action", "list_permissions")
    permission_filter = args.get("permission_filter", "")
    method = args.get("method", "")
    path = args.get("path", "")

    try:
        from app.permissions import (
            ALL_PERMISSIONS,
            get_permissions_by_category,
            resolve_permission,
        )

        if action == "list_permissions":
            all_perms = get_permissions_by_category()

            if permission_filter:
                all_perms = {
                    k: v for k, v in all_perms.items()
                    if k.startswith(permission_filter.lower())
                }

            # Filter by user's actual permissions if available
            if user_permissions:
                filtered = {}
                for cat, perms in all_perms.items():
                    user_perms = [p for p in perms if p in user_permissions]
                    if user_perms:
                        filtered[cat] = user_perms
                all_perms = filtered

            return json.dumps({
                "permissions": all_perms,
                "total_categories": len(all_perms),
                "note": "Use 'list_endpoints' to see API endpoints for these permissions.",
            })

        elif action == "list_endpoints":
            from app.permissions import _PATH_PERM_MAP

            endpoints = []
            for m, prefix, perm in _PATH_PERM_MAP:
                # Filter by user permissions
                if user_permissions and perm not in user_permissions:
                    continue

                # Filter by category
                if permission_filter and not perm.startswith(permission_filter.lower()):
                    continue

                endpoints.append({
                    "method": m,
                    "path": prefix,
                    "permission": perm,
                })

            return json.dumps({
                "endpoints": endpoints,
                "total": len(endpoints),
                "note": "Use 'get_endpoint_detail' to get full details of a specific endpoint.",
            })

        elif action == "get_endpoint_detail":
            if not method or not path:
                return json.dumps({"error": "method and path are required for get_endpoint_detail"})

            # Find the permission for this endpoint
            perm = resolve_permission(method, path)

            # Check user has this permission
            if user_permissions and perm and perm not in user_permissions:
                return json.dumps({
                    "error": f"User does not have permission '{perm}' for {method} {path}",
                })

            # Get endpoint details from OpenAPI schema
            from app.services.ai_service import load_openapi_schema
            compressed_str, _ = load_openapi_schema()

            try:
                schema = json.loads(compressed_str)
            except json.JSONDecodeError:
                return json.dumps({"error": "API schema not available"})

            # Find the endpoint in the schema
            for schema_path, methods in schema.items():
                if schema_path == path or path.startswith(schema_path):
                    for schema_method, details in methods.items():
                        if schema_method.upper() == method.upper():
                            detail = {
                                "method": method.upper(),
                                "path": schema_path,
                                "permission": perm,
                            }
                            if isinstance(details, dict):
                                detail.update(details)
                            return json.dumps(detail, ensure_ascii=False)

            return json.dumps({
                "method": method.upper(),
                "path": path,
                "permission": perm,
                "note": "Endpoint found in permission map but not in current schema detail.",
            })

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        return json.dumps({"error": f"API access request failed: {exc}"})


# ═══════════════════════════════════════════════════════════════════════
#  PostgreSQL Database Management Implementation (v1.8.5-2)
# ═══════════════════════════════════════════════════════════════════════


def _pg_get_conn(database: Optional[str] = None):
    """Get a psycopg2 connection, optionally to a different database.

    Uses the same PG credentials as the management DB pool (from config).
    If *database* is provided, connects to that database instead of the
    default one.  The caller is responsible for closing the connection.
    """
    try:
        import psycopg2
    except ImportError:
        raise ImportError(
            "psycopg2 is required for PostgreSQL management. "
            "Install with: apt-get install python3-psycopg2 or pip install psycopg2-binary"
        )

    settings = get_settings()
    dsn = getattr(settings, "SHELL_PROJET_PG_DSN", "") or ""
    dbname = database or getattr(settings, "SHELL_PROJET_PG_DBNAME", "samba_api")

    if dsn:
        # Replace the database name in the DSN if needed
        if database and "dbname=" in dsn:
            import re
            dsn = re.sub(r"dbname=\w+", f"dbname={database}", dsn)
        elif database:
            dsn = f"{dsn} dbname={database}" if not dsn.rstrip().endswith(" ") else f"{dsn}dbname={database}"
        conn = psycopg2.connect(dsn)
    else:
        conn = psycopg2.connect(
            host=getattr(settings, "SHELL_PROJET_PG_HOST", "localhost"),
            port=getattr(settings, "SHELL_PROJET_PG_PORT", 5432),
            dbname=dbname,
            user=getattr(settings, "SHELL_PROJET_PG_USER", "samba_api"),
            password=getattr(settings, "SHELL_PROJET_PG_PASSWORD", ""),
        )

    conn.autocommit = True
    return conn


def _pg_query(conn, sql: str, params: Optional[tuple] = None, fetch: bool = True) -> Any:
    """Execute a SQL statement on *conn* and return results."""
    with conn.cursor() as cur:
        cur.execute(sql, params)
        if fetch and cur.description:
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            return [dict(zip(columns, row)) for row in rows]
        if fetch:
            return []
        return {"rows_affected": cur.rowcount}


def _manage_postgresql(args: Dict[str, Any]) -> str:
    """Manage PostgreSQL databases via direct psycopg2 connections.

    v1.8.5-2 fix: Rewritten to use psycopg2 directly instead of going
    through app.api_ma / app.mgmt_db, because:

    1. The mgmt_db functions (execute_query, list_tables, etc.) do NOT
       accept a ``database`` keyword argument, causing "got an unexpected
       keyword argument 'database'" errors every time the AI agent tries
       to specify a database.

    2. The mgmt_db execute_select/insert/update/delete functions have
       hardcoded ``allowed_tables`` whitelists that only include internal
       management tables, so the agent cannot query user tables.

    This implementation opens its own psycopg2 connection (optionally to
    a different database) and closes it after each call, which avoids
    both problems while keeping the existing safety checks.

    Safety measures:
    - Destructive operations (drop_table, delete without WHERE) require confirm=True
    - Raw SQL queries are limited to SELECT statements (checked via regex)
    - Results are truncated to prevent token overflow
    - All operations are audit-logged
    """
    action = args.get("action", "")
    database = args.get("database") or None
    table = args.get("table", "")
    columns = args.get("columns", "*")
    where = args.get("where", "")
    order_by = args.get("order_by", "")
    limit = min(args.get("limit", 100), 1000)
    offset = args.get("offset", 0)
    data = args.get("data") or {}
    query = args.get("query", "")
    table_definition = args.get("table_definition", "")
    confirm = args.get("confirm", False)

    conn = None
    try:
        # list_databases must always connect to the default DB (or 'postgres')
        if action == "list_databases":
            target_db = database or "postgres"
        else:
            target_db = database

        conn = _pg_get_conn(target_db)

        if action == "list_databases":
            rows = _pg_query(
                conn,
                "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size "
                "FROM pg_database WHERE datistemplate = false ORDER BY datname",
            )
            return json.dumps({"databases": rows, "total": len(rows)}, ensure_ascii=False)

        elif action == "list_tables":
            rows = _pg_query(
                conn,
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name",
            )
            # Enrich with row counts
            result = []
            for r in rows:
                tbl = r["table_name"]
                try:
                    cnt = _pg_query(conn, f"SELECT COUNT(*) AS cnt FROM {tbl}")
                    result.append({"table": tbl, "row_count": cnt[0]["cnt"] if cnt else -1})
                except Exception:
                    result.append({"table": tbl, "row_count": -1})
            return json.dumps({"tables": result, "total": len(result)}, ensure_ascii=False)

        elif action == "describe_table":
            if not table:
                return json.dumps({"error": "table is required for describe_table action"})
            rows = _pg_query(
                conn,
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns "
                "WHERE table_name = %s AND table_schema = 'public' "
                "ORDER BY ordinal_position",
                (table,),
            )
            return json.dumps(
                {"table": table, "columns": [
                    {"column": r["column_name"], "type": r["data_type"],
                     "nullable": r["is_nullable"] == "YES", "default": r["column_default"]}
                    for r in rows
                ]},
                ensure_ascii=False,
            )

        elif action == "select":
            if not table:
                return json.dumps({"error": "table is required for select action"})
            cols = columns if columns else "*"
            sql = f"SELECT {cols} FROM {table}"
            if where:
                sql += f" WHERE {where}"
            if order_by:
                sql += f" ORDER BY {order_by}"
            sql += f" LIMIT {limit} OFFSET {offset}"
            rows = _pg_query(conn, sql)
            return json.dumps({"table": table, "rows": rows, "count": len(rows)}, ensure_ascii=False)

        elif action == "count":
            if not table:
                return json.dumps({"error": "table is required for count action"})
            sql = f"SELECT COUNT(*) AS count FROM {table}"
            if where:
                sql += f" WHERE {where}"
            rows = _pg_query(conn, sql)
            count_val = rows[0]["count"] if rows else 0
            return json.dumps({"table": table, "count": count_val})

        elif action == "insert":
            if not table:
                return json.dumps({"error": "table is required for insert action"})
            if not data:
                return json.dumps({"error": "data is required for insert action"})
            cols = ", ".join(data.keys())
            placeholders = ", ".join(["%s"] * len(data))
            values = list(data.values())
            sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders}) RETURNING *"
            rows = _pg_query(conn, sql, tuple(values))
            return json.dumps({"success": True, "table": table, "rows": rows}, ensure_ascii=False)

        elif action == "update":
            if not table:
                return json.dumps({"error": "table is required for update action"})
            if not data:
                return json.dumps({"error": "data is required for update action"})
            if not where:
                return json.dumps({"error": "where condition is required for update action (use confirm=true with '1=1' to update all)"})
            set_clause = ", ".join(f"{k} = %s" for k in data.keys())
            values = list(data.values())
            sql = f"UPDATE {table} SET {set_clause} WHERE {where} RETURNING *"
            rows = _pg_query(conn, sql, tuple(values))
            return json.dumps({"success": True, "table": table, "rows": rows, "message": f"Records updated in {table} where {where}"}, ensure_ascii=False)

        elif action == "delete":
            if not table:
                return json.dumps({"error": "table is required for delete action"})
            if not where and not confirm:
                return json.dumps({
                    "error": "Delete without WHERE condition is dangerous. Set confirm=true to delete all records.",
                    "hint": "Add a WHERE condition or set confirm=true to proceed.",
                })
            where_clause = where or "1=1"
            sql = f"DELETE FROM {table} WHERE {where_clause} RETURNING *"
            rows = _pg_query(conn, sql)
            return json.dumps({"success": True, "table": table, "rows_deleted": len(rows), "message": f"Records deleted from {table} where {where_clause}"}, ensure_ascii=False)

        elif action == "execute_query":
            if not query:
                return json.dumps({"error": "query is required for execute_query action"})
            # Safety: Only allow SELECT statements
            query_stripped = query.strip().upper()
            if not query_stripped.startswith("SELECT") and not query_stripped.startswith("WITH"):
                return json.dumps({"error": "Only SELECT/WITH queries are allowed for safety. Use insert/update/delete actions for data modifications."})
            # Block dangerous keywords
            dangerous = ["DROP ", "DELETE ", "UPDATE ", "INSERT ", "ALTER ", "CREATE ", "TRUNCATE ", "GRANT ", "REVOKE "]
            for kw in dangerous:
                if kw in query_stripped:
                    return json.dumps({"error": f"Query contains forbidden keyword '{kw.strip()}'. Use the appropriate action instead."})
            rows = _pg_query(conn, query)
            return json.dumps({"rows": rows, "count": len(rows)}, ensure_ascii=False)

        elif action == "create_table":
            if not table:
                return json.dumps({"error": "table is required for create_table action"})
            if not table_definition:
                return json.dumps({"error": "table_definition is required for create_table action (e.g. 'id SERIAL PRIMARY KEY, name TEXT NOT NULL')"})
            sql = f"CREATE TABLE IF NOT EXISTS {table} ({table_definition})"
            _pg_query(conn, sql, fetch=False)
            return json.dumps({
                "success": True,
                "table": table,
                "message": f"Table '{table}' created successfully. Use describe_table to verify structure.",
            })

        elif action == "drop_table":
            if not table:
                return json.dumps({"error": "table is required for drop_table action"})
            if not confirm:
                return json.dumps({
                    "error": f"Dropping table '{table}' is DANGEROUS and irreversible. Set confirm=true to proceed.",
                    "hint": f"Call again with confirm=true to drop table '{table}'.",
                })
            sql = f"DROP TABLE IF EXISTS {table} CASCADE"
            _pg_query(conn, sql, fetch=False)
            return json.dumps({
                "success": True,
                "table": table,
                "message": f"Table '{table}' dropped successfully.",
            })

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        logger.error("[AI-TOOL] manage_postgresql failed: %s", exc)
        return json.dumps({"error": f"PostgreSQL management failed: {exc}"})
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass



# ═══════════════════════════════════════════════════════════════════════
#  LDBSearch AD Query Implementation
# ═══════════════════════════════════════════════════════════════════════


# Default attributes per object type
_LDB_DEFAULT_ATTRS = {
    "user": "sAMAccountName cn displayName mail userAccountControl department",
    "group": "cn sAMAccountName description member groupType",
    "computer": "cn sAMAccountName dNSHostName operatingSystem operatingSystemVersion userAccountControl servicePrincipalName",
    "ou": "ou description",
    "gpo": "cn displayName gPCFileSysPath",
    "dns_zone": "dc dnsAllowDynamic",
    "trust": "cn flatName trustDirection trustType",
    "site": "cn",
    "contact": "cn mail displayName",
    "service_account": "sAMAccountName servicePrincipalName",
}

# Map object_type to LDAP objectClass
_LDB_OBJECT_CLASS = {
    "user": "user",  # NOTE: For 'user' type, LDAP filter also excludes computers (see _get_ldap_filter)
    "group": "group",
    "computer": "computer",
    "ou": "organizationalUnit",
    "gpo": "groupPolicyContainer",
    "dns_zone": "dnsZone",
    "trust": "trustedDomain",
    "site": "site",
    "contact": "contact",
    "service_account": "msDS-GroupManagedServiceAccount",
}

_LDB_DEFAULT_DB = "/var/lib/samba/private/sam.ldb"


# ═══════════════════════════════════════════════════════════════════════
#  LDBSearch Output Parsing & Post-Processing (v2.0)
# ═══════════════════════════════════════════════════════════════════════


def _parse_ldb_output_to_rows(raw_output: str) -> List[Dict[str, Any]]:
    """Parse ldbsearch text output into a list of dicts (tabular format).

    Handles:
    - Records separated by blank lines
    - Multi-valued attributes (same key appears multiple times → joined with ", ")
    - The "dn:" line as a regular attribute
    - Truncated output (doesn't crash on incomplete records)
    - Comment lines starting with #
    - Lines starting with "ref:" are skipped

    Example input:
        dn: CN=John,CN=Users,DC=example,DC=com
        sAMAccountName: john
        cn: John Smith
        department: IT

        dn: CN=Jane,CN=Users,DC=example,DC=com
        sAMAccountName: jane
        cn: Jane Doe

    Example output:
        [{"dn": "CN=John,...", "sAMAccountName": "john", "cn": "John Smith", "department": "IT"}, ...]
    """
    if not raw_output or raw_output.startswith("ERROR"):
        return []

    rows: List[Dict[str, Any]] = []
    current_row: Optional[Dict[str, Any]] = None

    for line in raw_output.splitlines():
        line = line.rstrip()

        # Skip comment lines and ref lines
        if line.startswith("#") or line.startswith("//"):
            continue
        if line.startswith("ref:"):
            continue

        # Blank line = record separator
        if not line.strip():
            if current_row is not None:
                rows.append(current_row)
                current_row = None
            continue

        # Attribute line: "key: value" (single colon = plain text)
        # or "key:: base64value" (double colon = base64 encoded, decode if possible)
        match = re.match(r"^([\w\-]+)::?\s+(.*)$", line)
        if match:
            key = match.group(1)
            value = match.group(2).strip()

            # Handle base64-encoded values (key:: value)
            if line[len(key):len(key) + 2] == "::":
                try:
                    import base64
                    value = base64.b64decode(value).decode("utf-8", errors="replace")
                except Exception:
                    pass  # Keep raw value if base64 decode fails

            if current_row is None:
                current_row = {}

            if key in current_row:
                # Multi-valued attribute: append with comma separator
                current_row[key] = str(current_row[key]) + ", " + value
            else:
                current_row[key] = value
        else:
            # Continuation line (starts with space) — append to previous attribute
            if current_row is not None and line.startswith(" "):
                last_key = list(current_row.keys())[-1] if current_row else None
                if last_key:
                    current_row[last_key] = str(current_row[last_key]) + line.strip()

    # Don't forget the last record
    if current_row is not None:
        rows.append(current_row)

    return rows


def _get_groups_bulk_map() -> Dict[str, List[str]]:
    """Fetch groups for ALL users in ONE step. Returns {username: [group1, group2, ...]}.

    v2.1: Replaced N+1 samba-tool user getgroups calls with a SINGLE ldbsearch
    query using memberOf attribute. This is dramatically faster for large AD
    deployments (1 query instead of N+1 queries, where N = number of users).

    How it works:
    - Runs ONE ldbsearch for all users with sAMAccountName + memberOf
    - Parses each memberOf DN to extract the CN (group name)
    - Returns a dict mapping username -> list of group names

    Fallback: If the memberOf query fails, falls back to the old N+1 approach.
    """
    db_path = _LDB_DEFAULT_DB
    users_groups: Dict[str, List[str]] = {}

    # ── Efficient approach: ONE ldbsearch with memberOf attribute ──
    try:
        cmd = (
            f'ldbsearch -H {db_path} '
            f'"(&(objectClass=user)(!(sAMAccountName=*$)))" '
            f'sAMAccountName memberOf'
        )
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60,
        )

        current_user = ""
        current_groups: List[str] = []

        for line in result.stdout.splitlines():
            if line.startswith("sAMAccountName:"):
                # Save previous user's groups
                if current_user:
                    users_groups[current_user] = current_groups
                current_user = line.split(":", 1)[1].strip()
                current_groups = []
            elif line.startswith("memberOf:"):
                dn = line.split(":", 1)[1].strip()
                # Extract CN from DN (e.g. "CN=Domain Admins,CN=Users,DC=..." -> "Domain Admins")
                match = re.match(r'CN=([^,]+)', dn, re.IGNORECASE)
                if match:
                    current_groups.append(match.group(1))

        # Don't forget the last user
        if current_user:
            users_groups[current_user] = current_groups

        if users_groups:
            logger.info("[AI-TOOL] _get_groups_bulk_map: found groups for %d users via memberOf (1 query)", len(users_groups))
            return users_groups

    except Exception as exc:
        logger.warning("[AI-TOOL] _get_groups_bulk_map memberOf approach failed: %s, trying fallback", exc)

    # ── Fallback: N+1 samba-tool approach (slower but more reliable) ──
    try:
        list_cmd = f'ldbsearch -H {db_path} "(&(objectClass=user)(!(sAMAccountName=*$)))" sAMAccountName'
        result = subprocess.run(
            list_cmd, shell=True, capture_output=True, text=True, timeout=30,
        )
        usernames: List[str] = []
        for line in result.stdout.splitlines():
            if line.startswith("sAMAccountName:"):
                uname = line.split(":", 1)[1].strip()
                if uname and not uname.endswith("$"):
                    usernames.append(uname)

        for uname in usernames:
            try:
                grp_cmd = f'samba-tool user getgroups {uname}'
                grp_result = subprocess.run(
                    grp_cmd, shell=True, capture_output=True, text=True, timeout=5,
                )
                groups: List[str] = []
                for gline in grp_result.stdout.splitlines():
                    gline = gline.strip()
                    if gline and not gline.startswith("User") and not gline.startswith("-") and gline != uname:
                        groups.append(gline)
                users_groups[uname] = groups
            except Exception:
                users_groups[uname] = []
    except Exception as exc:
        logger.warning("[AI-TOOL] _get_groups_bulk_map fallback also failed: %s", exc)

    return users_groups


def _get_samaccountname(row: Dict[str, Any]) -> str:
    """Extract sAMAccountName from a parsed ldbsearch row, case-insensitive.

    v1.9.1: ldbsearch output keys may have different casing depending on
    the query. This helper checks common variations.
    """
    for key in ("sAMAccountName", "samaccountname", "SamAccountName",
                "SAMAccountName", "SAMACCOUNTNAME"):
        if key in row:
            return str(row[key])
    # Fallback: search case-insensitively
    for key, val in row.items():
        if key.lower() == "samaccountname":
            return str(val)
    return ""


def _ldb_post_process(
    raw_output: str,
    action: str,
    snapshot_name: str = "",
    include_groups: bool = False,
    exclude_str: str = "",
    export_xlsx: str = "",
    export_columns: str = "",
    chart_type: str = "",
    chart_x: str = "",
    chart_y: str = "",
    chart_title: str = "",
    object_type: str = "",
    requested_attrs: str = "",
) -> Dict[str, Any]:
    """Post-process ldbsearch output: parse, validate, filter, exclude, add groups, save snapshot, export.

    v2.2: Added validation and schema-based filtering.
    Processing order:
    1. Parse raw ldbsearch text into tabular rows
    2. Validate result (approve/reject)
    3. Filter rows by schema weight (only W5+W3 attrs sent to AI)
    4. Apply exclude filter (remove specified sAMAccountNames)
    5. Apply include_groups (add 'groups' column via groups_bulk)
    6. Save FULL data to data snapshot (unfiltered — for XLSX export)
    7. Export to XLSX if requested
    8. Return filtered preview for AI + validation verdict
    """
    from app.services.ai_data_tools import _save_snapshot, _data_export_impl
    from app.services._ldb_validator import (
        validate_ldb_result,
        filter_result_by_schema,
    )

    result: Dict[str, Any] = {}

    # 1. Parse raw output to rows
    rows = _parse_ldb_output_to_rows(raw_output)
    if not rows:
        return {"snapshot_saved": False, "rows_parsed": 0, "post_process_note": "No tabular data found in ldbsearch output"}

    result["rows_parsed"] = len(rows)

    # 2. Apply exclude filter (v1.9.1: case-insensitive sAMAccountName lookup + computer account filtering)
    if exclude_str:
        exclude_names = {n.strip() for n in exclude_str.split(",") if n.strip()}
        before_count = len(rows)
        rows = [
            r for r in rows
            if _get_samaccountname(r) not in exclude_names
        ]
        result["excluded_count"] = before_count - len(rows)
        result["rows_after_exclude"] = len(rows)

    # 2b. Filter out computer accounts (sAMAccountName ending with '$')
    before_computer_filter = len(rows)
    rows = [
        r for r in rows
        if not _get_samaccountname(r).endswith("$")
    ]
    computer_filtered = before_computer_filter - len(rows)
    if computer_filtered > 0:
        result["computer_accounts_filtered"] = computer_filtered

    # 3. Apply include_groups
    if include_groups:
        try:
            groups_map = _get_groups_bulk_map()
            # Merge groups into each row based on sAMAccountName
            for row in rows:
                username = _get_samaccountname(row)
                user_groups = groups_map.get(username, [])
                row["groups"] = ", ".join(user_groups) if user_groups else ""
                # v2.1: Add group_count for easy charting (fixes group_count 0 bug)
                row["group_count"] = len(user_groups)
            # Also save the groups map to snapshots for data_transform enrich_with_groups
            _save_snapshot("__groups_bulk_map__", groups_map)
            result["groups_added"] = True
        except Exception as exc:
            logger.warning("[AI-TOOL] include_groups failed: %s", exc)
            result["groups_added"] = False
            result["groups_error"] = str(exc)

    # 4. Save FULL data to snapshot (before schema filtering — for XLSX export)
    # v2.3: ALWAYS auto-save snapshot (even without snapshot_name or export_xlsx)
    # so the AI doesn't need to re-query to save data. If no name given, use __ldb_auto__.
    snap_name = snapshot_name or "__ldb_auto__"
    _save_snapshot(snap_name, rows)
    result["snapshot_saved"] = True
    result["snapshot_name"] = snap_name
    result["rows"] = len(rows)
    cols = list(rows[0].keys()) if rows else []
    result["columns"] = cols

    # 5. Export to XLSX if requested (using FULL data from snapshot)
    if export_xlsx:
        try:
            export_args = {
                "action": "to_xlsx",
                "snapshot_name": snap_name or "__ldb_auto__",
                "filename": export_xlsx,
                "columns": export_columns or "",
                "chart_type": chart_type or "",
                "chart_x": chart_x or "",
                "chart_y": chart_y or "",
                "chart_title": chart_title or "",
            }
            export_result_str = _data_export_impl(export_args)
            try:
                result["export"] = json.loads(export_result_str)
            except (json.JSONDecodeError, TypeError):
                result["export"] = {"raw": str(export_result_str)[:500]}
        except Exception as exc:
            logger.warning("[AI-TOOL] export_xlsx failed: %s", exc)
            result["export_error"] = str(exc)

    # 6. v2.2: Validate result (approve/reject)
    validation = validate_ldb_result(
        object_type=object_type,
        requested_attrs=requested_attrs,
        result_data={
            "action": action,
            "rows": len(rows),
            "columns": list(rows[0].keys()) if rows else [],
            "preview": rows[:5],
        },
        action=action,
    )
    result["validation"] = validation

    if not validation["approved"]:
        logger.warning(
            "[AI-TOOL] ldbsearch_ad result REJECTED: %s",
            validation["validation_note"],
        )
        # Still return the result so AI can see the error, but mark it
        result["rejected"] = True
        return result

    # 7. v2.2: Filter preview by schema (only W5+W3 attributes for AI)
    # Full data stays in snapshot for XLSX export
    filtered_rows = filter_result_by_schema(
        object_type=object_type,
        rows=rows,
        min_weight="W3",  # W5 + W3 only (skip W1/rare attrs)
        extra_attrs=requested_attrs,
    )

    # v2.3: Remove 'dn' column from preview — AI doesn't need it and it
    # causes unnecessary data_transform select calls. Keep in snapshot.
    preview_rows = []
    for row in filtered_rows:
        preview_row = {k: v for k, v in row.items() if k != "dn"}
        preview_rows.append(preview_row)

    # v2.3: Dynamic preview size — show all rows when small result set
    # This prevents AI from showing [P*] tokens for rows beyond preview
    total_rows = len(preview_rows)
    if total_rows <= 30:
        preview_limit = total_rows  # Show ALL rows for small datasets
    elif total_rows <= 100:
        preview_limit = 20          # Show first 20 for medium datasets
    else:
        preview_limit = 5           # Show first 5 for large datasets

    result["preview"] = preview_rows[:preview_limit]
    result["preview_filtered"] = True
    result["preview_columns"] = list(preview_rows[0].keys()) if preview_rows else []

    return result


def _ldbsearch_ad(args: Dict[str, Any]) -> str:
    """Query Samba Active Directory database directly using ldbsearch.

    v2.3: Auto-saves snapshot always (no need to call twice with snapshot_name).
    Dynamic preview: shows all rows when ≤30, first 20 when ≤100, first 5 otherwise.
    'dn' column removed from preview (kept in snapshot for XLSX export).
    v2.0: Added snapshot_name, include_groups, exclude, export_xlsx params
    for one-step data export workflow (2 steps → 1 step).
    v2.3: Fix comma-separated attributes — ldbsearch expects SPACE-separated
    attrs, but AI sends comma-separated. Convert commas to spaces.
    """
    action = args.get("action", "")
    object_type = args.get("object_type", "")
    name = args.get("name", "")
    ldap_filter = args.get("filter", "")
    # v2.3: AI sends comma-separated attrs (e.g. "sAMAccountName,cn,department")
    # but ldbsearch expects space-separated. Keep original for validation.
    requested_attrs_raw = args.get("attributes", "")  # comma-separated, for validation
    attributes = requested_attrs_raw.replace(",", " ").strip()  # space-separated, for ldbsearch
    # Collapse multiple spaces into one
    attributes = re.sub(r'\s+', ' ', attributes)
    base_dn = args.get("base_dn", "")
    scope = args.get("scope", "sub")

    # v2.0: Post-processing parameters
    snapshot_name = args.get("snapshot_name", "")
    include_groups = args.get("include_groups", False)
    exclude_str = args.get("exclude", "")
    export_xlsx = args.get("export_xlsx", "")
    export_columns = args.get("export_columns", "")
    chart_type = args.get("chart_type", "")
    chart_x = args.get("chart_x", "")
    chart_y = args.get("chart_y", "")
    chart_title = args.get("chart_title", "")

    # 'export' action is alias for 'list' with auto-export
    if action == "export":
        action = "list"
        if not export_xlsx:
            export_xlsx = "export.xlsx"
        if not object_type:
            object_type = "user"

    db_path = _LDB_DEFAULT_DB

    # Capture full (untruncated) ldbsearch output for post-processing
    _full_ldb_output = ""

    def _run_ldb(cmd: str) -> str:
        """Run an ldbsearch command and return stdout, truncated to 3000 chars."""
        nonlocal _full_ldb_output
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30,
            )
            output = result.stdout
            if result.returncode != 0 and result.stderr:
                output += "\n" + result.stderr
            _full_ldb_output = output  # Save full output for post-processing
            if len(output) > 3000:
                output = output[:3000] + f"\n... [TRUNCATED: {len(output)} chars total]"
            return output
        except subprocess.TimeoutExpired:
            return "ERROR: ldbsearch command timed out after 30 seconds"
        except Exception as exc:
            return f"ERROR: {exc}"

    def _get_object_class() -> str:
        return _LDB_OBJECT_CLASS.get(object_type, object_type)

    def _get_ldap_filter() -> str:
        """Build LDAP filter for the object type.

        v1.9.1: For 'user' type, exclude computer accounts because in
        Active Directory, computer objects also have objectClass=user.
        We add (!(sAMAccountName=*$)) to exclude accounts ending with '$'
        (which are computer/workstation trust accounts).

        v2.1: Also add exclude filters at LDAP query level for efficiency
        (prevents fetching excluded users from the DB in the first place).
        """
        obj_class = _get_object_class()
        parts = [f"(objectClass={obj_class})"]

        # For 'user' type, exclude computer accounts
        if object_type == "user":
            parts.append("(!(sAMAccountName=*$))")

        # v2.1: Add exclude filters at LDAP level
        if exclude_str:
            for name in exclude_str.split(","):
                name = name.strip()
                if name:
                    # Escape special LDAP chars
                    escaped = name.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29").replace("*", "\\2a")
                    parts.append(f"(!(sAMAccountName={escaped}))")

        if len(parts) == 1:
            return parts[0]
        return "(&" + "".join(parts) + ")"

    def _get_default_attrs() -> str:
        return _LDB_DEFAULT_ATTRS.get(object_type, "dn")

    def _base_dn_arg() -> str:
        if base_dn:
            return f'-b "{base_dn}" '
        # For 'site' object type, search under Configuration naming context
        if object_type == "site":
            # Try to determine Configuration NC from the rootDSE
            try:
                r = subprocess.run(
                    f'ldbsearch -H {db_path} -s base -b "" defaultNamingContext configurationNamingContext',
                    shell=True, capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines():
                    if line.startswith("configurationNamingContext:"):
                        config_nc = line.split(":", 1)[1].strip()
                        return f'-b "{config_nc}" '
            except Exception:
                pass
        return ""

    def _scope_arg() -> str:
        if scope and scope != "sub":
            return f"-s {scope} "
        return ""

    # Import snapshot helper for structured output actions
    from app.services.ai_data_tools import _save_snapshot

    # Store the result for post-processing
    result = ""

    try:
        if action == "count":
            if not object_type:
                return json.dumps({"error": "object_type is required for count action"})
            base_arg = _base_dn_arg()
            ldap_filter = _get_ldap_filter()
            cmd = f'ldbsearch -H {db_path} {base_arg}"{ldap_filter}" dn'
            output = _run_ldb(cmd)
            # Count lines starting with 'dn:'
            count = sum(1 for line in output.splitlines() if line.startswith("dn:"))
            result = json.dumps({"object_type": object_type, "count": count})

        elif action == "search":
            if not ldap_filter:
                return json.dumps({"error": "filter is required for search action"})
            attrs = attributes if attributes else "dn"
            base_arg = _base_dn_arg()
            scope_arg = _scope_arg()
            cmd = f'ldbsearch -H {db_path} {base_arg}{scope_arg}{ldap_filter!r} {attrs}'
            output = _run_ldb(cmd)
            # Parse LDIF to structured rows (handles base64, multi-valued attrs)
            raw_for_parsing = _full_ldb_output if _full_ldb_output else output
            rows = _parse_ldb_output_to_rows(raw_for_parsing)

            # v2.3: Removed inline snapshot save + exclude filter —
            # _ldb_post_process handles these (avoids double-saves)

            # Build columns list
            columns = list(rows[0].keys()) if rows else []

            # Build structured result
            result_data = {
                "action": "search",
                "filter": ldap_filter,
                "rows": len(rows),
                "columns": columns,
                "preview": rows[:5],
            }
            result = json.dumps(result_data, ensure_ascii=False, default=str)

        elif action == "list":
            if not object_type:
                return json.dumps({"error": "object_type is required for list action"})
            attrs = attributes if attributes else _get_default_attrs()
            base_arg = _base_dn_arg()
            scope_arg = _scope_arg()
            ldap_filter = _get_ldap_filter()
            cmd = f'ldbsearch -H {db_path} {base_arg}{scope_arg}"{ldap_filter}" {attrs}'
            output = _run_ldb(cmd)
            # Parse LDIF to structured rows (handles base64, multi-valued attrs)
            raw_for_parsing = _full_ldb_output if _full_ldb_output else output
            rows = _parse_ldb_output_to_rows(raw_for_parsing)

            # v2.3: Removed inline snapshot save + exclude filter —
            # _ldb_post_process handles these (avoids double-saves)

            # Build columns list
            columns = list(rows[0].keys()) if rows else []

            # Build structured result
            result_data = {
                "action": "list",
                "object_type": object_type,
                "rows": len(rows),
                "columns": columns,
                "preview": rows[:5],
            }
            result = json.dumps(result_data, ensure_ascii=False, default=str)

        elif action == "show":
            if not name:
                return json.dumps({"error": "name is required for show action"})
            attrs = attributes if attributes else "dn"
            base_arg = _base_dn_arg()
            cmd = f'ldbsearch -H {db_path} {base_arg}"(sAMAccountName={name})" {attrs}'
            output = _run_ldb(cmd)
            # Parse LDIF to structured rows (handles base64, multi-valued attrs)
            raw_for_parsing = _full_ldb_output if _full_ldb_output else output
            rows = _parse_ldb_output_to_rows(raw_for_parsing)

            # Build columns list
            columns = list(rows[0].keys()) if rows else []

            # Build structured result — show returns a single object
            result_data = {
                "action": "show",
                "name": name,
                "found": len(rows) > 0,
                "columns": columns,
                "object": rows[0] if rows else {},
            }
            result = json.dumps(result_data, ensure_ascii=False, default=str)

        elif action == "groups_of":
            if not name:
                return json.dumps({"error": "name is required for groups_of action"})
            cmd = f'samba-tool user getgroups {name}'
            output = _run_ldb(cmd)
            result = json.dumps({"action": "groups_of", "name": name, "result": output})

        elif action == "members_of":
            if not name:
                return json.dumps({"error": "name is required for members_of action"})
            cmd = f'samba-tool group listmembers {name}'
            output = _run_ldb(cmd)
            result = json.dumps({"action": "members_of", "name": name, "result": output})

        elif action == "disabled":
            obj_class = _get_object_class() if object_type else "user"
            attrs = attributes if attributes else "sAMAccountName"
            base_arg = _base_dn_arg()
            # v1.9.1: For user type, also exclude computer accounts
            if (object_type or "user") == "user":
                ldap_filter_disabled = f"(&(objectClass={obj_class})(!(sAMAccountName=*$))(userAccountControl:1.2.840.113556.1.4.803:=2))"
            else:
                ldap_filter_disabled = f"(&(objectClass={obj_class})(userAccountControl:1.2.840.113556.1.4.803:=2))"
            cmd = (
                f'ldbsearch -H {db_path} {base_arg}'
                f'"{ldap_filter_disabled}" '
                f'{attrs}'
            )
            output = _run_ldb(cmd)
            # Parse LDIF to structured rows (handles base64, multi-valued attrs)
            raw_for_parsing = _full_ldb_output if _full_ldb_output else output
            rows = _parse_ldb_output_to_rows(raw_for_parsing)

            # Build columns list
            columns = list(rows[0].keys()) if rows else []

            # Build structured result
            result_data = {
                "action": "disabled",
                "object_type": object_type or "user",
                "rows": len(rows),
                "columns": columns,
                "preview": rows[:5],
            }
            result = json.dumps(result_data, ensure_ascii=False, default=str)

        elif action == "locked":
            obj_class = _get_object_class() if object_type else "user"
            base_arg = _base_dn_arg()
            # v1.9.1: For user type, also exclude computer accounts
            if (object_type or "user") == "user":
                ldap_filter_locked = f"(&(objectClass={obj_class})(!(sAMAccountName=*$))(lockoutTime>=1))"
            else:
                ldap_filter_locked = f"(&(objectClass={obj_class})(lockoutTime>=1))"
            attrs = attributes if attributes else "sAMAccountName lockoutTime"
            cmd = (
                f'ldbsearch -H {db_path} {base_arg}'
                f'"{ldap_filter_locked}" '
                f'{attrs}'
            )
            output = _run_ldb(cmd)
            # Parse LDIF to structured rows (handles base64, multi-valued attrs)
            raw_for_parsing = _full_ldb_output if _full_ldb_output else output
            rows = _parse_ldb_output_to_rows(raw_for_parsing)

            # Build columns list
            columns = list(rows[0].keys()) if rows else []

            # Build structured result
            result_data = {
                "action": "locked",
                "object_type": object_type or "user",
                "rows": len(rows),
                "columns": columns,
                "preview": rows[:5],
            }
            result = json.dumps(result_data, ensure_ascii=False, default=str)

        elif action == "groups_bulk":
            # v2.1: Use efficient _get_groups_bulk_map (1 query via memberOf)
            # instead of N+1 samba-tool user getgroups calls
            try:
                users_groups = _get_groups_bulk_map()

                # Also save groups mapping to data_tools snapshots for enrich_with_groups
                try:
                    from app.services.ai_data_tools import _save_snapshot
                    _save_snapshot("__groups_bulk_map__", users_groups)
                except Exception:
                    pass

                result = json.dumps({
                    "action": "groups_bulk",
                    "users": users_groups,
                    "total_users": len(users_groups),
                }, ensure_ascii=False)
            except Exception as exc:
                result = json.dumps({"error": f"groups_bulk failed: {exc}"})

        else:
            return json.dumps({"error": f"Unknown action: {action}. Available: count, search, list, show, groups_of, groups_bulk, members_of, disabled, locked, export"})

    except Exception as exc:
        logger.error("[AI-TOOL] ldbsearch_ad failed: %s", exc)
        return json.dumps({"error": f"LDBSearch AD query failed: {exc}"})

    # ── v2.0: Post-processing for tabular actions ────────────────────
    # Apply snapshot_name, include_groups, exclude, export_xlsx
    # only for actions that return tabular ldbsearch output.
    # v2.3: ALWAYS run post-processing for tabular actions (auto-save snapshot,
    # validation, schema filtering, dynamic preview). Even when no extra params.
    tabular_actions = {"list", "search", "show", "disabled", "locked"}

    if action in tabular_actions:
        try:
            # Use full (untruncated) output for parsing if available
            raw_for_parsing = _full_ldb_output if _full_ldb_output else ""
            enhanced = _ldb_post_process(
                raw_output=raw_for_parsing,
                action=action,
                snapshot_name=snapshot_name,
                include_groups=bool(include_groups),
                exclude_str=exclude_str,
                export_xlsx=export_xlsx,
                export_columns=export_columns,
                chart_type=chart_type,
                chart_x=chart_x,
                chart_y=chart_y,
                chart_title=chart_title,
                object_type=object_type,
                requested_attrs=requested_attrs_raw,  # v2.3: pass comma-separated for validation
            )
            # Merge enhanced info into original result
            result_data = json.loads(result)
            result_data.update(enhanced)
            result = json.dumps(result_data, ensure_ascii=False, default=str)
        except Exception as exc:
            logger.warning("[AI-TOOL] ldbsearch_ad post-processing failed: %s", exc)
            # Don't fail the whole request — just log the error

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Dispenser Execute Implementation (v1.9.1)
# ═══════════════════════════════════════════════════════════════════════


def _dispenser_execute(args: Dict[str, Any]) -> str:
    """Execute a validated command via the dispenser proxy.

    The dispenser acts as a validator between AI and actual command execution.
    AI sees only key fields (like sAMAccountName, displayName), while the
    user can access the full data through the dispenser.

    Returns a structured response with:
    - status: "confirmed" or "rejected"
    - keys: partial data for AI (key fields only)
    - full_data: full data for user (accessible via snapshot)
    """
    action = args.get("action", "")
    command = args.get("command", "")
    object_type = args.get("object_type", "user")
    attributes = args.get("attributes", "sAMAccountName,cn,displayName")
    ldap_filter = args.get("filter", "")
    validate_criteria = args.get("validate_criteria", "")
    snapshot_name = args.get("snapshot_name", "")

    try:
        if action == "ldb_query":
            # Execute ldbsearch query
            db_path = _LDB_DEFAULT_DB
            obj_class = _LDB_OBJECT_CLASS.get(object_type, object_type)

            # Build LDAP filter — exclude computer accounts for user type
            if object_type == "user":
                if ldap_filter:
                    effective_filter = f"(&(&(objectClass={obj_class})(!(sAMAccountName=*$))){ldap_filter})"
                else:
                    effective_filter = f"(&(objectClass={obj_class})(!(sAMAccountName=*$)))"
            else:
                if ldap_filter:
                    effective_filter = f"(&(objectClass={obj_class}){ldap_filter})"
                else:
                    effective_filter = f"(objectClass={obj_class})"

            # v2.3: Convert comma-separated attrs to space-separated for ldbsearch
            attrs_str = attributes.replace(",", " ").strip() if attributes else "sAMAccountName"
            cmd = f'ldbsearch -H {db_path} "{effective_filter}" {attrs_str}'
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30,
            )

            if result.returncode != 0 and result.stderr:
                return json.dumps({
                    "status": "rejected",
                    "error": f"ldbsearch failed: {result.stderr[:500]}",
                    "keys": [],
                    "full_data_available": False,
                })

            # Parse output
            rows = _parse_ldb_output_to_rows(result.stdout)

            if not rows:
                return json.dumps({
                    "status": "rejected",
                    "error": "No results found",
                    "keys": [],
                    "full_data_available": False,
                })

            # Filter out computer accounts
            rows = [r for r in rows if not _get_samaccountname(r).endswith("$")]

            # Extract key fields for AI
            key_fields = [a.strip() for a in attributes.split(",") if a.strip()]
            keys_data = []
            for row in rows:
                key_row = {k: row.get(k, "") for k in key_fields if k in row}
                keys_data.append(key_row)

            # Save full data as snapshot if requested
            full_snapshot = snapshot_name or f"__dispenser_{object_type}_{_now_compact()}"
            try:
                from app.services.ai_data_tools import _save_snapshot
                _save_snapshot(full_snapshot, rows)
            except Exception:
                pass

            # Validate
            status = "confirmed"
            validation_notes = []

            # Check if results look valid
            if not keys_data:
                status = "rejected"
                validation_notes.append("No key data extracted")
            else:
                # Basic validation: check for expected key fields
                for kf in key_fields:
                    has_any = any(kf in row and row[kf] for row in keys_data)
                    if not has_any and len(keys_data) > 0:
                        validation_notes.append(f"Key field '{kf}' not found in results")

            return json.dumps({
                "status": status,
                "keys": keys_data[:50],  # Limit keys shown to AI
                "total_rows": len(rows),
                "full_data_available": True,
                "full_data_snapshot": full_snapshot,
                "key_fields": key_fields,
                "validation_notes": validation_notes if validation_notes else None,
            }, ensure_ascii=False, default=str)

        elif action == "shell_query":
            if not command:
                return json.dumps({
                    "status": "rejected",
                    "error": "command is required for shell_query action",
                    "keys": [],
                    "full_data_available": False,
                })

            # Execute shell command
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30,
            )

            output = result.stdout or ""
            if result.returncode != 0:
                output += "\n" + (result.stderr or "")

            if result.returncode != 0:
                status = "rejected"
            else:
                status = "confirmed"

            return json.dumps({
                "status": status,
                "keys": {"exit_code": result.returncode, "output_preview": output[:500]},
                "full_data_available": True,
                "full_data": output[:3000],
                "exit_code": result.returncode,
            }, ensure_ascii=False, default=str)

        elif action == "validate":
            if not validate_criteria:
                return json.dumps({
                    "status": "rejected",
                    "error": "validate_criteria is required for validate action",
                })

            # Parse criteria
            criteria_list = [c.strip() for c in validate_criteria.split(",") if c.strip()]
            results = []

            for criterion in criteria_list:
                if criterion.startswith("must_have:"):
                    field = criterion.split(":", 1)[1]
                    results.append({"criterion": criterion, "status": "pending", "note": f"Field '{field}' check requires data context"})
                elif criterion.startswith("count_lt:"):
                    threshold = int(criterion.split(":", 1)[1])
                    results.append({"criterion": criterion, "status": "pending", "note": f"Count < {threshold} check requires data context"})
                elif criterion.startswith("count_gt:"):
                    threshold = int(criterion.split(":", 1)[1])
                    results.append({"criterion": criterion, "status": "pending", "note": f"Count > {threshold} check requires data context"})
                else:
                    results.append({"criterion": criterion, "status": "unknown", "note": "Unknown criterion format"})

            return json.dumps({
                "status": "confirmed",
                "validation_results": results,
                "note": "Validation criteria registered. Use with ldb_query or shell_query for full validation.",
            })

        else:
            return json.dumps({"error": f"Unknown dispenser action: {action}. Available: ldb_query, shell_query, validate"})

    except subprocess.TimeoutExpired:
        return json.dumps({
            "status": "rejected",
            "error": "Command timed out after 30 seconds",
            "keys": [],
            "full_data_available": False,
        })
    except Exception as exc:
        logger.error("[AI-TOOL] dispenser_execute failed: %s", exc)
        return json.dumps({
            "status": "rejected",
            "error": f"Dispenser execution failed: {exc}",
            "keys": [],
            "full_data_available": False,
        })


# ═══════════════════════════════════════════════════════════════════════
#  Dispatch for Extended Tools
# ═══════════════════════════════════════════════════════════════════════


async def dispatch_extended_tool_call(
    function_name: str,
    function_args: Dict[str, Any],
    user_permissions: Optional[set] = None,
) -> Optional[str]:
    """Route an extended tool call to the appropriate implementation.

    Returns None if the tool name is not recognized (so the caller
    can return an "unknown tool" error).

    v1.8.7: Added data_import, data_export, data_transform, data_diagram.
    """
    # ── Data Tools (v1.8.7) ───────────────────────────────────────
    if function_name in ("data_import", "data_export", "data_transform", "data_diagram"):
        from app.services.ai_data_tools import dispatch_data_tool_call
        return await dispatch_data_tool_call(function_name, function_args)

    # ── Original Extended Tools ──────────────────────────────────
    if function_name == "manage_samba_share":
        return await _async_wrap(_manage_samba_share, function_args)
    elif function_name == "manage_samba_config":
        return await _async_wrap(_manage_samba_config, function_args)
    elif function_name == "system_admin":
        return await _async_wrap(_system_admin, function_args)
    elif function_name == "network_admin":
        return await _async_wrap(_network_admin, function_args)
    elif function_name == "ai_skill_execute":
        return await _async_wrap(_ai_skill_execute, function_args)
    elif function_name == "request_api_access":
        return _request_api_access(function_args, user_permissions)
    elif function_name == "manage_postgresql":
        return _manage_postgresql(function_args)
    elif function_name == "ldbsearch_ad":
        return await _async_wrap(_ldbsearch_ad, function_args)
    elif function_name == "dispenser_execute":
        return await _async_wrap(_dispenser_execute, function_args)
    elif function_name == "execute_samba_api_as":
        return await _execute_samba_api_as(function_args)
    else:
        return json.dumps({"error": f"Unknown extended tool: {function_name}"})


async def _execute_samba_api_as(args: Dict[str, Any]) -> str:
    """Execute an API call on behalf of a specific management user.

    v1.9.6-4: This tool allows the AI agent to make API calls as a
    different user (by username or user ID) instead of the default
    admin API key. It works by:

    1. Looking up the user in the management DB (by username or ID)
    2. Getting their role and permissions
    3. Creating a temporary JWT access token for that user
    4. Making the API call using that JWT token
    5. Returning the response (including any RBAC permission errors)

    This enables RBAC testing from the AI agent — the agent can verify
    that a Junior Admin gets 403 on DELETE, while Admin gets 200.
    """
    import httpx

    method = args.get("method", "GET").upper()
    path = args.get("path", "/")
    as_user = args.get("as_user", "")
    query_params = args.get("query_params")
    body_params = args.get("body_params")

    if not as_user:
        return json.dumps({"error": "as_user parameter is required. Specify a username or user ID."})

    # ── Step 1: Look up user in management DB ─────────────────────────
    user_info = None
    try:
        from app.api_ma import get_user, get_user_by_username

        # If as_user is numeric, treat as user_id; otherwise as username
        try:
            user_id_int = int(as_user)
            user_info = get_user(user_id_int)
        except (ValueError, TypeError):
            user_info = get_user_by_username(as_user)
    except Exception as exc:
        return json.dumps({"error": f"Failed to look up user '{as_user}': {exc}"})

    if not user_info:
        return json.dumps({
            "error": f"User '{as_user}' not found. Use list_users to see available users.",
            "hint": "You can use execute_samba_api(method='GET', path='/api/v1/mgmt/users') to list users.",
        })

    username = user_info.get("username", as_user)
    role = user_info.get("role", "operator")
    is_active = user_info.get("is_active", True)

    if not is_active:
        return json.dumps({
            "error": f"User '{username}' (id={user_info.get('id')}) is deactivated.",
            "user_info": {"id": user_info.get("id"), "username": username, "role": role, "is_active": is_active},
        })

    # ── Step 2: Get role permissions ──────────────────────────────────
    permissions = []
    try:
        from app.api_ma import get_role_permissions
        permissions = sorted(get_role_permissions(role))
    except Exception:
        pass

    # ── Step 3: Create temporary JWT access token ─────────────────────
    try:
        from app.auth_jwt import create_access_token
        token_data = {
            "sub": username,
            "role": role,
            "permissions": permissions,
        }
        jwt_token = create_access_token(token_data)
    except Exception as exc:
        return json.dumps({"error": f"Failed to create JWT token for user '{username}': {exc}"})

    # ── Step 4: Make the API call with the JWT token ──────────────────
    settings = get_settings()

    # Normalize path
    if not path.startswith('/'):
        path = '/' + path

    url = f"{settings.AI_API_BASE.rstrip('/')}{path}"

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
    }

    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    logger.info(
        "[AI-TOOL] execute_samba_api_as: %s %s as_user=%s (role=%s, timeout=%ds)",
        method, url, username, role, int(api_timeout),
    )

    try:
        client = await _get_api_http_client_shared()
        resp = await client.request(
            method=method,
            url=url,
            headers=headers,
            params=query_params,
            json=body_params,
            timeout=api_timeout,
        )
        try:
            result = resp.json()
        except Exception:
            result = {"status_code": resp.status_code, "text": resp.text}

        # Enrich the response with the user context
        enriched = {
            "executed_as": {
                "username": username,
                "user_id": user_info.get("id"),
                "role": role,
            },
            "request": {
                "method": method,
                "path": path,
            },
            "response": result,
            "http_status": resp.status_code,
        }

        # Log if permission was denied (useful for RBAC testing)
        if resp.status_code == 403:
            logger.info(
                "[AI-TOOL] Permission denied: user=%s role=%s %s %s",
                username, role, method, path,
            )

        result_str = json.dumps(enriched, ensure_ascii=False)

        # Truncate if too long
        if len(result_str) > 3000:
            result_str = result_str[:3000] + f"\n... [TRUNCATED: {len(result_str)} chars total]"

        return result_str

    except Exception as exc:
        logger.error("[AI-TOOL] execute_samba_api_as failed: %s", exc)
        return json.dumps({
            "error": str(exc),
            "executed_as": {"username": username, "role": role},
            "request": {"method": method, "path": path},
        })


# Shared httpx client for execute_samba_api_as
_api_http_client_shared: Optional[Any] = None


async def _get_api_http_client_shared():
    """Get or create a reusable async httpx client for API calls."""
    global _api_http_client_shared
    if _api_http_client_shared is None or _api_http_client_shared.is_closed:
        import httpx
        _api_http_client_shared = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _api_http_client_shared


async def _async_wrap(func, args: Dict[str, Any]) -> str:
    """Run a sync function in a thread pool to avoid blocking the event loop."""
    import asyncio
    return await asyncio.to_thread(func, args)


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════


def _backup_file(filepath: str) -> str:
    """Create a timestamped backup of a file."""
    ts = _now_compact()
    backup_path = f"{filepath}.backup.{ts}"
    shutil.copy2(filepath, backup_path)
    logger.info("[AI-TOOL] Backed up %s to %s", filepath, backup_path)
    return backup_path


def _now_compact() -> str:
    """Return current time as compact string for filenames."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _truncate_tool_result(result: str, max_chars: int = 3000) -> str:
    """Truncate a tool result string to prevent token overflow."""
    if len(result) <= max_chars:
        return result
    return result[:max_chars] + f"\n... [TRUNCATED: {len(result)} chars total, showing first {max_chars}]"
