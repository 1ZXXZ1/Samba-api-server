"""
samba-tool command builder and executor.

This module translates high-level domain/action/args dictionaries into
concrete ``samba-tool`` command lines, appends common connection flags,
and runs them through the :mod:`app.worker` process pool.

Key design decisions
--------------------
* ``--json`` is NEVER added automatically by :func:`build_samba_command`.
  Routers must explicitly request JSON output by passing
  ``{"--json": True}`` or ``{"--output-format": "json"}`` in *args*.
* :func:`execute_samba_command` handles ``--json`` compatibility
  gracefully: if a command fails because the installed samba-tool version
  does not understand ``--json`` (or ``--output-format=json``), the
  executor automatically retries without the unsupported flag.
* The ``SAMBA_JSON_MODE`` environment variable controls JSON strategy:
  ``auto`` (default), ``force_json``, ``force_output_format``, ``text``.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

from app.config import Settings, get_settings
from app.worker import WorkerPool, get_worker_pool

logger = logging.getLogger(__name__)

# ── Command capability sets ────────────────────────────────────────────
#
# These sets describe which samba-tool sub-commands support certain flags.
# They are used by ``build_samba_command`` to decide which common options
# to append automatically.
#
# IMPORTANT: ``--json`` is NEVER added automatically.  Routers must
# explicitly request JSON output by passing ``{"--json": True}`` or
# ``{"--output-format": "json"}`` in the *args* dict.

# Commands that support ``--json`` (for explicit use by routers).
JSON_CAPABLE_COMMANDS: set[str] = {
    "user list",
    "user show",
    "group list",
    "group show",
    "group listmembers",
    "ou list",
    "ou show",
    "computer list",
    "computer show",
    "dns query",
    "drs showrepl",
    "fsmo show",
    "site list",
    "site show",
    "subnet list",
    "subnet show",
    # Fix v7-4: Removed "spn list" — samba-tool spn list does NOT
    # support --json. It was incorrectly listed here, causing
    # "no such option: --json" errors and 404 responses.
    "time",
    "gpo list",
    "gpo show",
    "contact list",
    "contact show",
    "group stats",
}

# Commands that support ``--output-format=json`` (Samba 4.9+).
# Prefer ``--output-format=json`` over ``--json`` when available.
OUTPUT_FORMAT_JSON_CAPABLE_COMMANDS: set[str] = {
    "user list",
    "user show",
    "group list",
    "group show",
    "group listmembers",
    "ou list",
    "ou show",
    "computer list",
    "computer show",
    "dns query",
    "drs showrepl",
    "fsmo show",
}

# Fix v3-16: Whitelist of commands known to support JSON output.
# In "auto" JSON mode, the executor will only attempt --json /
# --output-format=json for commands in this whitelist.  All other
# commands are immediately executed without JSON flags, avoiding
# wasted time on "no such option" retries.
#
# This is a UNION of JSON_CAPABLE_COMMANDS and
# OUTPUT_FORMAT_JSON_CAPABLE_COMMANDS, since either flag may work.
JSON_COMMANDS_WHITELIST: set[str] = JSON_CAPABLE_COMMANDS | OUTPUT_FORMAT_JSON_CAPABLE_COMMANDS

# Commands that DO NOT support the ``-H`` (LDAP URL) flag.
# All commands not listed here are assumed to support ``-H``.
# Extended to include DNS, DRS, GPO and other commands that use
# RPC/CLDAP instead of LDAP.
COMMANDS_NO_H_FLAG: set[str] = {
    # Domain commands that use CLDAP/RPC
    "domain info",
    "domain level",
    "domain join",
    "domain leave",
    "domain provision",
    "domain backup",
    # Domain trust commands do not support -H
    "domain trust",
    # DNS commands (use RPC, not LDAP)
    "dns serverinfo",
    "dns zonelist",
    "dns zoneinfo",
    "dns zonecreate",
    "dns zonedelete",
    "dns query",
    "dns add",
    "dns delete",
    "dns update",
    "dns zoneoptions",
    # DRS commands (use RPC, not LDAP)
    "drs showrepl",
    "drs bind",
    "drs options",
    "drs kcc",
    "drs replicate",
    # NOTE: drs uptodateness is different from other DRS commands.
    # It uses -H (LDAP URL) to connect to the local samdb, not RPC.
    # It is NOT listed here so that -H is NOT auto-stripped.
    # However, it is also not listed in the H auto-add logic below
    # because the router explicitly passes -H when needed.
    # Fix v7-6: drs options DOES NOT support -H according to samba-tool
    # man page. It was already listed here, confirming it should NOT
    # receive -H automatically. The router also now avoids passing
    # -H explicitly for drs options.
    # NOTE: gpo listall DOES support -H in samba-tool source code
    # (see samba/netcmd/gpo.py cmd_listall takes_options).
    # Removed from COMMANDS_NO_H_FLAG so that -H is auto-injected,
    # which avoids CLDAP-based DC discovery failures.
    # Database / file system commands
    "dbcheck",
    "ntacl get",
    "ntacl set",
    "ntacl sysvolreset",
    # Configuration / diagnostic
    "testparm",
    "time",
    "processes",
    "forest info",
}

# Commands that DO NOT support ``--configfile``.
COMMANDS_NO_CONFIGFILE: set[str] = {
    "domain info",
    "domain level",
    "domain trust",
    "domain provision",
    "domain backup",
    "ntacl get",
    "ntacl set",
    "ntacl sysvolreset",
    "testparm",
    "time",
    "processes",
    "forest info",
    # DNS commands don't accept --configfile
    "dns serverinfo",
    "dns zonelist",
    "dns zoneinfo",
    "dns zonecreate",
    "dns zonedelete",
    "dns query",
    "dns add",
    "dns delete",
    "dns update",
    "dns zoneoptions",
    # DRS commands don't accept --configfile
    "drs showrepl",
    "drs bind",
    "drs options",
    "drs kcc",
    "drs replicate",
    # drs uptodateness uses -H (LDAP) to connect to local samdb;
    # it does NOT accept --configfile but we leave it out because
    # the router passes -H explicitly and we don't want other
    # flags auto-injected.  It's also in COMMANDS_NO_REALM_FLAG
    # and COMMANDS_NO_U_FLAG to prevent unwanted flag injection.
    "drs uptodateness",
}

# Commands that DO NOT support the ``-U`` (credentials) flag.
# These are typically local/diagnostic commands that do not require
# authentication against the AD.
#
# IMPORTANT: DNS commands DO support -U and --use-kerberos.
# They were previously listed here incorrectly, causing authentication
# failures and timeouts.  Only truly local commands remain.
COMMANDS_NO_U_FLAG: set[str] = {
    "testparm",
    "processes",
    "time",
    "domain info",
    "domain level",
    # Domain trust commands do not support -U
    "domain trust",
    # Domain provision does not support -U
    "domain provision",
    # Domain join/leave do not support -U in the standard way
    "domain join",
    "domain leave",
    # Fix v3-8: domain backup offline does not support -U.
    # It operates on local files and doesn't need authentication.
    # Online backup also doesn't need -U since it uses its own
    # connection mechanism via --server.
    "domain backup",
    # Fix v11-8: domain demote does not support -U.
    # It operates on the local DC and uses its own connection.
    "domain demote",
    # Fix v25: DRS commands REMOVED from COMMANDS_NO_U_FLAG.
    # On ALT Linux, DRS RPC commands (showrepl, bind, options, replicate)
    # REQUIRE -U credentials for Kerberos authentication. Without -U,
    # they hang or fail with STATUS_QUOTA_EXCEEDED. With -U, they work
    # (though slowly, ~50s).
    # Fix v26: drs uptodateness REMOVED from NO_U — -H tdb:// causes
    # "Cannot contact any KDC". Now uses -U credentials instead.
    #
    # "drs uptodateness",   # ← removed in v26: needs -U, not -H tdb://
    # Fix v7-1: user getpassword requires LDAPI connection to sam.ldb.
    # When -U is added, samba-tool attempts LDAP authentication which
    # fails with LDAP_OPERATIONS_ERROR ("Operation unavailable without
    # authentication"). This command must run without -U since it
    # connects via ldapi:// which uses the process's Unix credentials.
    "user getpassword",
    # Fix v26: user get-kerberos-ticket REMOVED from NO_U — -H tdb://
    # causes "Cannot contact any KDC" (500). The command needs to
    # contact a KDC to issue the ticket, which requires proper
    # authentication via -U, not direct tdb:// file access.
    # "user get-kerberos-ticket",   # ← removed in v26
    # Fix v13-1: domain exportkeytab requires local sam.ldb access
    # via ldapi:// to export password keys. When -U is added,
    # samba-tool tries LDAP auth which fails with
    # "Failed to export domain keys... Consider connecting to a local DC".
    # Keytab export needs the process's Unix credentials, not -U auth.
    "domain exportkeytab",
}

# Commands that DO NOT support the ``--realm`` flag.
# These are local/diagnostic commands that operate on the local
# machine or file system and have no concept of a Kerberos realm.
# All commands NOT in this set will automatically receive
# ``--realm=<REALM>`` when ``Settings.REALM`` is configured.
COMMANDS_NO_REALM_FLAG: set[str] = {
    "testparm",
    "processes",
    "time",
    "ntacl get",
    "ntacl set",
    "ntacl sysvolreset",
    "dbcheck",
    "domain info",
    "domain level",
    "domain join",
    "domain leave",
    "domain provision",
    "domain backup",
    "domain exportkeytab",
    "forest info",
    # DRS commands use RPC, not LDAP; they accept positional <DC>
    # but do NOT support --realm.
    "drs showrepl",
    "drs bind",
    "drs options",
    "drs kcc",
    "drs replicate",
    "drs uptodateness",
    # Fix v11-1: user getpassword and user get-kerberos-ticket require LDAPI.
    # When --realm is auto-injected, samba-tool tries DNS-based DC discovery
    # instead of using the explicit -H ldapi:// URL, causing
    # LDAP_OPERATIONS_ERROR ("Operation unavailable without authentication").
    # These commands must not receive --realm.
    "user getpassword",
    "user get-kerberos-ticket",
    # Fix v11-8: domain demote does not support --realm.
    "domain demote",
}



# Fix v20: Commands that are READ-ONLY and should use tdb:// for -H.
# These commands only READ from sam.ldb and benefit from tdb:// because:
#   - No LDAP authentication needed (avoids LDAP_OPERATIONS_ERROR)
#   - Supports parallel reads (10+ concurrent requests)
#   - Faster than ldapi:// (no socket/auth overhead)
#
# IMPORTANT: Commands NOT in this set will NOT auto-get -H tdb://.
# Write commands should NOT use tdb:// (concurrent writes corrupt DB).
# They will use ldapi:// (see COMMANDS_WRITE_LDAPI) or auto-discover.
COMMANDS_READ_ONLY_TDB: set[str] = {
    # User read operations
    "user list",
    "user show",
    "user getgroups",
    "user getpassword",        # Still in TDB — pure read, no KDC contact needed
    # "user get-kerberos-ticket", # ← removed in v26: needs -U to contact KDC, not -H tdb://
    # Group read operations
    "group list",
    "group show",
    "group listmembers",
    "group stats",
    # Computer read operations
    "computer list",
    "computer show",
    # Contact read operations
    "contact list",
    "contact show",
    # OU read operations
    "ou list",
    "ou show",
    # Fix v25: GPO commands REMOVED from COMMANDS_READ_ONLY_TDB.
    # Unlike user/group/OU reads, GPO commands need credentials even
    # with -H tdb:// (e.g. gpo show prompts for password without -U).
    # Only gpo listall works without -U when -H tdb:// is given.
    # All other GPO commands require -U credentials.
    #
    # gpo listall is kept here because it's a pure LDAP search that
    # works fine with -H tdb:// and no -U.
    "gpo listall",
    # FSMO read
    "fsmo show",
    # DRS uptodateness — removed in v26: -H tdb:// causes
    # "Cannot contact any KDC". Now uses -U credentials.
    # "drs uptodateness",
    # Sites/subnets read
    "site list",
    "site show",
    "subnet list",
    "subnet show",
    # Schema read
    "schema query",
    # Domain keytab export (reads password keys from sam.ldb)
    "domain exportkeytab",
    # Domain password settings show (read-only)
    "domain passwordsettings",
}

# Fix v25: GPO commands that need -U credentials AND support -H tdb://.
# These commands can bypass CLDAP DC discovery by using -H tdb://,
# which avoids "Could not find a DC" errors in API subprocesses.
# They still need -U for authentication.
GPO_COMMANDS_NEED_U_AND_TDB: set[str] = {
    "gpo show",
    "gpo fetch",
    "gpo getinheritance",
    "gpo setlink",
    "gpo dellink",
    "gpo setinheritance",
    "gpo del",
    "gpo create",
    "gpo backup",
    "gpo restore",
}

# Fix v24: Commands that are WRITE operations.
# These commands MODIFY sam.ldb and are classified as writes for
# reference purposes.  However, as of v24, they NO LONGER get -H ldapi://
# auto-injected.  Instead, samba-tool auto-discovers the connection via
# -U credentials, which is ~60x faster (~0.5s vs 20-35s with -H ldapi://).
#
# Historical context (v21-v23):
#   - v21: Auto-injected -H ldapi:// for writes to avoid tdb:// corruption
#   - v24: REMOVED -H ldapi:// injection because it caused 20-35s delays
#     due to Kerberos/LDAP auth timeouts over the LDAPI socket.
#     samba-tool with just -U auto-discovers and works in ~0.5s.
#
# This set is kept for documentation/classification purposes and may be
# used by routers or the direct SamDB API for choosing connection methods.
COMMANDS_WRITE_LDAPI: set[str] = {
    # User write operations
    "user add",
    "user delete",
    "user setpassword",
    "user enable",
    "user disable",
    "user unlock",
    "user setexpiry",
    "user setprimarygroup",
    "user addunixattrs",
    "user sensitive",
    "user move",
    "user rename",
    # Group write operations
    "group add",
    "group delete",
    "group addmembers",
    "group removemembers",
    "group move",
    # Computer write operations
    "computer add",
    "computer delete",
    "computer move",
    # Contact write operations
    "contact add",
    "contact delete",
    "contact move",
    "contact rename",
    # OU write operations
    "ou add",
    "ou delete",
    "ou move",
    "ou rename",
    # GPO write operations
    "gpo create",
    "gpo del",
    "gpo setlink",
    "gpo dellink",
    "gpo setinheritance",
    "gpo backup",
    "gpo restore",
    # FSMO write operations
    "fsmo transfer",
    "fsmo seize",
    # Domain write operations
    "domain passwordsettings",  # set sub-command is a write
    "domain level",             # raise sub-command is a write
    # Sites write operations
    "sites create",
    "sites remove",
    "sites subnet",             # create/remove/set-site sub-commands
}

# Fix v21: Commands that use RPC (DCE/RPC) and require a REAL DC hostname
# as a positional argument, NOT -H.  These commands do NOT accept -H at all
# (they are also in COMMANDS_NO_H_FLAG).  They require the server's real
# network name (FQDN or short NetBIOS name) because:
#   - They use DCE/RPC over SMB, not LDAP
#   - Kerberos cannot issue a service ticket for "localhost" or "127.0.0.1"
#   - Using localhost causes NT_STATUS_INVALID_PARAMETER errors
#   - The server name must match the DC's real hostname in /etc/hosts or DNS
COMMANDS_RPC_SERVER: set[str] = {
    # DNS commands (use DNS RPC, not LDAP)
    "dns serverinfo",
    "dns zonelist",
    "dns zoneinfo",
    "dns zonecreate",
    "dns zonedelete",
    "dns query",
    "dns add",
    "dns delete",
    "dns update",
    "dns zoneoptions",
    # DRS commands (use DRSUAPI RPC, not LDAP)
    "drs showrepl",
    "drs bind",
    "drs options",
    "drs kcc",
    "drs replicate",
}
# ── JSON mode configuration ────────────────────────────────────────────
# SAMBA_JSON_MODE controls how --json / --output-format=json flags are
# handled when a command fails due to an unsupported flag.
#
#   "auto"                – Try --json first; on "no such option" error,
#                           retry with --output-format=json; on another
#                           error, retry without any JSON flag.  (default)
#   "force_json"          – Always use --json, never fall back.
#   "force_output_format" – Always use --output-format=json, never --json.
#   "text"                – Never add any JSON flag; always return text.
#
# The mode is read from ``Settings.JSON_MODE`` which in turn comes from
# the ``SAMBA_JSON_MODE`` environment variable.

# Error patterns indicating an unsupported flag.
_UNSUPPORTED_FLAG_PATTERNS: tuple[str, ...] = (
    "no such option",
    "unrecognised option",
    "unrecognized option",
    "option not recognized",
)


def _is_unsupported_flag_error(stderr: str, stdout: str) -> bool:
    """Return *True* if the error output indicates an unsupported flag."""
    combined = (stderr + " " + stdout).lower()
    return any(pat in combined for pat in _UNSUPPORTED_FLAG_PATTERNS)


def _strip_json_flags(cmd: list[str]) -> list[str]:
    """Return a copy of *cmd* with ``--json`` and ``--output-format``
    flags removed."""
    result: list[str] = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        if arg == "--json":
            continue
        if arg == "--output-format":
            # --output-format takes a value argument
            skip_next = True
            continue
        if arg.startswith("--output-format="):
            continue
        result.append(arg)
    return result


def _replace_json_with_output_format(cmd: list[str]) -> list[str]:
    """Return a copy of *cmd* where ``--json`` is replaced with
    ``--output-format json``."""
    result: list[str] = []
    for arg in cmd:
        if arg == "--json":
            result.extend(["--output-format", "json"])
        else:
            result.append(arg)
    return result


def _has_json_flag(cmd: list[str]) -> bool:
    """Return *True* if *cmd* contains ``--json`` or ``--output-format``."""
    return "--json" in cmd or any(
        a == "--output-format" or a.startswith("--output-format=") for a in cmd
    )


def _is_unknown_parameter_error(stderr: str, stdout: str) -> bool:
    """Return True if the error indicates an unknown parameter was encountered."""
    combined = (stderr + " " + stdout).lower()
    return "unknown parameter" in combined or "unknown option" in combined


def _strip_unknown_parameter(cmd: list[str], error_output: str) -> list[str]:
    """Strip the unknown parameter from the command line based on the error message.
    
    Error format: 'Unknown parameter encountered: "tmp dir"'
    The parameter name in quotes may contain spaces, so we need to
    reconstruct the flag form (--tmp-dir or --tmpdir).
    """
    import re as _re
    # Extract parameter name from error message
    # Pattern: Unknown parameter encountered: "param name"
    match = _re.search(r'unknown parameter encountered:\s*"([^"]+)"', error_output, _re.IGNORECASE)
    if not match:
        # Alternative pattern: Unknown option "--flag"
        match = _re.search(r'unknown option:\s*(--?\S+)', error_output, _re.IGNORECASE)
        if not match:
            return cmd  # Can't identify the parameter; return as-is
    
    param_name = match.group(1).strip()
    logger.info("Detected unknown parameter: '%s'", param_name)
    
    # Convert parameter name to possible flag forms:
    # "tmp dir" -> --tmp-dir, --tmpdir, -tmp-dir, -tmpdir
    param_dash = param_name.replace(" ", "-")
    possible_flags = [
        f"--{param_dash}",
        f"--{param_dash.replace('-', '')}",  # e.g., --tmpdir from "tmp dir"
        f"-{param_dash}",
    ]
    
    result: list[str] = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        # Check if this arg matches any of the possible flag forms
        is_unknown_flag = False
        for flag in possible_flags:
            if arg == flag:
                is_unknown_flag = True
                # Check if next arg is the value (not another flag)
                if i + 1 < len(cmd) and not cmd[i + 1].startswith("-"):
                    skip_next = True  # Skip the value too
                break
            if arg.startswith(flag + "="):
                # Handle --flag=value form
                is_unknown_flag = True
                break
        if not is_unknown_flag:
            result.append(arg)
    
    return result


def _add_common_options(
    cmd: list[str],
    settings: Settings,
    domain: str,
    action: str,
) -> list[str]:
    """Append common connection flags to *cmd* based on configuration.

    The following flags are conditionally added, **but only when the
    target command supports them** (see :data:`COMMANDS_NO_H_FLAG` and
    :data:`COMMANDS_NO_CONFIGFILE`):

    * ``--configfile=<path>`` – when ``SAMBA_SMB_CONF`` is set.
    * ``-H <LDAP_URL>`` – when ``SAMBA_LDAP_URL`` is set.
    * ``-U <user>%<password>`` – when both user and password are set.
    * ``--use-kerberos=required`` – when ``SAMBA_USE_KERBEROS`` is *True*.

    Parameters
    ----------
    cmd:
        The base command line (mutated in-place and returned).
    settings:
        Active application settings.
    domain:
        The samba-tool domain (e.g. ``"user"``, ``"domain"``).
    action:
        The samba-tool action (e.g. ``"list"``, ``"add"``).

    Returns
    -------
    list[str]
        The same list object, with extra flags appended.
    """
    command_key = f"{domain} {action}"

    # Fix v24: REMOVED --configfile auto-injection.
    # samba-tool auto-discovers /etc/samba/smb.conf by default.
    # Adding --configfile explicitly is unnecessary and can cause
    # issues with some samba-tool builds.  The SMB_CONF setting
    # is still used for testparm calls in get_tdb_url/get_ldapi_url.
    #
    # Old code:
    #   if command_key not in COMMANDS_NO_CONFIGFILE:
    #       if settings.SMB_CONF and "--configfile" not in cmd:
    #           cmd.append(f"--configfile={settings.SMB_CONF}")

    # Fix v25: Three-tier -H auto-injection strategy.
    #
    #   Tier 1 — Pure TDB reads (COMMANDS_READ_ONLY_TDB):
    #     Auto-inject -H tdb:// for fast, auth-free, parallel-safe reads.
    #     NO -U flag is added (no auth needed for TDB).
    #
    #   Tier 2 — GPO commands that need BOTH -H tdb:// AND -U
    #     (GPO_COMMANDS_NEED_U_AND_TDB):
    #     Auto-inject -H tdb:// to bypass CLDAP DC discovery (avoids
    #     "Could not find a DC" errors in API subprocesses) AND
    #     also add -U credentials (GPO commands need auth even with
    #     -H tdb://). This combination works reliably and avoids the
    #     30-60s CLDAP/RPC delays.
    #
    #   Tier 3 — WRITE commands (COMMANDS_WRITE_LDAPI):
    #     DO NOT inject -H.  samba-tool auto-discovers the connection
    #     via -U credentials.  Without -H, most commands work in ~0.5s.
    #
    #   Tier 4 — RPC commands (COMMANDS_RPC_SERVER / COMMANDS_NO_H_FLAG):
    #     Do NOT inject -H.  DNS and DRS commands use DCE/RPC and take
    #     a server hostname as a positional argument instead.
    #
    #   Routers that need to override can pass -H explicitly in args.
    _is_tdb_read = command_key in COMMANDS_READ_ONLY_TDB
    _is_gpo_need_u_tdb = command_key in GPO_COMMANDS_NEED_U_AND_TDB

    if _is_tdb_read:
        tdb_url = get_tdb_url(settings)
        if tdb_url and "-H" not in cmd:
            cmd.extend(["-H", tdb_url])
            logger.debug("Auto-injected -H tdb:// for read-only command '%s'", command_key)
    elif _is_gpo_need_u_tdb:
        # Fix v25: GPO commands need -H tdb:// to bypass CLDAP DC discovery
        # AND -U for authentication. Without -H, they fail with
        # "Could not find a DC" / "no network interfaces found".
        # Without -U, they prompt for a password and hang.
        tdb_url = get_tdb_url(settings)
        if tdb_url and "-H" not in cmd:
            cmd.extend(["-H", tdb_url])
            logger.debug("Auto-injected -H tdb:// for GPO command '%s' (needs both -H and -U)", command_key)
    # Fix v24: WRITE commands NO LONGER get -H ldapi://.
    # Old code injected -H ldapi:// which caused 20-35s delays.
    # Now samba-tool auto-discovers the connection via -U credentials.

    # -U is only added for commands that support it.
    # Fix v24: Skip -U for TDB read commands — TDB opens the database
    # file directly and does not need LDAP authentication.
    # Fix v25: GPO commands always need -U even with -H tdb://.
    if command_key in COMMANDS_NO_U_FLAG:
        logger.debug(
            "Skipping -U flag for '%s' (in COMMANDS_NO_U_FLAG)",
            command_key,
        )
    elif _is_tdb_read and not _is_gpo_need_u_tdb:
        logger.debug(
            "Skipping -U flag for '%s' (TDB read-only, no auth needed)",
            command_key,
        )
    elif settings.CREDENTIALS_USER and settings.CREDENTIALS_PASSWORD:
        cmd.extend([
            "-U",
            f"{settings.CREDENTIALS_USER}%{settings.CREDENTIALS_PASSWORD}",
        ])
        logger.debug("Added -U flag for '%s'", command_key)

    # --use-kerberos is only added for commands that support -U
    # AND are not pure TDB read-only commands (GPO commands with -H tdb://
    # still get -U but not --use-kerberos since they use tdb://).
    if command_key not in COMMANDS_NO_U_FLAG and not _is_tdb_read and not _is_gpo_need_u_tdb:
        if settings.USE_KERBEROS:
            cmd.append("--use-kerberos=required")

    # --realm is added for commands that support it, when REALM is configured.
    # Fix v24: Skip --realm for TDB read-only commands.
    # Fix v25: GPO commands with -H tdb:// still need --realm.
    if command_key not in COMMANDS_NO_REALM_FLAG and not _is_tdb_read:
        if settings.REALM and "--realm" not in cmd:
            cmd.append(f"--realm={settings.REALM}")

    return cmd


def build_samba_command(
    domain: str,
    action: str,
    args: Optional[dict[str, Any]] = None,
    positionals: Optional[list[str]] = None,
) -> list[str]:
    """Build a complete ``samba-tool`` command line.

    Parameters
    ----------
    domain:
        Top-level samba-tool domain, e.g. ``"user"``, ``"group"``,
        ``"dns"``, ``"drs"``, ``"gpo"``, etc.
    action:
        Sub-command under the domain, e.g. ``"list"``, ``"create"``,
        ``"delete"``.
    args:
        Optional mapping of flag/value pairs.  Keys starting with a
        single dash are treated as short flags (``"-H"``), keys starting
        with two dashes as long flags (``"--json"``).  Boolean *True*
        values emit the flag without a value; *False* values skip the
        flag entirely.  All other values are emitted as the next
        argument.
    positionals:
        Optional list of positional arguments (e.g. username, password)
        that are inserted **right after** the action keyword and **before**
        any flags.  This replaces the old ``_insert_positional`` helper.

    Returns
    -------
    list[str]
        Fully assembled command line ready for execution.

    Examples
    --------
    >>> build_samba_command("user", "list", {"--json": True})
    ['samba-tool', 'user', 'list', '--json', ...common_options...]

    >>> build_samba_command("user", "add", {"--userou": "OU=Users"}, positionals=["jdoe", "P@ss"])
    ['samba-tool', 'user', 'add', 'jdoe', 'P@ss', '--userou', 'OU=Users', ...]
    """
    settings = get_settings()
    args = args or {}
    positionals = positionals or []

    command_key = f"{domain} {action}"

    cmd: list[str] = [settings.TOOL_PATH, domain, action]

    # Insert positional arguments right after the action.
    cmd.extend(positionals)

    # Fix v3-16: In "auto" JSON mode, skip JSON flags for commands
    # that are not in the whitelist.  This avoids wasting time on
    # retry attempts for commands that will never support JSON output.
    json_mode = settings.JSON_MODE
    if json_mode == "auto" and command_key not in JSON_COMMANDS_WHITELIST:
        # This command is not known to support JSON — strip any
        # JSON flags that the router may have added to args.
        args.pop("--json", None)
        args.pop("--output-format", None)

    # Apply JSON mode transformation to args before building the command.
    if json_mode == "force_output_format" and "--json" in args:
        # Replace --json with --output-format=json
        del args["--json"]
        args["--output-format"] = "json"
    elif json_mode == "text":
        # Strip any JSON flags
        args.pop("--json", None)
        args.pop("--output-format", None)

    # Filter out -H for commands that don't support it.
    # Even if a router/user explicitly passes -H, it must be stripped
    # for commands in COMMANDS_NO_H_FLAG to avoid "no such option: -H".
    if command_key in COMMANDS_NO_H_FLAG and "-H" in args:
        logger.warning(
            "Stripping -H flag from '%s' — this command does not support -H",
            command_key,
        )
        del args["-H"]

    # Append caller-supplied flag arguments.
    for key, value in args.items():
        if isinstance(value, bool):
            if value:
                cmd.append(key)
            # False -> skip entirely
        else:
            cmd.extend([key, str(value)])

    # Append common connection flags (only for commands that support them).
    cmd = _add_common_options(cmd, settings, domain, action)

    logger.debug("Built command: %s", " ".join(cmd))
    return cmd


def build_samba_command_deep(
    parts: list[str],
    args: Optional[dict[str, Any]] = None,
    positionals: Optional[list[str]] = None,
) -> list[str]:
    """Build a ``samba-tool`` command line with arbitrary subcommand depth.

    Fix v9-5: Added JSON mode filtering (same logic as build_samba_command).
    Previously, this function did not apply JSON mode rules, causing
    ``--json`` to be passed to commands like ``sites view`` that don't
    support it, even when ``SAMBA_JSON_MODE=text``.

    Unlike :func:`build_samba_command` which takes separate *domain* and
    *action* parameters, this function accepts a flat list of command
    segments (e.g. ``["domain", "auth", "silo", "list"]``) and
    correctly determines the command key for flag-capability lookups.

    Positional arguments are kept **separate** from *parts* so they
    never corrupt the command-key lookup.  For example::

        build_samba_command_deep(["time"], positionals=[server])
        # command_key = "time" → correctly matched in COMMANDS_NO_H_FLAG

        build_samba_command_deep(["ntacl", "get"], positionals=[file_path])
        # command_key = "ntacl get" → correctly matched

    Parameters
    ----------
    parts:
        Command segments after the tool path
        (e.g. ``["domain", "auth", "silo", "list"]``).
        **Do NOT include positional arguments here** — use the
        *positionals* parameter instead.
    args:
        Optional mapping of flag/value pairs (same semantics as
        :func:`build_samba_command`).
    positionals:
        Optional list of positional arguments that are inserted
        right after the last element of *parts* and before any flags.

    Returns
    -------
    list[str]
        Fully assembled command line ready for execution.
    """
    settings = get_settings()
    args = args or {}
    positionals = positionals or []

    # Determine command key for capability lookups.
    # Use first 1-2 parts (the domain and action) to match against
    # COMMANDS_NO_H_FLAG, COMMANDS_NO_CONFIGFILE, COMMANDS_NO_U_FLAG.
    # For single-word commands like "time", "testparm", "processes",
    # "dbcheck", we use just the first part.
    if len(parts) >= 2:
        command_key = " ".join(parts[:2])
        # Also check if the single-part key exists (e.g. "time" vs "time <server>")
        single_key = parts[0]
        # Prefer the most specific match: if 2-part key is in a set, use it;
        # otherwise if single-part key is in a set, use that.
        # For lookups, we'll check both below.
    else:
        command_key = parts[0] if parts else ""
        single_key = command_key

    # Helper: check if a command key is in a given "no-flag" set.
    # Tries the 2-part key first, then the 1-part key.
    def _in_no_set(no_set: set[str]) -> bool:
        if command_key in no_set:
            return True
        if len(parts) >= 2 and single_key in no_set:
            return True
        return False

    cmd: list[str] = [settings.TOOL_PATH, *parts]

    # Insert positional arguments right after the command parts.
    cmd.extend(positionals)

    # Fix v9-5: JSON mode filtering — same logic as build_samba_command.
    # In "auto" mode, skip JSON flags for commands not in the whitelist.
    # In "text" mode, strip all JSON flags.  In "force_output_format"
    # mode, replace --json with --output-format=json.
    json_mode = settings.JSON_MODE
    if len(parts) >= 2:
        command_key_for_json = " ".join(parts[:2])
    else:
        command_key_for_json = parts[0] if parts else ""

    if json_mode == "auto" and command_key_for_json not in JSON_COMMANDS_WHITELIST:
        args.pop("--json", None)
        args.pop("--output-format", None)
    elif json_mode == "force_output_format" and "--json" in args:
        del args["--json"]
        args["--output-format"] = "json"
    elif json_mode == "text":
        args.pop("--json", None)
        args.pop("--output-format", None)

    # Fix v24: REMOVED --configfile auto-injection.
    # samba-tool auto-discovers /etc/samba/smb.conf by default.
    # See _add_common_options() for the detailed rationale.

    # Caller-supplied flags
    for key, value in args.items():
        if isinstance(value, bool):
            if value:
                cmd.append(key)
        else:
            cmd.extend([key, str(value)])

    # Fix v25: Three-tier -H auto-injection for deep commands.
    # tdb:// for pure reads, tdb://+U for GPO, NO -H for writes.
    # See _add_common_options() for the detailed rationale.
    _is_readonly = (
        command_key in COMMANDS_READ_ONLY_TDB
        or (len(parts) >= 2 and " ".join(parts[:2]) in COMMANDS_READ_ONLY_TDB)
    )
    _is_gpo_need_u_tdb = (
        command_key in GPO_COMMANDS_NEED_U_AND_TDB
        or (len(parts) >= 2 and " ".join(parts[:2]) in GPO_COMMANDS_NEED_U_AND_TDB)
    )

    if _is_readonly:
        tdb_url = get_tdb_url(settings)
        if tdb_url and "-H" not in args:
            cmd.extend(["-H", tdb_url])
            logger.debug("Auto-injected -H tdb:// for deep read-only command '%s'", command_key)
    elif _is_gpo_need_u_tdb:
        tdb_url = get_tdb_url(settings)
        if tdb_url and "-H" not in args:
            cmd.extend(["-H", tdb_url])
            logger.debug("Auto-injected -H tdb:// for deep GPO command '%s' (needs both -H and -U)", command_key)
    # Fix v24: WRITE commands NO LONGER get -H ldapi://.

    # -U
    # Fix v25: GPO commands always need -U even with -H tdb://.
    if _in_no_set(COMMANDS_NO_U_FLAG):
        logger.debug(
            "Skipping -U flag for '%s' (deep build, in COMMANDS_NO_U_FLAG)",
            command_key,
        )
    elif _is_readonly and not _is_gpo_need_u_tdb:
        logger.debug(
            "Skipping -U flag for '%s' (deep build, TDB read-only, no auth needed)",
            command_key,
        )
    elif settings.CREDENTIALS_USER and settings.CREDENTIALS_PASSWORD:
        cmd.extend([
            "-U",
            f"{settings.CREDENTIALS_USER}%{settings.CREDENTIALS_PASSWORD}",
        ])
        logger.debug("Added -U flag for '%s' (deep build)", command_key)

    # --use-kerberos
    if not _in_no_set(COMMANDS_NO_U_FLAG) and not _is_readonly and not _is_gpo_need_u_tdb:
        if settings.USE_KERBEROS:
            cmd.append("--use-kerberos=required")

    # --realm is added for commands that support it, when REALM is configured.
    # Fix v25: GPO commands with -H tdb:// still need --realm.
    if not _in_no_set(COMMANDS_NO_REALM_FLAG) and not _is_readonly:
        if settings.REALM and "--realm" not in args:
            cmd.append(f"--realm={settings.REALM}")

    logger.debug("Built command (deep): %s", " ".join(cmd))
    return cmd


async def execute_samba_command(
    cmd: list[str],
    timeout: int = 600,
    _depth: int = 0,
) -> dict[str, Any]:
    """Run *cmd* via the worker pool and parse its output.

    If ``stdout`` contains valid JSON it is decoded and returned
    directly.  Otherwise the raw text is wrapped in a dict under the
    ``"output"`` key so callers can always treat the result as a dict.

    **JSON fallback logic** (SAMBA_JSON_MODE = ``auto``, default):

    1. Run the command as-is.  If it succeeds and produces valid JSON,
       return the parsed result.
    2. If it fails with rc != 0 **and** the error indicates an
       unsupported flag (``--json`` or ``--output-format``), retry:
       a. If ``--json`` was in the command, replace it with
          ``--output-format json`` and retry.
       b. If the retry also fails with an unsupported flag, remove all
          JSON flags and retry once more, returning plain text.
    3. Any other non-zero return code raises :class:`SambaToolError`.

    The maximum retry depth is 2 (one for ``--output-format`` fallback,
    one for text-only fallback).

    Parameters
    ----------
    cmd:
        Full command line (typically from :func:`build_samba_command`).
    timeout:
        Maximum execution time in seconds.
    _depth:
        Internal retry counter.  Callers should not set this.

    Returns
    -------
    dict[str, Any]
        Parsed JSON from samba-tool, or ``{"output": raw_stdout}`` when
        JSON parsing fails.

    Raises
    ------
    SambaToolError
        If the samba-tool process returns a non-zero exit code.
        The exception carries an ``http_status`` attribute so that
        routers can easily map it to an appropriate HTTP response.
    """
    # ── Timing instrumentation ────────────────────────────────────────
    t_entry = time.monotonic()

    # Derive a short command label for timing logs (e.g. "user add")
    # cmd is like ["samba-tool", "user", "add", ...]
    _cmd_label = " ".join(cmd[1:3]) if len(cmd) >= 3 else " ".join(cmd[1:])

    t_build = time.monotonic()  # time spent building the command (before this point)

    pool = get_worker_pool()
    t_sub_start = time.monotonic()
    returncode, stdout, stderr = await pool.run_command(cmd, timeout=timeout)
    t_sub_end = time.monotonic()

    logger.debug(
        "Command finished: rc=%d stdout=%d chars stderr=%d chars",
        returncode,
        len(stdout),
        len(stderr),
    )
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Full command: %s", " ".join(cmd))
        if stdout:
            logger.debug("stdout: %s", stdout[:2000])
        if stderr:
            logger.debug("stderr: %s", stderr[:2000])

    settings = get_settings()
    json_mode = settings.JSON_MODE

    if returncode != 0:
        error_msg = stderr.strip() or stdout.strip() or f"Process exited with code {returncode}"

        # ── Timing for failed command ────────────────────────────────
        t_total = time.monotonic() - t_entry
        t_subprocess = t_sub_end - t_sub_start
        t_build_dur = t_sub_start - t_entry
        logger.info(
            "[TIMING] execute_samba_command '%s' FAILED total=%.2fs (build=%.2fs, subprocess=%.2fs, parse=0.00s)",
            _cmd_label, t_total, t_build_dur, t_subprocess,
        )

        # ── JSON fallback logic ──────────────────────────────────────
        # If the command failed because --json or --output-format is not
        # supported, retry with an alternative or without JSON flags.
        if (
            json_mode == "auto"
            and _depth < 2
            and _is_unsupported_flag_error(stderr, stdout)
            and _has_json_flag(cmd)
        ):
            if "--json" in cmd and "--output-format" not in cmd and _depth == 0:
                # Step 1: replace --json with --output-format json
                new_cmd = _replace_json_with_output_format(cmd)
                logger.info(
                    "Retrying with --output-format=json instead of --json: %s",
                    " ".join(new_cmd),
                )
                return await execute_samba_command(new_cmd, timeout=timeout, _depth=_depth + 1)
            else:
                # Step 2: remove all JSON flags and retry as text
                new_cmd = _strip_json_flags(cmd)
                logger.info(
                    "Retrying without JSON flags: %s",
                    " ".join(new_cmd),
                )
                return await execute_samba_command(new_cmd, timeout=timeout, _depth=_depth + 1)

        # Fix v10-1/v11-7/v12-1: Auto-retry on "Unknown parameter" errors.
        # Some samba-tool builds (ALT Linux) don't support flags like
        # --tmpdir that other builds accept. When we encounter an
        # "Unknown parameter encountered" error, we strip the offending
        # parameter from the command and retry.
        #
        # However, as of v12-1, most "Unknown parameter" warnings from
        # smb.conf parsing (e.g. "tmp dir = /var/tmp") are filtered out
        # in worker.py's _run_subprocess before they reach this point.
        # So this retry path now only triggers for CLI flags that are
        # truly not supported by the samba-tool build.
        #
        # If "Ignoring unknown parameter" appears, it means samba-tool
        # already ignored the parameter and continued — the real error
        # is something else.  These lines are also filtered in worker.py,
        # so if they still appear here, it means the error came from a
        # different code path.
        if _depth < 3 and _is_unknown_parameter_error(stderr, stdout):
            new_cmd = _strip_unknown_parameter(cmd, stderr + "\n" + stdout)
            if new_cmd != cmd:
                logger.info(
                    "Retrying after stripping unknown parameter: %s",
                    " ".join(new_cmd),
                )
                return await execute_samba_command(new_cmd, timeout=timeout, _depth=_depth + 1)
            else:
                # The unknown parameter is from smb.conf, not CLI.
                # Log it and continue to the real error.
                logger.debug(
                    "Unknown parameter warning is from smb.conf, not CLI — "
                    "skipping retry. The real error follows."
                )

        exc = SambaToolError(
            f"samba-tool failed (rc={returncode}): {error_msg}",
        )
        # Classify the error message to set an appropriate HTTP status
        # code instead of always defaulting to 500.
        exc.http_status = classify_samba_error(exc)
        raise exc

    # Attempt JSON parse.
    t_parse_start = time.monotonic()
    stdout_stripped = stdout.strip()
    if stdout_stripped:
        try:
            result = json.loads(stdout_stripped)
            t_parse_end = time.monotonic()
            # ── Timing for successful command (JSON result) ──────────
            t_total = t_parse_end - t_entry
            t_subprocess = t_sub_end - t_sub_start
            t_build_dur = t_sub_start - t_entry
            t_parse_dur = t_parse_end - t_parse_start
            logger.info(
                "[TIMING] execute_samba_command '%s' total=%.2fs (build=%.2fs, subprocess=%.2fs, parse=%.2fs)",
                _cmd_label, t_total, t_build_dur, t_subprocess, t_parse_dur,
            )
            if isinstance(result, dict):
                return result
            # Some commands return a JSON list – wrap it.
            return {"items": result}
        except json.JSONDecodeError:
            t_parse_end = time.monotonic()
            # ── Timing for successful command (text result) ──────────
            t_total = t_parse_end - t_entry
            t_subprocess = t_sub_end - t_sub_start
            t_build_dur = t_sub_start - t_entry
            t_parse_dur = t_parse_end - t_parse_start
            logger.info(
                "[TIMING] execute_samba_command '%s' total=%.2fs (build=%.2fs, subprocess=%.2fs, parse=%.2fs)",
                _cmd_label, t_total, t_build_dur, t_subprocess, t_parse_dur,
            )
            return {"output": stdout_stripped}

    t_parse_end = time.monotonic()
    t_total = t_parse_end - t_entry
    t_subprocess = t_sub_end - t_sub_start
    t_build_dur = t_sub_start - t_entry
    t_parse_dur = t_parse_end - t_parse_start
    logger.info(
        "[TIMING] execute_samba_command '%s' total=%.2fs (build=%.2fs, subprocess=%.2fs, parse=%.2fs)",
        _cmd_label, t_total, t_build_dur, t_subprocess, t_parse_dur,
    )
    return {"output": ""}


async def execute_samba_command_raw(
    cmd: list[str],
    timeout: int = 600,
) -> dict[str, Any]:
    """Run *cmd* and return raw stdout/stderr without JSON parsing.

    This is useful for commands that produce human-readable text or
    non-JSON structured output.

    Parameters
    ----------
    cmd:
        Full command line.
    timeout:
        Maximum execution time in seconds.

    Returns
    -------
    dict[str, Any]
        ``{"returncode": int, "stdout": str, "stderr": str}``
    """
    pool = get_worker_pool()
    returncode, stdout, stderr = await pool.run_command(cmd, timeout=timeout)

    logger.debug(
        "Raw command finished: rc=%d stdout=%d chars stderr=%d chars",
        returncode,
        len(stdout),
        len(stderr),
    )
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Full command: %s", " ".join(cmd))

    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


# ── Centralized error classification ──────────────────────────────────

def get_ldapi_url(settings: Settings) -> str:
    """Return the LDAPI URL for local sam.ldb access.

    Commands like ``user get-kerberos-ticket``, ``user getpassword``,
    and ``domain exportkeytab`` require local access to sam.ldb
    (via ``ldapi://``) because password attributes and keytab keys
    are only available over local connections, not over ``ldap://``.

    This function returns ``SAMBA_LDAPI_URL`` if configured,
    otherwise falls back to constructing an ldapi URL from
    ``smb.conf``'s ``private dir`` parameter, or finally to
    ``SAMBA_LDAP_URL``.

    The result is cached in-process to avoid repeated testparm calls.

    Parameters
    ----------
    settings:
        Active application settings.

    Returns
    -------
    str
        The best available LDAPI URL, or the LDAP URL as fallback.
    """
    global _cached_ldapi_url, _cached_ldapi_ts
    # Fix v3-14: TTL-based cache.  If the cached value is an empty
    # string (no socket found) and the TTL has expired, treat it as
    # uncached so we re-probe.  A non-empty cached value (actual URL)
    # is kept permanently until explicitly cleared.
    if _cached_ldapi_url is not None:
        if _cached_ldapi_url != "":
            # Positive result — cache permanently
            return _cached_ldapi_url
        # Negative result — check TTL
        import time as _time
        if _LDAPI_CACHE_TTL > 0 and (_time.monotonic() - _cached_ldapi_ts) < _LDAPI_CACHE_TTL:
            return _cached_ldapi_url
        # TTL expired — re-probe
        _cached_ldapi_url = None
        _cached_ldapi_ts = 0.0

    if settings.LDAPI_URL:
        _cached_ldapi_url = settings.LDAPI_URL
        _cached_ldapi_ts = 0.0  # positive result — no TTL needed
        return _cached_ldapi_url

    # Try to read private dir from smb.conf to construct ldapi URL
    try:
        import subprocess
        import urllib.parse
        cmd = [
            settings.TOOL_PATH, "testparm",
            "--parameter-name=private dir",
            f"--configfile={settings.SMB_CONF}",
            # Fix v3-11: Use --suppress-prompt instead of -s.
            # The -s flag requires an argument in some Samba builds
            # (ALT Linux), causing "testparm: error: -s option requires
            # 1 argument".  --suppress-prompt is the correct flag.
            "--suppress-prompt",
        ]
        logger.debug("Querying private dir: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=20,
            # Fix v18: Pass TMPDIR to testparm subprocess to avoid
            # STATUS_QUOTA_EXCEEDED on tmpfs-mounted /tmp.
            env={**os.environ, "TMPDIR": os.environ.get("TMPDIR", "/var/tmp")},
        )
        logger.debug(
            "testparm private dir: rc=%d stdout='%s' stderr='%s'",
            result.returncode, result.stdout.strip(), result.stderr.strip()[:200],
        )
        if result.returncode == 0:
            private_dir = result.stdout.strip()
            # testparm sometimes prints extra lines; take the last
            # non-empty line that looks like an absolute path
            for line in reversed(private_dir.splitlines()):
                line = line.strip()
                if line.startswith("/"):
                    private_dir = line
                    break
            else:
                # No absolute path found; use whatever we got
                private_dir = result.stdout.strip().split("\n")[-1].strip()
            if private_dir and private_dir.startswith("/"):
                # The ldapi socket path is {private_dir}/ldapi.
                # Some older Samba versions used {private_dir}/ldap_priv/ldapi,
                # so we check both and prefer the one that exists.
                ldapi_paths = [
                    f"{private_dir}/ldapi",
                    f"{private_dir}/ldap_priv/ldapi",
                ]
                for ldapi_path in ldapi_paths:
                    # Fix v6-2: Use os.path.exists() instead of os.path.isfile()
                    # for LDAPI socket detection.  Unix domain sockets are not
                    # regular files and may not be detected by isfile() on some
                    # systems (ALT Linux).  exists() returns True for any
                    # filesystem entry including sockets.
                    if os.path.exists(ldapi_path):
                        url = f"ldapi://{urllib.parse.quote(ldapi_path, safe='')}"
                        logger.info("Constructed LDAPI URL (socket exists): %s", url)
                        _cached_ldapi_url = url
                        _cached_ldapi_ts = 0.0  # positive result
                        return url
                # Fix v10-3: If private dir exists but no LDAPI socket file
                # was found, still construct and return the LDAPI URL.
                # samba-tool will create the socket on demand when connecting.
                # Returning empty would cause callers to fall back to ldap://
                # which always fails for password operations.
                # Only do this if the private directory itself exists.
                ldapi_path = ldapi_paths[0]
                if os.path.isdir(private_dir):
                    url = f"ldapi://{urllib.parse.quote(ldapi_path, safe='')}"
                    logger.info(
                        "Constructed LDAPI URL (socket not found at %s, "
                        "but private dir %s exists — samba-tool will create "
                        "socket on demand): %s",
                        ldapi_path, private_dir, url,
                    )
                    _cached_ldapi_url = url
                    _cached_ldapi_ts = 0.0  # positive result
                    return url
                logger.warning(
                    "testparm returned non-path private dir: '%s'", private_dir
                )
        else:
            logger.warning(
                "testparm failed (rc=%d): %s",
                result.returncode, result.stderr.strip()[:200],
            )
    except FileNotFoundError:
        logger.warning("testparm binary not found at '%s'", settings.TOOL_PATH)
    except subprocess.TimeoutExpired:
        logger.warning("testparm timed out querying private dir")
    except Exception as exc:
        logger.warning("Failed to get LDAPI URL from testparm: %s", exc)

    # Final fallback: check common LDAPI socket paths before falling
    # back to LDAP_URL.  On some systems testparm fails or is not
    # installed, but the LDAPI socket still exists.
    _STANDARD_LDAPI_PATHS = [
        "/var/lib/samba/private/ldapi",          # ALT Linux default (Fix v6-2)
        "/var/lib/samba/private/ldap_priv/ldapi", # Standard Samba path
        "/var/run/samba/ldapi",                   # Some distros
    ]
    for path in _STANDARD_LDAPI_PATHS:
        # Fix v6-2: Use os.path.exists() instead of os.path.isfile() —
        # LDAPI sockets are not regular files.
        if os.path.exists(path):
            url = f"ldapi://{urllib.parse.quote(path, safe='')}"
            logger.info(
                "Found LDAPI socket at %s (fallback from testparm): %s",
                path, url,
            )
            _cached_ldapi_url = url
            _cached_ldapi_ts = 0.0  # positive result
            return url

    # No LDAPI socket found anywhere — return empty string instead of
    # falling back to ldap://, because ldap:// will ALWAYS fail for
    # password/keytab operations with LDAP_OPERATIONS_ERROR.
    # Callers (e.g. get-kerberos-ticket) will see the empty string
    # and return a clear HTTP 422 error.
    logger.warning(
        "No LDAPI socket found (checked testparm and common paths: %s). "
        "Commands requiring local sam.ldb access will fail.",
        ", ".join(_STANDARD_LDAPI_PATHS),
    )
    _cached_ldapi_url = ""
    import time as _time_mod
    _cached_ldapi_ts = _time_mod.monotonic()
    return _cached_ldapi_url


# ── LDAPI URL cache ────────────────────────────────────────────────────
# Cache the result of get_ldapi_url() to avoid repeated testparm calls.
# Fix v3-14: TTL-based cache.  A negative result (empty string) is
# no longer cached permanently — it expires after _LDAPI_CACHE_TTL
# seconds, allowing re-discovery if the socket appears later.
_cached_ldapi_url: Optional[str] = None
_cached_ldapi_ts: float = 0.0  # timestamp of last cache write
_LDAPI_CACHE_TTL: float = 30.0  # seconds; 0 = no TTL (permanent)


def clear_ldapi_cache() -> None:
    """Clear the cached LDAPI URL (useful after config changes)."""
    global _cached_ldapi_url, _cached_ldapi_ts
    _cached_ldapi_url = None
    _cached_ldapi_ts = 0.0

# ── TDB URL for read-only access ─────────────────────────────────────
# Fix v20: tdb:// opens the sam.ldb database file directly, bypassing
# the Samba LDAP server entirely.  No authentication is needed — only
# file-system permissions on sam.ldb.  This makes tdb:// the preferred
# connection method for READ operations (getpassword, user list, etc.)
# because:
#   1. No LDAP_OPERATIONS_ERROR (unlike ldapi:// for getpassword)
#   2. Supports parallel reads (10+ concurrent requests)
#   3. Faster than ldapi:// (no socket/auth overhead)
#
# IMPORTANT: tdb:// MUST NEVER be used for WRITE operations.
# Concurrent writes via tdb:// will corrupt the database.
# All write operations MUST go through ldapi:// or ldap://
# (which route through the Samba server that serialises writes).

_cached_tdb_url: Optional[str] = None
_cached_tdb_url_ts: float = 0.0
_TDB_CACHE_TTL: float = 60.0  # seconds


def clear_tdb_cache() -> None:
    """Clear the cached TDB URL."""
    global _cached_tdb_url, _cached_tdb_url_ts
    _cached_tdb_url = None
    _cached_tdb_url_ts = 0.0


def get_tdb_url(settings: Settings) -> str:
    """Return the TDB URL for direct read-only sam.ldb access.

    TDB (``tdb://<path>``) opens the database file directly, bypassing
    the Samba LDAP server.  This is the preferred method for READ
    operations because it avoids LDAP authentication issues and supports
    parallel reads.

    **NEVER use tdb:// for write operations** — concurrent writes will
    corrupt the database.  Use :func:`get_ldapi_url` for writes.

    Detection order:
      1. ``settings.TDB_URL`` if explicitly configured
      2. Auto-detect from ``settings.TDB_SAM_LDB_PATH``
      3. Auto-detect from testparm's ``private dir`` + ``sam.ldb``
      4. Fallback to common paths

    The result is cached to avoid repeated testparm calls.

    Parameters
    ----------
    settings:
        Active application settings.

    Returns
    -------
    str
        TDB URL (e.g. ``tdb:///var/lib/samba/private/sam.ldb``),
        or empty string if sam.ldb cannot be found.
    """
    global _cached_tdb_url, _cached_tdb_url_ts

    # Check cache
    if _cached_tdb_url is not None:
        if _cached_tdb_url != "":
            return _cached_tdb_url
        import time as _time
        if _TDB_CACHE_TTL > 0 and (_time.monotonic() - _cached_tdb_url_ts) < _TDB_CACHE_TTL:
            return _cached_tdb_url
        _cached_tdb_url = None
        _cached_tdb_url_ts = 0.0

    # 1. Explicit TDB_URL
    if settings.TDB_URL:
        _cached_tdb_url = settings.TDB_URL
        _cached_tdb_url_ts = 0.0
        return _cached_tdb_url

    # 2. Explicit TDB_SAM_LDB_PATH
    if settings.TDB_SAM_LDB_PATH:
        import os as _os
        if _os.path.exists(settings.TDB_SAM_LDB_PATH):
            url = f"tdb://{settings.TDB_SAM_LDB_PATH}"
            logger.info("Constructed TDB URL from TDB_SAM_LDB_PATH: %s", url)
            _cached_tdb_url = url
            _cached_tdb_url_ts = 0.0
            return url

    # 3. Auto-detect from testparm's private dir
    try:
        import subprocess
        cmd = [
            settings.TOOL_PATH, "testparm",
            "--parameter-name=private dir",
            f"--configfile={settings.SMB_CONF}",
            "--suppress-prompt",
        ]
        logger.debug("Querying private dir for TDB URL: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=20,
            env={**os.environ, "TMPDIR": os.environ.get("TMPDIR", "/var/tmp")},
        )
        if result.returncode == 0:
            private_dir = result.stdout.strip()
            for line in reversed(private_dir.splitlines()):
                line = line.strip()
                if line.startswith("/"):
                    private_dir = line
                    break
            else:
                private_dir = result.stdout.strip().split("\n")[-1].strip()
            if private_dir and private_dir.startswith("/"):
                sam_ldb_path = f"{private_dir}/sam.ldb"
                import os as _os
                if _os.path.exists(sam_ldb_path):
                    url = f"tdb://{sam_ldb_path}"
                    logger.info("Auto-detected TDB URL: %s", url)
                    _cached_tdb_url = url
                    _cached_tdb_url_ts = 0.0
                    return url
    except FileNotFoundError:
        logger.warning("testparm binary not found at '%s'", settings.TOOL_PATH)
    except subprocess.TimeoutExpired:
        logger.warning("testparm timed out querying private dir for TDB URL")
    except Exception as exc:
        logger.warning("Failed to auto-detect TDB URL from testparm: %s", exc)

    # 4. Fallback: check common sam.ldb paths
    import os as _os
    _STANDARD_SAM_LDB_PATHS = [
        "/var/lib/samba/private/sam.ldb",          # ALT Linux / standard
        "/var/lib/samba/private/sam.ldb",           # Same, but explicit
        "/var/lib/samba/state/sam.ldb",             # Some distros
    ]
    for path in _STANDARD_SAM_LDB_PATHS:
        if _os.path.exists(path):
            url = f"tdb://{path}"
            logger.info("TDB URL from standard path: %s", url)
            _cached_tdb_url = url
            _cached_tdb_url_ts = 0.0
            return url

    logger.warning(
        "No sam.ldb found — TDB URL not available. "
        "READ operations that need -H will fall back to ldapi/ldap. "
        "Set SAMBA_TDB_URL or SAMBA_TDB_SAM_LDB_PATH to configure manually."
    )
    _cached_tdb_url = ""
    import time as _time_mod
    _cached_tdb_url_ts = _time_mod.monotonic()
    return _cached_tdb_url


# ── DC hostname for RPC commands ───────────────────────────────────────
# Fix v21: DNS and DRS commands use DCE/RPC, not LDAP.  They take the
# server hostname as a positional argument, NOT via -H.  Kerberos
# cannot issue a service ticket for "localhost" or "127.0.0.1", so
# using these as the server name causes NT_STATUS_INVALID_PARAMETER.
# The hostname MUST be the DC's real network name (FQDN or short name)
# that resolves via DNS or /etc/hosts.

_cached_dc_hostname: Optional[str] = None
_DC_HOSTNAME_CACHE_TTL: float = 300.0  # 5 minutes
_cached_dc_hostname_ts: float = 0.0


def clear_dc_hostname_cache() -> None:
    """Clear the cached DC hostname."""
    global _cached_dc_hostname, _cached_dc_hostname_ts
    _cached_dc_hostname = None
    _cached_dc_hostname_ts = 0.0


def get_dc_hostname(settings: Settings) -> str:
    """Return the real DC hostname for DNS/DRS RPC commands.

    DNS and DRS commands in samba-tool use DCE/RPC over SMB, not LDAP.
    They require the DC's real network hostname as a positional argument.
    Using "localhost" or "127.0.0.1" causes Kerberos to fail with
    NT_STATUS_INVALID_PARAMETER because it cannot obtain a service
    ticket for the name "localhost".

    Detection order:
      1. ``settings.DC_HOSTNAME`` if explicitly configured
      2. ``settings.SERVER`` if it is NOT localhost/127.0.0.1
      3. Auto-detect from system hostname + realm
      4. Auto-detect from /etc/hosts
      5. Fallback to settings.SERVER with a warning

    The result is cached for 5 minutes.

    Parameters
    ----------
    settings:
        Active application settings.

    Returns
    -------
    str
        The real DC hostname (e.g. ``dc1.kcrb.local``), or the
        configured SERVER as fallback (with a warning if it is
        localhost).
    """
    global _cached_dc_hostname, _cached_dc_hostname_ts

    # Check cache
    if _cached_dc_hostname is not None:
        import time as _time
        if _DC_HOSTNAME_CACHE_TTL > 0 and (_time.monotonic() - _cached_dc_hostname_ts) < _DC_HOSTNAME_CACHE_TTL:
            return _cached_dc_hostname
        _cached_dc_hostname = None
        _cached_dc_hostname_ts = 0.0

    # 1. Explicit DC_HOSTNAME setting
    if settings.DC_HOSTNAME:
        _cached_dc_hostname = settings.DC_HOSTNAME
        _cached_dc_hostname_ts = 0.0
        logger.debug("Using explicit DC_HOSTNAME: %s", _cached_dc_hostname)
        return _cached_dc_hostname

    # 2. Check if SERVER is a real hostname (not localhost)
    _LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "127.0.0.1", "::1"}
    if settings.SERVER and settings.SERVER.lower() not in _LOCALHOST_NAMES:
        _cached_dc_hostname = settings.SERVER
        _cached_dc_hostname_ts = 0.0
        logger.debug("Using SERVER as DC hostname: %s", _cached_dc_hostname)
        return _cached_dc_hostname

    # 3. Auto-detect from system hostname + realm
    try:
        import socket
        import subprocess

        # Try hostname --fqdn first
        try:
            result = subprocess.run(
                ["hostname", "--fqdn"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                fqdn = result.stdout.strip().lower()
                if fqdn and fqdn not in _LOCALHOST_NAMES and "." in fqdn:
                    _cached_dc_hostname = fqdn
                    import time as _time
                    _cached_dc_hostname_ts = _time.monotonic()
                    logger.info("Auto-detected DC hostname from hostname --fqdn: %s", fqdn)
                    return _cached_dc_hostname
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try socket.getfqdn()
        fqdn = socket.getfqdn().lower()
        if fqdn and fqdn not in _LOCALHOST_NAMES and "." in fqdn:
            _cached_dc_hostname = fqdn
            import time as _time
            _cached_dc_hostname_ts = _time.monotonic()
            logger.info("Auto-detected DC hostname from socket.getfqdn(): %s", fqdn)
            return _cached_dc_hostname
    except Exception as exc:
        logger.debug("Failed to auto-detect DC hostname from system: %s", exc)

    # 4. Try to construct from hostname + realm
    try:
        import socket
        short_name = socket.gethostname().split(".")[0].lower()
        if short_name and short_name not in _LOCALHOST_NAMES and settings.REALM:
            fqdn = f"{short_name}.{settings.REALM.lower()}"
            _cached_dc_hostname = fqdn
            import time as _time
            _cached_dc_hostname_ts = _time.monotonic()
            logger.info("Constructed DC hostname from hostname + realm: %s", fqdn)
            return _cached_dc_hostname
    except Exception as exc:
        logger.debug("Failed to construct DC hostname from hostname + realm: %s", exc)

    # 5. Fallback to settings.SERVER with warning
    fallback = settings.SERVER or "localhost"
    logger.warning(
        "Could not determine real DC hostname for DNS/DRS RPC commands. "
        "Falling back to '%s'. DNS and DRS commands may fail with "
        "NT_STATUS_INVALID_PARAMETER if this is 'localhost' or '127.0.0.1'. "
        "Set SAMBA_DC_HOSTNAME to the real DC hostname (e.g. 'dc1.kcrb.local') "
        "to fix this. Kerberos cannot issue service tickets for 'localhost'.",
        fallback,
    )
    _cached_dc_hostname = fallback
    import time as _time
    _cached_dc_hostname_ts = _time.monotonic()
    return _cached_dc_hostname


def probe_connection(settings: Settings) -> dict[str, str]:
    """Probe available connection methods and return the best URLs.
    
    Returns a dict with:
      - 'ldapi_url': Best available LDAPI URL (empty string if not available)
      - 'ldap_url': Best available LDAP URL (empty string if not available)
      - 'tdb_url': Best available TDB URL for read operations (empty if N/A)
      - 'preferred': 'ldapi' or 'ldap' — which to use for local operations
    
    Fix v10-3: Auto-detect LDAPI and LDAP connection availability.
    Tries to connect via LDAPI first (most reliable for local samdb),
    then falls back to LDAP.  Results are cached briefly.
    """
    global _cached_ldapi_url, _cached_ldapi_ts
    result = {"ldapi_url": "", "ldap_url": "", "tdb_url": "", "preferred": ""}
    
    # Try LDAPI first
    clear_ldapi_cache()
    ldapi_url = get_ldapi_url(settings)
    if ldapi_url and ldapi_url.startswith("ldapi://"):
        # Verify the connection works by trying a quick samba-tool command
        try:
            import subprocess as _sp
            test_cmd = [
                settings.TOOL_PATH, "user", "list",
                "-H", ldapi_url,
                "--configfile=" + settings.SMB_CONF,
                "--suppress-prompt",
            ]
            # Quick 5-second test
            # Fix v18: Read TMPDIR from Settings/os.environ for probe subprocess.
            _probe_tmpdir = os.environ.get("TMPDIR", getattr(settings, "TMPDIR", "/var/tmp"))
            probe_result = _sp.run(
                test_cmd, capture_output=True, text=True, timeout=10,
                env={**os.environ, "TMPDIR": _probe_tmpdir, "PYTHONWARNINGS": "ignore"},
            )
            # Fix v12-4: Filter non-fatal warnings from probe stderr,
            # same as worker.py does for subprocess execution.
            # "Unknown parameter encountered" from smb.conf parsing
            # is harmless and should not cause probe to fail.
            _NON_FATAL_PATTERNS = (
                "Unknown parameter encountered",
                "Ignoring unknown parameter",
                "Using passwords on command line",
            )
            probe_stderr_lines = probe_result.stderr.splitlines()
            filtered_probe_stderr = "\n".join(
                line for line in probe_stderr_lines
                if not any(pat in line for pat in _NON_FATAL_PATTERNS)
            )

            if probe_result.returncode == 0 or not filtered_probe_stderr.strip():
                result["ldapi_url"] = ldapi_url
                result["preferred"] = "ldapi"
                logger.info("probe_connection: LDAPI connection verified: %s", ldapi_url)
            else:
                # LDAPI URL constructed but connection failed
                err = (filtered_probe_stderr + probe_result.stdout).lower()
                if "no such option" in err:
                    # The connection itself might work, just a flag issue
                    result["ldapi_url"] = ldapi_url
                    result["preferred"] = "ldapi"
                    logger.info("probe_connection: LDAPI URL constructed (flag issue, not connection): %s", ldapi_url)
                else:
                    logger.warning("probe_connection: LDAPI connection test failed: %s", (filtered_probe_stderr or probe_result.stdout)[:200])
        except Exception as e:
            logger.warning("probe_connection: LDAPI probe exception: %s", e)
    
    # Try TDB URL (for read operations)
    tdb_url = get_tdb_url(settings)
    if tdb_url:
        result["tdb_url"] = tdb_url
        logger.info("probe_connection: TDB URL available: %s", tdb_url)

    # Try LDAP
    if settings.LDAP_URL:
        result["ldap_url"] = settings.LDAP_URL
        if not result["preferred"]:
            result["preferred"] = "ldap"
    
    if not result["preferred"]:
        logger.warning("probe_connection: No working LDAPI or LDAP connection found")
    
    return result


class SambaToolError(RuntimeError):
    """Raised when samba-tool returns a non-zero exit code.

    The ``http_status`` attribute carries a suggested HTTP status code
    that routers can use directly.
    """

    def __init__(self, message: str, http_status: int = 500) -> None:
        super().__init__(message)
        self.http_status = http_status


def classify_samba_error(exc: RuntimeError) -> int:
    """Analyse a :class:`RuntimeError` from samba-tool and return the
    most appropriate HTTP status code.

    Routers should call this function (or use :func:`raise_classified_error`)
    instead of hard-coding 500 for every error.

    Parameters
    ----------
    exc:
        The exception to classify.

    Returns
    -------
    int
        An HTTP status code (e.g. 400, 404, 409, 403, 500).
    """
    # If we already have a SambaToolError with a specific status, use it.
    if isinstance(exc, SambaToolError) and exc.http_status != 500:
        return exc.http_status

    msg = str(exc).lower()

    # Fix v7-5: "no such option" / "unrecognised option" → 400 Bad Request.
    # These indicate a bad command-line flag was passed, which is a
    # client/API configuration error, NOT a missing resource (404).
    # MUST come before the generic "no such" → 404 check below,
    # because "no such option" contains "no such" which would
    # otherwise be classified as 404.
    if "no such option" in msg or "unrecogni" in msg:
        return 400

    # Fix v12-1: Removed "Unknown parameter encountered" → 400 rule.
    # These warnings are now filtered out of stderr in worker.py's
    # _run_subprocess (Fix v12-1), so they should never appear in
    # the error message.  If they still do appear (e.g. from a
    # non-worker subprocess path), they are harmless warnings from
    # smb.conf parsing and should NOT be classified as 400 errors.
    # Previously, this rule caused many false 400 responses when
    # smb.conf contained "tmp dir = /var/tmp" which ALT Linux's
    # samba-tool doesn't recognize.

    # ── Upstream connection failures → 502 Bad Gateway ──────────────────
    # These MUST come before generic "not found" checks because DRS/LDAP
    # connection errors often contain "not found" in NT_STATUS details,
    # but the root cause is connectivity/misconfiguration, not a missing
    # resource.

    # DRS connection failure → 502 (upstream DC unreachable)
    if "drs connection to" in msg and "failed" in msg:
        return 502

    # LDAP connection failure to a server → 502 Bad Gateway
    if "ldap connection to" in msg and "failed" in msg:
        return 502

    # DC discovery failure → 502 (upstream connectivity issue, not a missing resource)
    # These MUST come before the generic "could not find" / "failed to find" → 404
    # checks, because "Could not find a DC for domain" is a connectivity/
    # configuration error, not a "resource not found" error.
    if "could not find a dc" in msg:
        return 502
    if "failed to find dc" in msg or "failed to find a dc" in msg:
        return 502
    # Fix v11-2: Trust domain discovery failure → 400, not 404.
    # "failed to find a writeable dc for domain" means the trusted domain
    # is unreachable via DNS, not that the object doesn't exist in our AD.
    if "failed to find a writeable dc for domain" in msg:
        return 400
    if "failed to find a writeable dc" in msg:
        return 400

    # Fix v22: Trust domain DNS resolution errors → 400, not 404.
    # When samba-tool trust commands fail because the trusted domain
    # cannot be found via DNS, the error message typically contains
    # both "trust" and a "not found"/"does not exist" pattern.
    # This is a client error (bad domain name), not a missing resource.
    # MUST come before the generic "not found" → 404 check.
    # Note: "Failed to find trust" (trust OBJECT not in our AD) should
    # remain 404, so we specifically check for domain-related patterns.
    if ("trust" in msg and "domain" in msg and
            ("does not exist" in msg or "not found" in msg or "failed to find" in msg)):
        return 400

    # Not found / does not exist
    if "not found" in msg or "no such" in msg or "does not exist" in msg:
        return 404

    # No keys found for keytab export (resource not found)
    if "no keys found" in msg or "failed to export" in msg:
        return 404

    # Already exists / already being used (conflict)
    if (
        "already exist" in msg
        or "already a" in msg
        or "already exists" in msg
        or "already being used" in msg
    ):
        return 409

    # Domain functional level cannot be raised to current or lower level
    if "can't be smaller than or equal to" in msg:
        return 409

    # Domain functional level cannot exceed the lowest DC level
    if "can't be higher than the lowest function level of a dc" in msg:
        return 409

    # Domain functional level is higher than forest level
    if "forest function level is higher than the domain" in msg:
        return 409

    # Forest functional level cannot exceed domain level
    if "forest function level can't be higher than the domain" in msg:
        return 409

    # Multiple results for a non-unique search → 400 Bad Request
    if "multiple results" in msg or "multiple objects" in msg:
        return 400

    # Password not available (e.g. Kerberos ticket export for non-gMSA)
    # This happens when connecting via ldap:// instead of ldapi://
    if "no password was available" in msg:
        return 422

    # LDAP authentication / operations error → 422 Unprocessable Entity
    # These occur when samba-tool connects via ldap:// instead of ldapi://
    # for password-retrieval commands. The operation requires local
    # ldapi:// access but was attempted over an insecure/unauthenticated
    # LDAP connection.
    if "operation unavailable without authentication" in msg:
        return 422
    if "ldap_operations_error" in msg:
        return 422

    # Permission denied / access denied / insufficient rights
    if "permission" in msg or "access deni" in msg or "insufficient" in msg:
        return 403

    # Server role mismatch (e.g. trust commands on member server)
    if "invalid server_role" in msg or "role_domain_member" in msg:
        return 403

    # Connection / pipe errors → 502 Bad Gateway (upstream failure)
    if "connection to" in msg and "pipe" in msg and "failed" in msg:
        return 502
    # v1.2.6 fix: NT_STATUS_UNSUCCESSFUL (error code 3221225473) from
    # samba-tool time / SRVSVC pipe → 503 Service Unavailable.
    # This is a transient condition — the SRVSVC pipe is not responding,
    # often because it hasn't started yet or is temporarily overloaded.
    # Previously mapped to 502, but 503 is more accurate: the service
    # exists but is currently unable to handle the request.  Clients
    # should retry after a delay rather than treating it as a gateway
    # problem.  Also detect the numeric error code 3221225473 which is
    # the Windows NT status value for NT_STATUS_UNSUCCESSFUL.
    if "nt_status_unsuccessful" in msg or "3221225473" in msg:
        return 503
    if "connection error" in msg or "connection refused" in msg:
        return 502
    # SRVSVC pipe failure → 502
    if "srvsvc pipe" in msg:
        return 502

    # Invalid argument / usage error
    if "invalid" in msg or "usage:" in msg:
        return 400

    # Missing required argument
    if "missing" in msg or "required" in msg:
        return 400

    # Additional not-found patterns (Samba-specific error strings)
    if "unable to find" in msg:
        return 404
    if "failed to find" in msg:
        return 404
    if "failed to find trust" in msg:
        return 404
    if "no such object" in msg:
        return 404
    if "could not find" in msg:
        return 404
    if "werr_not_found" in msg or "status_not_found" in msg:
        return 404

    # NT status object-not-found patterns
    if "nt_status_object_name_not_found" in msg:
        return 404
    if "no such file or directory" in msg:
        return 404

    # Parent does not exist (move target not found)
    if "parent does not exist" in msg or "cannot rename" in msg:
        return 404

    # Unable to parse DN string → 400 bad request
    if "unable to parse dn" in msg:
        return 400

    # Device Timeout / DNS RPC connection failure → 503 Service Unavailable
    # These indicate the DNS RPC server is overloaded or unreachable,
    # which is a transient condition, not a permanent error.
    if "device timeout" in msg:
        return 503
    if "connecting to dns rpc server" in msg and "failed" in msg:
        return 503

    # Not Enough Quota → 507 Insufficient Storage
    # The DC has insufficient virtual memory / resources to process
    # DRSUAPI RPC requests. This is a resource constraint on the
    # server side, not a transient condition.
    # Also catches the Windows error code 0x800705AD variant.
    # Fix v4: Also catch STATUS_QUOTA_EXCEEDED (0xC0000073 / 3221225495)
    # which is the NT status code returned by net.finddc() when it
    # fails to allocate virtual memory during CLDAP DC discovery.
    # This is the primary error for GPO creation failures.
    if ("not enough quota" in msg or "0x800705ad" in msg
            or "status_quota_exceeded" in msg or "0xc0000073" in msg
            or "insufficient_storage" in msg):
        # Enhance the exception message with recovery suggestions
        # if it doesn't already contain them.
        original = str(exc)
        if "increase swap" not in original.lower() and "virtual memory" not in original.lower() and "finddc" not in original.lower():
            original += (
                " Suggestion: increase swap space (e.g. 'fallocate -l 2G /swapfile && "
                "mkswap /swapfile && swapon /swapfile'), increase VM/container memory limits, "
                "or try using -H ldapi:// for local samdb access instead of RPC. "
                "For GPO creation: this is likely caused by Samba bug in net.finddc(address=...) "
                "in python/samba/netcmd/gpo.py — set SAMBA_LDAPI_URL to bypass CLDAP discovery."
            )
        exc.args = (original,)
        return 507

    # SystemError from domain leave → 412 Precondition Failed
    # The machine is not joined to a domain or is a DC — leave not applicable.
    if "systemerror" in msg:
        return 412

    # DRSUAPI connection timeout / unreachable → 502 Bad Gateway
    # When DRS commands hang, we want to return 502 quickly instead of 500
    if "drs connection to" in msg and ("timed out" in msg or "timeout" in msg):
        return 502

    # Generic command timeout (from worker pool subprocess.TimeoutExpired)
    # → 504 Gateway Timeout
    if "command timed out" in msg:
        return 504

    # Please specify --attributes (samba-tool user getpassword)
    if "please specify --attributes" in msg:
        return 400

    # Fix v22: Trust operations - DNS lookup failure for trusted domain
    # should return 400 (bad request) not 404 (resource not found),
    # because the problem is the client passing a non-existent domain name.
    if "trust" in msg and ("does not exist" in msg or "not found" in msg or "dns_error_name_does_not_exist" in msg or "failed to find" in msg):
        return 400

    # Default: internal server error
    return 500


def raise_classified_error(exc: RuntimeError) -> None:
    """Classify a :class:`RuntimeError` from samba-tool and raise an
    :class:`HTTPException` with the most appropriate status code.

    This is a convenience wrapper that routers can call in their
    ``except RuntimeError`` blocks.
    """
    from fastapi import HTTPException
    http_status = classify_samba_error(exc)
    raise HTTPException(status_code=http_status, detail=str(exc))
