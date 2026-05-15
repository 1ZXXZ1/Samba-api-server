"""
Domain management router.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``domain_info``          → ``fetch_domain_info()`` (ldbsearch, no IP required)
- ``get_domain_level``     → ``fetch_domain_level()`` (ldbsearch)
- ``get_password_settings`` → ``fetch_domain_password_settings()`` (ldbsearch)
- ``list_trusts``          → ``fetch_domain_trusts()`` (ldbsearch)
- ``list_kds_root_keys``   → ``fetch_kds_root_keys()`` (ldbsearch)
Write operations still use samba-tool.

v1.2.4_fix: Fixed domain level GET returning "Unknown ()" — the forest
level attribute ``msDS-forestBehaviorVersion`` is on the Partitions
container, not the domain object.  ``fetch_domain_level()`` now uses a
combined filter ``(|(objectClass=domain)(cn=Partitions)(objectClass=nTDSDSA))``
and classifies results by DN pattern.  Also replaced the ``samba-tool
domain level show`` pre-check in ``PUT /level`` with ``fetch_domain_level()``
so the 409 Conflict error is returned correctly instead of the raw
samba-tool error.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import build_samba_command, execute_samba_command, get_dc_hostname, get_ldapi_url, get_tdb_url, raise_classified_error
from app.models.common import SuccessResponse, TaskResponse
from app.models.domain import (
    BackupRequest,
    DomainLevelSetRequest,
    ForceActionRequest,
    PasswordSettingsSetRequest,
    TrustCreateRequest,
)
from app.tasks import get_task_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/domain", tags=["Domain"])


# ── Domain info via ldbsearch (fast) ──────────────────────────────────

@router.get("/full", summary="Get domain info (fast, via ldbsearch)")
async def domain_info_full(_auth: ApiKeyDep) -> dict:
    """Return domain information and forest level via ldbsearch.

    This endpoint uses the fast ``ldbsearch`` backend instead of
    ``samba-tool domain info`` (which requires an IP address).
    Returns the domain DN, SID, functional level, and FSMO role owner.
    Results are cached for 30 seconds.
    """
    from app.ldb_reader import fetch_domain_info
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/domain/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_domain_info()
    result = {"status": "ok", "domain": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── DC role check for trust commands ─────────────────────────────────────

def _get_server_role() -> str:
    """Return the cached server role from Settings.

    The role is auto-detected once at application startup via
    ``Settings.ensure_server_role()`` and cached in ``Settings.SERVER_ROLE``.
    This avoids repeated testparm invocations on every request.

    Fix v13: If the cached role is 'unknown', force a re-detection.
    The samba service may have started after the API server, so
    retrying can now succeed where the initial attempt failed.
    """
    settings = get_settings()
    role = settings.ensure_server_role()
    if role == "unknown":
        # Force re-detection: clear the cached 'unknown' and retry.
        # This handles the case where the API started before samba
        # was fully initialized.
        settings.SERVER_ROLE = ""
        role = settings.ensure_server_role()
        if role != "unknown":
            logger.info("Re-detected server role: '%s' (was 'unknown')", role)
    return role


async def _require_dc_role() -> None:
    """Verify the current server is a Domain Controller.

    Trust management commands only work on a DC.  If the server has
    the role ``ROLE_DOMAIN_MEMBER`` (or any non-DC role), raise 403.

    The server role is cached in ``Settings.SERVER_ROLE`` at startup,
    so this check is instant — no testparm subprocess is spawned.
    If the role is 'unknown', the command proceeds and the executor's
    ``classify_samba_error`` handles the samba-tool error output.

    API documentation should note that all ``/api/v1/domain/trust/*``
    endpoints require the server to be a Domain Controller (DC).
    """
    role = _get_server_role()
    if role != "unknown":
        if "domain member" in role or "standalone" in role or "member server" in role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Trust operations are only available on Domain Controllers. "
                    f"Current server role: '{role.strip()}'. "
                    f"Trust commands (create, delete, list, validate, namespaces) "
                    f"require a Samba Active Directory Domain Controller. "
                    f"See: /health endpoint for server role information."
                ),
            )


# ── Domain info ──────────────────────────────────────────────────────────

@router.get("/info", summary="Domain info")
async def domain_info(_auth: ApiKeyDep) -> dict:
    """Return general information about the Samba AD domain via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool domain info``.
    No IP address is required — ldbsearch reads directly from sam.ldb.
    Returns domain DN, SID, functional level, and FSMO role owner.
    """
    from app.ldb_reader import fetch_domain_info

    data = await fetch_domain_info()
    return {"status": "ok", "domain": data}


# ── Domain functional level ─────────────────────────────────────────────

@router.get("/level", summary="Get domain functional level")
async def get_domain_level(_auth: ApiKeyDep) -> dict:
    """Retrieve the current domain, forest, and lowest DC functional levels.

    v1.2.4_fix: Rewritten to use ``fetch_domain_level()`` which queries
    three object types in one ldbsearch call:

    - Domain object → ``msDS-Behavior-Version`` (domain level)
    - Partitions container → ``msDS-Behavior-Version`` (forest level)
    - nTDSDSA objects → minimum ``msDS-Behavior-Version`` (lowest DC level)

    The ``msDS-Behavior-Version`` integer maps to:

    - 0 = Windows 2000 Mixed/Native
    - 1 = Windows 2003 Interim
    - 2 = Windows 2003
    - 3 = Windows 2008
    - 4 = Windows 2008 R2
    - 5 = Windows 2012
    - 6 = Windows 2012 R2
    - 7 = Windows 2016
    """
    from app.ldb_reader import fetch_domain_level

    data = await fetch_domain_level()
    if not data:
        return {
            "status": "ok",
            "domain_function_level": None,
            "forest_function_level": None,
            "lowest_dc_function_level": None,
        }

    return {
        "status": "ok",
        "domain_function_level": data.get("domain_functional_level"),
        "forest_function_level": data.get("forest_functional_level"),
        "lowest_dc_function_level": data.get("lowest_dc_level"),
        "msDS-Behavior-Version": data.get("domain_version"),
        "msDS-forestBehaviorVersion": data.get("forest_version"),
        "lowest_dc_msDS-Behavior-Version": data.get("lowest_dc_version"),
    }


@router.put(
    "/level",
    summary="Set domain functional level",
    response_model=SuccessResponse,
)
async def set_domain_level(
    body: DomainLevelSetRequest,
    _: ApiKeyDep,
) -> SuccessResponse:
    """Set the domain functional level.

    **Warning:** raising the functional level is irreversible.

    The samba-tool ``domain level raise`` command requires the new
    level to be strictly higher than the current one.  This endpoint
    first queries the current level via ldbsearch and, if the requested
    level is equal or lower, returns HTTP 409 with a clear message
    instead of letting samba-tool fail with a confusing error.

    v1.2.4_fix: Replaced ``samba-tool domain level show`` pre-check
    with ``fetch_domain_level()`` (ldbsearch) for consistency and
    reliability.  The old pre-check could fail or return incorrect
    data, leading to the raw samba-tool error being surfaced.
    """
    # Pre-check: query the current domain level via ldbsearch.
    # This prevents the confusing "can't be smaller than or equal to"
    # error from samba-tool and gives the caller a helpful message.
    # Level name → msDS-Behavior-Version integer mapping
    _LEVEL_TO_INT: dict[str, int] = {
        "2000": 0,
        "2000_mixed": 0,
        "2000_native": 0,
        "2003_interim": 1,
        "2003": 2,
        "2008": 3,
        "2008_r2": 4,
        "2012": 5,
        "2012_r2": 6,
        "2016": 7,
    }

    try:
        from app.ldb_reader import fetch_domain_level
        current_data = await fetch_domain_level()
        if current_data and current_data.get("domain_version") is not None:
            current_ver_str = current_data["domain_version"]
            try:
                current_ver_int = int(current_ver_str)
            except (ValueError, TypeError):
                current_ver_int = None

            # Normalize the requested level to an integer
            requested_normalized = str(body.level).lower().replace("windows ", "").replace(" ", "_").replace("(windows) ", "")
            requested_ver_int = _LEVEL_TO_INT.get(requested_normalized)

            if requested_ver_int is not None and current_ver_int is not None:
                if requested_ver_int == current_ver_int:
                    current_level_name = current_data.get("domain_functional_level", current_ver_str)
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            f"Domain functional level is already '{current_level_name}' "
                            f"(version {current_ver_int}). "
                            f"samba-tool domain level raise requires a strictly higher level. "
                            f"Current: {requested_normalized}, requested: {requested_normalized}. "
                            f"To raise the level, specify a higher level (e.g. 2012_R2 or 2016)."
                        ),
                    )
                if requested_ver_int < current_ver_int:
                    current_level_name = current_data.get("domain_functional_level", current_ver_str)
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            f"Cannot lower domain functional level from '{current_level_name}' "
                            f"(version {current_ver_int}) to '{body.level}' (version {requested_ver_int}). "
                            f"Raising the functional level is irreversible — it cannot be lowered. "
                            f"Current level: {current_level_name}, requested: {body.level}."
                        ),
                    )
    except HTTPException:
        raise  # Re-raise the 409 we just generated
    except Exception:
        pass  # Non-critical pre-check; proceed with the raise attempt

    try:
        cmd = build_samba_command(
            "domain", "level",
            {"--domain-level": str(body.level)},
            positionals=["raise"],
        )
        await execute_samba_command(cmd)
        # Invalidate ldb_reader cache so next GET /level returns fresh data
        from app.ldb_reader import invalidate_cache
        invalidate_cache()
        return SuccessResponse(
            message=f"Domain functional level set to {body.level}",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Password settings ───────────────────────────────────────────────────

@router.get("/passwordsettings", summary="Get password settings")
async def get_password_settings(_auth: ApiKeyDep) -> dict:
    """Retrieve the current password policy settings via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of
    ``samba-tool domain passwordsettings show``.
    Reads password policy attributes directly from the domain object.
    """
    from app.ldb_reader import fetch_domain_password_settings

    data = await fetch_domain_password_settings()
    if not data:
        return {"status": "ok", "password_settings": None}

    return {"status": "ok", "password_settings": data}


@router.put(
    "/passwordsettings",
    summary="Set password settings",
    response_model=SuccessResponse,
)
async def set_password_settings(
    body: PasswordSettingsSetRequest,
    _: ApiKeyDep,
) -> SuccessResponse:
    """Update one or more password-policy settings."""
    args: dict = {}
    field_map = {
        "min_password_length": "--min-pwd-length",
        "password_history_length": "--history-length",
        "min_password_age": "--min-pwd-age",
        "max_password_age": "--max-pwd-age",
        "complexity": "--complexity",
        "store_plaintext": "--store-plaintext",
        "account_lockout_duration": "--account-lockout-duration",
        "account_lockout_threshold": "--account-lockout-threshold",
        "reset_account_lockout_after": "--reset-account-lockout-after",
    }
    for py_field, cli_flag in field_map.items():
        value = getattr(body, py_field, None)
        if value is not None:
            if isinstance(value, bool):
                args[cli_flag] = "on" if value else "off"
            else:
                args[cli_flag] = str(value)

    if not args:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one password setting must be provided.",
        )

    try:
        cmd = build_samba_command("domain", "passwordsettings", args, positionals=["set"])
        await execute_samba_command(cmd)
        return SuccessResponse(message="Password settings updated.")
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Trust management ────────────────────────────────────────────────────

@router.post(
    "/trust/create",
    summary="Create trust",
    response_model=SuccessResponse,
)
async def create_trust(
    body: TrustCreateRequest,
    _: ApiKeyDep,
) -> SuccessResponse:
    """Create a trust relationship with another domain.

    **Fix v6-19**: Before calling samba-tool, a fast DNS SRV pre-check
    verifies that the trusted domain has discoverable DCs.  This avoids
    a long (10+ second) CLDAP timeout from samba-tool when the trusted
    domain does not exist or has no SRV records.  If the SRV query
    fails, the endpoint returns 404 immediately instead of waiting for
    samba-tool to time out.
    """
    await _require_dc_role()

    # Fix v6-19: DNS SRV pre-check for the trusted domain.
    # samba-tool domain trust create uses CLDAP (net.finddc) to locate
    # DCs for the trusted domain.  If the domain doesn't exist or has no
    # SRV records, this hangs for 10+ seconds before returning an error.
    # We do a quick DNS lookup first and return 404 immediately if the
    # domain has no discoverable DCs.
    try:
        import socket
        import dns.resolver  # type: ignore[import-untyped]
        srv_name = f"_ldap._tcp.dc._msdcs.{body.trusted_domain_name}"
        try:
            dns.resolver.resolve(srv_name, "SRV", lifetime=5)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                Exception) as dns_err:
            # Fix v12-7: Return 400 instead of 404 when DNS lookup fails.
            # The domain itself may not exist, but this is NOT a "resource
            # not found" error — it's a client-side configuration issue.
            # The trusted domain either doesn't exist or doesn't have proper
            # DNS SRV records.  A 400 Bad Request is more appropriate because
            # the request itself is invalid (refers to a non-existent domain),
            # not that an existing resource was not found.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Trusted domain '{body.trusted_domain_name}' has no "
                    f"discoverable DCs (DNS SRV lookup for '{srv_name}' failed: "
                    f"{dns_err}).  Trust creation requires the domain to have "
                    f"at least one Domain Controller with a valid SRV record.  "
                    f"Verify that DNS is properly configured for the trusted domain.  "
                    f"If the domain does not exist, this error is expected."
                ),
            )
    except ImportError:
        # dnspython not installed — skip the pre-check and let samba-tool
        # handle it (will be slower but still correct).
        logger.debug("dnspython not installed, skipping DNS SRV pre-check for trust create")
    except HTTPException:
        raise  # Re-raise the 404 from the pre-check

    settings = get_settings()
    args: dict = {}
    if settings.REALM:
        args["--realm"] = settings.REALM
    if body.trusted_username:
        args["--username"] = body.trusted_username
    if body.trusted_password:
        args["--password"] = body.trusted_password
    if body.trust_type:
        args["--type"] = body.trust_type
    if body.trust_direction:
        args["--direction"] = body.trust_direction

    try:
        cmd = build_samba_command(
            "domain", "trust", args,
            positionals=["create", body.trusted_domain_name],
        )
        await execute_samba_command(cmd)
        return SuccessResponse(
            message=f"Trust with '{body.trusted_domain_name}' created.",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


@router.delete(
    "/trust/delete",
    summary="Delete trust",
    response_model=SuccessResponse,
)
async def delete_trust(
    trusted_domain_name: str = Query(..., description="FQDN of the trusted domain."),
    _: ApiKeyDep = None,
) -> SuccessResponse:
    """Remove a trust relationship."""
    await _require_dc_role()
    settings = get_settings()
    args: dict = {}
    if settings.REALM:
        args["--realm"] = settings.REALM
    try:
        cmd = build_samba_command(
            "domain", "trust", args,
            positionals=["delete", trusted_domain_name],
        )
        await execute_samba_command(cmd)
        return SuccessResponse(
            message=f"Trust with '{trusted_domain_name}' deleted.",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


@router.get("/trust/list", summary="List trusts")
async def list_trusts(_auth: ApiKeyDep) -> dict:
    """List all trust relationships via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of
    ``samba-tool domain trust list``.
    Reads trustedDomain objects directly from the directory.
    """
    await _require_dc_role()
    from app.ldb_reader import fetch_domain_trusts

    data = await fetch_domain_trusts()
    return {"status": "ok", "trusts": data}


@router.get("/trust/namespaces", summary="Trust namespaces")
async def trust_namespaces(
    trusted_domain_name: str = Query(..., description="FQDN of the trusted domain."),
    _: ApiKeyDep = None,
) -> dict:
    """Show namespace information for a trusted domain.

    Fix v22: Added DNS SRV pre-check (same as trust create/validate).
    When the trusted domain has no discoverable DCs, returns 400
    instead of 404/502, because the error is a client-side
    configuration issue (bad domain name), not a missing resource.
    """
    await _require_dc_role()

    # Fix v22: DNS SRV pre-check for the trusted domain.
    # Same rationale as create_trust — avoid long CLDAP timeouts
    # and return 400 immediately for non-existent domains.
    try:
        import socket
        import dns.resolver  # type: ignore[import-untyped]
        srv_name = f"_ldap._tcp.dc._msdcs.{trusted_domain_name}"
        try:
            dns.resolver.resolve(srv_name, "SRV", lifetime=5)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                Exception) as dns_err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Trusted domain '{trusted_domain_name}' has no "
                    f"discoverable DCs (DNS SRV lookup for '{srv_name}' failed: "
                    f"{dns_err}).  Trust namespace queries require the domain to have "
                    f"at least one Domain Controller with a valid SRV record.  "
                    f"Verify that DNS is properly configured for the trusted domain.  "
                    f"If the domain does not exist, this error is expected."
                ),
            )
    except ImportError:
        logger.debug("dnspython not installed, skipping DNS SRV pre-check for trust namespaces")
    except HTTPException:
        raise  # Re-raise the 400 from the pre-check

    settings = get_settings()
    args: dict = {}
    if settings.REALM:
        args["--realm"] = settings.REALM
    try:
        cmd = build_samba_command(
            "domain", "trust", args,
            positionals=["namespaces", trusted_domain_name],
        )
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


@router.post(
    "/trust/validate",
    summary="Validate trust",
    response_model=SuccessResponse,
)
async def validate_trust(
    trusted_domain_name: str = Query(..., description="FQDN of the trusted domain."),
    _: ApiKeyDep = None,
) -> SuccessResponse:
    """Validate an existing trust relationship.

    Fix v22: Added DNS SRV pre-check (same as trust create/namespaces).
    When the trusted domain has no discoverable DCs, returns 400
    instead of 404/502, because the error is a client-side
    configuration issue (bad domain name), not a missing resource.
    """
    await _require_dc_role()

    # Fix v22: DNS SRV pre-check for the trusted domain.
    # Same rationale as create_trust — avoid long CLDAP timeouts
    # and return 400 immediately for non-existent domains.
    try:
        import socket
        import dns.resolver  # type: ignore[import-untyped]
        srv_name = f"_ldap._tcp.dc._msdcs.{trusted_domain_name}"
        try:
            dns.resolver.resolve(srv_name, "SRV", lifetime=5)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                Exception) as dns_err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Trusted domain '{trusted_domain_name}' has no "
                    f"discoverable DCs (DNS SRV lookup for '{srv_name}' failed: "
                    f"{dns_err}).  Trust validation requires the domain to have "
                    f"at least one Domain Controller with a valid SRV record.  "
                    f"Verify that DNS is properly configured for the trusted domain.  "
                    f"If the domain does not exist, this error is expected."
                ),
            )
    except ImportError:
        logger.debug("dnspython not installed, skipping DNS SRV pre-check for trust validate")
    except HTTPException:
        raise  # Re-raise the 400 from the pre-check

    settings = get_settings()
    args: dict = {}
    if settings.REALM:
        args["--realm"] = settings.REALM
    try:
        cmd = build_samba_command(
            "domain", "trust", args,
            positionals=["validate", trusted_domain_name],
        )
        await execute_samba_command(cmd)
        return SuccessResponse(
            message=f"Trust with '{trusted_domain_name}' validated.",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Backup ───────────────────────────────────────────────────────────────

@router.post(
    "/backup/online",
    summary="Online backup",
    response_model=TaskResponse,
)
async def backup_online(
    body: BackupRequest,
    _: ApiKeyDep,
) -> TaskResponse:
    """Start an online backup of the domain controller.

    This is a long-running operation tracked by the task manager.
    Returns a task ID that can be polled for status.
    """
    settings = get_settings()
    args: dict = {}
    if body.target_dir:
        args["--targetdir"] = body.target_dir
    # Fix v3-6: --server is REQUIRED for online backup. If not provided
    # in the request body, default to the auto-detected DC hostname.
    # Fix v21: Use get_dc_hostname() instead of settings.SERVER because
    # backup uses RPC and needs the real DC name (not localhost).
    if body.server:
        args["--server"] = body.server
    else:
        dc_host = get_dc_hostname(settings)
        if dc_host:
            args["--server"] = dc_host
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Server parameter is required for online backup. "
                    "Provide 'server' in the request body or set SAMBA_DC_HOSTNAME "
                    "or SAMBA_SERVER to the real DC hostname."
                ),
            )

    try:
        cmd = build_samba_command("domain", "backup", args, positionals=["online"])
        task_manager = get_task_manager()
        task_id = task_manager.submit_task(cmd, timeout=1200)
        return TaskResponse(
            message="Online backup task submitted.",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


@router.post(
    "/backup/offline",
    summary="Offline backup",
    response_model=TaskResponse,
)
async def backup_offline(
    body: BackupRequest,
    _: ApiKeyDep,
) -> TaskResponse:
    """Start an offline backup of the domain controller.

    This is a long-running operation tracked by the task manager.
    Returns a task ID that can be polled for status.
    """
    args: dict = {}
    if body.target_dir:
        args["--targetdir"] = body.target_dir

    try:
        cmd = build_samba_command("domain", "backup", args, positionals=["offline"])
        task_manager = get_task_manager()
        task_id = task_manager.submit_task(cmd, timeout=1200)
        return TaskResponse(
            message="Offline backup task submitted.",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Tombstones ──────────────────────────────────────────────────────────
# NOTE: ``samba-tool domain tombstones`` is a command group, not a
# direct listing command.  The only available sub-command is
# ``samba-tool domain tombstones expunge``, which is a destructive
# operation.  There is no way to *list* tombstones via samba-tool;
# that would require a direct LDAP query.  The endpoint has been
# removed to avoid returning errors.


# ── KDS root key ────────────────────────────────────────────────────────

@router.post(
    "/kds/root-key/create",
    summary="Create KDS root key",
    response_model=SuccessResponse,
)
async def create_kds_root_key(_: ApiKeyDep) -> SuccessResponse:
    """Create a new KDS (Group Key Distribution Service) root key."""
    try:
        # samba-tool domain kds root-key create
        cmd = build_samba_command("domain", "kds", {}, positionals=["root-key", "create"])
        await execute_samba_command(cmd)
        return SuccessResponse(message="KDS root key created.")
    except RuntimeError as exc:
        raise_classified_error(exc)


@router.get("/kds/root-key/list", summary="List KDS root keys")
async def list_kds_root_keys(_auth: ApiKeyDep) -> dict:
    """List all KDS root keys via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of
    ``samba-tool domain kds root-key list``.
    Reads msKds-ProvRootKey objects directly from the directory.
    """
    from app.ldb_reader import fetch_kds_root_keys

    data = await fetch_kds_root_keys()
    return {"status": "ok", "kds_root_keys": data}


# ── Export keytab ───────────────────────────────────────────────────────

@router.post(
    "/exportkeytab",
    summary="Export keytab",
    response_model=TaskResponse,
)
async def export_keytab(
    principal: str = Query(..., description="Service principal name to export."),
    keytab_path: str = Query(
        default="/tmp/exported.keytab",
        description="Path where the keytab file will be written.",
    ),
    _: ApiKeyDep = None,
) -> TaskResponse:
    """Export a keytab file for a given service principal.

    Note: ``samba-tool domain exportkeytab`` requires the keytab path
    as the first positional argument.

    **Important**: Keytab export requires local access to sam.ldb
    (via ``ldapi://``) unless exporting gMSA accounts.  This endpoint
    overrides the connection URL to use ``LDAPI_URL`` when available.

    This is a potentially long-running operation that is dispatched
    as a background task.  Returns a task ID that can be polled for
    status and results.
    """
    settings = get_settings()
    # Fix v20: Keytab export is READ-ONLY (reads password keys from sam.ldb).
    # Use tdb:// for fast, auth-free access.  Fall back to ldapi:// if tdb://
    # is unavailable.  This avoids the LDAP_OPERATIONS_ERROR that ldapi://
    # sometimes causes for password/key access.
    from app.executor import clear_tdb_cache, clear_ldapi_cache
    clear_tdb_cache()
    db_url = get_tdb_url(settings)
    if not db_url:
        # Fall back to ldapi://
        clear_ldapi_cache()
        db_url = get_ldapi_url(settings)
        if not db_url or not db_url.startswith("ldapi://"):
            import os as _os
            import urllib.parse as _up
            for _p in ["/var/lib/samba/private/ldapi", "/var/lib/samba/private/ldap_priv/ldapi", "/var/run/samba/ldapi"]:
                if _os.path.exists(_p):
                    db_url = f"ldapi://{_up.quote(_p, safe='')}"
                    break
    if not db_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "No database URL available for keytab export. "
                "Keytab export needs local sam.ldb access via tdb:// (recommended) "
                "or ldapi://. Set SAMBA_TDB_URL (e.g. "
                "tdb:///var/lib/samba/private/sam.ldb) or SAMBA_LDAPI_URL."
            ),
        )
    # Fix v9-7: Pre-check principal type — reject computer accounts.
    # Computer accounts (cifs/hostname, host/hostname) don't have
    # exportable keys.  samba-tool returns "No keys found" which is
    # confusing.  We check the account type via LDAP and return a
    # clear 422 error before creating the background task.
    principal_lower = principal.lower()
    _COMPUTER_SPN_PREFIXES = ("cifs/", "host/", "ldap/", "gc/", "kadmin/")
    is_likely_computer = any(principal_lower.startswith(p) for p in _COMPUTER_SPN_PREFIXES)
    if is_likely_computer:
        # Try LDAP lookup to confirm it's a computer account
        try:
            import subprocess as _sp
            import urllib.parse as _up
            search_url = db_url or settings.LDAP_URL
            if search_url:
                # Search for the SPN in the directory
                search_cmd = [
                    "ldbsearch", "-H", search_url,
                    "-s", "sub",
                    f"(servicePrincipalName={principal})",
                    "objectClass", "userAccountControl",
                ]
                sr = _sp.run(search_cmd, capture_output=True, text=True, timeout=20)
                if sr.returncode == 0:
                    output_lower = sr.stdout.lower()
                    if "objectclass: computer" in output_lower:
                        raise HTTPException(
                            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=(
                                f"Keytab export is not supported for computer accounts. "
                                f"The principal '{principal}' belongs to a computer account, "
                                f"which stores passwords as NT hashes managed by Netlogon. "
                                f"Only user accounts and Group Managed Service Accounts (gMSA) "
                                f"support keytab export. Use a user principal or gMSA instead."
                            ),
                        )
        except HTTPException:
            raise
        except Exception as e:
            logger.debug("exportkeytab: principal type pre-check failed: %s", e)
            # If the check fails, proceed anyway — samba-tool will give
            # its own "No keys found" error if keys aren't available.
    args = {"--principal": principal, "-H": db_url}
    try:
        cmd = build_samba_command("domain", "exportkeytab", args, positionals=[keytab_path])
        task_manager = get_task_manager()
        task_id = task_manager.submit_task(cmd, timeout=600)
        return TaskResponse(
            message=f"Keytab export task submitted for principal '{principal}'.",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Join / Leave (dangerous) ───────────────────────────────────────────

@router.post(
    "/join",
    summary="Join domain",
    response_model=SuccessResponse,
)
async def join_domain(
    body: ForceActionRequest,
    _: ApiKeyDep,
) -> SuccessResponse:
    """Join the machine to a Samba AD domain.

    **Dangerous operation** – requires ``force=true`` in the request body.
    """
    if not body.domain_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A 'domain_name' (DNS domain) is required for joining.",
        )
    if not body.force:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Joining a domain is a dangerous operation. Set 'force' to true to confirm.",
        )

    # Fast-fail: if this server is already a DC or already a domain
    # member, joining is not applicable.  A DC cannot join another
    # domain; a domain member is already joined.  samba-tool would
    # either hang (trying to discover a DC via CLDAP) or return an
    # error after a long delay.  Check early to return immediately.
    #
    # Fix v15: Check for DC role using both canonical and
    # non-standard role strings.  After config.py _ROLE_MAP normalisation
    # this should always be 'active directory domain controller', but
    # add extra checks as safety net for any unmapped variants.
    server_role = _get_server_role()
    if "domain controller" in server_role or "active directory" in server_role or server_role.endswith("_dc"):
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                f"Cannot join a domain controller to another domain. "
                f"This server has role '{server_role.strip()}'. "
                f"A DC can only be the first DC in a new domain (provision) "
                f"or join as an additional DC via 'samba-tool domain join ... DC'."
            ),
        )
    if "domain member" in server_role:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                f"This server is already a domain member (role: '{server_role.strip()}'). "
                f"Domain join is not applicable — the machine is already joined. "
                f"To join a different domain, first leave the current one via "
                f"POST /api/v1/domain/leave."
            ),
        )

    try:
        cmd = build_samba_command("domain", "join", {}, positionals=[body.domain_name])
        # domain join can hang if the DC is unreachable; use a moderate
        # timeout (25s) to accommodate slower servers while still
        # returning 504 quickly enough for interactive use.
        # If the DC is reachable, join typically completes in under 5 seconds;
        # if unreachable, we don't want to block for the full 300s default.
        await execute_samba_command(cmd, timeout=50)
        return SuccessResponse(message="Domain join initiated.")
    except RuntimeError as exc:
        raise_classified_error(exc)


@router.post(
    "/leave",
    summary="Leave domain",
    response_model=SuccessResponse,
)
async def leave_domain(
    body: ForceActionRequest,
    _: ApiKeyDep,
) -> SuccessResponse:
    """Leave the current Samba AD domain.

    **Dangerous operation** – requires ``force=true`` in the request body.
    """
    if not body.force:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Leaving a domain is a dangerous operation. Set 'force' to true to confirm.",
        )

    # Fast-fail: if this server is a DC, leaving is not applicable.
    # A DC cannot leave its own domain — it would need to be demoted first.
    # Also check if the server is a standalone server (not joined).
    # Checking early prevents the long timeout that samba-tool would incur.
    #
    # Fix v15: Check for DC role using both canonical and
    # non-standard role strings (see join_domain for rationale).
    #
    # Fix v16: Add explicit "unknown role" guard — if the role is
    # neither DC, standalone, nor domain member, return 500 instead
    # of proceeding with a command that will likely hang.  Also
    # require "member" in role string to allow the leave to proceed.
    server_role = _get_server_role()
    if "domain controller" in server_role or "active directory" in server_role or server_role.endswith("_dc"):
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                f"Cannot leave the domain on a domain controller. "
                f"This server has role '{server_role.strip()}'. "
                f"A DC must be demoted before it can leave the domain. "
                f"Use 'samba-tool domain demote' on the server console."
            ),
        )
    if "standalone" in server_role:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                f"This server is a standalone server (role: '{server_role.strip()}'). "
                f"Domain leave is not applicable — the machine is not joined to any domain."
            ),
        )
    if "member" not in server_role:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Cannot determine if this server is a domain member. "
                f"Detected role: '{server_role.strip()}'. Expected one of: "
                f"'active directory domain controller', 'domain member', 'standalone server'. "
                f"Check SAMBA_SERVER_ROLE env var or smb.conf 'server role' setting."
            ),
        )

    try:
        cmd = build_samba_command("domain", "leave", {})
        # Fix v16: Reduce timeout from 25s to 10s — a domain member
        # should respond quickly to a leave request.  If the DC is
        # unreachable, 10s is enough to detect it; 25s is unnecessarily
        # long for an interactive API call.
        await execute_samba_command(cmd, timeout=20)
        return SuccessResponse(message="Domain leave initiated.")
    except RuntimeError as exc:
        # SystemError from s3_net.leave() indicates the machine
        # is not joined to a domain or is a DC — leave not applicable.
        error_msg = str(exc).lower()
        if "systemerror" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=(
                    "Machine is not joined to a domain or is a DC — "
                    "leave operation not applicable. "
                    "samba-tool domain leave requires the machine to be "
                    "a domain member that was previously joined."
                ),
            ) from exc
        # Fix v16: If the error indicates a timeout, return 504 with
        # a clear message about DC unreachability.
        if "command timed out" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=(
                    "Domain leave timed out — the domain controller may be unreachable. "
                    "samba-tool domain leave requires communication with a DC. "
                    "Verify that the DC is online and accessible from this machine, "
                    "then retry the operation."
                ),
            ) from exc
        raise_classified_error(exc)


# ── Demote (DC → member) ────────────────────────────────────────────────

class DemoteRequest(BaseModel):
    """Request body for domain demote operation."""
    force: bool = Field(
        default=False,
        description="Must be true to proceed with the demote operation.",
    )

@router.post(
    "/demote",
    summary="Demote domain controller",
    response_model=TaskResponse,
)
async def demote_domain(
    body: DemoteRequest,
    _: ApiKeyDep,
) -> TaskResponse:
    """Demote a Domain Controller to a regular domain member.

    This is a long-running and destructive operation that removes the
    DC role from the current server using ``samba-tool domain demote``.
    Unlike ``domain leave`` (which is for member servers), ``demote``
    is the correct way to remove a DC from the domain — it properly
    cleans up AD objects, FSMO role transfers, and replication metadata.

    **Dangerous operation** – requires ``force=true`` in the request body.

    The command is dispatched as a background task because demotion can
    take a significant amount of time (FSMO role transfers, metadata
    cleanup, etc.).  Returns a task ID that can be polled for status.
    """
    if not body.force:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Domain demote is a dangerous operation. Set 'force' to true to confirm.",
        )

    # Fast-fail: if the server is not a DC, demote is not applicable.
    server_role = _get_server_role()
    if "domain controller" not in server_role and "active directory" not in server_role and not server_role.endswith("_dc"):
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                f"Cannot demote a non-DC server. "
                f"This server has role '{server_role.strip()}'. "
                f"Domain demote is only applicable to Domain Controllers."
            ),
        )

    try:
        # Fix v6-1: samba-tool domain demote does NOT support --force flag.
        # The command has no flags for non-interactive mode; it always
        # proceeds without confirmation when run non-interactively.
        # Previously, passing --force caused "error: no such option: --force".
        args: dict = {}
        cmd = build_samba_command("domain", "demote", args)
        task_manager = get_task_manager()
        task_id = task_manager.submit_task(cmd, timeout=1200)
        return TaskResponse(
            message="Domain demote task submitted.",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Provision (disabled) ────────────────────────────────────────────────
#
# ``samba-tool domain provision`` is an extremely destructive operation
# that creates a brand-new AD domain from scratch.  It can hang in
# non-interactive mode, destroys the existing database, and is never
# safe to call from an API.  The endpoint has been disabled to prevent
# accidental use.  If provisioning is truly needed, run samba-tool
# directly on the server console.
#
# The original POST /domain/provision endpoint is replaced with a
# stub that always returns 403 Forbidden.


@router.post(
    "/provision",
    summary="Provision (disabled)",
    response_model=SuccessResponse,
    deprecated=True,
)
async def provision_domain(_: ApiKeyDep) -> SuccessResponse:
    """**Disabled** – domain provision is too destructive for API use.

    ``samba-tool domain provision`` creates a new AD domain from scratch
    and destroys the existing database.  It can also hang in
    non-interactive mode.  This endpoint always returns 403 Forbidden.

    If you need to provision, run ``samba-tool domain provision``
    directly on the server console.
    """
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "Domain provision is disabled via the API because it is "
            "destructive and may hang in non-interactive mode.  "
            "Run 'samba-tool domain provision' directly on the server "
            "console instead."
        ),
    )


# ── Claim types ─────────────────────────────────────────────────────────

@router.get("/claim/types", summary="List claim types")
async def list_claim_types(_: ApiKeyDep) -> dict:
    """List claim types defined in the domain.

    Note: The correct samba-tool invocation is
    ``samba-tool domain claim claim-type list`` (nested sub-command).
    """
    try:
        cmd = build_samba_command("domain", "claim", {}, positionals=["claim-type", "list"])
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
