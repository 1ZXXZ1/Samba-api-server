"""
DNS management router.

Wraps ``samba-tool dns`` sub-commands behind a REST API.  Every
endpoint requires API-key authentication.

DNS commands in samba-tool require a **server** positional argument.
The ``server`` query parameter defaults to the configured
``SAMBA_SERVER`` value but can be overridden per-request.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import build_samba_command, execute_samba_command, get_dc_hostname, raise_classified_error
from app.models.common import SuccessResponse
from app.models.dns import (
    DNSRecordCreateRequest,
    DNSRecordDeleteRequest,
    DNSRecordUpdateRequest,
    DNSZoneCreateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dns", tags=["DNS"])


# ── DNS timeout and retry configuration ─────────────────────────────────

# DNS RPC commands are more prone to connection timeouts than LDAP ones.
# Fix v6-15/v6-16/v6-17: Split timeouts into fast (120s) and long (600s).
# Quick operations (query, add, delete, update, serverinfo, zonelist,
# zoneinfo, zoneoptions) use DNS_TIMEOUT.  Slow operations (zonecreate,
# zonedelete) use DNS_TIMEOUT_LONG.  Also reduced retries for fast ops.
DNS_TIMEOUT = 240  # seconds for quick DNS operations (reduced from 600)
DNS_TIMEOUT_LONG = 1200  # seconds for slow DNS operations (zonecreate, zonedelete)
DNS_MAX_RETRIES = 2  # reduced from 3 to avoid excessive retries on fast ops
DNS_MAX_RETRIES_LONG = 3  # retries for slow operations
DNS_RETRY_BASE_DELAY = 5  # base delay in seconds between retries (exponential backoff)


def _is_transient_dns_error(exc: RuntimeError) -> bool:
    """Return True if the DNS error looks like a transient connection issue.

    Includes device timeout errors and DNS RPC server connection failures,
    which may resolve on retry after the RPC service recovers.
    """
    msg = str(exc).lower()
    return (
        "timeout" in msg
        or "timed out" in msg
        or "device timeout" in msg
        or ("connecting to dns rpc server" in msg and "failed" in msg)
    )


async def _execute_dns_with_retry(
    cmd: list[str],
    timeout: int = DNS_TIMEOUT,
    max_retries: int = DNS_MAX_RETRIES,
) -> dict:
    """Execute a DNS command with automatic retry on transient failures.

    Parameters
    ----------
    cmd:
        Full command line.
    timeout:
        Per-attempt timeout in seconds.
    max_retries:
        Maximum number of retries after the first attempt.

    Returns
    -------
    dict
        Parsed command result.
    """
    last_exc: Optional[RuntimeError] = None
    # Fix v9-8: Track command execution time for slow operation diagnostics.
    cmd_label = " ".join(cmd[:6]) + ("..." if len(cmd) > 6 else "")
    for attempt in range(1 + max_retries):
        attempt_start = time.monotonic()
        try:
            result = await execute_samba_command(cmd, timeout=timeout)
            elapsed = time.monotonic() - attempt_start
            if elapsed > 5:
                logger.warning(
                    "DNS command completed slowly (%.1fs, attempt %d/%d): %s",
                    elapsed, attempt + 1, 1 + max_retries, cmd_label,
                )
            return result
        except RuntimeError as exc:
            elapsed = time.monotonic() - attempt_start
            last_exc = exc
            if _is_transient_dns_error(exc) and attempt < max_retries:
                # Exponential backoff: 5s, 10s, 20s, ...
                delay = DNS_RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "DNS command transient failure (attempt %d/%d, %.1fs): %s — "
                    "retrying in %ds",
                    attempt + 1,
                    1 + max_retries,
                    elapsed,
                    str(exc)[:200],
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            logger.error(
                "DNS command failed (attempt %d/%d, %.1fs): %s",
                attempt + 1, 1 + max_retries, elapsed, str(exc)[:200],
            )
            raise
    # Should not be reached, but just in case
    raise last_exc  # type: ignore[misc]


# ── Server info ─────────────────────────────────────────────────────────

@router.get("/serverinfo", summary="DNS server info")
async def dns_serverinfo(
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname. Defaults to configured SAMBA_SERVER.",
    ),
    client_version: Optional[str] = Query(
        default=None,
        description="Client version string for the serverinfo request.",
    ),
) -> dict:
    """Retrieve DNS server information.

    .. note::

       ``samba-tool dns serverinfo`` does NOT support ``--json``; the
       output is always human-readable text.

    Fix v21: DNS commands use DCE/RPC, not LDAP.  They require the
    DC's real network hostname (not localhost/127.0.0.1) because
    Kerberos cannot issue service tickets for "localhost".  The server
    parameter defaults to the auto-detected DC hostname.

    v1.2.6 fix: ``samba-tool dns serverinfo`` is inherently slow
    (>20 seconds) because the RPC call to the DNS server involves
    DCE/RPC over SMB with Kerberos authentication.  Since DNS server
    information changes rarely (only when the DC is restarted or
    reconfigured), this endpoint now caches the response for 300
    seconds (5 minutes).  Retries are disabled (max_retries=0) because
    retrying a slow command only makes the latency worse.  The timeout
    is reduced from 240s to 30s — if the command doesn't complete in
    30 seconds, it's unlikely to succeed on retry either.
    """
    from app.cache import get_cache

    # Build cache key for this specific query
    settings = get_settings()
    srv = server or get_dc_hostname(settings)
    cache = get_cache()
    cache_key_params = {"server": srv}
    if client_version:
        cache_key_params["client_version"] = client_version
    from app.cache import ResponseCache
    cache_key = ResponseCache.build_key("GET", "/api/v1/dns/serverinfo", cache_key_params)

    # Check cache first (TTL 300s)
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return {**cached_result, "cached": True}

    args: dict = {}

    if client_version:
        args["--client-version"] = client_version

    try:
        cmd = build_samba_command("dns", "serverinfo", args, positionals=[srv])
        # v1.2.6: No retries for serverinfo — it's slow and retrying
        # only makes it worse.  Use a reduced 30s timeout instead of 240s.
        result = await execute_samba_command(cmd, timeout=30)
        # Cache the result for 300 seconds
        cache.set(cache_key, result, ttl=300)
        return result
    except RuntimeError as exc:
        logger.error("dns serverinfo failed: %s", exc)
        raise_classified_error(exc)


# ── Zone listing ────────────────────────────────────────────────────────

@router.get("/zones", summary="List DNS zones")
async def list_zones(
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
    primary: bool = Query(default=False, description="List primary zones."),
    secondary: bool = Query(default=False, description="List secondary zones."),
    cache: bool = Query(default=False, description="List cache zones."),
    auto: bool = Query(default=False, description="List auto-created zones."),
    forward: bool = Query(default=False, description="List forward zones."),
    reverse: bool = Query(default=False, description="List reverse zones."),
    ds: bool = Query(default=False, description="List AD-integrated zones."),
    non_ds: bool = Query(default=False, description="List non-AD-integrated zones."),
) -> dict:
    """List DNS zones, optionally filtered by type."""
    srv = server or get_dc_hostname(get_settings())
    args: dict = {}

    # Boolean zone-type filters
    if primary:
        args["--primary"] = True
    if secondary:
        args["--secondary"] = True
    if cache:
        args["--cache"] = True
    if auto:
        args["--auto"] = True
    if forward:
        args["--forward"] = True
    if reverse:
        args["--reverse"] = True
    if ds:
        args["--ds"] = True
    if non_ds:
        args["--non-ds"] = True

    try:
        cmd = build_samba_command("dns", "zonelist", args, positionals=[srv])
        return await _execute_dns_with_retry(cmd)
    except RuntimeError as exc:
        logger.error("dns zonelist failed: %s", exc)
        raise_classified_error(exc)


# ── Single zone operations ──────────────────────────────────────────────

@router.get("/zones/{zone}", summary="Zone info")
async def zone_info(
    zone: str,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
) -> dict:
    """Retrieve detailed information about a DNS zone."""
    srv = server or get_dc_hostname(get_settings())
    try:
        cmd = build_samba_command(
            "dns", "zoneinfo", {}, positionals=[srv, zone],
        )
        return await _execute_dns_with_retry(cmd)
    except RuntimeError as exc:
        logger.error("dns zoneinfo failed: %s", exc)
        raise_classified_error(exc)


@router.post(
    "/zones",
    summary="Create DNS zone",
    response_model=SuccessResponse,
)
async def create_zone(
    body: DNSZoneCreateRequest,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
    overwrite: bool = Query(
        default=False,
        description="If true, delete existing zone before creating. Useful for idempotent test scenarios.",
    ),
) -> SuccessResponse:
    """Create a new DNS zone."""
    srv = server or get_dc_hostname(get_settings())
    args: dict = {}

    # Fix v22: If overwrite=true, attempt to delete existing zone first
    if overwrite:
        try:
            del_cmd = build_samba_command(
                "dns", "zonedelete", {}, positionals=[srv, body.zone],
            )
            await _execute_dns_with_retry(del_cmd, timeout=DNS_TIMEOUT_LONG, max_retries=1)
        except RuntimeError as del_exc:
            # Ignore "zone does not exist" errors - we only want to delete if it exists
            del_msg = str(del_exc).lower()
            if "does not exist" not in del_msg and "not_found" not in del_msg and "zone not found" not in del_msg:
                logger.warning("Failed to delete existing zone '%s' during overwrite: %s", body.zone, del_exc)
            # If zone didn't exist, that's fine - proceed to create

    # samba-tool dns zonecreate accepts 'domain' or 'forest' directly
    # (NOT 'DomainDnsZones' / 'ForestDnsZones').
    args["--dns-directory-partition"] = body.dns_directory_partition

    try:
        cmd = build_samba_command(
            "dns", "zonecreate", args, positionals=[srv, body.zone],
        )
        # Fix v6-15: Use DNS_TIMEOUT_LONG for zonecreate (slow operation)
        await _execute_dns_with_retry(cmd, timeout=DNS_TIMEOUT_LONG, max_retries=DNS_MAX_RETRIES_LONG)
        return SuccessResponse(message=f"Zone '{body.zone}' created.")
    except RuntimeError as exc:
        logger.error("dns zonecreate failed: %s", exc)
        raise_classified_error(exc)


@router.delete(
    "/zones/{zone}",
    summary="Delete DNS zone",
    response_model=SuccessResponse,
)
async def delete_zone(
    zone: str,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
) -> SuccessResponse:
    """Delete an existing DNS zone."""
    srv = server or get_dc_hostname(get_settings())
    try:
        cmd = build_samba_command(
            "dns", "zonedelete", {}, positionals=[srv, zone],
        )
        # Fix v6-15: Use DNS_TIMEOUT_LONG for zonedelete (slow operation)
        await _execute_dns_with_retry(cmd, timeout=DNS_TIMEOUT_LONG, max_retries=DNS_MAX_RETRIES_LONG)
        return SuccessResponse(message=f"Zone '{zone}' deleted.")
    except RuntimeError as exc:
        logger.error("dns zonedelete failed: %s", exc)
        raise_classified_error(exc)


# ── Record operations ───────────────────────────────────────────────────

@router.get("/zones/{zone}/records", summary="List DNS records")
async def list_records(
    zone: str,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
    name: Optional[str] = Query(
        default=None,
        description="Record name to filter by.",
    ),
    record_type: Optional[str] = Query(
        default=None,
        description="Record type to filter by (e.g. A, CNAME, MX).",
    ),
) -> dict:
    """List DNS records in a zone, optionally filtered by name and type."""
    srv = server or get_dc_hostname(get_settings())
    args: dict = {"--json": True}

    # samba-tool dns query <server> <zone> <name> <type>
    # Use '@' as the wildcard for "all records at zone root", not 'ALL'.
    # If a specific name is provided, use it as-is.
    record_name = name or "@"
    rtype = record_type or "ALL"

    try:
        cmd = build_samba_command(
            "dns", "query", args, positionals=[srv, zone, record_name, rtype],
        )
        return await _execute_dns_with_retry(cmd)
    except RuntimeError as exc:
        logger.error("dns query failed: %s", exc)
        raise_classified_error(exc)


@router.post(
    "/zones/{zone}/records",
    summary="Create DNS record",
    response_model=SuccessResponse,
)
async def create_record(
    zone: str,
    body: DNSRecordCreateRequest,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
) -> SuccessResponse:
    """Add a DNS record to a zone."""
    srv = server or get_dc_hostname(get_settings())
    try:
        cmd = build_samba_command(
            "dns", "add", {},
            positionals=[srv, zone, body.name, body.record_type, body.data],
        )
        await _execute_dns_with_retry(cmd)
        return SuccessResponse(
            message=f"Record '{body.name}' ({body.record_type}) created in zone '{zone}'.",
        )
    except RuntimeError as exc:
        logger.error("dns add failed: %s", exc)
        raise_classified_error(exc)


@router.delete(
    "/zones/{zone}/records",
    summary="Delete DNS record",
    response_model=SuccessResponse,
)
async def delete_record(
    zone: str,
    body: DNSRecordDeleteRequest,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
) -> SuccessResponse:
    """Remove a DNS record from a zone."""
    srv = server or get_dc_hostname(get_settings())
    try:
        cmd = build_samba_command(
            "dns", "delete", {},
            positionals=[srv, zone, body.name, body.record_type, body.data],
        )
        await _execute_dns_with_retry(cmd)
        return SuccessResponse(
            message=f"Record '{body.name}' ({body.record_type}) deleted from zone '{zone}'.",
        )
    except RuntimeError as exc:
        logger.error("dns delete failed: %s", exc)
        raise_classified_error(exc)


@router.put(
    "/zones/{zone}/records",
    summary="Update DNS record",
    response_model=SuccessResponse,
)
async def update_record(
    zone: str,
    body: DNSRecordUpdateRequest,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
) -> SuccessResponse:
    """Update (replace) a DNS record in a zone.

    samba-tool dns update <server> <zone> <name> <type> <olddata> <newdata>
    Note: only ONE record type is passed as a positional; there is no
    separate old/new type.
    """
    srv = server or get_dc_hostname(get_settings())
    try:
        cmd = build_samba_command(
            "dns", "update", {},
            positionals=[
                srv,
                zone,
                body.name,
                body.old_record_type,
                body.old_data,
                body.new_data,
            ],
        )
        await _execute_dns_with_retry(cmd)
        return SuccessResponse(
            message=f"Record '{body.name}' updated in zone '{zone}'.",
        )
    except RuntimeError as exc:
        logger.error("dns update failed: %s", exc)
        raise_classified_error(exc)


# ── Read-only records query ─────────────────────────────────────────────

@router.get("/zones/{zone}/rorecords", summary="Query DNS records (read-only)")
async def query_rorecords(
    zone: str,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
    name: Optional[str] = Query(
        default=None,
        description="Record name to query.",
    ),
    record_type: Optional[str] = Query(
        default=None,
        description="Record type to query.",
    ),
) -> dict:
    """Query DNS records in read-only mode.

    Semantically distinct endpoint for read-only access; uses the same
    ``samba-tool dns query`` command as the regular records endpoint.
    """
    srv = server or get_dc_hostname(get_settings())
    args: dict = {"--json": True}

    # samba-tool dns query <server> <zone> <name> <type>
    # Use '@' as the wildcard for "all records at zone root", not 'ALL'.
    record_name = name or "@"
    rtype = record_type or "ALL"

    try:
        cmd = build_samba_command(
            "dns", "query", args, positionals=[srv, zone, record_name, rtype],
        )
        return await _execute_dns_with_retry(cmd)
    except RuntimeError as exc:
        logger.error("dns query (readonly) failed: %s", exc)
        raise_classified_error(exc)


# ── Zone options ────────────────────────────────────────────────────────

@router.put(
    "/zones/{zone}/options",
    summary="Set zone options",
    response_model=SuccessResponse,
)
async def set_zone_options(
    zone: str,
    _: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="DNS server hostname.",
    ),
    body: dict = {},
) -> SuccessResponse:
    """Set aging/scavenging options for a DNS zone.

    Accepts a JSON body with option flags, for example::

        {"aging": true, "no_scavenge": false}
    """
    srv = server or get_dc_hostname(get_settings())
    args: dict = {}

    for key, value in body.items():
        flag = f"--{key}"
        if isinstance(value, bool):
            args[flag] = 1 if value else 0
        else:
            args[flag] = str(value)

    try:
        cmd = build_samba_command(
            "dns", "zoneoptions", args, positionals=[srv, zone],
        )
        # Fix v6-17: Reduce retries for zoneoptions (should be fast)
        await _execute_dns_with_retry(cmd, max_retries=1)
        return SuccessResponse(message=f"Options for zone '{zone}' updated.")
    except RuntimeError as exc:
        logger.error("dns zoneoptions failed: %s", exc)
        raise_classified_error(exc)
