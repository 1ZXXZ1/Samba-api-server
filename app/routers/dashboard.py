"""
Dashboard router — full AD overview via ldbsearch.

Provides ``GET /api/v1/dashboard/full`` and ``GET /api/v1/dashboard/overview``
endpoints that gather all key Active Directory data in one request,
using the fast ``ldbsearch`` backend exclusively (no ``samba-tool`` calls).

v1.2.1_fix: Initial implementation with parallel data fetching
via ``asyncio.gather()`` and 10-second response cache.

v1.2.2_fix: Fixed ``AttributeError: '_Link' object has no attribute 'expire'``
in ``app.cache`` — replaced ``cachetools.TTLCache`` internals with a manual
per-entry TTL implementation using plain ``dict`` + ``(value, expire_at)``
tuples.

v1.2.4_fix: No direct changes; benefits from the fixed
``fetch_domain_level()`` in ``ldb_reader.py`` which now correctly
reads forest functional level from the Partitions container.

v1.2.9_fix: Added ``/overview`` endpoint — single request returns AD objects
counts, FSMO roles, domain info, server time (via ldbsearch tdb://),
and system metrics (CPU, memory, disk, uptime). All data collected
in parallel via ``asyncio.gather()``, cached for 30 seconds.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter

from app.auth import ApiKeyDep

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/full",
    summary="Full AD dashboard (fast, via ldbsearch)",
)
async def dashboard_full(_auth: ApiKeyDep) -> dict[str, Any]:
    """Return a complete Active Directory overview in one request.

    Collects all key AD data using ``ldbsearch`` exclusively:
    users, groups, computers, contacts, OUs, GPOs, domain info,
    and FSMO roles.  All eight fetch calls run in parallel via
    ``asyncio.gather()`` for maximum speed.

    The response is cached for 10 seconds to support rapid polling
    from a web dashboard without overloading the LDAP backend.
    """
    import asyncio

    from app.cache import get_cache
    from app.ldb_reader import (
        fetch_computers,
        fetch_contacts,
        fetch_domain_info,
        fetch_fsmo,
        fetch_gpos,
        fetch_groups,
        fetch_ous,
        fetch_users,
    )

    cache = get_cache()
    cache_key = "GET:/api/v1/dashboard/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    # Fetch all data in parallel
    users, groups, computers, contacts, ous, gpos, domain, fsmo = (
        await asyncio.gather(
            fetch_users(),
            fetch_groups(),
            fetch_computers(),
            fetch_contacts(),
            fetch_ous(),
            fetch_gpos(),
            fetch_domain_info(),
            fetch_fsmo(),
        )
    )

    result = {
        "status": "ok",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "users": users,
        "groups": groups,
        "computers": computers,
        "contacts": contacts,
        "ous": ous,
        "gpos": gpos,
        "domain": domain,
        "fsmo_roles": fsmo,
    }

    cache.set(cache_key, result, ttl=10)
    return result


# ── Helper: get server time via ldbsearch tdb:// ──────────────────────

async def _get_server_time_ldb() -> str:
    """Get server time via ldbsearch tdb:// (fastest, no RPC).

    Reads ``currentTime`` from the root DSE of ``sam.ldb`` using the
    ``tdb://`` URL.  This is the fastest and most reliable method —
    no RPC, no LDAP authentication, works even when SRVSVC is down.
    Falls back to system clock if ldbsearch fails.
    """
    import asyncio
    import re

    from app.config import get_settings
    from app.executor import get_tdb_url

    settings = get_settings()
    tdb_url = get_tdb_url(settings)
    if tdb_url:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.LDBSEARCH_PATH, "-H", tdb_url,
                "-b", "", "-s", "base", "currentTime",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode == 0:
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                for line in stdout.splitlines():
                    if line.startswith("currentTime:"):
                        raw = line.split(":", 1)[1].strip()
                        # Parse LDAP Generalized Time (YYYYMMDDHHMMSS.0Z) to ISO 8601
                        m = re.match(r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})', raw)
                        if m:
                            dt = datetime(
                                int(m.group(1)), int(m.group(2)), int(m.group(3)),
                                int(m.group(4)), int(m.group(5)), int(m.group(6)),
                                tzinfo=timezone.utc,
                            )
                            return dt.isoformat()
                        return raw
        except Exception as e:
            logger.debug("ldbsearch time error: %s", e)

    # Fallback to system clock
    return datetime.now(tz=timezone.utc).isoformat()


# ── Helper: format FSMO roles ────────────────────────────────────────

def _format_fsmo(fsmo_records: list) -> dict[str, str]:
    """Convert FSMO records into a readable role->owner mapping."""
    roles: dict[str, str] = {}
    for rec in fsmo_records:
        dn = str(rec.get("dn", "")).lower()
        owner = rec.get("fSMORoleOwner", rec.get("fsmoroleowner", ""))
        if isinstance(owner, list):
            owner = owner[0] if owner else ""
        owner = str(owner)

        if "schema" in dn:
            roles["schema_master"] = owner
        elif "partitions" in dn:
            roles["domain_naming_master"] = owner
        elif "rid manager" in dn or "rid" in dn:
            roles["rid_master"] = owner
        elif "infrastructure" in dn:
            roles["infrastructure_master"] = owner
        elif "pdc" in dn or len(roles) >= 3:
            roles.setdefault("pdc_emulator", owner)
    return roles


@router.get(
    "/overview",
    summary="AD + system overview (one request, fast)",
)
async def dashboard_overview(_auth: ApiKeyDep) -> dict[str, Any]:
    """Single-request overview combining AD object counts, FSMO, domain
    info, server time, and system metrics.

    All data is collected in parallel via ``asyncio.gather()`` for maximum
    speed.  The result is cached for 30 seconds.

    Returns:
    - **domain**: DNS domain, realm, NetBIOS, DC hostname, functional
      levels, server time (via ldbsearch tdb://).
    - **fsmo_roles**: All 5 FSMO roles and their owners.
    - **objects**: Counts of users, groups, computers, OUs, contacts, GPOs.
    - **server_status**: Role, CPU%, memory%, disk%, uptime, load, Samba
      processes, samdb size, replication status.
    """
    import asyncio

    from app.cache import get_cache
    from app.config import get_settings
    from app.ldb_reader import (
        fetch_computers,
        fetch_contacts,
        fetch_domain_info,
        fetch_fsmo,
        fetch_gpos,
        fetch_groups,
        fetch_ous,
        fetch_users,
    )
    from app.monitoring import get_samba_stats, get_system_stats

    cache = get_cache()
    cache_key = "GET:/api/v1/dashboard/overview:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    # Run all queries in parallel
    (
        users,
        groups,
        computers,
        contacts,
        ous,
        gpos,
        domain_info,
        fsmo_roles_raw,
        sys_stats,
        samba_stats,
        server_time,
    ) = await asyncio.gather(
        fetch_users(),
        fetch_groups(),
        fetch_computers(),
        fetch_contacts(),
        fetch_ous(),
        fetch_gpos(),
        fetch_domain_info(),
        fetch_fsmo(),
        asyncio.to_thread(get_system_stats),
        asyncio.to_thread(get_samba_stats),
        _get_server_time_ldb(),
    )

    # Extract domain DNS from rootDSE
    domain_dn = ""
    if domain_info:
        first = domain_info[0] if isinstance(domain_info, list) else domain_info
        domain_dn = first.get("distinguishedName", first.get("defaultNamingContext", ""))

    result = {
        "status": "ok",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "domain": {
            "dns_domain": domain_dn,
            "realm": samba_stats.get("realm", ""),
            "netbios": samba_stats.get("dc_hostname", ""),
            "dc_hostname": samba_stats.get("dc_hostname", ""),
            "forest_level": samba_stats.get("forest_functional_level", ""),
            "domain_level": samba_stats.get("domain_functional_level", ""),
            "server_time": server_time,
        },
        "fsmo_roles": _format_fsmo(fsmo_roles_raw),
        "objects": {
            "users": len(users) if isinstance(users, list) else 0,
            "groups": len(groups) if isinstance(groups, list) else 0,
            "computers": len(computers) if isinstance(computers, list) else 0,
            "ous": len(ous) if isinstance(ous, list) else 0,
            "contacts": len(contacts) if isinstance(contacts, list) else 0,
            "gpos": len(gpos) if isinstance(gpos, list) else 0,
        },
        "server_status": {
            "role": samba_stats.get("server_role", "unknown"),
            "cpu_percent": sys_stats.get("cpu_percent"),
            "memory_percent": sys_stats.get("memory_percent"),
            "memory_total_mb": sys_stats.get("memory_total_mb"),
            "memory_available_mb": sys_stats.get("memory_available_mb"),
            "disk_percent": sys_stats.get("disk_percent"),
            "disk_free_gb": sys_stats.get("disk_free_gb"),
            "uptime_seconds": sys_stats.get("uptime_seconds"),
            "uptime_human": sys_stats.get("uptime_human"),
            "load_1min": sys_stats.get("load_1min"),
            "samba_processes": samba_stats.get("samba_processes"),
            "samdb_size_mb": samba_stats.get("samdb_size_mb"),
            "replication_status": samba_stats.get("replication_status"),
        },
    }

    cache.set(cache_key, result, ttl=30)
    return result
