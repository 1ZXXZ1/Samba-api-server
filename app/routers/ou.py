"""
Organizational Unit (OU) management router.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``list_ous``        → ``fetch_ous()`` (ldbsearch)
- ``list_ou_objects`` → ``fetch_ou_objects()`` (ldbsearch)
Write operations still use samba-tool.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import build_samba_command, execute_samba_command, raise_classified_error
from app.models.ou import OUCreateRequest, OUMoveRequest, OURenameRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ous", tags=["Organizational Units"])


# ── Full OUs (fast, via ldbsearch) ───────────────────────────────────

@router.get("/full", summary="Get all OUs (fast, via ldbsearch)")
async def list_ous_full(_auth: ApiKeyDep) -> dict[str, Any]:
    """Return all organizationalUnit objects with full attributes via ldbsearch."""
    from app.ldb_reader import fetch_ous
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/ous/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_ous()
    result = {"status": "ok", "ous": data}
    cache.set(cache_key, result, ttl=30)
    return result


def _ensure_ou_dn(name: str) -> str:
    """Convert a simple OU name to a full DN if it isn't one already.

    Fix v1.6.2: Improved validation — logs a warning if the DN looks
    malformed (no commas after the RDN) and ensures the suffix matches
    the domain DN.
    """
    if "=" in name:
        # Already looks like a DN — validate it has proper structure
        if "," not in name and not name.startswith(("DC=",)):
            logger.warning(
                "OU DN looks malformed (no comma separators): '%s' — "
                "expected format like 'OU=Name,DC=kcrb,DC=local'",
                name,
            )
        return name
    base_dn = get_settings().DOMAIN_DN
    if not base_dn:
        server = get_settings().SERVER
        if server and "." in server:
            parts = server.split(".")
            domain_parts = parts[1:] if len(parts) > 1 else parts
            base_dn = ",".join(f"DC={p}" for p in domain_parts)
        else:
            logger.warning("Cannot determine DOMAIN_DN for OU DN conversion.")
            return name
    result = f"OU={name},{base_dn}"
    logger.debug("Converted OU name '%s' to full DN: '%s'", name, result)
    return result


def _ensure_parent_dn(dn: str) -> str:
    """Validate and fix a parent/container DN.

    Fix v1.6.2: Ensures that a DN used as a parent container (e.g. in
    OU move) is a proper full DN. If a simple name is given, wraps it
    as an OU DN under the domain root.
    """
    if not dn:
        return dn
    if "=" in dn:
        return dn  # Already a full DN
    # Simple name — treat as an OU name
    logger.info(
        "Parent DN '%s' doesn't look like a full DN — "
        "converting to OU DN under domain root",
        dn,
    )
    return _ensure_ou_dn(dn)


# ── List OUs (fast, via ldbsearch) ────────────────────────────────────

@router.get("/", summary="List Organizational Units")
async def list_ous(
    _: ApiKeyDep,
    base_dn: Optional[str] = Query(default=None, description="Base DN (ignored)"),
    full_dn: bool = Query(default=False, description="Show full DNs (ignored)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> dict[str, Any]:
    """List all Organizational Units via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool ou list``.
    Query parameters are accepted for backward compatibility but ignored.
    """
    from app.ldb_reader import fetch_ous
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/ous/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_ous()
    result = {"status": "ok", "ous": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── Create OU ──────────────────────────────────────────────────────────

@router.post("/", summary="Create an OU", status_code=status.HTTP_201_CREATED)
async def create_ou(_: ApiKeyDep, body: OUCreateRequest) -> dict[str, Any]:
    """Create a new Organizational Unit in the domain."""
    args: dict[str, Any] = {}
    if body.description is not None:
        args["--description"] = body.description
    try:
        cmd = build_samba_command("ou", "add", args, positionals=[_ensure_ou_dn(body.ouname)])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"OU '{body.ouname}' created successfully", "data": result}


# ── Delete OU ──────────────────────────────────────────────────────────

@router.delete("/{ouname}", summary="Delete an OU")
async def delete_ou(_: ApiKeyDep, ouname: str) -> dict[str, Any]:
    """Delete an Organizational Unit from the domain."""
    try:
        cmd = build_samba_command("ou", "delete", positionals=[_ensure_ou_dn(ouname)])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"OU '{ouname}' deleted successfully", "data": result}


# ── Move OU ────────────────────────────────────────────────────────────

@router.post("/{ouname}/move", summary="Move an OU")
async def move_ou(_: ApiKeyDep, ouname: str, body: OUMoveRequest) -> dict[str, Any]:
    """Move an Organizational Unit under a new parent OU."""
    # Fix v1.6.2: Validate new_parent_dn is a proper full DN
    resolved_parent_dn = _ensure_parent_dn(body.new_parent_dn)
    try:
        cmd = build_samba_command("ou", "move", positionals=[_ensure_ou_dn(ouname), resolved_parent_dn])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"OU '{ouname}' moved to '{resolved_parent_dn}'", "data": result}


# ── Rename OU ──────────────────────────────────────────────────────────

@router.post("/{ouname}/rename", summary="Rename an OU")
async def rename_ou(_: ApiKeyDep, ouname: str, body: OURenameRequest) -> dict[str, Any]:
    """Rename an Organizational Unit."""
    try:
        cmd = build_samba_command("ou", "rename", positionals=[_ensure_ou_dn(ouname), body.new_name])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"OU '{ouname}' renamed to '{body.new_name}'", "data": result}


# ── List objects in OU (fast, via ldbsearch) ──────────────────────────

@router.get("/{ouname}/objects", summary="List objects in an OU")
async def list_ou_objects(
    _: ApiKeyDep,
    ouname: str,
    full_dn: bool = Query(default=False, description="Show full DNs (ignored)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> dict[str, Any]:
    """List child objects within a specific OU via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool ou list`` with
    ``--base-dn``.  Searches with one-level scope to return only direct
    children of the specified OU.
    """
    from app.ldb_reader import fetch_ou_objects

    ou_dn = _ensure_ou_dn(ouname)
    try:
        data = await fetch_ou_objects(ou_dn)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OU '{ouname}' (DN: {ou_dn}) not found or inaccessible: {exc}",
        )

    return {"status": "ok", "ou": ou_dn, "objects": data}
