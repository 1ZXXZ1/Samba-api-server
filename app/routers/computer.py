"""
Computer account management router.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``list_computers``  → ``fetch_computers()`` (ldbsearch)
- ``show_computer``   → ``fetch_computer_by_name()`` (ldbsearch)
Write operations still use samba-tool.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth import ApiKeyDep
from app.executor import build_samba_command, execute_samba_command, raise_classified_error
from app.models.computer import ComputerCreateRequest

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/computers",
    tags=["Computers"],
)


class ComputerMoveRequest(BaseModel):
    new_ou_dn: str = Field(..., description="Distinguished name of the destination OU.")


# ── Full computers (fast, via ldbsearch) ──────────────────────────────

@router.get("/full", summary="Get all computers (fast, via ldbsearch)")
async def list_computers_full(_auth: ApiKeyDep) -> dict[str, Any]:
    """Return all computer objects with full attributes via ldbsearch."""
    from app.ldb_reader import fetch_computers
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/computers/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_computers()
    result = {"status": "ok", "computers": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── List computers (fast, via ldbsearch) ──────────────────────────────

@router.get("/", summary="List computers")
async def list_computers(
    _: ApiKeyDep,
    base_dn: Optional[str] = Query(default=None, description="Base DN (ignored)"),
    full_dn: bool = Query(default=False, description="Show full DNs (ignored)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> dict[str, Any]:
    """List all computer accounts via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool computer list``.
    Returns full LDAP attribute data for all computer objects.
    Query parameters are accepted for backward compatibility but ignored.
    """
    from app.ldb_reader import fetch_computers
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/computers/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_computers()
    result = {"status": "ok", "computers": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── Create computer ────────────────────────────────────────────────────

@router.post("/", summary="Create a computer", status_code=status.HTTP_201_CREATED)
async def create_computer(_: ApiKeyDep, body: ComputerCreateRequest) -> dict[str, Any]:
    """Create a new computer account in the domain."""
    args: dict[str, Any] = {}
    if body.computerou is not None:
        args["--computerou"] = body.computerou
    if body.description is not None:
        args["--description"] = body.description
    if body.prepare_oldjoin:
        args["--prepare-oldjoin"] = True

    try:
        cmd = build_samba_command("computer", "add", args, positionals=[body.computername])
        if body.ip_address_list:
            for ip in body.ip_address_list:
                cmd.extend(["--ip-address", ip])
        if body.service_principal_name_list:
            for spn in body.service_principal_name_list:
                cmd.extend(["--service-principal-name", spn])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)

    return {"status": "ok", "message": f"Computer '{body.computername}' created successfully", "data": result}


# ── Show computer (fast, via ldbsearch) ───────────────────────────────

@router.get("/{computername}", summary="Show computer details")
async def show_computer(
    _: ApiKeyDep,
    computername: str,
    attributes: Optional[str] = Query(default=None, description="Attributes (ignored, all returned)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> dict[str, Any]:
    """Retrieve the attributes of a specific computer account via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool computer show``.
    """
    from app.ldb_reader import fetch_computer_by_name

    data = await fetch_computer_by_name(computername)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Computer '{computername}' not found",
        )
    return {"status": "ok", "computer": data}


# ── Delete computer ────────────────────────────────────────────────────

@router.delete("/{computername}", summary="Delete a computer")
async def delete_computer(_: ApiKeyDep, computername: str) -> dict[str, Any]:
    """Delete a computer account from the domain."""
    try:
        cmd = build_samba_command("computer", "delete", positionals=[computername])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"Computer '{computername}' deleted successfully", "data": result}


# ── Move computer ──────────────────────────────────────────────────────

@router.post("/{computername}/move", summary="Move a computer")
async def move_computer(_: ApiKeyDep, computername: str, body: ComputerMoveRequest) -> dict[str, Any]:
    """Move a computer account to a different OU."""
    try:
        cmd = build_samba_command("computer", "move", positionals=[computername, body.new_ou_dn])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"Computer '{computername}' moved to '{body.new_ou_dn}'", "data": result}
