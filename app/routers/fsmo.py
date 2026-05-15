"""
FSMO Roles management router.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``show_fsmo``  → ``fetch_fsmo()`` (ldbsearch)
Write operations still use samba-tool.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.executor import build_samba_command, execute_samba_command, raise_classified_error
from app.models.common import ErrorResponse
from app.models.fsmo import FsmoSeizeRequest, FsmoSeizeResponse, FsmoShowResponse, FsmoTransferRequest, FsmoTransferResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/fsmo",
    tags=["FSMO Roles"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
    },
)


@router.get("/full", summary="Get FSMO roles (fast, via ldbsearch)")
async def show_fsmo_full(_auth: ApiKeyDep) -> dict:
    """Return FSMO role owner information via ldbsearch."""
    from app.ldb_reader import fetch_fsmo
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/fsmo/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_fsmo()
    result = {"status": "ok", "fsmo_roles": data}
    cache.set(cache_key, result, ttl=30)
    return result


@router.get("/", summary="Show FSMO roles", response_model=FsmoShowResponse)
async def show_fsmo(
    _auth: ApiKeyDep,
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> FsmoShowResponse:
    """Show the current holders of all FSMO roles via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool fsmo show``.
    """
    from app.ldb_reader import fetch_fsmo

    data = await fetch_fsmo()
    return FsmoShowResponse(
        message="FSMO roles retrieved successfully",
        data={"fsmo_roles": data},
    )


@router.put("/transfer", summary="Transfer FSMO role", response_model=FsmoTransferResponse)
async def transfer_fsmo(body: FsmoTransferRequest, _auth: ApiKeyDep) -> FsmoTransferResponse:
    """Transfer a FSMO role to the current server."""
    try:
        cmd = build_samba_command("fsmo", "transfer", {"--role": body.role.value})
        await execute_samba_command(cmd, timeout=600)
        return FsmoTransferResponse(message=f"FSMO role '{body.role.value}' transferred successfully", role=body.role.value)
    except RuntimeError as exc:
        logger.error("Failed to transfer FSMO role '%s': %s", body.role.value, exc)
        raise_classified_error(exc)


@router.put("/seize", summary="Seize FSMO role", response_model=FsmoSeizeResponse)
async def seize_fsmo(body: FsmoSeizeRequest, _auth: ApiKeyDep) -> FsmoSeizeResponse:
    """Seize a FSMO role on the current server."""
    try:
        cmd = build_samba_command("fsmo", "seize", {"--role": body.role.value})
        await execute_samba_command(cmd, timeout=600)
        return FsmoSeizeResponse(message=f"FSMO role '{body.role.value}' seized successfully", role=body.role.value)
    except RuntimeError as exc:
        logger.error("Failed to seize FSMO role '%s': %s", body.role.value, exc)
        raise_classified_error(exc)
