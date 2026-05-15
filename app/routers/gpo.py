"""
Group Policy (GPO) management router.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``list_gpos``  → ``fetch_gpos()`` (ldbsearch)
- ``show_gpo``   → ``fetch_gpo_by_id()`` (ldbsearch)
Write operations (create, delete, link, unlink, inherit, backup,
restore, fetch) still use samba-tool.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import build_samba_command, execute_samba_command, raise_classified_error
from app.models.common import ErrorResponse, TaskResponse
from app.models.gpo import (
    GpoBackupRequest,
    GpoBackupResponse,
    GpoCreateRequest,
    GpoCreateResponse,
    GpoDeleteResponse,
    GpoFetchResponse,
    GpoGetInheritResponse,
    GpoLinkRequest,
    GpoLinkResponse,
    GpoListResponse,
    GpoRestoreRequest,
    GpoRestoreResponse,
    GpoSetInheritRequest,
    GpoSetInheritResponse,
    GpoShowResponse,
    GpoUnlinkRequest,
    GpoUnlinkResponse,
)
from app.tasks import get_task_manager

logger = logging.getLogger(__name__)


def _ensure_gpo_braces(gpo_id: str) -> str:
    """Ensure GPO GUID has surrounding braces.
    
    samba-tool gpo show/del/link/inherit/fetch expect the GUID in
    curly braces: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
    The API may receive it with or without braces from the URL path.
    
    Fix v10-5: Always add braces if missing to prevent
    "GPO '...' does not exist" 404 errors.
    """
    if not gpo_id.startswith("{"):
        gpo_id = "{" + gpo_id
    if not gpo_id.endswith("}"):
        gpo_id = gpo_id + "}"
    return gpo_id

router = APIRouter(
    prefix="/gpo",
    tags=["Group Policy"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
    },
)


@router.get(
    "/full",
    summary="Get all GPOs (fast, via ldbsearch)",
)
async def list_gpos_full(_auth: ApiKeyDep) -> dict:
    """Return all Group Policy Objects with full attributes via ldbsearch.

    This endpoint uses the fast ``ldbsearch`` backend instead of
    ``samba-tool``, returning complete LDAP attribute data for every
    GPO in a single query.  This includes attributes like
    ``gPCFileSysPath``, ``versionNumber``, ``gPLink``, etc.
    Results are cached for 30 seconds.
    """
    from app.ldb_reader import fetch_gpos
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/gpo/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_gpos()
    result = {"status": "ok", "gpos": data}
    cache.set(cache_key, result, ttl=30)
    return result


@router.get(
    "/",
    summary="List GPOs",
    response_model=GpoListResponse,
)
async def list_gpos(
    _auth: ApiKeyDep,
) -> GpoListResponse:
    """List all Group Policy Objects in the domain via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool gpo listall``.
    Reads groupPolicyContainer objects directly from the directory.
    """
    from app.ldb_reader import fetch_gpos

    data = await fetch_gpos()
    return GpoListResponse(
        message="GPOs listed successfully",
        data={"gpos": data},
    )


@router.post(
    "/",
    summary="Create GPO",
    status_code=status.HTTP_201_CREATED,
    response_model=GpoCreateResponse,
)
async def create_gpo(
    body: GpoCreateRequest,
    _auth: ApiKeyDep,
    overwrite: bool = Query(
        default=False,
        description=(
            "If true, delete any existing GPO with the same displayname "
            "before creating.  Useful for idempotent test scenarios.  "
            "When false (default), a 409 Conflict is returned if the "
            "GPO already exists."
        ),
    ),
) -> GpoCreateResponse:
    """Create a new Group Policy Object.

    GPO creation via ``samba-tool gpo create`` typically completes in
    under a second on a local DC.  We execute it synchronously so that
    the response includes the GPO GUID, which downstream endpoints
    (show, delete, link, inherit, fetch) require as a path parameter.

    The command outputs a line like::

        GPO 'Test Policy' created as {31B2F340-016D-11D2-945F-00C04FB984F9}

    We extract the GUID from that output so callers can immediately
    use it in subsequent requests.

    **Fix v8: Idempotent GPO creation with ``overwrite`` parameter.**
    When ``overwrite=true`` and a GPO with the same displayname already
    exists (HTTP 409), the endpoint automatically deletes the existing
    GPO and retries creation.  This is particularly useful for test
    scenarios where a GPO like ``_debug_test_gpo`` may persist from a
    previous test run, causing 409 conflicts on subsequent runs.  The
    default behavior (``overwrite=false``) preserves the original 409
    response for production safety.

    The overwrite process:

    1. Attempt to create the GPO normally.
    2. If creation fails with 409 ("already exists") and ``overwrite=true``:
       a. List all GPOs to find the existing one's GUID by displayname.
       b. Delete the existing GPO using ``samba-tool gpo del``.
       c. Retry the creation.
    3. If the deletion or retry fails, return the appropriate error.

    **Fix v4: Bypassing CLDAP DC discovery to avoid "insufficient virtual
    memory" errors.**  The root cause of the STATUS_QUOTA_EXCEEDED error
    (3221225495 / 0xC0000073) in ``samba-tool gpo create`` is that
    ``python/samba/netcmd/gpo.py`` calls ``net.finddc(address=dc_hostname,
    flags=flags)`` which triggers a CLDAP request that attempts to allocate
    too much virtual memory on systems with limited resources.  By passing
    ``-H <ldapi_url>`` we force samba-tool to connect directly to the local
    sam.ldb via the LDAPI socket, completely bypassing the CLDAP-based DC
    discovery code path and avoiding the memory allocation issue.

    Additionally, ``TMPDIR`` is set to ``/var/tmp`` in the subprocess
    environment (via ``app/worker.py``) and ``--tmpdir /var/tmp`` is
    passed to samba-tool to ensure that temporary files created during
    GPO creation are written to a directory with sufficient space,
    avoiding "No space left on device" errors that can also manifest
    as quota errors.

    **Fix v5**: GPO create timeout increased from 60s to 120s.  The
    previous 60-second timeout was insufficient on systems where
    CLDAP DC discovery is slow (even with the LDAPI bypass), causing
    false 504 timeout errors.  The ``--tmpdir /var/tmp`` flag is now
    explicitly passed to ``samba-tool gpo create`` as an additional
    safeguard for temporary file placement.

    If a ``Not Enough Quota`` error still occurs (insufficient virtual
    memory), the endpoint returns HTTP 507 immediately without retrying,
    as this error is not transient — it indicates a persistent resource
    constraint that requires administrator intervention (increasing
    swap space, virtual memory limits, or container memory).
    """
    settings = get_settings()
    args: Dict[str, Any] = {}

    # Fix v25: The executor now auto-injects -H tdb:// AND -U for
    # GPO commands (GPO_COMMANDS_NEED_U_AND_TDB).  This bypasses
    # CLDAP DC discovery which was the root cause of the
    # STATUS_QUOTA_EXCEEDED error and "Could not find a DC" errors.

    if settings.REALM:
        args["--realm"] = settings.REALM

    # Fix v7-2: Removed --server from gpo create.
    # samba-tool gpo create on ALT Linux (4.21.9) does NOT
    # support --server flag. It supports -H and --realm but
    # not --server.
    #
    # Fix v25: gpo create is in GPO_COMMANDS_NEED_U_AND_TDB.
    # The executor auto-injects -H tdb:// AND -U for GPO commands.
    # This bypasses CLDAP DC discovery (which caused
    # STATUS_QUOTA_EXCEEDED and "Could not find a DC" errors)
    # and provides credentials.

    # Fix v10-1: Removed --tmpdir /var/tmp flag.
    # samba-tool on ALT Linux returns "Unknown parameter encountered: "tmp dir""
    # when --tmpdir is passed. The TMPDIR environment variable is already
    # set to /var/tmp in worker.py's subprocess environment (Fix v10-2),
    # so the --tmpdir flag is redundant and causes errors on some builds.
    # if os.path.isdir("/var/tmp"):
    #     args["--tmpdir"] = "/var/tmp"

    cmd = build_samba_command(
        "gpo",
        "create",
        args,
        positionals=[body.displayname],
    )

    try:
        # Fix v5: Increase timeout from 60s to 120s.  GPO creation
        # involves SMB connections to the sysvol share, which can be
        # slow on resource-constrained systems.  The 60s timeout was
        # causing false 504 errors.
        result = await execute_samba_command(cmd, timeout=240)

        # Extract the GPO GUID from samba-tool output.
        # Output format: "GPO '<displayname>' created as {GUID}"
        gpo_id: Optional[str] = None
        output = result.get("output", "")
        if output:
            match = re.search(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}", output)
            if match:
                gpo_id = match.group(0)
                logger.info("Created GPO '%s' with ID %s", body.displayname, gpo_id)
            else:
                logger.warning(
                    "GPO created but could not parse GUID from output: %s",
                    output[:200],
                )

        return GpoCreateResponse(
            message=f"GPO '{body.displayname}' created successfully",
            displayname=body.displayname,
            gpo_id=gpo_id,
        )
    except RuntimeError as exc:
        logger.error("Failed to create GPO '%s': %s", body.displayname, exc)
        # Fix v4: Enhanced error handling for "insufficient virtual memory"
        # errors during GPO creation.  The root cause is a bug in Samba's
        # python/samba/netcmd/gpo.py where net.finddc() is called with
        # address=dc_hostname instead of domain=realm, causing excessive
        # virtual memory allocation during CLDAP queries.
        exc_msg = str(exc).lower()
        if "not enough quota" in exc_msg or "0x800705ad" in exc_msg or "insufficient_storage" in exc_msg or "status_quota_exceeded" in exc_msg or "0xc0000073" in exc_msg:
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail=(
                    f"GPO creation failed due to insufficient virtual memory (STATUS_QUOTA_EXCEEDED): {exc}. "
                    f"Root cause: Samba bug in python/samba/netcmd/gpo.py — net.finddc(address=dc_hostname) "
                    f"allocates excessive virtual memory during CLDAP DC discovery. "
                    f"Workarounds: "
                    f"(1) Set SAMBA_LDAPI_URL to bypass CLDAP discovery entirely (recommended); "
                    f"(2) Apply the Samba source patch to change net.finddc(address=...) to "
                    f"net.finddc(domain=self.lp.get('realm'), ...) in python/samba/netcmd/gpo.py; "
                    f"(3) Increase swap space: 'fallocate -l 2G /swapfile && mkswap /swapfile && swapon /swapfile'; "
                    f"(4) Set TMPDIR=/var/tmp before running samba-tool. "
                    f"See: Samba bug #15462 and the included patch in patches/samba_gpo_finddc.patch"
                ),
            ) from exc
        # Fix v4: Also catch "finddc" errors specifically — these occur when
        # CLDAP DC discovery fails, which is the precursor to the quota error.
        if "finddc" in exc_msg or "could not find a dc" in exc_msg or "failed to find dc" in exc_msg:
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail=(
                    f"GPO creation failed during DC discovery: {exc}. "
                    f"This is likely caused by the Samba net.finddc() bug where "
                    f"address=dc_hostname triggers excessive memory allocation. "
                    f"Set SAMBA_LDAPI_URL to bypass CLDAP discovery entirely, or "
                    f"apply the patch in patches/samba_gpo_finddc.patch to fix the "
                    f"root cause in python/samba/netcmd/gpo.py."
                ),
            ) from exc

        # Fix v8: Handle 409 Conflict (GPO already exists) with overwrite.
        # When a GPO with the same displayname already exists (typically
        # from a previous test run), samba-tool returns an "already exists"
        # error.  If overwrite=true, we attempt to delete the existing GPO
        # and retry creation, making the endpoint idempotent for test use.
        from app.executor import classify_samba_error
        http_status = classify_samba_error(exc)
        if http_status == 409 and overwrite:
            logger.info(
                "GPO '%s' already exists (409), overwrite=true — "
                "attempting to delete and recreate",
                body.displayname,
            )
            try:
                # Step 1: List GPOs to find the existing one's GUID.
                list_args: Dict[str, Any] = {"--json": True}
                # Fix v25: executor auto-injects -H tdb:// for gpo listall.
                if settings.REALM:
                    list_args["--realm"] = settings.REALM
                list_cmd = build_samba_command("gpo", "listall", list_args)
                list_result = await execute_samba_command(list_cmd, timeout=120)

                # Step 2: Find the GPO GUID by displayname.
                existing_gpo_id: Optional[str] = None
                gpos = list_result if isinstance(list_result, dict) else {}
                # gpo listall --json returns a dict keyed by GUID
                for gpo_guid, gpo_data in gpos.items():
                    if isinstance(gpo_data, dict):
                        gpo_name = gpo_data.get("displayname", gpo_data.get("name", ""))
                        if gpo_name == body.displayname:
                            existing_gpo_id = gpo_guid
                            break
                    elif isinstance(gpo_data, str) and gpo_data == body.displayname:
                        existing_gpo_id = gpo_guid
                        break

                if existing_gpo_id:
                    # Step 3: Delete the existing GPO.
                    logger.info(
                        "Deleting existing GPO '%s' (GUID: %s) before recreate",
                        body.displayname, existing_gpo_id,
                    )
                    del_args: Dict[str, Any] = {}
                    if settings.REALM:
                        del_args["--realm"] = settings.REALM
                    del_cmd = build_samba_command(
                        "gpo", "del", del_args, positionals=[existing_gpo_id],
                    )
                    await execute_samba_command(del_cmd, timeout=240)
                    logger.info(
                        "Successfully deleted GPO '%s' (GUID: %s)",
                        body.displayname, existing_gpo_id,
                    )
                else:
                    # GPO exists but we couldn't find its GUID via listall.
                    # This can happen when listall returns non-JSON output.
                    # Fall through to the normal 409 error.
                    logger.warning(
                        "GPO '%s' already exists but could not find its GUID "
                        "in gpo listall output; cannot auto-delete",
                        body.displayname,
                    )
                    raise_classified_error(exc)

                # Step 4: Retry GPO creation after deletion.
                retry_result = await execute_samba_command(cmd, timeout=240)

                # Extract GPO GUID from retry output.
                gpo_id: Optional[str] = None
                output = retry_result.get("output", "")
                if output:
                    match = re.search(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}", output)
                    if match:
                        gpo_id = match.group(0)

                return GpoCreateResponse(
                    message=f"GPO '{body.displayname}' recreated successfully (overwritten)",
                    displayname=body.displayname,
                    gpo_id=gpo_id,
                )
            except HTTPException:
                raise
            except RuntimeError as retry_exc:
                logger.error(
                    "Failed to overwrite GPO '%s': %s",
                    body.displayname, retry_exc,
                )
                raise_classified_error(retry_exc)
            except Exception as retry_exc:
                logger.exception(
                    "Unexpected error overwriting GPO '%s'",
                    body.displayname,
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Unexpected error during overwrite: {retry_exc}",
                ) from retry_exc

        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error creating GPO '%s'", body.displayname)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.get(
    "/{gpo_id}",
    summary="Show GPO detail",
    response_model=GpoShowResponse,
)
async def show_gpo(
    gpo_id: str,
    _auth: ApiKeyDep,
) -> GpoShowResponse:
    """Show details of a specific Group Policy Object via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool gpo show``.
    Reads the groupPolicyContainer object directly from the directory
    by its GUID (cn attribute).
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    from app.ldb_reader import fetch_gpo_by_id

    data = await fetch_gpo_by_id(gpo_id)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GPO '{gpo_id}' not found",
        )
    return GpoShowResponse(
        message=f"GPO '{gpo_id}' details retrieved",
        data=data,
    )


@router.delete(
    "/{gpo_id}",
    summary="Delete GPO",
    response_model=TaskResponse,
)
async def delete_gpo(
    gpo_id: str,
    _auth: ApiKeyDep,
) -> TaskResponse:
    """Delete a Group Policy Object.

    Because GPO deletion can be slow (involves SMB connections),
    the command is dispatched as a background task.
    Returns a task ID that can be polled for status.
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    try:
        settings = get_settings()
        args: Dict[str, Any] = {}
        if settings.REALM:
            args["--realm"] = settings.REALM
        cmd = build_samba_command("gpo", "del", args, positionals=[gpo_id])
        task_mgr = get_task_manager()
        task_id = task_mgr.submit_task(cmd, timeout=240)
        return TaskResponse(
            message=f"GPO deletion task submitted for '{gpo_id}'",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except RuntimeError as exc:
        logger.error("Failed to delete GPO '%s': %s", gpo_id, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error deleting GPO '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


# Fix v8: Convenience endpoint for deleting GPO by displayname.
# This is useful for test scenarios where the GPO's GUID is unknown
# but the displayname is known (e.g. "_debug_test_gpo").
@router.delete(
    "/by-name/{displayname}",
    summary="Delete GPO by displayname",
)
async def delete_gpo_by_name(
    displayname: str,
    _auth: ApiKeyDep,
) -> dict:
    """Delete a Group Policy Object by its displayname.

    This convenience endpoint finds the GPO GUID by displayname using
    ``gpo listall``, then deletes the GPO.  It is primarily intended
    for test cleanup scenarios where a GPO like ``_debug_test_gpo``
    was created in a previous test run and needs to be removed before
    the next run.

    If no GPO with the given displayname exists, returns 404.
    If multiple GPOs share the same displayname, all are deleted.

    The deletion is performed synchronously (not as a background task)
    so that test scripts can verify the deletion completed before
    proceeding.
    """
    settings = get_settings()
    try:
        # Step 1: List GPOs to find GUID(s) by displayname.
        list_args: Dict[str, Any] = {"--json": True}
        # Fix v25: gpo listall is in COMMANDS_READ_ONLY_TDB.
        # The executor auto-injects -H tdb://. No manual -H needed.
        if settings.REALM:
            list_args["--realm"] = settings.REALM
        list_cmd = build_samba_command("gpo", "listall", list_args)
        list_result = await execute_samba_command(list_cmd, timeout=120)

        # Step 2: Find GPO GUID(s) matching the displayname.
        gpos = list_result if isinstance(list_result, dict) else {}
        matching_guids: list[str] = []
        for gpo_guid, gpo_data in gpos.items():
            if isinstance(gpo_data, dict):
                gpo_name = gpo_data.get("displayname", gpo_data.get("name", ""))
                if gpo_name == displayname:
                    matching_guids.append(gpo_guid)
            elif isinstance(gpo_data, str) and gpo_data == displayname:
                matching_guids.append(gpo_guid)

        if not matching_guids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No GPO found with displayname '{displayname}'",
            )

        # Step 3: Delete each matching GPO.
        deleted: list[dict] = []
        for gpo_guid in matching_guids:
            del_args: Dict[str, Any] = {}
            if settings.REALM:
                del_args["--realm"] = settings.REALM
            del_cmd = build_samba_command(
                "gpo", "del", del_args, positionals=[gpo_guid],
            )
            try:
                await execute_samba_command(del_cmd, timeout=240)
                deleted.append({"gpo_id": gpo_guid, "displayname": displayname, "status": "deleted"})
                logger.info("Deleted GPO '%s' (GUID: %s)", displayname, gpo_guid)
            except RuntimeError as del_exc:
                deleted.append({"gpo_id": gpo_guid, "displayname": displayname, "status": "failed", "error": str(del_exc)})
                logger.error("Failed to delete GPO '%s' (GUID: %s): %s", displayname, gpo_guid, del_exc)

        return {
            "message": f"Deleted {len([d for d in deleted if d['status'] == 'deleted'])} GPO(s) with displayname '{displayname}'",
            "results": deleted,
        }
    except HTTPException:
        raise
    except RuntimeError as exc:
        logger.error("Failed to delete GPO by name '%s': %s", displayname, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error deleting GPO by name '%s'", displayname)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


# NOTE: get_gpo_acl and set_gpo_acl endpoints have been removed.
# samba-tool does not provide "gpo getacl" or "gpo setacl" subcommands.


@router.post(
    "/{gpo_id}/link",
    summary="Link GPO",
    response_model=GpoLinkResponse,
)
async def link_gpo(
    gpo_id: str,
    body: GpoLinkRequest,
    _auth: ApiKeyDep,
) -> GpoLinkResponse:
    """Link a Group Policy Object to a container.

    samba-tool gpo setlink <container_dn> <gpo_id>
    The container DN is the first positional, GPO ID is second.
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    try:
        # Fix v25: gpo setlink is in GPO_COMMANDS_NEED_U_AND_TDB.
        # The executor auto-injects -H tdb:// AND -U.
        # This bypasses CLDAP DC discovery that was causing
        # "Could not find a DC" / "no network interfaces found".
        settings = get_settings()
        args: Dict[str, Any] = {}
        if settings.REALM:
            args["--realm"] = settings.REALM
        cmd = build_samba_command(
            "gpo",
            "setlink",
            args,
            positionals=[body.container_dn, gpo_id],
        )
        await execute_samba_command(cmd)
        return GpoLinkResponse(
            message=f"GPO '{gpo_id}' linked to '{body.container_dn}'",
            gpo_id=gpo_id,
        )
    except RuntimeError as exc:
        logger.error("Failed to link GPO '%s': %s", gpo_id, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error linking GPO '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.delete(
    "/{gpo_id}/link",
    summary="Unlink GPO",
    response_model=GpoUnlinkResponse,
)
async def unlink_gpo(
    gpo_id: str,
    body: GpoUnlinkRequest,
    _auth: ApiKeyDep,
) -> GpoUnlinkResponse:
    """Unlink a Group Policy Object from a container.

    samba-tool gpo dellink <container_dn> <gpo_id>
    The container DN is the first positional, GPO ID is second.
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    try:
        # Fix v25: gpo dellink is in GPO_COMMANDS_NEED_U_AND_TDB.
        # The executor auto-injects -H tdb:// AND -U.
        settings = get_settings()
        args: Dict[str, Any] = {}
        if settings.REALM:
            args["--realm"] = settings.REALM
        cmd = build_samba_command(
            "gpo",
            "dellink",
            args,
            positionals=[body.container_dn, gpo_id],
        )
        await execute_samba_command(cmd)
        return GpoUnlinkResponse(
            message=f"GPO '{gpo_id}' unlinked from '{body.container_dn}'",
            gpo_id=gpo_id,
        )
    except RuntimeError as exc:
        logger.error("Failed to unlink GPO '%s': %s", gpo_id, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error unlinking GPO '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.get(
    "/{gpo_id}/inherit",
    summary="Get inheritance",
    response_model=GpoGetInheritResponse,
)
async def get_gpo_inherit(
    gpo_id: str,
    _auth: ApiKeyDep,
    container_dn: Optional[str] = Query(
        default=None,
        description="Container DN to check inheritance for (e.g. 'DC=kcrb,DC=local'). If not provided, defaults to the domain DN from settings.",
    ),
    H: Optional[str] = Query(
        default=None,
        description="LDAP URL to connect to (overrides config).",
    ),
) -> GpoGetInheritResponse:
    """Get the inheritance settings for a GPO container.

    Fix v11-4: samba-tool gpo getinheritance takes a container DN,
    not a GPO GUID. Added container_dn parameter to specify the
    container to check. Defaults to domain DN if not provided.
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    # Fix v12-2: Move container_dn/domain DN validation BEFORE the
    # try block.  Previously, raise HTTPException(400) inside the
    # try block was caught by the generic except Exception handler
    # and turned into a 500 Internal Server Error.  Now the
    # validation happens first and returns a clean 400.
    settings = get_settings()
    target_dn = container_dn or settings.DOMAIN_DN
    if not target_dn and settings.REALM:
        target_dn = f"DC={settings.REALM.replace('.', ',DC=')}"
    if not target_dn:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="container_dn query parameter is required when domain DN cannot be auto-detected",
        )
    try:
        # Fix v11-4: Use container_dn, not gpo_id, for the positional arg.
        # samba-tool gpo getinheritance <container_dn> expects an OU/container DN.
        args: Dict[str, Any] = {}
        if H:
            args["-H"] = H
        # Fix v25: gpo getinheritance is in GPO_COMMANDS_NEED_U_AND_TDB.
        # The executor auto-injects -H tdb:// AND -U.
        if settings.REALM:
            args["--realm"] = settings.REALM
        cmd = build_samba_command("gpo", "getinheritance", args, positionals=[target_dn])
        result = await execute_samba_command(cmd)
        return GpoGetInheritResponse(
            message=f"Inheritance for '{target_dn}' retrieved successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to get inheritance for '%s': %s", target_dn, exc)
        raise_classified_error(exc)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error getting inheritance for '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.put(
    "/{gpo_id}/inherit",
    summary="Set inheritance",
    response_model=GpoSetInheritResponse,
)
async def set_gpo_inherit(
    gpo_id: str,
    body: GpoSetInheritRequest,
    _auth: ApiKeyDep,
    container_dn: Optional[str] = Query(
        default=None,
        description="Container DN to set inheritance for (e.g. 'DC=kcrb,DC=local'). If not provided, defaults to the domain DN from settings.",
    ),
) -> GpoSetInheritResponse:
    """Set the inheritance blocking state for a GPO container.

    Fix v11-4: samba-tool gpo setinheritance takes a container DN,
    not a GPO GUID. Added container_dn parameter. Defaults to domain DN.

    Set ``block=true`` to block inheritance, ``block=false`` to allow it.
    samba-tool gpo setinheritance <container_dn> <block|inherit>
    The block/inherit state is a positional argument, not a flag.
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    # Fix v12-2: Move container_dn/domain DN validation BEFORE the
    # try block.  Same fix as get_gpo_inherit — previously
    # HTTPException(400) inside try was caught by except Exception
    # and turned into 500 Internal Server Error.
    settings = get_settings()
    target_dn = container_dn or settings.DOMAIN_DN
    if not target_dn and settings.REALM:
        target_dn = f"DC={settings.REALM.replace('.', ',DC=')}"
    if not target_dn:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="container_dn query parameter is required when domain DN cannot be auto-detected",
        )
    try:
        # Fix v11-4: Use container_dn, not gpo_id, for the positional arg.
        # Fix v25: gpo setinheritance is in GPO_COMMANDS_NEED_U_AND_TDB.
        # The executor auto-injects -H tdb:// AND -U.
        settings = get_settings()
        args: Dict[str, Any] = {}
        if settings.REALM:
            args["--realm"] = settings.REALM
        cmd = build_samba_command(
            "gpo", "setinheritance", args,
            positionals=[target_dn, "block" if body.block else "inherit"],
        )
        await execute_samba_command(cmd)
        state = "blocked" if body.block else "unblocked"
        return GpoSetInheritResponse(
            message=f"Inheritance for '{target_dn}' {state} successfully",
            gpo_id=gpo_id,
        )
    except RuntimeError as exc:
        logger.error("Failed to set inheritance for '%s': %s", target_dn, exc)
        raise_classified_error(exc)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error setting inheritance for '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.post(
    "/{gpo_id}/backup",
    summary="Backup GPO",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=GpoBackupResponse,
)
async def backup_gpo(
    gpo_id: str,
    body: GpoBackupRequest,
    _auth: ApiKeyDep,
) -> GpoBackupResponse:
    """Backup a Group Policy Object.

    Because backup can be slow, the command is dispatched as a background
    task.  The response includes a ``task_id`` that can be polled via the
    ``/tasks/{task_id}`` endpoint.

    Fix v1.6.2: Validates and fixes the target_dir parameter:
    - Replaces invalid paths like ``/var/`` with a proper subdirectory
      (``/var/lib/samba/api_backups/``)
    - Creates the target directory if it does not exist
    - Removes the ``-H tdb://`` flag for backup (backup needs proper
      LDAP/SMB connection, not direct TDB file access)
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    try:
        settings = get_settings()
        args: Dict[str, Any] = {}
        if settings.REALM:
            args["--realm"] = settings.REALM

        # Fix v1.6.2: Validate and fix target_dir
        target_dir = body.target_dir
        _INVALID_TARGET_DIRS = {"/var", "/var/", "/tmp", "/tmp/", "/", "/root"}
        if not target_dir or target_dir.rstrip("/") in _INVALID_TARGET_DIRS:
            # Use a proper backup directory instead of root paths
            target_dir = "/var/lib/samba/api_backups"
            logger.info(
                "GPO backup target_dir '%s' is invalid — using '%s' instead",
                body.target_dir, target_dir,
            )

        # Ensure the target directory exists
        os.makedirs(target_dir, exist_ok=True)

        cmd = build_samba_command(
            "gpo",
            "backup",
            args,
            positionals=[gpo_id, target_dir],
        )

        task_mgr = get_task_manager()
        task_id = task_mgr.submit_task(cmd, timeout=1200)

        return GpoBackupResponse(
            message=f"Backup task for GPO '{gpo_id}' submitted",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except Exception as exc:
        logger.exception("Unexpected error submitting GPO backup task for '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.post(
    "/{gpo_id}/restore",
    summary="Restore GPO",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=GpoRestoreResponse,
)
async def restore_gpo(
    gpo_id: str,
    body: GpoRestoreRequest,
    _auth: ApiKeyDep,
) -> GpoRestoreResponse:
    """Restore a Group Policy Object from a backup directory.

    Because restore can be slow, the command is dispatched as a background
    task.  The response includes a ``task_id`` that can be polled via the
    ``/tasks/{task_id}`` endpoint.
    """
    gpo_id = _ensure_gpo_braces(gpo_id)
    try:
        # Fix v25: gpo restore is in GPO_COMMANDS_NEED_U_AND_TDB.
        # The executor auto-injects -H tdb:// AND -U.
        settings = get_settings()
        args: Dict[str, Any] = {}
        if settings.REALM:
            args["--realm"] = settings.REALM
        cmd = build_samba_command(
            "gpo",
            "restore",
            args,
            positionals=[gpo_id, body.source_dir],
        )

        task_mgr = get_task_manager()
        task_id = task_mgr.submit_task(cmd, timeout=1200)

        return GpoRestoreResponse(
            message=f"Restore task for GPO '{gpo_id}' submitted",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except Exception as exc:
        logger.exception("Unexpected error submitting GPO restore task for '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


# NOTE: listall_gpo per-GPO endpoint has been removed.
# samba-tool "gpo listall" is a global command that takes no positional
# arguments and lists all GPOs in the domain.  The global list_gpos
# endpoint (GET /gpo/) already covers this functionality.


@router.get(
    "/{gpo_id}/fetch",
    summary="Fetch GPO data",
    response_model=GpoFetchResponse,
)
async def fetch_gpo(
    gpo_id: str,
    _auth: ApiKeyDep,
    H: Optional[str] = Query(
        default=None,
        description="LDAP URL to connect to (overrides config).",
    ),
) -> GpoFetchResponse:
    """Fetch data for a Group Policy Object."""
    gpo_id = _ensure_gpo_braces(gpo_id)
    try:
        settings = get_settings()
        args: Dict[str, Any] = {}
        if H:
            args["-H"] = H
        # Fix v25: gpo fetch is in GPO_COMMANDS_NEED_U_AND_TDB.
        # The executor auto-injects -H tdb:// AND -U.
        if settings.REALM:
            args["--realm"] = settings.REALM
        cmd = build_samba_command("gpo", "fetch", args, positionals=[gpo_id])
        result = await execute_samba_command(cmd)
        return GpoFetchResponse(
            message=f"GPO '{gpo_id}' data fetched successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to fetch GPO '%s': %s", gpo_id, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error fetching GPO '%s'", gpo_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc
