"""
DRS Replication management router.

Wraps ``samba-tool drs`` CLI commands behind a REST API.
All endpoints require API-key authentication.

Long-running operations (replicate) are dispatched through the
background task manager and return a task ID for polling.

Important: DRS commands have different argument signatures:

- ``drs showrepl`` — takes optional positional ``<DC>``, supports ``--json``.
- ``drs bind`` — takes optional positional ``<DC>``, no JSON output.
- ``drs options`` — takes optional positional ``<DC>``, no JSON output.
- ``drs kcc`` — takes optional positional ``<DC>``, no JSON output.
- ``drs replicate`` — takes 3 positional args: ``<DEST_DC> <SOURCE_DC> <NC>``.
- ``drs uptodateness`` — takes NO positional args, uses ``-H`` (LDAP URL)
  to connect to the local database.  Does NOT use DRSUAPI RPC.

None of the DRS commands support ``--server``, ``--realm``, or ``--configfile``.
The executor automatically strips these flags via capability sets.

Fix v5: DRS "Not Enough Quota" / STATUS_QUOTA_EXCEEDED errors
---------------------------------------------------------------
DRS commands that use DRSUAPI RPC (showrepl, bind, options, kcc, replicate)
call ``drsuapi.drsuapi(binding_string, lp, creds)`` in
``python/samba/drs_utils.py``.  During DRSUAPI bind, Samba creates
temporary files for GSSAPI/Kerberos authentication.  If TMPDIR points
to a tmpfs with limited space or quota, this triggers
STATUS_QUOTA_EXCEEDED (3221225495 / 0xC0000073).

The API-level workaround (already in worker.py since v4) sets
TMPDIR=/var/tmp for ALL samba-tool subprocesses.  However, the DRSUAPI
C extension may not respect the Python-level TMPDIR, so a Samba source
patch is also required.

Samba source patches required:
  - patches/samba_drs_utils_tmpdir.patch — Sets TMPDIR before drsuapi bind
  - patches/samba_drs_timeout.patch — Increases request_timeout values

If patching is not possible, increase system swap space::

    fallocate -l 2G /swapfile && mkswap /swapfile && swapon /swapfile
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import build_samba_command, execute_samba_command, get_dc_hostname, raise_classified_error
from app.models.common import ErrorResponse
from app.models.drs import (
    DrsBindResponse,
    DrsOptionsResponse,
    DrsReplicateRequest,
    DrsReplicateResponse,
    DrsShowreplResponse,
    DrsUptodatenessResponse,
)
from app.tasks import get_task_manager
import os
import urllib.parse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/drs",
    tags=["DRS Replication"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
    },
)


# ── DRS quota error patterns ────────────────────────────────────────────
# These patterns indicate the DRSUAPI bind failed due to insufficient
# virtual memory / paging file quota.  This is NOT a transient error —
# it requires system-level or Samba source patch intervention.
_DRS_QUOTA_PATTERNS: tuple[str, ...] = (
    "not enough quota",
    "status_quota_exceeded",
    "0xc0000073",
    "0x800705ad",
    "insufficient_storage",
    "3221225495",  # NTSTATUS decimal for STATUS_QUOTA_EXCEEDED
)


def _is_drs_quota_error(msg: str) -> bool:
    """Return True if the error message indicates a DRS quota/memory error."""
    msg_lower = msg.lower()
    return any(pat in msg_lower for pat in _DRS_QUOTA_PATTERNS)


@router.get(
    "/showrepl",
    summary="Show replication status",
    response_model=DrsShowreplResponse,
)
async def showrepl(
    _auth: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="Target DC hostname (positional <DC> argument). Defaults to Settings.SERVER.",
    ),
    timeout: int = Query(
        default=120,
        ge=5,
        le=1200,
        description="Execution timeout in seconds (default: 60). DRS RPC can be slow under load.",
    ),
) -> DrsShowreplResponse:
    """Show the current DRS replication status.

    Note: ``samba-tool drs showrepl`` uses DRSUAPI RPC which can be
    slow under resource pressure (e.g. "Not Enough Quota" on VMs).
    The default timeout is 60 seconds to accommodate slower systems.
    If the DC is completely unreachable, the timeout returns 504.

    If a "Not Enough Quota" error is encountered, the endpoint returns
    HTTP 507 with detailed guidance on applying the Samba source patch
    or increasing system swap space.

    The command accepts an optional positional ``<DC>`` argument. If the
    ``server`` query parameter is provided, it is used; otherwise
    ``Settings.SERVER`` is used as fallback.

    **Fix v5: DRS Quota Error Resolution**

    The STATUS_QUOTA_EXCEEDED error in DRS commands is caused by
    ``drsuapi.drsuapi()`` in ``python/samba/drs_utils.py`` creating
    temporary files in a tmpfs-limited /tmp directory during GSSAPI
    authentication.  The fix requires:

    1. Apply ``patches/samba_drs_utils_tmpdir.patch`` to set TMPDIR=/var/tmp
       before the DRSUAPI bind call.
    2. Or set TMPDIR=/var/tmp in the system environment before starting
       the samba-tool process.
    3. Or increase system swap space.
    """
    try:
        settings = get_settings()
        # Fix v22: Always replace 'localhost' with real DC hostname for DRS RPC
        _LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "127.0.0.1", "::1"}
        dc = server if (server and server.lower() not in _LOCALHOST_NAMES) else get_dc_hostname(settings)
        positionals = [dc] if dc else []
        cmd = build_samba_command("drs", "showrepl", {"--json": True}, positionals=positionals)
        result = await execute_samba_command(cmd, timeout=timeout)
        return DrsShowreplResponse(
            message="DRS replication status retrieved successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to get DRS showrepl: %s", exc)
        exc_msg = str(exc)
        # Fix v5: Specific DRS quota error handling
        if _is_drs_quota_error(exc_msg):
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail=(
                    f"DRS showrepl failed due to insufficient virtual memory (STATUS_QUOTA_EXCEEDED): {exc}. "
                    f"Root cause: python/samba/drs_utils.py drsuapi_connect() creates temp files in "
                    f"TMPDIR during GSSAPI/Kerberos authentication for DRSUAPI bind.  When TMPDIR is "
                    f"a tmpfs with limited space, this triggers STATUS_QUOTA_EXCEEDED (3221225495). "
                    f"Workarounds: "
                    f"(1) Apply patches/samba_drs_utils_tmpdir.patch to set TMPDIR=/var/tmp before "
                    f"drsuapi.drsuapi() call in python/samba/drs_utils.py; "
                    f"(2) Set TMPDIR=/var/tmp in the system environment before starting the API server; "
                    f"(3) Increase swap space: 'fallocate -l 2G /swapfile && mkswap /swapfile && swapon /swapfile'; "
                    f"(4) Increase swap space or add 'tmp dir = /var/tmp' to [global] section of smb.conf "
                    f"(WARNING: some samba-tool builds report 'Unknown parameter encountered: \"tmp dir\"' "
                    f"when this smb.conf directive is present — if so, remove it and rely on TMPDIR "
                    f"environment variable instead). "
                    f"See: patches/samba_drs_utils_tmpdir.patch and patches/samba_drs_timeout.patch"
                ),
            ) from exc
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error getting DRS showrepl")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.post(
    "/replicate",
    summary="Replicate naming context",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DrsReplicateResponse,
)
async def replicate(
    body: DrsReplicateRequest,
    _auth: ApiKeyDep,
) -> DrsReplicateResponse:
    """Trigger DRS replication of a naming context.

    Because replication can be slow, the command is dispatched as a
    background task.  The response includes a ``task_id`` that can be
    polled via the ``/tasks/{task_id}`` endpoint.
    """
    try:
        # Fix v3-9: samba-tool drs replicate takes 3 POSITIONAL args:
        #   samba-tool drs replicate <DEST_DC> <SOURCE_DC> <NC>
        # NOT --destination/--source flags.  The previous code passed
        # them as flags, causing "no such option: --destination".
        cmd = build_samba_command(
            "drs", "replicate", {},
            positionals=[body.destination_dsa, body.source_dsa, body.nc_dn],
        )

        task_mgr = get_task_manager()
        task_id = task_mgr.submit_task(cmd, timeout=1200)

        return DrsReplicateResponse(
            message=f"Replication task submitted for NC '{body.nc_dn}'",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except Exception as exc:
        logger.exception("Unexpected error submitting DRS replicate task")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.get(
    "/uptodateness",
    summary="Check uptodateness",
    response_model=DrsUptodatenessResponse,
)
async def uptodateness(
    _auth: ApiKeyDep,
    H: Optional[str] = Query(
        default=None,
        description="Optional LDB URL override. If not set, -U credentials are used and samba-tool auto-discovers the connection.",
    ),
    object_dn: Optional[str] = Query(
        default=None,
        description="Distinguished name of the partition to restrict check to.",
    ),
    timeout: int = Query(
        default=900,
        ge=60,
        le=1800,
        description="Execution timeout in seconds (default: 900).",
    ),
) -> DrsUptodatenessResponse:
    """Check the uptodateness vector for domain partitions.

    Note: Unlike other DRS commands, ``samba-tool drs uptodateness`` does
    NOT take a positional ``<DC>`` argument.

    **Fix v26-2**: Removed ALL ``-H`` flags (tdb://, ldapi://, ldap://).
    Neither ``-H tdb://`` nor ``-H ldapi://`` are needed — just ``-U``
    credentials are sufficient.  samba-tool auto-discovers the DC
    connection when ``-U`` is provided.

    Previous versions used ``-H tdb://`` (caused ``Cannot contact any
    KDC``) then ``-H ldapi://`` (also unnecessary complexity).  Both
    are removed — ``-U`` is all that's needed.
    """
    try:
        settings = get_settings()
        # Fix v26-2: NO -H at all — just -U credentials.
        # v20 used -H tdb:// → "Cannot contact any KDC"
        # v26 used -H ldapi:// → unnecessary, samba-tool auto-discovers
        # v26-2: just -U, no -H. Simple and working.
        #
        # The executor auto-injects -U from CREDENTIALS_USER/PASSWORD.
        args: Dict[str, Any] = {}
        if H:
            # Only use explicit -H if caller passes it manually
            args["-H"] = H
        # else: no -H — -U is enough, samba-tool auto-discovers

        if object_dn:
            args["--partition"] = object_dn
        # NO positional DC argument — uptodateness does not accept one
        cmd = build_samba_command("drs", "uptodateness", args)
        result = await execute_samba_command(cmd, timeout=timeout)
        return DrsUptodatenessResponse(
            message="Uptodateness check completed successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to check uptodateness: %s", exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error checking uptodateness")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.get(
    "/bind",
    summary="DRS bind info",
    response_model=DrsBindResponse,
)
async def drs_bind(
    _auth: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="Target DC hostname (positional <DC> argument). Defaults to Settings.SERVER.",
    ),
    timeout: int = Query(
        default=120,
        ge=5,
        le=1200,
        description="Execution timeout in seconds (default: 60). DRS RPC can be slow under load.",
    ),
) -> DrsBindResponse:
    """Retrieve DRS bind information from a server.

    Note: DRS bind uses DRSUAPI RPC which can be slow under resource
    pressure (e.g. "Not Enough Quota"). The default timeout is 60 seconds
    to accommodate slower systems. If the DC is completely unreachable,
    the timeout returns 504.

    If a "Not Enough Quota" error is encountered, the endpoint returns
    HTTP 507 with detailed guidance on applying the Samba source patch
    or increasing system swap space.

    The command accepts an optional positional ``<DC>`` argument. If the
    ``server`` query parameter is provided, it is used; otherwise
    ``Settings.SERVER`` is used as fallback.

    **Fix v5: DRS Quota Error Resolution**

    The STATUS_QUOTA_EXCEEDED error in DRS bind is caused by
    ``drsuapi.drsuapi()`` in ``python/samba/drs_utils.py`` creating
    temporary files in a tmpfs-limited /tmp directory during GSSAPI
    authentication.  See ``showrepl`` docstring for full details.
    """
    try:
        settings = get_settings()
        # Fix v22: Always replace 'localhost' with real DC hostname for DRS RPC
        _LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "127.0.0.1", "::1"}
        dc = server if (server and server.lower() not in _LOCALHOST_NAMES) else get_dc_hostname(settings)
        positionals = [dc] if dc else []
        cmd = build_samba_command("drs", "bind", {}, positionals=positionals)
        result = await execute_samba_command(cmd, timeout=timeout)
        return DrsBindResponse(
            message="DRS bind information retrieved successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to get DRS bind info: %s", exc)
        exc_msg = str(exc)
        # Fix v5: Specific DRS quota error handling
        if _is_drs_quota_error(exc_msg):
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail=(
                    f"DRS bind failed due to insufficient virtual memory (STATUS_QUOTA_EXCEEDED): {exc}. "
                    f"Root cause: python/samba/drs_utils.py drsuapi_connect() creates temp files in "
                    f"TMPDIR during GSSAPI/Kerberos authentication for DRSUAPI bind.  When TMPDIR is "
                    f"a tmpfs with limited space, this triggers STATUS_QUOTA_EXCEEDED (3221225495). "
                    f"Workarounds: "
                    f"(1) Apply patches/samba_drs_utils_tmpdir.patch to set TMPDIR=/var/tmp before "
                    f"drsuapi.drsuapi() call in python/samba/drs_utils.py; "
                    f"(2) Set TMPDIR=/var/tmp in the system environment before starting the API server; "
                    f"(3) Increase swap space: 'fallocate -l 2G /swapfile && mkswap /swapfile && swapon /swapfile'; "
                    f"(4) Increase swap space or add 'tmp dir = /var/tmp' to [global] section of smb.conf "
                    f"(WARNING: some samba-tool builds report 'Unknown parameter encountered: \"tmp dir\"' "
                    f"when this smb.conf directive is present — if so, remove it and rely on TMPDIR "
                    f"environment variable instead). "
                    f"See: patches/samba_drs_utils_tmpdir.patch and patches/samba_drs_timeout.patch"
                ),
            ) from exc
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error getting DRS bind info")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.get(
    "/options",
    summary="Get DRS options",
    response_model=DrsOptionsResponse,
)
async def drs_options(
    _auth: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="Target DC hostname (positional <DC> argument). Defaults to Settings.SERVER.",
    ),
    timeout: int = Query(
        default=600,
        ge=30,
        le=1200,
        description="Execution timeout in seconds (default: 300). DRS RPC can be slow under load.",
    ),
) -> DrsOptionsResponse:
    """Get the current DRS options from a server.

    Note: DRS options uses DRSUAPI RPC which can be slow under resource
    pressure (e.g. "Not Enough Quota"). The default timeout is 300 seconds
    to accommodate slower systems. If the DC is completely unreachable,
    the timeout returns 504.

    If a "Not Enough Quota" error is encountered, the endpoint returns
    HTTP 507 with detailed guidance on applying the Samba source patch
    or increasing system swap space.

    The command accepts an optional positional ``<DC>`` argument. If the
    ``server`` query parameter is provided, it is used; otherwise
    ``Settings.SERVER`` is used as fallback.

    **Fix v5/v11-5**: Default timeout increased from 45s to 120s, then to 180s (Fix v10-4),
    then to 300s (Fix v11-5).  DRS options can hang for extended periods when the
    DRSUAPI bind encounters resource constraints, and the previous timeouts were too
    aggressive, causing false 504 errors on loaded systems.

    **Fix v5: DRS Quota Error Resolution**

    The STATUS_QUOTA_EXCEEDED error in DRS options is caused by
    ``drsuapi.drsuapi()`` in ``python/samba/drs_utils.py`` creating
    temporary files in a tmpfs-limited /tmp directory during GSSAPI
    authentication.  See ``showrepl`` docstring for full details.
    """
    try:
        settings = get_settings()
        # Fix v7-6: drs options does NOT support -H (it's in COMMANDS_NO_H_FLAG).
        # It also does NOT take a positional <DC> argument in some samba-tool
        # versions.  When server is provided, we still pass it as positional
        # since the command MAY accept it, but we do NOT add -H.
        # Fix v22: Always replace 'localhost' with real DC hostname for DRS RPC
        _LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "127.0.0.1", "::1"}
        dc = server if (server and server.lower() not in _LOCALHOST_NAMES) else get_dc_hostname(settings)
        positionals = [dc] if dc else []
        cmd = build_samba_command("drs", "options", {}, positionals=positionals)
        result = await execute_samba_command(cmd, timeout=timeout)
        return DrsOptionsResponse(
            message="DRS options retrieved successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to get DRS options: %s", exc)
        exc_msg = str(exc)
        # Fix v5: Specific DRS quota error handling
        if _is_drs_quota_error(exc_msg):
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail=(
                    f"DRS options failed due to insufficient virtual memory (STATUS_QUOTA_EXCEEDED): {exc}. "
                    f"Root cause: python/samba/drs_utils.py drsuapi_connect() creates temp files in "
                    f"TMPDIR during GSSAPI/Kerberos authentication for DRSUAPI bind.  When TMPDIR is "
                    f"a tmpfs with limited space, this triggers STATUS_QUOTA_EXCEEDED (3221225495). "
                    f"Workarounds: "
                    f"(1) Apply patches/samba_drs_utils_tmpdir.patch to set TMPDIR=/var/tmp before "
                    f"drsuapi.drsuapi() call in python/samba/drs_utils.py; "
                    f"(2) Set TMPDIR=/var/tmp in the system environment before starting the API server; "
                    f"(3) Increase swap space: 'fallocate -l 2G /swapfile && mkswap /swapfile && swapon /swapfile'; "
                    f"(4) Increase swap space or add 'tmp dir = /var/tmp' to [global] section of smb.conf "
                    f"(WARNING: some samba-tool builds report 'Unknown parameter encountered: \"tmp dir\"' "
                    f"when this smb.conf directive is present — if so, remove it and rely on TMPDIR "
                    f"environment variable instead). "
                    f"See: patches/samba_drs_utils_tmpdir.patch and patches/samba_drs_timeout.patch"
                ),
            ) from exc
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error getting DRS options")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc
