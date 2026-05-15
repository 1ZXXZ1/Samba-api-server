"""
Miscellaneous management router for the Samba AD DC Management API.

Wraps various ``samba-tool`` commands that don't belong to a specific
domain sub-group, including database checks, NT ACL management,
SPN operations, and diagnostic utilities.

Long-running operations (dbcheck, ntacl sysvolreset, testparm) use the
background task manager; all others execute synchronously.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import (
    build_samba_command_deep,
    execute_samba_command,
    execute_samba_command_raw,
    get_ldapi_url,
    raise_classified_error,
)
from app.models.common import TaskResponse
from app.tasks import get_task_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/misc", tags=["Miscellaneous"])


# ── Request models ──────────────────────────────────────────────────────


class DbcheckFixRequest(BaseModel):
    """Request body for database fix operation."""

    yes: bool = Field(
        default=True,
        description="Confirm the fix operation (defaults to True).",
    )


class SetNtaclRequest(BaseModel):
    """Request body for setting an NT ACL."""

    file_path: str = Field(..., description="Path to the file or directory.")
    sddl: str = Field(..., description="SDDL string for the ACL.")


class SpnRequest(BaseModel):
    """Request body for adding or deleting an SPN."""

    accountname: str = Field(..., description="Account name for the SPN.")
    spn: str = Field(..., description="Service Principal Name to add or delete.")


# ── Database check ─────────────────────────────────────────────────────


@router.get("/dbcheck", summary="Run database check")
async def dbcheck(
    api_key: ApiKeyDep,
) -> TaskResponse:
    """Run a database consistency check as a background task.

    Returns a task ID that can be polled for status and results.
    """
    try:
        cmd = build_samba_command_deep(["dbcheck"])
        task_id = get_task_manager().submit_task(cmd)
        return TaskResponse(
            status="ok",
            message="Database check started",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except Exception as exc:
        logger.error("Failed to submit dbcheck task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit dbcheck task: {exc}",
        )


@router.post("/dbcheck/fix", summary="Fix database errors")
async def dbcheck_fix(
    body: DbcheckFixRequest,
    api_key: ApiKeyDep,
) -> TaskResponse:
    """Fix database errors as a background task.

    Returns a task ID that can be polled for status and results.
    """
    try:
        args: dict = {
            "--fix": True,
        }
        if body.yes:
            args["--yes"] = True

        cmd = build_samba_command_deep(["dbcheck"], args=args)
        task_id = get_task_manager().submit_task(cmd)
        return TaskResponse(
            status="ok",
            message="Database fix started",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except Exception as exc:
        logger.error("Failed to submit dbcheck fix task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit dbcheck fix task: {exc}",
        )


# ── NT ACL ──────────────────────────────────────────────────────────────


@router.get("/ntacl", summary="Get NT ACL")
async def get_ntacl(
    file_path: str,
    api_key: ApiKeyDep,
) -> dict:
    """Get the NT ACL for a file or directory.

    Note: ``samba-tool ntacl get`` expects the file path as a positional
    argument, not via ``--file``.
    """
    try:
        cmd = build_samba_command_deep(["ntacl", "get"], positionals=[file_path])
        result = await execute_samba_command_raw(cmd)
        if result["returncode"] != 0:
            error_msg = result["stderr"].strip() or result["stdout"].strip()
            raise RuntimeError(
                f"samba-tool ntacl get failed (rc={result['returncode']}): {error_msg}"
            )
        return {
            "status": "ok",
            "file_path": file_path,
            "data": {"output": result["stdout"].strip()},
        }
    except RuntimeError as exc:
        logger.error("Failed to get NT ACL for '%s': %s", file_path, exc)
        raise_classified_error(exc)


@router.post("/ntacl/set", summary="Set NT ACL")
async def set_ntacl(
    body: SetNtaclRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Set the NT ACL on a file or directory using an SDDL string.

    Note: ``samba-tool ntacl set`` expects the SDDL string and the file
    path as positional arguments.
    """
    try:
        # ntacl set <sddl> <file> — both are positional arguments.
        cmd = build_samba_command_deep(
            ["ntacl", "set"], positionals=[body.sddl, body.file_path],
        )
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"NT ACL set on '{body.file_path}'",
            "data": result,
        }
    except RuntimeError as exc:
        error_msg = str(exc).lower()
        # Check if the file doesn't exist — return 404 with clear message
        if "no such file or directory" in error_msg or "object_name_not_found" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"File not found: '{body.file_path}'. "
                       f"The NT ACL set operation requires the target file to exist.",
            ) from exc
        logger.error(
            "Failed to set NT ACL on '%s': %s", body.file_path, exc
        )
        raise_classified_error(exc)


@router.post("/ntacl/sysvolreset", summary="Reset sysvol ACLs")
async def ntacl_sysvolreset(
    api_key: ApiKeyDep,
) -> TaskResponse:
    """Reset sysvol ACLs as a background task.

    Returns a task ID that can be polled for status and results.
    """
    try:
        cmd = build_samba_command_deep(["ntacl", "sysvolreset"])
        task_id = get_task_manager().submit_task(cmd)
        return TaskResponse(
            status="ok",
            message="Sysvol ACL reset started",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except Exception as exc:
        logger.error("Failed to submit sysvolreset task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit sysvolreset task: {exc}",
        )


# ── Diagnostic utilities ───────────────────────────────────────────────


@router.get("/testparm", summary="Test configuration")
async def testparm(
    api_key: ApiKeyDep,
) -> TaskResponse:
    """Test the Samba configuration file for correctness.

    Because testparm can be slow on large configurations, it is
    dispatched as a background task.  Returns a task ID that can
    be polled for status and results.

    Note: ``samba-tool testparm`` does NOT support ``-H``, ``-U``, or
    ``--configfile``; the unified command builder automatically omits
    them based on the capability sets.
    """
    try:
        cmd = build_samba_command_deep(["testparm"])
        task_id = get_task_manager().submit_task(cmd, timeout=600)
        return TaskResponse(
            status="ok",
            message="Testparm check started",
            task_id=task_id,
            result_url=f"/api/v1/tasks/{task_id}",
        )
    except Exception as exc:
        logger.error("Failed to submit testparm task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit testparm task: {exc}",
        )


@router.get("/processes", summary="List Samba processes")
async def list_processes(
    api_key: ApiKeyDep,
) -> dict:
    """List all running Samba processes.

    Note: ``samba-tool processes`` does NOT support ``-H``, ``-U``, or
    ``--configfile``; the unified command builder automatically omits
    them.
    """
    try:
        cmd = build_samba_command_deep(["processes"])
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error("Failed to list Samba processes: %s", exc)
        raise_classified_error(exc)


@router.get("/time", summary="Get server time")
async def get_server_time(
    api_key: ApiKeyDep,
    server: Optional[str] = Query(
        default=None,
        description="Server hostname to query time from. Defaults to configured SAMBA_SERVER.",
    ),
) -> dict:
    """Get the current server time from the domain controller.

    Note: ``samba-tool time`` does NOT support ``-H``, ``-U``, or
    ``--configfile``; the unified command builder automatically omits
    them.  The server can be specified as a query parameter; if
    omitted, the configured SAMBA_SERVER is used.

    If ``samba-tool time`` fails (e.g. SRVSVC pipe unavailable on
    domain member servers, NT_STATUS_UNSUCCESSFUL), this endpoint
    tries multiple fallbacks in order:

    1. ``samba-tool domain info`` via CLDAP — lightweight protocol that
       works without SRVSVC pipe and returns the DC's current time.
    2. ``ldbsearch`` to read ``currentTime`` from the LDAP root DSE.
    3. System clock as last resort.

    v1.2.6 fix: Explicitly detect ``NT_STATUS_UNSUCCESSFUL`` (error code
    3221225473) from ``samba-tool time`` and immediately fall through to
    CLDAP/ldbsearch fallbacks instead of letting the error propagate as
    HTTP 500.  Also improved error handling so that fallback methods
    always receive a chance to succeed even when the primary method
    raises an uncaught RuntimeError.

    v1.2.9 fix: Added ``ldbsearch -H tdb://`` as the PRIMARY method
    (Method 0).  This reads ``currentTime`` directly from ``sam.ldb``
    via TDB file access — no RPC, no LDAP authentication, <0.1s.
    It works even when SRVSVC pipe is down and NetBIOS is disabled.
    ``samba-tool time`` is now the second fallback (was primary).
    """
    settings = get_settings()
    srv = server or settings.SERVER

    # ── Method 0 (v1.2.9): ldbsearch -H tdb:// — PRIMARY ─────────────
    # Reads currentTime directly from sam.ldb via TDB file access.
    # No RPC, no LDAP auth, <0.1s. Works even when SRVSVC is down.
    try:
        from app.executor import get_tdb_url
        import asyncio as _asyncio
        import re as _re

        tdb_url = get_tdb_url(settings)
        if tdb_url:
            proc = await _asyncio.create_subprocess_exec(
                settings.LDBSEARCH_PATH, "-H", tdb_url,
                "-b", "", "-s", "base", "currentTime",
                stdout=_asyncio.subprocess.PIPE,
                stderr=_asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await _asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode == 0:
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                for line in stdout.splitlines():
                    if line.startswith("currentTime:"):
                        raw_time = line.split(":", 1)[1].strip()
                        # Parse LDAP Generalized Time (YYYYMMDDHHMMSS.0Z) to ISO 8601
                        m = _re.match(r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})', raw_time)
                        if m:
                            import datetime as _dt
                            dt = _dt.datetime(
                                int(m.group(1)), int(m.group(2)), int(m.group(3)),
                                int(m.group(4)), int(m.group(5)), int(m.group(6)),
                                tzinfo=_dt.timezone.utc,
                            )
                            return {
                                "status": "ok",
                                "source": "ldbsearch_tdb",
                                "data": {"output": dt.isoformat(), "raw": raw_time},
                            }
                        return {
                            "status": "ok",
                            "source": "ldbsearch_tdb",
                            "data": {"output": raw_time},
                        }
            logger.debug("ldbsearch tdb:// currentTime failed, falling through")
    except Exception as e:
        logger.debug("ldbsearch tdb:// time error: %s", e)

    # Method 1: samba-tool time (uses SRVSVC pipe)
    # v1.2.6 fix: Wrap in explicit try/except and detect
    # NT_STATUS_UNSUCCESSFUL / SRVSVC pipe failures to trigger fallback.
    try:
        cmd = build_samba_command_deep(["time"], positionals=[srv])
        result = await execute_samba_command(cmd)
        return {"status": "ok", "source": "samba-tool time", "data": result}
    except RuntimeError as exc:
        exc_msg = str(exc)
        exc_lower = exc_msg.lower()
        # v1.2.6: Detect SRVSVC / NT_STATUS_UNSUCCESSFUL and log at
        # INFO level (not WARNING) since fallback is expected.
        if ("nt_status_unsuccessful" in exc_lower
                or "srvsvc" in exc_lower
                or "connection to" in exc_lower and "pipe" in exc_lower):
            logger.info(
                "samba-tool time SRVSVC unavailable (expected on some configs), "
                "falling through to CLDAP/ldbsearch: %s",
                exc_msg[:200],
            )
        else:
            logger.warning("samba-tool time failed: %s", exc_msg[:200])

    # Method 2 (Fix v3-15): samba-tool domain info via CLDAP.
    # This is a lightweight protocol that doesn't require SRVSVC pipe
    # and always works when port 389 is accessible.  It returns the
    # DC's current time among other domain information.
    try:
        # Determine IP: use server name resolution or 127.0.0.1 for local
        ip_target = srv
        # If srv is a hostname like "localhost", try resolving it
        if srv in ("localhost", "127.0.0.1"):
            ip_target = "127.0.0.1"
        cmd = build_samba_command_deep(["domain", "info"], positionals=[ip_target])
        result = await execute_samba_command(cmd, timeout=30)
        output = result.get("output", "")
        if output:
            # Parse the output for time-related fields
            for line in output.splitlines():
                line_lower = line.lower()
                if "time" in line_lower and ":" in line:
                    time_val = line.split(":", 1)[1].strip()
                    return {
                        "status": "ok",
                        "source": "cldap_domain_info",
                        "data": {"output": time_val},
                    }
        # If we got here, domain info worked but no time field found.
        # Return whatever we got.
        if result:
            return {
                "status": "ok",
                "source": "cldap_domain_info",
                "data": result,
            }
    except RuntimeError as exc:
        logger.warning("CLDAP domain info fallback for time failed: %s", exc)
    except Exception as exc:
        logger.warning("CLDAP domain info fallback error: %s", exc)

    # Method 3: ldbsearch to LDAP root DSE
    try:
        ldapi_url = get_ldapi_url(settings)
        ldap_url = ldapi_url or settings.LDAP_URL
        if ldap_url:
            import subprocess
            result_fb = subprocess.run(
                ["ldbsearch", "-H", ldap_url,
                 "-s", "base", "-b", "",
                 "currentTime"],
                capture_output=True, text=True, timeout=20,
            )
            if result_fb.returncode == 0:
                for line in result_fb.stdout.splitlines():
                    if line.startswith("currentTime:"):
                        time_val = line.split(":", 1)[1].strip()
                        return {
                            "status": "ok",
                            "source": "ldap_rootdse_fallback",
                            "data": {"output": time_val},
                        }
            logger.warning(
                "ldbsearch fallback failed (rc=%d): %s",
                result_fb.returncode,
                result_fb.stderr.strip()[:200],
            )
    except FileNotFoundError:
        logger.warning("ldbsearch not found for time fallback")
    except Exception as fb_exc:
        logger.warning("LDAP time fallback also failed: %s", fb_exc)

    # Method 4: system clock as last resort
    import datetime
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return {
        "status": "ok",
        "source": "system_clock_fallback",
        "data": {"output": now.strftime("%a %b %d %H:%M:%S UTC %Y")},
        "warning": "All time retrieval methods (samba-tool time, CLDAP, ldbsearch) failed; using system clock",
    }


# ── SPN operations ─────────────────────────────────────────────────────


@router.get("/spn/list", summary="List SPNs")
async def list_spns(
    accountname: str,
    api_key: ApiKeyDep,
) -> dict:
    """List Service Principal Names for an account.

    Note: ``samba-tool spn list`` expects the account name as a
    positional argument, not via ``--accountname``.

    Fix v7-4: Removed --json flag.  samba-tool spn list does NOT
    support --json output.  The command was previously in
    JSON_CAPABLE_COMMANDS, causing "no such option: --json" errors.
    """
    try:
        # Fix v7-4: Do NOT pass --json — spn list doesn't support it.
        # The auto-mode in executor.py will also strip it since
        # "spn list" is no longer in JSON_COMMANDS_WHITELIST.
        cmd = build_samba_command_deep(
            ["spn", "list"], positionals=[accountname],
        )
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error(
            "Failed to list SPNs for '%s': %s", accountname, exc
        )
        raise_classified_error(exc)


@router.post("/spn/add", summary="Add SPN", status_code=status.HTTP_201_CREATED)
async def add_spn(
    body: SpnRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Add a Service Principal Name to an account.

    Note: ``samba-tool spn add <name> <user>`` expects both arguments
    as positional.
    """
    try:
        cmd = build_samba_command_deep(
            ["spn", "add"], positionals=[body.spn, body.accountname],
        )
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"SPN '{body.spn}' added to '{body.accountname}'",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to add SPN '%s' to '%s': %s",
            body.spn,
            body.accountname,
            exc,
        )
        raise_classified_error(exc)


@router.delete("/spn/delete", summary="Delete SPN")
async def delete_spn(
    body: SpnRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Delete a Service Principal Name from an account.

    Note: ``samba-tool spn delete <name> <user>`` expects both arguments
    as positional.
    """
    try:
        cmd = build_samba_command_deep(
            ["spn", "delete"], positionals=[body.spn, body.accountname],
        )
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"SPN '{body.spn}' deleted from '{body.accountname}'",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to delete SPN '%s' from '%s': %s",
            body.spn,
            body.accountname,
            exc,
        )
        raise_classified_error(exc)
