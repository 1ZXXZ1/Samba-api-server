"""
FastAPI router for user operations.

Every endpoint requires API-key authentication via ``ApiKeyDep``.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``list_users``  → ``fetch_users()`` (ldbsearch)
- ``show_user``   → ``fetch_user_by_name()`` (ldbsearch)
- ``getgroups``   → ``fetch_user_groups()`` (ldbsearch)
Write operations still use samba-tool.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import build_samba_command, clear_ldapi_cache, clear_tdb_cache, execute_samba_command, execute_samba_command_raw, get_ldapi_url, get_tdb_url, raise_classified_error

import os
import urllib.parse
from app.models.user import (
    UserAddUnixAttrsRequest,
    UserCreateRequest,
    UserPasswordRequest,
    UserSensitiveRequest,
    UserSetExpiryRequest,
    UserUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])


# ── Helpers ────────────────────────────────────────────────────────────


def _get_ldb_cache_key(resource: str) -> str:
    """Build a cache key for ldb_reader full endpoint responses."""
    return f"GET:/api/v1/{resource}/full:none"

def _clean_args(args: dict[str, Any]) -> dict[str, Any]:
    """Remove keys whose values are *None* or empty strings."""
    return {k: v for k, v in args.items() if v is not None and v != ""}


# ── List users (fast, via ldbsearch) ──────────────────────────────────

@router.get("/", summary="List users")
async def list_users(
    _: ApiKeyDep,
    verbose: Optional[bool] = Query(default=None, description="Verbose output (ignored, always full)"),
    base_dn: Optional[str] = Query(default=None, description="Base DN for search (ignored)"),
    full_dn: Optional[bool] = Query(default=None, description="Show full DNs (ignored, always included)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> Dict[str, Any]:
    """List all user accounts in the domain via ldbsearch.

    v1.2.3_fix: Now uses the fast ldbsearch backend instead of
    ``samba-tool user list``.  Returns full LDAP attribute data
    for every user (same as the ``/full`` endpoint).

    Query parameters ``verbose``, ``base_dn``, ``full_dn``, and ``H``
    are accepted for backward compatibility but are ignored — ldbsearch
    always returns all attributes with full DNs.
    """
    from app.ldb_reader import fetch_users
    from app.cache import get_cache

    cache = get_cache()
    cache_key = _get_ldb_cache_key("users")
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_users()
    result = {"status": "ok", "users": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── Full users (fast, via ldbsearch) ──────────────────────────────────

@router.get("/full", summary="Get all users (fast, via ldbsearch)")
async def list_users_full(_auth: ApiKeyDep) -> Dict[str, Any]:
    """Return all user objects with full attributes via ldbsearch.

    This endpoint uses the fast ``ldbsearch`` backend instead of
    ``samba-tool``, returning complete LDAP attribute data for every
    user in a single query.  Results are cached for 30 seconds.
    """
    from app.ldb_reader import fetch_users
    from app.cache import get_cache

    cache = get_cache()
    cache_key = _get_ldb_cache_key("users")
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_users()
    result = {"status": "ok", "users": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── Create user ────────────────────────────────────────────────────────

@router.post("/", summary="Create user", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Create a new user account.

    Fix v22/v23: Attempts direct SamDB API call first (fast path, ~1-2s).
    Falls back to samba-tool subprocess if the samba Python package
    is not available or the direct call fails.

    Fix v23 Method 1: Direct SamDB write operations now use ldapi://
    with authentication credentials (either explicit Credentials from
    SAMBA_CREDENTIALS_USER/PASSWORD or system_session for root).
    This resolves the LDAP_OPERATIONS_ERROR that previously blocked
    writes in ProcessPoolExecutor workers.
    """
    # Fix v23 Method 1: Direct SamDB write operations are RE-ENABLED
    # with proper authentication via ldapi:// + creds/session_info.
    try:
        from app.samdb_direct import is_samba_available, async_user_create
        if is_samba_available():
            try:
                result = await async_user_create(
                    username=body.username,
                    password=body.password,
                    userou=body.userou,
                    surname=body.surname,
                    given_name=body.given_name,
                    initials=body.initials,
                    profile_path=body.profile_path,
                    script_path=body.script_path,
                    home_drive=body.home_drive,
                    home_directory=body.home_directory,
                    job_title=body.job_title,
                    department=body.department,
                    company=body.company,
                    description=body.description,
                    mail_address=body.mail_address,
                    internet_address=body.internet_address,
                    telephone_number=body.telephone_number,
                    physical_delivery_office=body.physical_delivery_office,
                    must_change_at_next_login=body.must_change_at_next_login or False,
                    use_username_as_cn=body.use_username_as_cn or False,
                    random_password=body.random_password or False,
                    smartcard_required=body.smartcard_required or False,
                    uid_number=body.uid_number,
                    gid_number=body.gid_number,
                    gecos=body.gecos,
                    login_shell=body.login_shell,
                    uid=body.uid,
                    nis_domain=body.nis_domain,
                    unix_home=body.unix_home,
                )
                logger.info("User '%s' created via direct SamDB API", body.username)
                return result
            except RuntimeError as direct_exc:
                direct_msg = str(direct_exc).lower()
                if "already exist" in direct_msg or "already exists" in direct_msg or "already a" in direct_msg:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"User '{body.username}' already exists: {direct_exc}",
                    ) from direct_exc
                logger.debug(
                    "Direct SamDB user create not available, using samba-tool: %s",
                    direct_exc,
                )
    except ImportError:
        pass

    # Fallback: samba-tool subprocess
    args: dict[str, Any] = _clean_args({
        "--must-change-at-next-login": body.must_change_at_next_login or None,
        "--random-password": body.random_password or None,
        "--smartcard-required": body.smartcard_required or None,
        "--use-username-as-cn": body.use_username_as_cn or None,
        "--userou": body.userou,
        "--surname": body.surname,
        "--given-name": body.given_name,
        "--initials": body.initials,
        "--profile-path": body.profile_path,
        "--script-path": body.script_path,
        "--home-drive": body.home_drive,
        "--home-directory": body.home_directory,
        "--job-title": body.job_title,
        "--department": body.department,
        "--company": body.company,
        "--description": body.description,
        "--mail-address": body.mail_address,
        "--internet-address": body.internet_address,
        "--telephone-number": body.telephone_number,
        "--physical-delivery-office": body.physical_delivery_office,
        "--rfc2307-from-nss": body.rfc2307_from_nss or None,
        "--nis-domain": body.nis_domain,
        "--unix-home": body.unix_home,
        "--uid": body.uid,
        "--uid-number": body.uid_number,
        "--gid-number": body.gid_number,
        "--gecos": body.gecos,
        "--login-shell": body.login_shell,
    })

    positionals = [body.username]
    if body.password is not None:
        positionals.append(body.password)

    cmd = build_samba_command("user", "add", args, positionals=positionals)

    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Show user (fast, via ldbsearch) ───────────────────────────────────

@router.get("/{username}", summary="Show user details")
async def show_user(
    username: str,
    _: ApiKeyDep,
    attributes: Optional[str] = Query(
        default=None, description="Comma-separated list of attributes to show (ignored, all returned)",
    ),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> Dict[str, Any]:
    """Display details for a single user account via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool user show``.
    Returns all LDAP attributes for the user object.

    The ``attributes`` and ``H`` query parameters are accepted for
    backward compatibility but are ignored — ldbsearch always returns
    all attributes.
    """
    from app.ldb_reader import fetch_user_by_name

    data = await fetch_user_by_name(username)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )
    return {"status": "ok", "user": data}


# ── Edit user ──────────────────────────────────────────────────────────

# REMOVED: The `samba-tool user edit` sub-command opens an interactive editor
# (e.g. vi) and does NOT support flag-based attribute modifications.


# ── Delete user ────────────────────────────────────────────────────────

@router.delete("/{username}", summary="Delete user")
async def delete_user(
    username: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Delete a user account from the domain.

    Fix v22/v23: Attempts direct SamDB API call first (fast path, ~1s).
    Falls back to samba-tool subprocess if the samba Python package
    is not available or the direct call fails.
    """
    try:
        from app.samdb_direct import is_samba_available, async_user_delete
        if is_samba_available():
            try:
                result = await async_user_delete(username)
                logger.info("User '%s' deleted via direct SamDB API", username)
                return result
            except RuntimeError as direct_exc:
                logger.debug(
                    "Direct SamDB user delete not available, using samba-tool: %s",
                    direct_exc,
                )
    except ImportError:
        pass

    cmd = build_samba_command("user", "delete", {}, positionals=[username])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Enable user ────────────────────────────────────────────────────────

@router.post("/{username}/enable", summary="Enable user")
async def enable_user(
    username: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Enable a disabled user account."""
    try:
        from app.samdb_direct import is_samba_available, async_user_enable
        if is_samba_available():
            try:
                result = await async_user_enable(username)
                logger.info("User '%s' enabled via direct SamDB API", username)
                return result
            except RuntimeError as direct_exc:
                logger.debug(
                    "Direct SamDB user enable not available, using samba-tool: %s",
                    direct_exc,
                )
    except ImportError:
        pass

    cmd = build_samba_command("user", "enable", {}, positionals=[username])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Disable user ───────────────────────────────────────────────────────

@router.post("/{username}/disable", summary="Disable user")
async def disable_user(
    username: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Disable a user account."""
    try:
        from app.samdb_direct import is_samba_available, async_user_disable
        if is_samba_available():
            try:
                result = await async_user_disable(username)
                logger.info("User '%s' disabled via direct SamDB API", username)
                return result
            except RuntimeError as direct_exc:
                logger.debug(
                    "Direct SamDB user disable not available, using samba-tool: %s",
                    direct_exc,
                )
    except ImportError:
        pass

    cmd = build_samba_command("user", "disable", {}, positionals=[username])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Unlock user ────────────────────────────────────────────────────────

@router.post("/{username}/unlock", summary="Unlock user")
async def unlock_user(
    username: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Unlock a locked user account."""
    try:
        from app.samdb_direct import is_samba_available, async_user_unlock
        if is_samba_available():
            try:
                result = await async_user_unlock(username)
                logger.info("User '%s' unlocked via direct SamDB API", username)
                return result
            except RuntimeError as direct_exc:
                logger.debug(
                    "Direct SamDB user unlock not available, using samba-tool: %s",
                    direct_exc,
                )
    except ImportError:
        pass

    cmd = build_samba_command("user", "unlock", {}, positionals=[username])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Set password ───────────────────────────────────────────────────────

@router.put("/{username}/password", summary="Set user password")
async def set_password(
    username: str,
    body: UserPasswordRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Set or reset a user's password."""
    try:
        from app.samdb_direct import is_samba_available, async_user_setpassword
        if is_samba_available():
            try:
                result = await async_user_setpassword(
                    username,
                    body.new_password,
                    must_change_at_next_login=body.must_change_at_next_login or False,
                )
                logger.info("Password set for user '%s' via direct SamDB API", username)
                return result
            except RuntimeError as direct_exc:
                logger.debug(
                    "Direct SamDB set password not available, using samba-tool: %s",
                    direct_exc,
                )
    except ImportError:
        pass

    args: dict[str, Any] = {
        "--newpassword": body.new_password,
    }
    if body.must_change_at_next_login:
        args["--must-change-at-next-login"] = True
    cmd = build_samba_command("user", "setpassword", args, positionals=[username])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Get user groups (fast, via ldbsearch) ─────────────────────────────

@router.get("/{username}/groups", summary="Get user groups")
async def get_user_groups(
    username: str,
    _: ApiKeyDep,
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> Dict[str, Any]:
    """List groups that the user belongs to via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool user getgroups``.
    Returns the user's ``memberOf`` attribute as a list of DNs.
    """
    from app.ldb_reader import fetch_user_groups, fetch_user_by_name

    # First verify user exists
    user = await fetch_user_by_name(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )

    groups = await fetch_user_groups(username)
    return {"status": "ok", "username": username, "groups": groups}


# ── Set expiry ─────────────────────────────────────────────────────────

@router.put("/{username}/setexpiry", summary="Set user account expiry")
async def set_expiry(
    username: str,
    body: UserSetExpiryRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Set the number of days until a user account expires."""
    args: dict[str, Any] = {"--days": body.days}
    cmd = build_samba_command("user", "setexpiry", args, positionals=[username])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Set primary group ──────────────────────────────────────────────────

class _SetPrimaryGroupBody(BaseModel):
    groupname: str


@router.put("/{username}/setprimarygroup", summary="Set user primary group")
async def set_primary_group(
    username: str,
    body: _SetPrimaryGroupBody,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Change the primary group for a user account."""
    cmd = build_samba_command("user", "setprimarygroup", {}, positionals=[username, body.groupname])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Add Unix attributes ────────────────────────────────────────────────

@router.post("/{username}/addunixattrs", summary="Add Unix attributes to user")
async def add_unix_attrs(
    username: str,
    body: UserAddUnixAttrsRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Add RFC 2307 Unix attributes to a user account."""
    args: dict[str, Any] = _clean_args({
        "--gid-number": body.gid_number,
        "--unix-home": body.unix_home,
        "--login-shell": body.login_shell,
        "--gecos": body.gecos,
        "--nis-domain": body.nis_domain,
        "--uid": body.uid,
    })
    positionals = [username, str(body.uid_number)]
    cmd = build_samba_command("user", "addunixattrs", args, positionals=positionals)
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Set sensitive flag ─────────────────────────────────────────────────

@router.put("/{username}/sensitive", summary="Set sensitive flag on user")
async def set_sensitive(
    username: str,
    body: UserSensitiveRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Mark or unmark a user account as sensitive (not delegatable)."""
    cmd = build_samba_command(
        "user", "sensitive", {}, positionals=[username, "on" if body.on else "off"]
    )
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Move user ──────────────────────────────────────────────────────────

class _MoveUserBody(BaseModel):
    new_parent_dn: str


@router.post("/{username}/move", summary="Move user to a new OU")
async def move_user(
    username: str,
    body: _MoveUserBody,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Move a user account to a different organizational unit."""
    cmd = build_samba_command("user", "move", {}, positionals=[username, body.new_parent_dn])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Rename user ────────────────────────────────────────────────────────

class _RenameUserBody(BaseModel):
    new_name: str


@router.post("/{username}/rename", summary="Rename user")
async def rename_user(
    username: str,
    body: _RenameUserBody,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Rename a user account.

    samba-tool user rename <username> --samaccountname=<new_name>
    """
    cmd = build_samba_command(
        "user", "rename",
        {"--samaccountname": body.new_name},
        positionals=[username],
    )
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Get password ───────────────────────────────────────────────────────

@router.get("/{username}/getpassword", summary="Get user password")
async def get_password(
    username: str,
    _: ApiKeyDep,
    attributes: Optional[str] = Query(
        default="virtualClearTextUTF16",
        description="Comma-separated password attributes to retrieve",
    ),
) -> Dict[str, Any]:
    """Retrieve the password for a user account (requires elevated privileges).

    This endpoint still uses samba-tool because it needs tdb:// access
    for password retrieval, which ldbsearch does not support.
    """
    settings = get_settings()

    clear_tdb_cache()
    tdb_url = get_tdb_url(settings)
    
    if not tdb_url:
        server_role = settings.ensure_server_role()
        if "domain controller" not in server_role and "active directory" not in server_role and server_role != "unknown":
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=(
                    f"getpassword is only available on a Domain Controller. "
                    f"This server has role '{server_role}'."
                ),
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "No sam.ldb found for tdb:// access. Password attributes "
                "require direct sam.ldb access via tdb://."
            ),
        )
    args: dict[str, Any] = {"--attributes": attributes, "-H": tdb_url}
    logger.info("getpassword: using TDB URL: %s", tdb_url)

    cmd = build_samba_command("user", "getpassword", args, positionals=[username])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        exc_msg = str(exc).lower()
        if "ldap_operations_error" in exc_msg or "operation unavailable without authentication" in exc_msg:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"getpassword failed with an LDAP operations error. "
                    f"Original error: {exc}"
                ),
            ) from exc
        raise_classified_error(exc)


# ── Get Kerberos ticket ────────────────────────────────────────────────

@router.get(
    "/{username}/get-kerberos-ticket",
    summary="Get Kerberos ticket for user",
)
async def get_kerberos_ticket(
    username: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Retrieve a Kerberos ticket for a user account.

    This endpoint still uses samba-tool because it needs to contact
    the KDC to issue the ticket, which ldbsearch cannot do.
    """
    settings = get_settings()

    if not settings.CREDENTIALS_USER or not settings.CREDENTIALS_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "get-kerberos-ticket requires -U credentials to contact the KDC. "
                "Set CREDENTIALS_USER and CREDENTIALS_PASSWORD in environment."
            ),
        )

    import tempfile
    tmp_ccache = tempfile.mktemp(suffix='.ccache')
    args: dict[str, Any] = {"--output-krb5-ccache": tmp_ccache}
    logger.info("get-kerberos-ticket: using -U credentials (no -H tdb://)")

    cmd = build_samba_command("user", "get-kerberos-ticket", args, positionals=[username])
    try:
        result = await execute_samba_command(cmd)
        try:
            import os as _os
            if _os.path.exists(tmp_ccache):
                with open(tmp_ccache, "rb") as f:
                    ccache_data = f.read()
                import base64
                result["krb5_ccache_base64"] = base64.b64encode(ccache_data).decode("ascii")
                result["krb5_ccache_path"] = tmp_ccache
                _os.unlink(tmp_ccache)
        except Exception as ccache_err:
            logger.warning("Failed to read/clean ccache file %s: %s", tmp_ccache, ccache_err)
        return result
    except RuntimeError as exc:
        exc_msg = str(exc).lower()
        if "cannot contact any kdc" in exc_msg:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"get-kerberos-ticket: Cannot contact any KDC. "
                    f"Original error: {exc}"
                ),
            ) from exc
        if "ldap_operations_error" in exc_msg or "operation unavailable without authentication" in exc_msg:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"get-kerberos-ticket failed with an LDAP operations error. "
                    f"Original error: {exc}"
                ),
            ) from exc
        raise_classified_error(exc)
