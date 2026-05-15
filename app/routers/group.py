"""
FastAPI router for group operations.

Every endpoint requires API-key authentication via ``ApiKeyDep``.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``list_groups``    → ``fetch_groups()`` (ldbsearch)
- ``group_stats``    → ``fetch_group_stats()`` (ldbsearch)
- ``show_group``     → ``fetch_group_by_name()`` (ldbsearch)
- ``list_members``   → ``fetch_group_members()`` (ldbsearch)
Write operations still use samba-tool.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.executor import build_samba_command, execute_samba_command, execute_samba_command_raw, raise_classified_error
from app.models.group import (
    GroupCreateRequest,
    GroupMembersRequest,
    GroupMoveRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/groups", tags=["Groups"])


# ── Helpers ────────────────────────────────────────────────────────────

def _clean_args(args: dict[str, Any]) -> dict[str, Any]:
    """Remove keys whose values are *None* or empty strings."""
    return {k: v for k, v in args.items() if v is not None and v != ""}


def _decode_member_dn(value: str) -> str:
    """Decode a member DN that may be Base64-encoded.

    Fix v1.6.2: Some frontends send LDAP DN values as Base64-encoded
    strings (e.g. from LDIF ``attribute:: base64_value`` lines).
    samba-tool expects plain DN strings like
    ``CN=User,CN=Users,DC=kcrb,DC=local``, not Base64.

    This function detects Base64-encoded DNs and decodes them.
    A value is considered Base64 if:
    - It does NOT contain ``=`` or ``,`` (which are present in real DNs)
    - It passes base64 decoding and the result looks like a DN
      (starts with ``CN=``, ``OU=``, or ``DC=``)
    """
    import base64 as _b64

    if not value:
        return value

    # If the value already looks like a DN, return as-is
    if "=" in value and ("," in value or value.startswith(("CN=", "OU=", "DC="))):
        return value

    # Try Base64 decode
    try:
        decoded = _b64.b64decode(value).decode("utf-8")
        if decoded.startswith(("CN=", "OU=", "DC=")):
            return decoded
    except Exception:
        pass

    # Not Base64 or decode failed — return as-is
    return value


def _decode_member_list(members: list[str]) -> list[str]:
    """Decode a list of member identifiers, handling Base64-encoded DNs.

    Fix v1.6.2: Applies _decode_member_dn to each member in the list.
    """
    return [_decode_member_dn(m) for m in members]


# ── Full groups (fast, via ldbsearch) ─────────────────────────────────

@router.get("/full", summary="Get all groups (fast, via ldbsearch)")
async def list_groups_full(_auth: ApiKeyDep) -> Dict[str, Any]:
    """Return all group objects with full attributes via ldbsearch."""
    from app.ldb_reader import fetch_groups
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/groups/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_groups()
    result = {"status": "ok", "groups": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── List groups (fast, via ldbsearch) ─────────────────────────────────

@router.get("/", summary="List groups")
async def list_groups(
    _: ApiKeyDep,
    verbose: Optional[bool] = Query(default=None, description="Verbose output (ignored, always full)"),
    base_dn: Optional[str] = Query(default=None, description="Base DN for search (ignored)"),
    full_dn: Optional[bool] = Query(default=None, description="Show full DNs (ignored)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> Dict[str, Any]:
    """List all groups in the domain via ldbsearch.

    v1.2.3_fix: Now uses the fast ldbsearch backend instead of
    ``samba-tool group list``.  Returns full LDAP attribute data.
    Query parameters are accepted for backward compatibility but ignored.
    """
    from app.ldb_reader import fetch_groups
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/groups/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_groups()
    result = {"status": "ok", "groups": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── Create group ───────────────────────────────────────────────────────

@router.post("/", summary="Create group", status_code=status.HTTP_201_CREATED)
async def create_group(
    body: GroupCreateRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Create a new group in the domain."""
    args: dict[str, Any] = _clean_args({
        "--groupou": body.groupou,
        "--group-scope": body.group_scope,
        "--group-type": body.group_type,
        "--description": body.description,
        "--mail-address": body.mail_address,
        "--notes": body.notes,
        "--gid-number": body.gid_number,
        "--nis-domain": body.nis_domain,
        "--special": body.special or None,
    })
    cmd = build_samba_command("group", "add", args, positionals=[body.groupname])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Group stats (fast, via ldbsearch) ─────────────────────────────────

@router.get("/stats", summary="Group statistics")
async def group_stats(
    _: ApiKeyDep,
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> Dict[str, Any]:
    """Display group statistics for the domain via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch to compute group statistics
    instead of ``samba-tool group stats``.
    """
    from app.ldb_reader import fetch_group_stats

    data = await fetch_group_stats()
    return {"status": "ok", "stats": data}


# ── Show group (fast, via ldbsearch) ──────────────────────────────────

@router.get("/{groupname}", summary="Show group details")
async def show_group(
    groupname: str,
    _: ApiKeyDep,
    attributes: Optional[str] = Query(
        default=None, description="Comma-separated list of attributes (ignored, all returned)",
    ),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> Dict[str, Any]:
    """Display details for a single group via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool group show``.
    Returns all LDAP attributes for the group object.
    """
    from app.ldb_reader import fetch_group_by_name

    data = await fetch_group_by_name(groupname)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group '{groupname}' not found",
        )
    return {"status": "ok", "group": data}


# ── Delete group ───────────────────────────────────────────────────────

@router.delete("/{groupname}", summary="Delete group")
async def delete_group(
    groupname: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Delete a group from the domain."""
    cmd = build_samba_command("group", "delete", {}, positionals=[groupname])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Add members ────────────────────────────────────────────────────────

@router.post("/{groupname}/members", summary="Add members to group")
async def add_members(
    groupname: str,
    body: GroupMembersRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Add one or more members to a group."""
    args: dict[str, Any] = _clean_args({
        "--object-types": body.object_types if body.object_types != "user,group,computer" else None,
        "--member-base-dn": body.member_base_dn,
    })

    # Fix v1.6.2: Decode Base64-encoded member DNs before passing to
    # samba-tool. Frontends may send DNs as Base64 from LDIF output.
    decoded_member_dn = _decode_member_list(body.member_dn) if body.member_dn else None
    if decoded_member_dn:
        for dn in decoded_member_dn:
            args[f"--member-dn={dn}"] = True

    decoded_members = _decode_member_list(list(body.members))
    positionals = [groupname] + decoded_members
    cmd = build_samba_command("group", "addmembers", args, positionals=positionals)

    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── Remove members ─────────────────────────────────────────────────────

@router.delete("/{groupname}/members", summary="Remove members from group")
async def remove_members(
    groupname: str,
    body: GroupMembersRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Remove one or more members from a group."""
    args: dict[str, Any] = _clean_args({
        "--object-types": body.object_types if body.object_types != "user,group,computer" else None,
        "--member-base-dn": body.member_base_dn,
    })

    # Fix v1.6.2: Decode Base64-encoded member DNs before passing to
    # samba-tool. Frontends may send DNs as Base64 from LDIF output.
    decoded_member_dn = _decode_member_list(body.member_dn) if body.member_dn else None
    if decoded_member_dn:
        for dn in decoded_member_dn:
            args[f"--member-dn={dn}"] = True

    decoded_members = _decode_member_list(list(body.members))
    positionals = [groupname] + decoded_members
    cmd = build_samba_command("group", "removemembers", args, positionals=positionals)

    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)


# ── List members (fast, via ldbsearch) ────────────────────────────────

@router.get("/{groupname}/members", summary="List group members")
async def list_members(
    groupname: str,
    _: ApiKeyDep,
    hide_expired: Optional[bool] = Query(
        default=None, description="Hide expired members (ignored)",
    ),
    hide_disabled: Optional[bool] = Query(
        default=None, description="Hide disabled members (ignored)",
    ),
    full_dn: Optional[bool] = Query(
        default=None, description="Show full DNs (ignored, always included)",
    ),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> Dict[str, Any]:
    """List all members of a group via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool group listmembers``.
    Returns the group's ``member`` attribute as a list of DNs.
    """
    from app.ldb_reader import fetch_group_members, fetch_group_by_name

    # First verify group exists
    group = await fetch_group_by_name(groupname)
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group '{groupname}' not found",
        )

    members = await fetch_group_members(groupname)
    return {"status": "ok", "groupname": groupname, "members": members}


# ── Move group ─────────────────────────────────────────────────────────

@router.post("/{groupname}/move", summary="Move group to a new OU")
async def move_group(
    groupname: str,
    body: GroupMoveRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Move a group to a different organizational unit."""
    cmd = build_samba_command("group", "move", {}, positionals=[groupname, body.new_parent_dn])
    try:
        return await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
