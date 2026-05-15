"""
Contact management router.

v1.2.3_fix: All READ endpoints now use ldbsearch instead of samba-tool.
- ``list_contacts``  → ``fetch_contacts()`` (ldbsearch)
- ``show_contact``   → ``fetch_contact_by_name()`` (ldbsearch)
Write operations still use samba-tool.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.executor import build_samba_command, execute_samba_command, raise_classified_error
from app.models.contact import ContactCreateRequest, ContactMoveRequest, ContactRenameRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/contacts", tags=["Contacts"])


# ── Full contacts (fast, via ldbsearch) ───────────────────────────────

@router.get("/full", summary="Get all contacts (fast, via ldbsearch)")
async def list_contacts_full(_auth: ApiKeyDep) -> dict[str, Any]:
    """Return all contact objects with full attributes via ldbsearch."""
    from app.ldb_reader import fetch_contacts
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/contacts/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_contacts()
    result = {"status": "ok", "contacts": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── List contacts (fast, via ldbsearch) ───────────────────────────────

@router.get("/", summary="List contacts")
async def list_contacts(
    _: ApiKeyDep,
    base_dn: Optional[str] = Query(default=None, description="Base DN (ignored)"),
    full_dn: bool = Query(default=False, description="Show full DNs (ignored)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> dict[str, Any]:
    """List all contacts via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool contact list``.
    Query parameters are accepted for backward compatibility but ignored.
    """
    from app.ldb_reader import fetch_contacts
    from app.cache import get_cache

    cache = get_cache()
    cache_key = "GET:/api/v1/contacts/full:none"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    data = await fetch_contacts()
    result = {"status": "ok", "contacts": data}
    cache.set(cache_key, result, ttl=30)
    return result


# ── Create contact ─────────────────────────────────────────────────────

@router.post("/", summary="Create a contact", status_code=status.HTTP_201_CREATED)
async def create_contact(_: ApiKeyDep, body: ContactCreateRequest) -> dict[str, Any]:
    """Create a new contact in the domain."""
    args: dict[str, Any] = {}
    if body.ou is not None: args["--ou"] = body.ou
    if body.surname is not None: args["--surname"] = body.surname
    if body.given_name is not None: args["--given-name"] = body.given_name
    if body.initials is not None: args["--initials"] = body.initials
    if body.display_name is not None: args["--display-name"] = body.display_name
    if body.description is not None: args["--description"] = body.description
    if body.mail_address is not None: args["--mail-address"] = body.mail_address
    if body.telephone_number is not None: args["--telephone-number"] = body.telephone_number
    if body.job_title is not None: args["--job-title"] = body.job_title
    if body.department is not None: args["--department"] = body.department
    if body.company is not None: args["--company"] = body.company
    if body.mobile_number is not None: args["--mobile-number"] = body.mobile_number
    if body.internet_address is not None: args["--internet-address"] = body.internet_address
    if body.physical_delivery_office is not None: args["--physical-delivery-office"] = body.physical_delivery_office

    try:
        cmd = build_samba_command("contact", "add", args, positionals=[body.contactname])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"Contact '{body.contactname}' created successfully", "data": result}


# ── Show contact (fast, via ldbsearch) ────────────────────────────────

@router.get("/{contactname}", summary="Show contact details")
async def show_contact(
    _: ApiKeyDep,
    contactname: str,
    attributes: Optional[str] = Query(default=None, description="Attributes (ignored, all returned)"),
    H: Optional[str] = Query(default=None, description="LDAP URL override (ignored)"),
) -> dict[str, Any]:
    """Retrieve the attributes of a specific contact via ldbsearch.

    v1.2.3_fix: Now uses ldbsearch instead of ``samba-tool contact show``.
    """
    from app.ldb_reader import fetch_contact_by_name

    data = await fetch_contact_by_name(contactname)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Contact '{contactname}' not found. If the contact is in a non-default OU, try using the full DN.",
        )
    return {"status": "ok", "contact": data}


# ── Delete contact ─────────────────────────────────────────────────────

@router.delete("/{contactname}", summary="Delete a contact")
async def delete_contact(_: ApiKeyDep, contactname: str) -> dict[str, Any]:
    """Delete a contact from the domain."""
    try:
        cmd = build_samba_command("contact", "delete", positionals=[contactname])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"Contact '{contactname}' deleted successfully", "data": result}


# ── Move contact ───────────────────────────────────────────────────────

@router.post("/{contactname}/move", summary="Move a contact")
async def move_contact(_: ApiKeyDep, contactname: str, body: ContactMoveRequest) -> dict[str, Any]:
    """Move a contact to a different OU."""
    try:
        cmd = build_samba_command("contact", "move", positionals=[contactname, body.new_parent_dn])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        msg = str(exc)
        if "multiple results" in msg.lower() or "multiple objects" in msg.lower():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Multiple contacts match '{contactname}'. Please specify the full DN instead.")
        raise_classified_error(exc)
    return {"status": "ok", "message": f"Contact '{contactname}' moved to '{body.new_parent_dn}'", "data": result}


# ── Rename contact ─────────────────────────────────────────────────────

@router.post("/{contactname}/rename", summary="Rename a contact")
async def rename_contact(_: ApiKeyDep, contactname: str, body: ContactRenameRequest) -> dict[str, Any]:
    """Rename a contact in the domain."""
    try:
        cmd = build_samba_command("contact", "rename", {"--force-new-cn": body.new_name}, positionals=[contactname])
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
    return {"status": "ok", "message": f"Contact '{contactname}' renamed to '{body.new_name}'", "data": result}
