"""
Service account management router for the Samba AD DC Management API.

Wraps ``samba-tool service-account *`` and
``samba-tool service-account group-msa-membership *`` commands behind
RESTful endpoints.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import build_samba_command_deep, execute_samba_command, raise_classified_error

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/service-accounts", tags=["Service Accounts"])


# ── Request models ──────────────────────────────────────────────────────


class CreateServiceAccountRequest(BaseModel):
    """Request body for creating a new service account."""

    accountname: str = Field(..., description="Name of the service account to create.")
    dns_host_name: str = Field(
        ...,
        description="DNS hostname for the service account (required by samba-tool). "
                    "Example: 'svc_krbt.kcrb.local'.",
    )
    description: Optional[str] = Field(
        None, description="Optional description for the service account."
    )


class GmsaMembersRequest(BaseModel):
    """Request body for adding or removing gMSA members."""

    members: list[str] = Field(
        ..., description="List of member account names to add or remove."
    )


# ── Service-account CRUD ───────────────────────────────────────────────


@router.get("/", summary="List service accounts")
async def list_service_accounts(
    api_key: ApiKeyDep,
) -> dict:
    """List all managed service accounts in the domain."""
    try:
        cmd = build_samba_command_deep(["service-account", "list"])
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error("Failed to list service accounts: %s", exc)
        raise_classified_error(exc)


@router.post(
    "/",
    summary="Create service account",
    status_code=status.HTTP_201_CREATED,
)
async def create_service_account(
    body: CreateServiceAccountRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Create a new managed service account.

    samba-tool service-account create --name=<name> --dns-host-name=<dns> [--description=<desc>]
    The account name is passed via the ``--name`` flag, DNS hostname via
    ``--dns-host-name``, both required by samba-tool.
    """
    try:
        args: dict = {
            "--name": body.accountname,
            "--dns-host-name": body.dns_host_name,
        }
        if body.description is not None:
            args["--description"] = body.description

        cmd = build_samba_command_deep(["service-account", "create"], args=args)
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Service account '{body.accountname}' created successfully",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to create service account '%s': %s", body.accountname, exc
        )
        raise_classified_error(exc)


@router.get("/{accountname}", summary="Show service account")
async def show_service_account(
    accountname: str,
    api_key: ApiKeyDep,
) -> dict:
    """Show detailed information about a specific service account.

    samba-tool service-account view --name=<name>
    The account name is passed via the ``--name`` flag, not as a positional.
    """
    try:
        cmd = build_samba_command_deep(["service-account", "view"], args={"--name": accountname})
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error(
            "Failed to show service account '%s': %s", accountname, exc
        )
        raise_classified_error(exc)


@router.delete("/{accountname}", summary="Delete service account")
async def delete_service_account(
    accountname: str,
    api_key: ApiKeyDep,
) -> dict:
    """Delete a managed service account.

    samba-tool service-account delete --name=<name>
    The account name is passed via the ``--name`` flag, not as a positional.
    """
    try:
        cmd = build_samba_command_deep(["service-account", "delete"], args={"--name": accountname})
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Service account '{accountname}' deleted successfully",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to delete service account '%s': %s", accountname, exc
        )
        raise_classified_error(exc)


# ── gMSA membership ────────────────────────────────────────────────────


@router.post(
    "/{accountname}/gmsa-members/add",
    summary="Add gMSA member",
    status_code=status.HTTP_201_CREATED,
)
async def add_gmsa_member(
    accountname: str,
    body: GmsaMembersRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Add members to the group Managed Service Account membership list.

    Each member is added individually via a separate
    ``samba-tool service-account group-msa-membership add`` invocation
    because the correct flags are ``--name`` (for the gMSA) and
    ``--principal`` (for each member account), and each member requires
    its own command.
    """
    try:
        results: list = []
        for member in body.members:
            args: dict = {
                "--name": accountname,
                "--principal": member,
            }
            cmd = build_samba_command_deep(
                ["service-account", "group-msa-membership", "add"], args=args
            )
            result = await execute_samba_command(cmd)
            results.append(result)
        return {
            "status": "ok",
            "message": f"Members added to gMSA '{accountname}' successfully",
            "data": results,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to add gMSA members to '%s': %s", accountname, exc
        )
        raise_classified_error(exc)


@router.delete(
    "/{accountname}/gmsa-members/remove",
    summary="Remove gMSA member",
)
async def remove_gmsa_member(
    accountname: str,
    body: GmsaMembersRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Remove members from the group Managed Service Account membership list.

    Each member is removed individually via a separate
    ``samba-tool service-account group-msa-membership remove`` invocation
    because the correct flags are ``--name`` (for the gMSA) and
    ``--principal`` (for each member account).
    """
    try:
        results: list = []
        for member in body.members:
            args: dict = {
                "--name": accountname,
                "--principal": member,
            }
            cmd = build_samba_command_deep(
                ["service-account", "group-msa-membership", "remove"], args=args
            )
            result = await execute_samba_command(cmd)
            results.append(result)
        return {
            "status": "ok",
            "message": f"Members removed from gMSA '{accountname}' successfully",
            "data": results,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to remove gMSA members from '%s': %s", accountname, exc
        )
        raise_classified_error(exc)


@router.get(
    "/{accountname}/gmsa-members",
    summary="List gMSA members",
)
async def list_gmsa_members(
    accountname: str,
    api_key: ApiKeyDep,
) -> dict:
    """List members of the group Managed Service Account.

    Uses ``samba-tool service-account group-msa-membership show``
    with ``--name`` flag (not ``list``, which does not exist).
    """
    try:
        args: dict = {"--name": accountname}
        cmd = build_samba_command_deep(
            ["service-account", "group-msa-membership", "show"], args=args
        )
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error(
            "Failed to list gMSA members for '%s': %s", accountname, exc
        )
        raise_classified_error(exc)
