"""
Authentication policy and silo management router for the Samba AD DC
Management API.

Wraps ``samba-tool domain auth silo *``,
``samba-tool domain auth silo member *``, and
``samba-tool domain auth policy *`` commands behind RESTful endpoints.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.auth import ApiKeyDep
from app.executor import (
    build_samba_command_deep,
    execute_samba_command,
    raise_classified_error,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication Policies"])


# ── Request models ──────────────────────────────────────────────────────


class CreateSiloRequest(BaseModel):
    """Request body for creating an authentication silo."""

    siloname: str = Field(..., description="Name of the authentication silo.")
    description: Optional[str] = Field(
        None, description="Optional description for the silo."
    )


class SiloMemberRequest(BaseModel):
    """Request body for adding/removing a member from a silo."""

    accountname: str = Field(
        ..., description="Account name to add or remove from the silo."
    )


class CreatePolicyRequest(BaseModel):
    """Request body for creating an authentication policy."""

    policyname: str = Field(
        ..., description="Name of the authentication policy."
    )
    description: Optional[str] = Field(
        None, description="Optional description for the policy."
    )


# ── Silo endpoints ─────────────────────────────────────────────────────


@router.get("/silos", summary="List authentication silos")
async def list_silos(
    api_key: ApiKeyDep,
) -> dict:
    """List all authentication silos in the domain."""
    try:
        cmd = build_samba_command_deep(["domain", "auth", "silo", "list"])
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error("Failed to list authentication silos: %s", exc)
        raise_classified_error(exc)


@router.post(
    "/silos",
    summary="Create authentication silo",
    status_code=status.HTTP_201_CREATED,
)
async def create_silo(
    body: CreateSiloRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Create a new authentication silo."""
    try:
        args: dict = {"--name": body.siloname}
        if body.description is not None:
            args["--description"] = body.description

        cmd = build_samba_command_deep(["domain", "auth", "silo", "create"], args=args)
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Silo '{body.siloname}' created successfully",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to create silo '%s': %s", body.siloname, exc
        )
        raise_classified_error(exc)


@router.get("/silos/{siloname}", summary="Show authentication silo")
async def show_silo(
    siloname: str,
    api_key: ApiKeyDep,
) -> dict:
    """Show detailed information about an authentication silo.

    samba-tool domain auth silo view --name=<siloname>
    The silo name is passed via the ``--name`` flag, not as a positional.
    """
    try:
        cmd = build_samba_command_deep(["domain", "auth", "silo", "view"], args={"--name": siloname})
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error(
            "Failed to show silo '%s': %s", siloname, exc
        )
        raise_classified_error(exc)


@router.delete("/silos/{siloname}", summary="Delete authentication silo")
async def delete_silo(
    siloname: str,
    api_key: ApiKeyDep,
) -> dict:
    """Delete an authentication silo."""
    try:
        args: dict = {"--name": siloname}
        cmd = build_samba_command_deep(["domain", "auth", "silo", "delete"], args=args)
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Silo '{siloname}' deleted successfully",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to delete silo '%s': %s", siloname, exc
        )
        raise_classified_error(exc)


# ── Silo member endpoints ──────────────────────────────────────────────


@router.post(
    "/silos/{siloname}/members",
    summary="Add member to silo",
    status_code=status.HTTP_201_CREATED,
)
async def add_silo_member(
    siloname: str,
    body: SiloMemberRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Add an account as a member of an authentication silo.

    samba-tool domain auth silo member grant --name=<siloname> --member=<account>
    The correct flags are ``--name`` (for the silo) and ``--member``
    (for the account), not ``--silo``/``--accountname``.
    """
    try:
        args: dict = {
            "--name": siloname,
            "--member": body.accountname,
        }
        cmd = build_samba_command_deep(["domain", "auth", "silo", "member", "grant"], args=args)
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Member '{body.accountname}' added to silo '{siloname}'",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to add member '%s' to silo '%s': %s",
            body.accountname,
            siloname,
            exc,
        )
        raise_classified_error(exc)


@router.delete(
    "/silos/{siloname}/members",
    summary="Remove member from silo",
)
async def remove_silo_member(
    siloname: str,
    body: SiloMemberRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Remove an account from an authentication silo.

    samba-tool domain auth silo member revoke --name=<siloname> --member=<account>
    The correct flags are ``--name`` (for the silo) and ``--member``
    (for the account), not ``--silo``/``--accountname``.
    """
    try:
        args: dict = {
            "--name": siloname,
            "--member": body.accountname,
        }
        cmd = build_samba_command_deep(
            ["domain", "auth", "silo", "member", "revoke"], args=args
        )
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Member '{body.accountname}' removed from silo '{siloname}'",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to remove member '%s' from silo '%s': %s",
            body.accountname,
            siloname,
            exc,
        )
        raise_classified_error(exc)


# ── Policy endpoints ───────────────────────────────────────────────────


@router.get("/policies", summary="List authentication policies")
async def list_policies(
    api_key: ApiKeyDep,
) -> dict:
    """List all authentication policies in the domain."""
    try:
        cmd = build_samba_command_deep(["domain", "auth", "policy", "list"])
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error("Failed to list authentication policies: %s", exc)
        raise_classified_error(exc)


@router.post(
    "/policies",
    summary="Create authentication policy",
    status_code=status.HTTP_201_CREATED,
)
async def create_policy(
    body: CreatePolicyRequest,
    api_key: ApiKeyDep,
) -> dict:
    """Create a new authentication policy."""
    try:
        args: dict = {"--name": body.policyname}
        if body.description is not None:
            args["--description"] = body.description

        cmd = build_samba_command_deep(["domain", "auth", "policy", "create"], args=args)
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Policy '{body.policyname}' created successfully",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to create policy '%s': %s", body.policyname, exc
        )
        raise_classified_error(exc)


@router.get(
    "/policies/{policyname}",
    summary="Show authentication policy",
)
async def show_policy(
    policyname: str,
    api_key: ApiKeyDep,
) -> dict:
    """Show detailed information about an authentication policy.

    samba-tool domain auth policy view --name=<policyname>
    The policy name is passed via the ``--name`` flag, not as a positional.
    """
    try:
        cmd = build_samba_command_deep(["domain", "auth", "policy", "view"], args={"--name": policyname})
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error(
            "Failed to show policy '%s': %s", policyname, exc
        )
        raise_classified_error(exc)


@router.delete(
    "/policies/{policyname}",
    summary="Delete authentication policy",
)
async def delete_policy(
    policyname: str,
    api_key: ApiKeyDep,
) -> dict:
    """Delete an authentication policy."""
    try:
        args: dict = {"--name": policyname}
        cmd = build_samba_command_deep(["domain", "auth", "policy", "delete"], args=args)
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Policy '{policyname}' deleted successfully",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to delete policy '%s': %s", policyname, exc
        )
        raise_classified_error(exc)
