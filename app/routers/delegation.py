"""
Delegation management router for the Samba AD DC Management API.

Wraps ``samba-tool delegation *`` commands behind RESTful endpoints.

Note: ``samba-tool delegation`` does NOT have a ``list`` sub-command;
the only query command is ``show`` for a specific account.  The list
endpoint has been removed accordingly.

The ``add-service`` and ``del-service`` sub-commands expect the
account name and service principal as positional arguments.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.auth import ApiKeyDep
from app.executor import (
    build_samba_command_deep,
    execute_samba_command,
    raise_classified_error,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/delegation", tags=["Delegation"])


# ── Request models ──────────────────────────────────────────────────────


class DelegationAccountService(BaseModel):
    """Request body for delegation add/remove operations."""

    accountname: str = Field(..., description="Account name for the delegation.")
    service: str = Field(..., description="Service principal for the delegation.")


# ── Endpoints ───────────────────────────────────────────────────────────
# NOTE: ``samba-tool delegation`` has no ``list`` sub-command.
# To list delegations, query individual accounts via the ``show`` command.


@router.post("/add", summary="Add delegation", status_code=status.HTTP_201_CREATED)
async def add_delegation(
    body: DelegationAccountService,
    api_key: ApiKeyDep,
) -> dict:
    """Add a service delegation for an account.

    Note: ``samba-tool delegation add-service <accountname> <principal>``
    expects both arguments as positional.
    """
    try:
        cmd = build_samba_command_deep(["delegation", "add-service"], positionals=[body.accountname, body.service])
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Delegation added for '{body.accountname}' to service '{body.service}'",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to add delegation for '%s' / '%s': %s",
            body.accountname,
            body.service,
            exc,
        )
        raise_classified_error(exc)


@router.delete("/remove", summary="Remove delegation")
async def remove_delegation(
    body: DelegationAccountService,
    api_key: ApiKeyDep,
) -> dict:
    """Remove a service delegation from an account.

    Note: ``samba-tool delegation del-service <accountname> <principal>``
    expects both arguments as positional.
    """
    try:
        cmd = build_samba_command_deep(["delegation", "del-service"], positionals=[body.accountname, body.service])
        result = await execute_samba_command(cmd)
        return {
            "status": "ok",
            "message": f"Delegation removed for '{body.accountname}' from service '{body.service}'",
            "data": result,
        }
    except RuntimeError as exc:
        logger.error(
            "Failed to remove delegation for '%s' / '%s': %s",
            body.accountname,
            body.service,
            exc,
        )
        raise_classified_error(exc)


@router.get("/for-account", summary="Show delegations for account")
async def show_delegations_for_account(
    accountname: str,
    api_key: ApiKeyDep,
) -> dict:
    """Show all delegations configured for a specific account.

    Note: The correct samba-tool invocation is
    ``samba-tool delegation show <accountname>`` — the account name
    is passed as a positional argument, not via ``--accountname``.
    """
    try:
        cmd = build_samba_command_deep(["delegation", "show"], positionals=[accountname])
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error(
            "Failed to show delegations for account '%s': %s", accountname, exc
        )
        raise_classified_error(exc)
