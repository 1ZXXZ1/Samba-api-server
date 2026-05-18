"""
Sites & Subnets management router.

Wraps ``samba-tool sites`` CLI commands behind a REST API.
All endpoints require API-key authentication.

Note: ``samba-tool sites view <sitename>`` expects the site name as a
positional argument, NOT via ``--site``.  Similarly, subnet commands
use nested sub-commands (e.g. ``samba-tool sites subnet list``).

Fix v7-3: Replaced custom ``_build_cmd`` helper with the standard
``build_samba_command_deep`` from ``app.executor``.  The custom helper
did not integrate with the JSON whitelist/auto-mode, causing ``--json``
to be passed to commands that don't support it (``sites view``,
``sites subnet view``).  Using ``build_samba_command_deep`` ensures
that the JSON auto-mode correctly strips ``--json`` for commands not
in the whitelist, avoiding "no such option: --json" errors.

Important: Site names in Samba AD often have a ``-Name`` suffix (e.g.
``Default-First-Site-Name``).  The names are case-sensitive and must
match exactly what ``samba-tool sites list`` returns.  Using an
incorrect name (e.g. ``Default-First-Site`` instead of
``Default-First-Site-Name``) will result in a 404 error.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import (
    build_samba_command_deep,
    execute_samba_command,
    raise_classified_error,
)
from app.models.common import ErrorResponse
from app.models.sites import (
    SiteCreateRequest,
    SiteCreateResponse,
    SiteDeleteResponse,
    SiteListResponse,
    SiteViewResponse,
    SubnetCreateRequest,
    SubnetCreateResponse,
    SubnetDeleteResponse,
    SubnetListResponse,
    SubnetSetSiteRequest,
    SubnetSetSiteResponse,
    SubnetViewResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/sites",
    tags=["Sites & Subnets"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
    },
)


# ── Site endpoints ─────────────────────────────────────────────────────


@router.get(
    "/",
    summary="List sites",
    response_model=SiteListResponse,
)
async def list_sites(
    _auth: ApiKeyDep,
) -> SiteListResponse:
    """List all sites in the Active Directory domain."""
    try:
        # Fix v7-3: Use build_samba_command_deep instead of custom
        # _build_cmd.  This integrates with JSON_COMMANDS_WHITELIST
        # so that --json is only sent to commands that support it.
        # "site list" is in JSON_CAPABLE_COMMANDS, so --json is safe.
        cmd = build_samba_command_deep(["sites", "list"], args={"--json": True})
        result = await execute_samba_command(cmd)
        return SiteListResponse(
            message="Sites listed successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to list sites: %s", exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error listing sites")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.get(
    "/{sitename}",
    summary="View site detail",
    response_model=SiteViewResponse,
)
async def view_site(
    sitename: str,
    _auth: ApiKeyDep,
) -> SiteViewResponse:
    """View details of a specific site.

    Note: ``samba-tool sites view`` expects the site name as a positional
    argument, not via ``--site``.

    Fix v7-3: Positional sitename is now passed via the ``positionals``
    parameter of build_samba_command_deep, keeping it separate from the
    command parts for correct command-key lookup.
    """
    try:
        # Fix v7-3: Use build_samba_command_deep.  "sites view" is NOT
        # in JSON_CAPABLE_COMMANDS, so in "auto" mode the --json flag
        # will be automatically stripped, avoiding "no such option: --json".
        cmd = build_samba_command_deep(
            ["sites", "view"],
            args={"--json": True},
            positionals=[sitename],
        )
        result = await execute_samba_command(cmd)
        return SiteViewResponse(
            message=f"Site '{sitename}' details retrieved",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to view site '%s': %s", sitename, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error viewing site '%s'", sitename)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.post(
    "/",
    summary="Create site",
    status_code=status.HTTP_201_CREATED,
    response_model=SiteCreateResponse,
)
async def create_site(
    body: SiteCreateRequest,
    _auth: ApiKeyDep,
) -> SiteCreateResponse:
    """Create a new site in the Active Directory domain."""
    try:
        cmd = build_samba_command_deep(
            ["sites", "create"],
            positionals=[body.sitename],
        )
        await execute_samba_command(cmd)
        return SiteCreateResponse(
            message=f"Site '{body.sitename}' created successfully",
            sitename=body.sitename,
        )
    except RuntimeError as exc:
        logger.error("Failed to create site '%s': %s", body.sitename, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error creating site '%s'", body.sitename)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.delete(
    "/{sitename}",
    summary="Delete site",
    response_model=SiteDeleteResponse,
)
async def delete_site(
    sitename: str,
    _auth: ApiKeyDep,
) -> SiteDeleteResponse:
    """Delete a site from the Active Directory domain."""
    try:
        cmd = build_samba_command_deep(
            ["sites", "remove"],
            positionals=[sitename],
        )
        await execute_samba_command(cmd)
        return SiteDeleteResponse(
            message=f"Site '{sitename}' deleted successfully",
            sitename=sitename,
        )
    except RuntimeError as exc:
        logger.error("Failed to delete site '%s': %s", sitename, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error deleting site '%s'", sitename)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


# ── Subnet endpoints ───────────────────────────────────────────────────


@router.get(
    "/{sitename}/subnets",
    summary="List subnets in site",
    response_model=SubnetListResponse,
)
async def list_subnets(
    sitename: str,
    _auth: ApiKeyDep,
) -> SubnetListResponse:
    """List all subnets belonging to a specific site.

    Note: ``samba-tool sites subnet list <site>`` expects the site name
    as a positional argument, not via ``--site``.
    """
    try:
        # Fix v7-3: Use build_samba_command_deep.  "sites subnet" is
        # not a 2-part command key, but the 2-part key "sites subnet"
        # is checked against the whitelist.  --json for subnet list
        # is supported ("subnet list" is in JSON_CAPABLE_COMMANDS).
        cmd = build_samba_command_deep(
            ["sites", "subnet", "list"],
            args={"--json": True},
            positionals=[sitename],
        )
        result = await execute_samba_command(cmd)
        return SubnetListResponse(
            message=f"Subnets for site '{sitename}' listed successfully",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to list subnets for site '%s': %s", sitename, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error listing subnets for site '%s'", sitename)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.get(
    "/subnets/",
    summary="View subnet detail",
    response_model=SubnetViewResponse,
)
async def view_subnet(
    _auth: ApiKeyDep,
    subnetname: str = Query(..., description="Subnet name (CIDR notation, e.g. 10.0.0.0/24)"),
) -> SubnetViewResponse:
    """View details of a specific subnet.

    Note: ``samba-tool sites subnet view`` expects the subnet name as a
    positional argument.
    """
    try:
        # Fix v7-3: "sites subnet" command key → "sites subnet" checked
        # against JSON_COMMANDS_WHITELIST.  "subnet view" IS in
        # JSON_CAPABLE_COMMANDS, so --json should work for this command.
        cmd = build_samba_command_deep(
            ["sites", "subnet", "view"],
            args={"--json": True},
            positionals=[subnetname],
        )
        result = await execute_samba_command(cmd)
        return SubnetViewResponse(
            message=f"Subnet '{subnetname}' details retrieved",
            data=result,
        )
    except RuntimeError as exc:
        logger.error("Failed to view subnet '%s': %s", subnetname, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error viewing subnet '%s'", subnetname)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.post(
    "/{sitename}/subnets",
    summary="Create subnet",
    status_code=status.HTTP_201_CREATED,
    response_model=SubnetCreateResponse,
)
async def create_subnet(
    sitename: str,
    body: SubnetCreateRequest,
    _auth: ApiKeyDep,
) -> SubnetCreateResponse:
    """Create a new subnet and assign it to a site.

    Note: ``samba-tool sites subnet create <subnet> <site-of-subnet>``
    expects both subnet name and site-of-subnet as positional arguments.
    """
    try:
        cmd = build_samba_command_deep(
            ["sites", "subnet", "create"],
            positionals=[body.subnetname, body.site_of_subnet],
        )
        await execute_samba_command(cmd)
        return SubnetCreateResponse(
            message=f"Subnet '{body.subnetname}' created in site '{body.site_of_subnet}'",
            subnetname=body.subnetname,
        )
    except RuntimeError as exc:
        logger.error("Failed to create subnet '%s': %s", body.subnetname, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error creating subnet '%s'", body.subnetname)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.delete(
    "/subnets/",
    summary="Delete subnet",
    response_model=SubnetDeleteResponse,
)
async def delete_subnet(
    _auth: ApiKeyDep,
    subnetname: str = Query(..., description="Subnet name (CIDR notation)"),
) -> SubnetDeleteResponse:
    """Delete a subnet from the Active Directory domain."""
    try:
        cmd = build_samba_command_deep(
            ["sites", "subnet", "remove"],
            positionals=[subnetname],
        )
        await execute_samba_command(cmd)
        return SubnetDeleteResponse(
            message=f"Subnet '{subnetname}' deleted successfully",
            subnetname=subnetname,
        )
    except RuntimeError as exc:
        logger.error("Failed to delete subnet '%s': %s", subnetname, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error deleting subnet '%s'", subnetname)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc


@router.put(
    "/subnets/site",
    summary="Set subnet site",
    response_model=SubnetSetSiteResponse,
)
async def set_subnet_site(
    _auth: ApiKeyDep,
    body: SubnetSetSiteRequest,
    subnetname: str = Query(..., description="Subnet name (CIDR notation)"),
) -> SubnetSetSiteResponse:
    """Change the site assignment of an existing subnet.

    Note: ``samba-tool sites subnet set-site <subnet> <site-of-subnet>``
    expects both arguments as positional.
    """
    try:
        cmd = build_samba_command_deep(
            ["sites", "subnet", "set-site"],
            positionals=[subnetname, body.site_of_subnet],
        )
        await execute_samba_command(cmd)
        return SubnetSetSiteResponse(
            message=f"Subnet '{subnetname}' assigned to site '{body.site_of_subnet}'",
            subnetname=subnetname,
        )
    except RuntimeError as exc:
        logger.error("Failed to set site for subnet '%s': %s", subnetname, exc)
        raise_classified_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error setting site for subnet '%s'", subnetname)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {exc}",
        ) from exc
