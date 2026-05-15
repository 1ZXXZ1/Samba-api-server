"""
Pydantic models for the Sites & Subnets router.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.common import APIResponse, SuccessResponse


# ── Request models ─────────────────────────────────────────────────────


class SiteCreateRequest(BaseModel):
    """Request body for creating a new site."""

    sitename: str = Field(
        ...,
        description="Name of the new site to create.",
        min_length=1,
        max_length=256,
    )


class SubnetCreateRequest(BaseModel):
    """Request body for creating a new subnet within a site."""

    subnetname: str = Field(
        ...,
        description="Name (CIDR notation) of the subnet to create, e.g. '10.0.0.0/24'.",
        min_length=1,
        max_length=256,
    )
    site_of_subnet: str = Field(
        ...,
        description="Name of the site to which the subnet belongs.",
        min_length=1,
        max_length=256,
    )


class SubnetSetSiteRequest(BaseModel):
    """Request body for changing the site assignment of a subnet."""

    site_of_subnet: str = Field(
        ...,
        description="Name of the site to assign the subnet to.",
        min_length=1,
        max_length=256,
    )


# ── Response models ────────────────────────────────────────────────────


class SiteListResponse(SuccessResponse):
    """Response for listing sites."""

    data: Optional[Any] = Field(
        default=None,
        description="List of sites or samba-tool output.",
    )


class SiteViewResponse(SuccessResponse):
    """Response for viewing a single site's details."""

    data: Optional[Any] = Field(
        default=None,
        description="Site detail from samba-tool.",
    )


class SubnetListResponse(SuccessResponse):
    """Response for listing subnets in a site."""

    data: Optional[Any] = Field(
        default=None,
        description="List of subnets in the site.",
    )


class SubnetViewResponse(SuccessResponse):
    """Response for viewing subnet details."""

    data: Optional[Any] = Field(
        default=None,
        description="Subnet detail from samba-tool.",
    )


class SiteCreateResponse(SuccessResponse):
    """Response after creating a site."""

    sitename: str = Field(
        ...,
        description="Name of the created site.",
    )


class SiteDeleteResponse(SuccessResponse):
    """Response after deleting a site."""

    sitename: str = Field(
        ...,
        description="Name of the deleted site.",
    )


class SubnetCreateResponse(SuccessResponse):
    """Response after creating a subnet."""

    subnetname: str = Field(
        ...,
        description="Name of the created subnet.",
    )


class SubnetDeleteResponse(SuccessResponse):
    """Response after deleting a subnet."""

    subnetname: str = Field(
        ...,
        description="Name of the deleted subnet.",
    )


class SubnetSetSiteResponse(SuccessResponse):
    """Response after setting a subnet's site."""

    subnetname: str = Field(
        ...,
        description="Name of the subnet that was updated.",
    )
