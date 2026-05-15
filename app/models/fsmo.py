"""
Pydantic models for the FSMO Roles router.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.models.common import SuccessResponse


# ── Enums ──────────────────────────────────────────────────────────────


class FsmoRole(str, Enum):
    """Valid FSMO role names recognised by samba-tool."""

    pdc = "pdc"
    rid = "rid"
    infrastructure = "infrastructure"
    naming = "naming"
    schema = "schema"


# ── Request models ─────────────────────────────────────────────────────


class FsmoTransferRequest(BaseModel):
    """Request body for transferring a FSMO role."""

    role: FsmoRole = Field(
        ...,
        description="FSMO role to transfer.",
    )


class FsmoSeizeRequest(BaseModel):
    """Request body for seizing a FSMO role."""

    role: FsmoRole = Field(
        ...,
        description="FSMO role to seize.",
    )


# ── Response models ────────────────────────────────────────────────────


class FsmoShowResponse(SuccessResponse):
    """Response showing current FSMO role holders."""

    data: Optional[Any] = Field(
        default=None,
        description="FSMO role holder information from samba-tool.",
    )


class FsmoTransferResponse(SuccessResponse):
    """Response after transferring a FSMO role."""

    role: str = Field(
        ...,
        description="The FSMO role that was transferred.",
    )


class FsmoSeizeResponse(SuccessResponse):
    """Response after seizing a FSMO role."""

    role: str = Field(
        ...,
        description="The FSMO role that was seized.",
    )
