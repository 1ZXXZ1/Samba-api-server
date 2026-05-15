"""
Pydantic models for the DRS Replication router.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from app.models.common import SuccessResponse, TaskResponse


# ── Request models ─────────────────────────────────────────────────────


class DrsReplicateRequest(BaseModel):
    """Request body for triggering DRS replication."""

    source_dsa: str = Field(
        ...,
        description="Source DSA server (e.g. 'dc1.example.com').",
        min_length=1,
    )
    destination_dsa: str = Field(
        ...,
        description="Destination DSA server (e.g. 'dc2.example.com').",
        min_length=1,
    )
    nc_dn: str = Field(
        ...,
        description="Distinguished name of the naming context to replicate (e.g. 'DC=example,DC=com').",
        min_length=1,
    )


# ── Response models ────────────────────────────────────────────────────


class DrsShowreplResponse(SuccessResponse):
    """Response for DRS showrepl output."""

    data: Optional[Any] = Field(
        default=None,
        description="Replication status information from samba-tool.",
    )


class DrsReplicateResponse(TaskResponse):
    """Response for an asynchronous DRS replicate task."""

    pass


class DrsUptodatenessResponse(SuccessResponse):
    """Response for DRS uptodateness check."""

    data: Optional[Any] = Field(
        default=None,
        description="Uptodateness vector information.",
    )


class DrsBindResponse(SuccessResponse):
    """Response for DRS bind information."""

    data: Optional[Any] = Field(
        default=None,
        description="DRS bind information from samba-tool.",
    )


class DrsOptionsResponse(SuccessResponse):
    """Response for DRS options."""

    data: Optional[Any] = Field(
        default=None,
        description="DRS options from samba-tool.",
    )
