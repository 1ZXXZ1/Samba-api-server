"""
Pydantic models for the Group Policy (GPO) router.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from app.models.common import SuccessResponse, TaskResponse


# ── Request models ─────────────────────────────────────────────────────


class GpoCreateRequest(BaseModel):
    """Request body for creating a new GPO."""

    displayname: str = Field(
        ...,
        description="Display name for the new GPO.",
        min_length=1,
        max_length=512,
    )


class GpoSetAclRequest(BaseModel):
    """Request body for setting a GPO's ACL."""

    sddl: str = Field(
        ...,
        description="SDDL string representing the new ACL.",
        min_length=1,
    )


class GpoLinkRequest(BaseModel):
    """Request body for linking a GPO to a container."""

    container_dn: str = Field(
        ...,
        description="Distinguished name of the container to link the GPO to.",
        min_length=1,
    )


class GpoUnlinkRequest(BaseModel):
    """Request body for unlinking a GPO from a container."""

    container_dn: str = Field(
        ...,
        description="Distinguished name of the container to unlink the GPO from.",
        min_length=1,
    )


class GpoSetInheritRequest(BaseModel):
    """Request body for setting GPO inheritance blocking."""

    block: bool = Field(
        ...,
        description="True to block inheritance, False to allow it.",
    )


class GpoBackupRequest(BaseModel):
    """Request body for backing up a GPO."""

    target_dir: str = Field(
        ...,
        description="Directory path to store the GPO backup.",
        min_length=1,
    )


class GpoRestoreRequest(BaseModel):
    """Request body for restoring a GPO."""

    source_dir: str = Field(
        ...,
        description="Directory path containing the GPO backup to restore.",
        min_length=1,
    )


# ── Response models ────────────────────────────────────────────────────


class GpoListResponse(SuccessResponse):
    """Response for listing GPOs."""

    data: Optional[Any] = Field(
        default=None,
        description="List of GPOs or samba-tool output.",
    )


class GpoShowResponse(SuccessResponse):
    """Response for showing GPO details."""

    data: Optional[Any] = Field(
        default=None,
        description="GPO detail from samba-tool.",
    )


class GpoCreateResponse(SuccessResponse):
    """Response after creating a GPO."""

    displayname: str = Field(
        ...,
        description="Display name of the created GPO.",
    )
    gpo_id: Optional[str] = Field(
        default=None,
        description="GUID of the created GPO (if extracted from samba-tool output).",
    )


class GpoDeleteResponse(SuccessResponse):
    """Response after deleting a GPO."""

    gpo_id: str = Field(
        ...,
        description="ID of the deleted GPO.",
    )


class GpoGetAclResponse(SuccessResponse):
    """Response for GPO ACL retrieval."""

    data: Optional[Any] = Field(
        default=None,
        description="GPO ACL information from samba-tool.",
    )


class GpoSetAclResponse(SuccessResponse):
    """Response after setting a GPO's ACL."""

    gpo_id: str = Field(
        ...,
        description="ID of the GPO whose ACL was set.",
    )


class GpoLinkResponse(SuccessResponse):
    """Response after linking a GPO."""

    gpo_id: str = Field(
        ...,
        description="ID of the linked GPO.",
    )


class GpoUnlinkResponse(SuccessResponse):
    """Response after unlinking a GPO."""

    gpo_id: str = Field(
        ...,
        description="ID of the unlinked GPO.",
    )


class GpoGetInheritResponse(SuccessResponse):
    """Response for GPO inheritance retrieval."""

    data: Optional[Any] = Field(
        default=None,
        description="GPO inheritance information from samba-tool.",
    )


class GpoSetInheritResponse(SuccessResponse):
    """Response after setting GPO inheritance."""

    gpo_id: str = Field(
        ...,
        description="ID of the GPO whose inheritance was set.",
    )


class GpoBackupResponse(TaskResponse):
    """Response for an asynchronous GPO backup task."""

    pass


class GpoRestoreResponse(TaskResponse):
    """Response for an asynchronous GPO restore task."""

    pass


class GpoListallResponse(SuccessResponse):
    """Response for listing all GPO contents."""

    data: Optional[Any] = Field(
        default=None,
        description="All GPO contents from samba-tool.",
    )


class GpoFetchResponse(SuccessResponse):
    """Response for fetching GPO data."""

    data: Optional[Any] = Field(
        default=None,
        description="GPO data from samba-tool.",
    )
