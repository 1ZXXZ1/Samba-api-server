"""
Pydantic request models for Organizational Unit (OU) endpoints.

These models validate the request bodies sent to the
``/api/v1/ous`` router before they are translated into
``samba-tool ou`` command arguments.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class OUCreateRequest(BaseModel):
    """Request body for creating a new Organizational Unit.

    Maps to ``samba-tool ou add <ouname> [options]``.
    """

    ouname: str = Field(
        ...,
        description="Name of the OU to create.",
        examples=["Engineering"],
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description stored on the OU object.",
        examples=["Engineering department"],
    )


class OUMoveRequest(BaseModel):
    """Request body for moving an OU to a new parent.

    Maps to ``samba-tool ou move <ouname> <new_parent_dn>``.
    """

    new_parent_dn: str = Field(
        ...,
        description="Distinguished name of the new parent OU.",
        examples=["OU=Departments,DC=example,DC=com"],
    )


class OURenameRequest(BaseModel):
    """Request body for renaming an OU.

    Maps to ``samba-tool ou rename <ouname> <new_name>``.
    """

    new_name: str = Field(
        ...,
        description="New name for the OU.",
        examples=["R&D"],
    )
