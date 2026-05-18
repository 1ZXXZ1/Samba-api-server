"""
Pydantic request models for samba-tool group operations.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class GroupCreateRequest(BaseModel):
    """Request body for creating a new group.

    Maps to ``samba-tool group add``.
    """

    groupname: str = Field(
        ...,
        description="sAMAccountName for the new group.",
    )
    groupou: Optional[str] = Field(
        default=None,
        description="Organizational unit where the group will be created "
                    "(e.g. 'OU=Groups,OU=Corp'). Must be a valid DN or None.",
    )

    @field_validator("groupou", mode="before")
    @classmethod
    def _validate_groupou(cls, v: Optional[str]) -> Optional[str]:
        """Validate that groupou is a valid DN or None."""
        if v is None or v == "":
            return None
        if not v.startswith("OU=") and not v.startswith("CN=") and not v.startswith("DC="):
            raise ValueError(
                f"groupou must be a valid Distinguished Name starting with "
                f"OU=, CN=, or DC=.  Examples: 'OU=Groups,DC=example,DC=com', "
                f"'OU=Security Groups'.  Got '{v}'"
            )
        return v

    group_scope: Optional[Literal["Domain", "Global", "Universal"]] = Field(
        default=None,
        description="Group scope.",
    )
    group_type: Optional[Literal["Security", "Distribution"]] = Field(
        default=None,
        description="Group type.",
    )
    description: Optional[str] = Field(
        default=None, description="Group description.",
    )
    mail_address: Optional[str] = Field(
        default=None, description="E-mail address for the group.",
    )
    notes: Optional[str] = Field(
        default=None, description="Group notes / info attribute.",
    )
    gid_number: Optional[int] = Field(
        default=None, description="Unix GID number.",
    )
    nis_domain: Optional[str] = Field(
        default=None, description="NIS domain.",
    )
    special: bool = Field(
        default=False,
        description="Create a special (well-known) group.",
    )


class GroupMembersRequest(BaseModel):
    """Request body for adding or removing group members.

    Maps to ``samba-tool group addmembers`` / ``removemembers``.
    """

    members: List[str] = Field(
        ...,
        description="List of sAMAccountNames to add or remove.",
    )
    member_dn: Optional[List[str]] = Field(
        default=None,
        description="List of distinguished names to add or remove "
                    "(used instead of sAMAccountNames with --member-dn).",
    )
    object_types: str = Field(
        default="user,group,computer",
        description="Comma-separated object types to search for "
                    "(--object-types).",
    )
    member_base_dn: Optional[str] = Field(
        default=None,
        description="Base DN to search for members (--member-base-dn).",
    )


class GroupMoveRequest(BaseModel):
    """Request body for moving a group to a new OU.

    Maps to ``samba-tool group move``.
    """

    new_parent_dn: str = Field(
        ...,
        description="Distinguished name of the new parent container.",
    )
