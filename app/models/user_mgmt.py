"""
Pydantic models for extended user management and OU tree endpoints.

These models support the web-interface-facing router endpoints for
CSV import/export, user search, batch operations, and OU tree browsing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── User edit (LDAP modify) ───────────────────────────────────────────────

class UserEditRequest(BaseModel):
    """Request body for editing user attributes via direct LDAP modify.

    All fields are optional — only supplied attributes are modified.
    Maps to LDAP modify operations (replace) on the user object.
    """

    given_name: Optional[str] = Field(
        default=None, description="Given name (givenName).",
    )
    surname: Optional[str] = Field(
        default=None, description="Surname (sn).",
    )
    initials: Optional[str] = Field(
        default=None, description="Initials.",
    )
    display_name: Optional[str] = Field(
        default=None, description="Display name (displayName).",
    )
    description: Optional[str] = Field(
        default=None, description="Description.",
    )
    mail: Optional[str] = Field(
        default=None, description="E-mail address (mail).",
    )
    telephone_number: Optional[str] = Field(
        default=None, description="Telephone number (telephoneNumber).",
    )
    department: Optional[str] = Field(
        default=None, description="Department.",
    )
    company: Optional[str] = Field(
        default=None, description="Company.",
    )
    job_title: Optional[str] = Field(
        default=None, description="Job title (title).",
    )
    profile_path: Optional[str] = Field(
        default=None, description="Roaming profile path (profilePath).",
    )
    script_path: Optional[str] = Field(
        default=None, description="Logon script path (scriptPath).",
    )
    home_drive: Optional[str] = Field(
        default=None, description="Home drive letter (homeDrive).",
    )
    home_directory: Optional[str] = Field(
        default=None, description="Home directory UNC path (homeDirectory).",
    )
    physical_delivery_office: Optional[str] = Field(
        default=None, description="Physical delivery office name.",
    )
    internet_address: Optional[str] = Field(
        default=None, description="Internet home page URL (wWWHomePage).",
    )
    street_address: Optional[str] = Field(
        default=None, description="Street address (streetAddress).",
    )
    city: Optional[str] = Field(
        default=None, description="City / locality (l).",
    )
    state: Optional[str] = Field(
        default=None, description="State / province (st).",
    )
    postal_code: Optional[str] = Field(
        default=None, description="Postal code (postalCode).",
    )
    country: Optional[str] = Field(
        default=None, description="Country code (c / co).",
    )


# ── User import result ────────────────────────────────────────────────────

class UserImportRowResult(BaseModel):
    """Outcome for a single row in the CSV import."""

    username: str = Field(
        ..., description="Username from the CSV row.",
    )
    status: str = Field(
        ...,
        description="One of 'created', 'skipped', 'failed'.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Reason for skip or failure.",
    )


class UserImportResult(BaseModel):
    """Aggregated result of a CSV user import operation."""

    total_rows: int = Field(
        ..., description="Total number of data rows in the CSV.",
    )
    created: int = Field(
        default=0, description="Number of users created successfully.",
    )
    skipped: int = Field(
        default=0, description="Number of users skipped (already exist).",
    )
    failed: int = Field(
        default=0, description="Number of rows that failed.",
    )
    details: List[UserImportRowResult] = Field(
        default_factory=list,
        description="Per-row outcome details.",
    )


# ── User search result ────────────────────────────────────────────────────

class UserSearchResult(BaseModel):
    """Paginated user search result."""

    items: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="User records matching the search criteria.",
    )
    total: int = Field(
        ..., description="Total number of matching records.",
    )
    offset: int = Field(
        default=0,
        description="Zero-based index of the first item in this page.",
    )
    limit: int = Field(
        default=100,
        description="Maximum number of items per page.",
    )


# ── OU tree node ──────────────────────────────────────────────────────────

class OUTreeNode(BaseModel):
    """A single node in the OU hierarchical tree.

    The tree is built from LDAP query results by resolving parent-child
    DN relationships.  Each node represents an organizationalUnit object.
    """

    name: str = Field(
        ..., description="OU name (e.g. 'Engineering').",
    )
    dn: str = Field(
        ..., description="Full distinguished name of the OU.",
    )
    children: List["OUTreeNode"] = Field(
        default_factory=list,
        description="Child OU nodes.",
    )
    object_count: int = Field(
        default=0,
        description="Number of direct child objects (users, groups, etc.) "
                    "in this OU (non-recursive).",
    )


# ── OU statistics ─────────────────────────────────────────────────────────

class OUStats(BaseModel):
    """Statistics for an Organizational Unit and its sub-OUs."""

    ou_dn: str = Field(
        ..., description="DN of the OU these stats belong to.",
    )
    user_count: int = Field(
        default=0,
        description="Number of user objects in this OU and sub-OUs.",
    )
    group_count: int = Field(
        default=0,
        description="Number of group objects in this OU and sub-OUs.",
    )
    computer_count: int = Field(
        default=0,
        description="Number of computer objects in this OU and sub-OUs.",
    )
    contact_count: int = Field(
        default=0,
        description="Number of contact objects in this OU and sub-OUs.",
    )
    ou_count: int = Field(
        default=0,
        description="Number of sub-OUs (direct and nested).",
    )
    total_objects: int = Field(
        default=0,
        description="Sum of all object counts above.",
    )
