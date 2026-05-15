"""
Pydantic request models for the Domain router.

These models validate the incoming JSON bodies (and in some cases
hint at query parameters) before they reach the route handlers.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class DomainLevelSetRequest(BaseModel):
    """Set the domain functional level."""

    level: str = Field(
        ...,
        description=(
            "Domain functional level as a string. "
            "Valid values: '2003', '2008', '2008_R2', '2012', "
            "'2012_R2', '2016'.  Note: raising the level is irreversible."
        ),
        examples=["2008_R2", "2016"],
    )


class PasswordSettingsShowRequest(BaseModel):
    """Placeholder for password-settings show.

    All parameters are supplied via query strings, so the body is empty.
    The model exists for symmetry and future extensibility.
    """


class PasswordSettingsSetRequest(BaseModel):
    """Update one or more password-policy settings."""

    min_password_length: Optional[int] = Field(
        default=None,
        description="Minimum password length.",
    )
    password_history_length: Optional[int] = Field(
        default=None,
        description="Number of passwords remembered in history.",
    )
    min_password_age: Optional[int] = Field(
        default=None,
        description="Minimum password age in days.",
    )
    max_password_age: Optional[int] = Field(
        default=None,
        description="Maximum password age in days.",
    )
    complexity: Optional[bool] = Field(
        default=None,
        description="Whether password complexity is required.",
    )
    store_plaintext: Optional[bool] = Field(
        default=None,
        description="Whether to store passwords in plaintext.",
    )
    account_lockout_duration: Optional[int] = Field(
        default=None,
        description="Lockout duration in minutes.",
    )
    account_lockout_threshold: Optional[int] = Field(
        default=None,
        description="Number of failed logins before lockout.",
    )
    reset_account_lockout_after: Optional[int] = Field(
        default=None,
        description="Minutes before lockout counter resets.",
    )


class TrustCreateRequest(BaseModel):
    """Create a trust relationship with another domain."""

    trusted_domain_name: str = Field(
        ...,
        description="FQDN of the domain to trust.",
    )
    trusted_username: Optional[str] = Field(
        default=None,
        description="Administrative username in the trusted domain.",
    )
    trusted_password: Optional[str] = Field(
        default=None,
        description="Password for the trusted-domain admin user.",
    )
    trust_type: Optional[str] = Field(
        default=None,
        description="Type of trust (e.g. 'forest' or 'external').",
    )
    trust_direction: Optional[str] = Field(
        default=None,
        description="Direction of trust (e.g. 'inbound', 'outbound', 'both').",
    )


class BackupRequest(BaseModel):
    """Request body for backup operations."""

    target_dir: Optional[str] = Field(
        default=None,
        description="Directory to write the backup file to.",
    )
    server: Optional[str] = Field(
        default=None,
        description="Target server for online backup (required by samba-tool domain backup online).",
    )


class ForceActionRequest(BaseModel):
    """Dangerous operations require an explicit ``force=true`` confirmation."""

    force: bool = Field(
        default=False,
        description="Must be ``true`` to proceed with the dangerous action.",
    )
    domain_name: Optional[str] = Field(
        default=None,
        description="DNS domain name for join operations (positional argument to samba-tool domain join).",
    )
