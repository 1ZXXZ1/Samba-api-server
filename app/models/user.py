"""
Pydantic request models for samba-tool user operations.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class UserCreateRequest(BaseModel):
    """Request body for creating a new user.

    Maps to ``samba-tool user add``.
    """

    username: str = Field(
        ...,
        description="sAMAccountName for the new user.",
    )
    password: Optional[str] = Field(
        default=None,
        description="Initial password. Omit when using --random-password.",
    )
    must_change_at_next_login: bool = Field(
        default=False,
        description="Force password change on first logon.",
    )
    random_password: bool = Field(
        default=False,
        description="Generate a random password instead of providing one.",
    )
    smartcard_required: bool = Field(
        default=False,
        description="Require smart-card for interactive logon.",
    )
    use_username_as_cn: bool = Field(
        default=False,
        description="Use the username as the common-name (CN) attribute.",
    )
    userou: Optional[str] = Field(
        default=None,
        description="Organizational unit where the user will be created "
                    "(e.g. 'OU=Users,OU=Corp'). Must be a valid DN or None.",
    )

    @field_validator("userou", mode="before")
    @classmethod
    def _validate_userou(cls, v: Optional[str]) -> Optional[str]:
        """Validate that userou is a valid DN or None."""
        if v is None or v == "":
            return None
        # Reject obviously invalid values like "string".
        if not v.startswith("OU=") and not v.startswith("CN=") and not v.startswith("DC="):
            raise ValueError(
                f"userou must be a valid Distinguished Name starting with "
                f"OU=, CN=, or DC=.  Examples: 'OU=Users,DC=example,DC=com', "
                f"'OU=Corp Users'.  Got '{v}'"
            )
        return v

    surname: Optional[str] = Field(default=None, description="Surname (sn).")
    given_name: Optional[str] = Field(default=None, description="Given name.")
    initials: Optional[str] = Field(default=None, description="Initials.")
    profile_path: Optional[str] = Field(
        default=None, description="Roaming profile path.",
    )
    script_path: Optional[str] = Field(
        default=None, description="Logon script path.",
    )
    home_drive: Optional[str] = Field(
        default=None, description="Home drive letter (e.g. 'H:').",
    )
    home_directory: Optional[str] = Field(
        default=None, description="Home directory UNC path.",
    )
    job_title: Optional[str] = Field(default=None, description="Job title.")
    department: Optional[str] = Field(default=None, description="Department.")
    company: Optional[str] = Field(default=None, description="Company.")
    description: Optional[str] = Field(default=None, description="Description.")
    mail_address: Optional[str] = Field(
        default=None, description="E-mail address.",
    )
    internet_address: Optional[str] = Field(
        default=None, description="Internet home page URL.",
    )
    telephone_number: Optional[str] = Field(
        default=None, description="Telephone number.",
    )
    physical_delivery_office: Optional[str] = Field(
        default=None, description="Physical delivery office name.",
    )
    rfc2307_from_nss: bool = Field(
        default=False,
        description="Populate RFC 2307 attributes from local NSS data.",
    )
    nis_domain: Optional[str] = Field(
        default=None, description="NIS domain.",
    )
    unix_home: Optional[str] = Field(
        default=None, description="Unix home directory.",
    )
    uid: Optional[str] = Field(default=None, description="Unix username (uid).")
    uid_number: Optional[int] = Field(
        default=None, description="Unix UID number.",
    )
    gid_number: Optional[int] = Field(
        default=None, description="Unix GID number.",
    )
    gecos: Optional[str] = Field(default=None, description="GECOS field.")
    login_shell: Optional[str] = Field(
        default=None, description="Login shell path.",
    )


class UserUpdateRequest(BaseModel):
    """Request body for editing user attributes.

    Maps to ``samba-tool user edit``.
    """

    surname: Optional[str] = Field(default=None, description="Surname (sn).")
    given_name: Optional[str] = Field(default=None, description="Given name.")
    initials: Optional[str] = Field(default=None, description="Initials.")
    profile_path: Optional[str] = Field(
        default=None, description="Roaming profile path.",
    )
    script_path: Optional[str] = Field(
        default=None, description="Logon script path.",
    )
    home_drive: Optional[str] = Field(
        default=None, description="Home drive letter.",
    )
    home_directory: Optional[str] = Field(
        default=None, description="Home directory UNC path.",
    )
    job_title: Optional[str] = Field(default=None, description="Job title.")
    department: Optional[str] = Field(default=None, description="Department.")
    company: Optional[str] = Field(default=None, description="Company.")
    description: Optional[str] = Field(default=None, description="Description.")
    mail_address: Optional[str] = Field(
        default=None, description="E-mail address.",
    )
    internet_address: Optional[str] = Field(
        default=None, description="Internet home page URL.",
    )
    telephone_number: Optional[str] = Field(
        default=None, description="Telephone number.",
    )
    physical_delivery_office: Optional[str] = Field(
        default=None, description="Physical delivery office name.",
    )


class UserPasswordRequest(BaseModel):
    """Request body for setting a user password.

    Maps to ``samba-tool user setpassword``.
    """

    new_password: str = Field(
        ..., description="New password for the user.",
    )
    must_change_at_next_login: bool = Field(
        default=False,
        description="Force password change on next logon.",
    )


class UserSetExpiryRequest(BaseModel):
    """Request body for setting the user account expiry.

    Maps to ``samba-tool user setexpiry``.
    """

    days: int = Field(
        ...,
        description="Number of days until the account expires. "
                    "Use 0 to disable expiry.",
    )


class UserAddUnixAttrsRequest(BaseModel):
    """Request body for adding Unix attributes to a user.

    Maps to ``samba-tool user addunixattrs``.

    Both uid_number and gid_number are required because samba-tool
    requires gidNumber to be present when adding Unix attributes
    (LDAP schema constraint).
    """

    uid_number: int = Field(
        ..., description="Unix UID number (required).",
    )
    gid_number: int = Field(
        ..., description="Unix GID number (required by samba-tool).",
    )
    unix_home: Optional[str] = Field(
        default=None, description="Unix home directory.",
    )
    login_shell: Optional[str] = Field(
        default=None, description="Login shell path.",
    )
    gecos: Optional[str] = Field(default=None, description="GECOS field.")
    nis_domain: Optional[str] = Field(
        default=None, description="NIS domain.",
    )
    uid: Optional[str] = Field(default=None, description="Unix username (uid).")


class UserSensitiveRequest(BaseModel):
    """Request body for setting the sensitive flag on a user.

    Maps to ``samba-tool user sensitive``.
    """

    on: bool = Field(
        default=True,
        description="True to mark the account as sensitive "
                    "(--on), False to clear (--off).",
    )
