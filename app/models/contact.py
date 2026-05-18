"""
Pydantic request models for Contact endpoints.

These models validate the request bodies sent to the
``/api/v1/contacts`` router before they are translated into
``samba-tool contact`` command arguments.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ContactCreateRequest(BaseModel):
    """Request body for creating a new contact.

    Maps to ``samba-tool contact add <contactname> [options]``.
    """

    contactname: str = Field(
        ...,
        description="Common name (CN) of the contact to create.",
        examples=["John Smith"],
    )
    ou: Optional[str] = Field(
        default=None,
        description=(
            "Distinguished name of the OU in which the contact should be "
            "created.  When omitted the default Users container is used.  "
            "Maps to ``--ou`` in samba-tool."
        ),
        examples=["OU=Contacts,DC=example,DC=com"],
    )
    surname: Optional[str] = Field(
        default=None,
        description="Surname (sn / last name) of the contact.",
        examples=["Smith"],
    )
    given_name: Optional[str] = Field(
        default=None,
        description="Given name (first name) of the contact.",
        examples=["John"],
    )
    initials: Optional[str] = Field(
        default=None,
        description="Initials of the contact.",
        examples=["JS"],
    )
    display_name: Optional[str] = Field(
        default=None,
        description="Display name shown in address lists.",
        examples=["John Smith (Contractor)"],
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description of the contact.",
        examples=["External consultant"],
    )
    mail_address: Optional[str] = Field(
        default=None,
        description="SMTP mail address for the contact.",
        examples=["john.smith@example.com"],
    )
    telephone_number: Optional[str] = Field(
        default=None,
        description="Telephone number for the contact.",
        examples=["+1-555-0123"],
    )
    job_title: Optional[str] = Field(
        default=None,
        description="Job title of the contact.",
        examples=["Senior Engineer"],
    )
    department: Optional[str] = Field(
        default=None,
        description="Department of the contact.",
        examples=["IT"],
    )
    company: Optional[str] = Field(
        default=None,
        description="Company of the contact.",
        examples=["Acme Corp"],
    )
    mobile_number: Optional[str] = Field(
        default=None,
        description="Mobile phone number for the contact.",
        examples=["+1-555-0124"],
    )
    internet_address: Optional[str] = Field(
        default=None,
        description="Home page / internet address of the contact.",
        examples=["https://example.com/jsmith"],
    )
    physical_delivery_office: Optional[str] = Field(
        default=None,
        description="Office location of the contact.",
        examples=["Building A, Room 301"],
    )


class ContactMoveRequest(BaseModel):
    """Request body for moving a contact to a new OU.

    Maps to ``samba-tool contact move <contactname> <new_parent_dn>``.
    """

    new_parent_dn: str = Field(
        ...,
        description="Distinguished name of the destination OU.",
        examples=["OU=Vendors,DC=example,DC=com"],
    )


class ContactRenameRequest(BaseModel):
    """Request body for renaming a contact.

    Maps to ``samba-tool contact rename <contactname> --force-new-cn=<new_name>``.
    """

    new_name: str = Field(
        ...,
        description="New common name (CN) for the contact.",
        examples=["Jane Doe"],
    )
