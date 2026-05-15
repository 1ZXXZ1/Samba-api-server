"""
Pydantic request models for Computer account endpoints.

These models validate the request bodies sent to the
``/api/v1/computers`` router before they are translated into
``samba-tool computer`` command arguments.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ComputerCreateRequest(BaseModel):
    """Request body for creating a new computer account.

    Maps to ``samba-tool computer add <computername> [options]``.
    """

    computername: str = Field(
        ...,
        description="sAMAccountName of the computer account to create.",
        examples=["DESKTOP01$"],
    )
    computerou: Optional[str] = Field(
        default=None,
        description=(
            "Distinguished name of the OU in which the computer account "
            "should be created.  When omitted the default Computers container "
            "is used."
        ),
        examples=["OU=Workstations,DC=example,DC=com"],
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description stored on the computer object.",
        examples=["Engineering workstation"],
    )
    prepare_oldjoin: bool = Field(
        default=False,
        description=(
            "Prepare the account for an old-style (pre-AD) domain join.  "
            "Passed as ``--prepare-oldjoin`` to samba-tool."
        ),
    )
    ip_address_list: Optional[list[str]] = Field(
        default=None,
        description=(
            "List of IP addresses to assign to the computer account.  "
            "Each entry is emitted as a separate ``--ip-address`` flag."
        ),
        examples=[["10.0.0.42", "10.0.1.42"]],
    )
    service_principal_name_list: Optional[list[str]] = Field(
        default=None,
        description=(
            "List of Service Principal Names (SPNs) to register.  "
            "Each entry is emitted as a separate ``--service-principal-name`` "
            "flag."
        ),
        examples=[["HOST/desktop01.example.com"]],
    )
