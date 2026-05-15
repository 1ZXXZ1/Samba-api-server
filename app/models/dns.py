"""
Pydantic request models for the DNS router.

These models validate the incoming JSON bodies for DNS zone and
record management operations.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class DNSZoneCreateRequest(BaseModel):
    """Create a new DNS zone."""

    zone: str = Field(
        ...,
        description="Name of the DNS zone to create (e.g. 'example.com').",
    )
    dns_directory_partition: Literal["domain", "forest"] = Field(
        default="domain",
        description=(
            "Directory partition for the zone: "
            "'domain' (DomainDnsZones) or 'forest' (ForestDnsZones)."
        ),
    )


class DNSRecordCreateRequest(BaseModel):
    """Add a DNS record to a zone."""

    name: str = Field(
        ...,
        description="Relative name of the record (e.g. 'www').",
    )
    record_type: str = Field(
        ...,
        description="DNS record type (e.g. 'A', 'CNAME', 'MX', 'SRV').",
    )
    data: str = Field(
        ...,
        description="Record data / rdata (e.g. '192.168.1.1' for an A record).",
    )


class DNSRecordDeleteRequest(BaseModel):
    """Remove a DNS record from a zone."""

    name: str = Field(
        ...,
        description="Relative name of the record to delete.",
    )
    record_type: str = Field(
        ...,
        description="DNS record type of the record to delete.",
    )
    data: str = Field(
        ...,
        description="Record data matching the record to delete.",
    )


class DNSRecordUpdateRequest(BaseModel):
    """Update (replace) a DNS record in a zone.

    samba-tool dns update <server> <zone> <name> <type> <olddata> <newdata>
    Only ONE record type is needed — there is no separate old/new type.
    The ``record_type`` field specifies the type for both old and new data.
    """

    name: str = Field(
        ...,
        description="Relative name of the record to update.",
    )
    old_record_type: str = Field(
        ...,
        description="DNS record type (used for both old and new data).",
    )
    old_data: str = Field(
        ...,
        description="Current record data.",
    )
    new_data: str = Field(
        ...,
        description="New record data.",
    )
