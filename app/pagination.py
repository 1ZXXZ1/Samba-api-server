"""
Pagination utilities for the Samba AD DC Management API.

Provides:

- :func:`paginate_list` — slice a list into a page of results
- :class:`PaginationParams` — Pydantic model for offset/limit query params
- :class:`SearchParams` — Pydantic model for search/filter query params
- :func:`build_ldap_filter` — construct safe LDAP filter strings
- :func:`make_paginated_response` — convenience helper for
  :class:`~app.models.common.PaginatedResponse`
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from app.models.common import PaginatedResponse


# ── Core pagination ─────────────────────────────────────────────────────

def paginate_list(
    items: list,
    offset: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    """Paginate a list of items.

    Parameters
    ----------
    items:
        Full list of results to paginate.
    offset:
        Zero-based index of the first item to return.
    limit:
        Maximum number of items to return.

    Returns
    -------
    dict
        ``{"items": [...], "total": N, "offset": O, "limit": L,
        "has_next": bool}``

    Notes
    -----
    If *offset* is out of range (greater than the length of *items*),
    an empty ``items`` list is returned with the correct ``total``
    count.  No exception is raised.
    """
    total = len(items)

    # Gracefully handle offset out of range
    if offset < 0:
        offset = 0
    if offset >= total:
        return {
            "items": [],
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_next": False,
        }

    end = offset + limit
    page = items[offset:end]
    has_next = end < total

    return {
        "items": page,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_next": has_next,
    }


# ── Pydantic models ────────────────────────────────────────────────────

class PaginationParams(BaseModel):
    """Common query parameters for paginated endpoints.

    Usage with FastAPI ``Depends``::

        @router.get("/users")
        async def list_users(pagination: PaginationParams = Depends()):
            ...
    """

    offset: int = Field(
        default=0,
        ge=0,
        description="Zero-based index of the first item to return.",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of items to return per page.",
    )


class SearchParams(BaseModel):
    """Query parameters for search/filter endpoints.

    Combines pagination with search capabilities, supporting both
    simple substring matching and full LDAP filter expressions.
    """

    filter: Optional[str] = Field(
        default=None,
        description=(
            "Raw LDAP filter expression, e.g. "
            "``(sAMAccountName=john*)`` or "
            "``(&(objectClass=user)(department=Engineering))``."
        ),
    )
    search: Optional[str] = Field(
        default=None,
        description=(
            "Simple substring search term.  Automatically wrapped as "
            "a substring LDAP filter on *sAMAccountName* unless "
            "*filter* is also provided."
        ),
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Zero-based index of the first item to return.",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of items to return per page.",
    )


# ── LDAP filter builder ────────────────────────────────────────────────

# LDAP special characters that must be escaped per RFC 4515
_LDAP_SPECIAL_CHARS = re.compile(r"([\\\*\(\)\0])")


def _escape_ldap_value(value: str) -> str:
    """Escape special LDAP characters in a filter value.

    The following characters are escaped according to RFC 4515 §4:

    - ``*`` → ``\\2a``
    - ``(`` → ``\\28``
    - ``)`` → ``\\29``
    - ``\\`` → ``\\5c``
    - ``\\0`` (NUL) → ``\\00``

    Parameters
    ----------
    value:
        Raw string to escape.

    Returns
    -------
    str
        The escaped string safe for use inside an LDAP filter.
    """
    # Process character by character to handle NUL correctly
    result: list[str] = []
    for ch in value:
        if ch == "\\":
            result.append("\\5c")
        elif ch == "*":
            result.append("\\2a")
        elif ch == "(":
            result.append("\\28")
        elif ch == ")":
            result.append("\\29")
        elif ch == "\0":
            result.append("\\00")
        else:
            result.append(ch)
    return "".join(result)


def build_ldap_filter(
    search: str,
    attribute: str = "sAMAccountName",
) -> str:
    """Convert a user-supplied search string to an LDAP filter.

    Rules:

    - If *search* already contains ``(`` it is assumed to be a
      complete LDAP filter and is returned verbatim.
    - If *search* ends with ``*`` (e.g. ``john*``), the wildcard
      is preserved: ``(sAMAccountName=john*)``.
    - If *search* starts with ``*`` (e.g. ``*son``), the wildcard
      is preserved: ``(sAMAccountName=*son)``.
    - Otherwise, the value is wrapped as a substring match:
      ``(sAMAccountName=*john*)``.
    - Special LDAP characters in the *non-wildcard* parts of the
      search value are escaped.

    Parameters
    ----------
    search:
        User search input.
    attribute:
        LDAP attribute to filter on (default ``sAMAccountName``).

    Returns
    -------
    str
        A valid LDAP filter string.

    Examples
    --------
    >>> build_ldap_filter("john*")
    '(sAMAccountName=john*)'
    >>> build_ldap_filter("john")
    '(sAMAccountName=*john*)'
    >>> build_ldap_filter("(sAMAccountName=john*)")
    '(sAMAccountName=john*)'
    """
    search = search.strip()

    if not search:
        return ""

    # If the user provided a full LDAP filter, return it as-is
    if "(" in search:
        return search

    # Preserve leading/trailing wildcards from user input
    leading_wildcard = search.startswith("*")
    trailing_wildcard = search.endswith("*")

    # Strip user wildcards so we can escape the raw value
    raw_value = search.strip("*")

    # Escape LDAP special characters in the value portion
    escaped = _escape_ldap_value(raw_value)

    # Determine the filter pattern
    if leading_wildcard and trailing_wildcard:
        # User typed *john* → substring match (default behaviour)
        value = f"*{escaped}*"
    elif trailing_wildcard:
        # User typed john* → prefix match
        value = f"{escaped}*"
    elif leading_wildcard:
        # User typed *son → suffix match
        value = f"*{escaped}"
    else:
        # No wildcards → default substring match
        value = f"*{escaped}*"

    return f"({attribute}={value})"


# ── Convenience response helper ─────────────────────────────────────────

def make_paginated_response(
    items: List[Any],
    total: int,
    offset: int = 0,
    limit: int = 100,
    message: str = "",
) -> PaginatedResponse:
    """Create a :class:`PaginatedResponse` instance with sensible defaults.

    This is a convenience wrapper that avoids repeating the field
    assignments at every call site.

    Parameters
    ----------
    items:
        The page of items to include in the response.
    total:
        Total number of items across all pages.
    offset:
        Zero-based offset of the first item in this page.
    limit:
        Requested page size.
    message:
        Optional human-readable message.

    Returns
    -------
    PaginatedResponse
        A fully populated response model.

    Example
    -------
    ::

        all_users = fetch_all_users()
        page = paginate_list(all_users, offset=p.offset, limit=p.limit)
        return make_paginated_response(
            items=page["items"],
            total=page["total"],
            offset=page["offset"],
            limit=page["limit"],
            message=f"Found {page['total']} users",
        )
    """
    return PaginatedResponse(
        status="ok",
        message=message,
        items=items,
        total=total,
        offset=offset,
        limit=limit,
    )
