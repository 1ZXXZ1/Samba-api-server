"""
Schema management router for the Samba AD DC Management API.

Wraps ``samba-tool schema attribute *`` and ``samba-tool schema objectclass *``
commands behind RESTful endpoints.

Note: The correct samba-tool sub-command for class operations is
``objectclass``, not ``class``.  Additionally, ``samba-tool schema
attribute`` does not have a ``list`` sub-command (only ``show``,
``modify``, ``show_oc``); the attribute list endpoint has been removed.

Similarly, ``samba-tool schema objectclass`` does not have a ``list``
sub-command (only ``show``); the class list endpoint has been removed.
To enumerate classes, use an LDAP query against
CN=Schema,CN=Configuration,<base_dn>.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter
# NOTE: HTTPException, status, BaseModel, and Field imports removed —
# the add_attribute and add_class endpoints that used them have been
# removed because samba-tool does not have ``add`` sub-commands.

from app.auth import ApiKeyDep
from app.executor import build_samba_command_deep, execute_samba_command, raise_classified_error

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/schema", tags=["Schema"])


# ── Request models ──────────────────────────────────────────────────────


# NOTE: AddAttributeRequest and AddClassRequest have been REMOVED.
# ``samba-tool schema attribute add`` and ``samba-tool schema objectclass add``
# do NOT exist — samba-tool only provides ``show`` and ``modify`` sub-commands
# for schema attribute and objectclass.  New attributes/classes must be
# created via direct LDAP operations against
# CN=Schema,CN=Configuration,<base_dn>.


# ── Attribute endpoints ────────────────────────────────────────────────
# NOTE: ``samba-tool schema attribute`` has no ``list`` sub-command.
# Available sub-commands are: show, modify, show_oc.
# To enumerate attributes, use an LDAP query against
# cn=schema,cn=configuration,<base_dn>.


@router.get(
    "/attributes/{attribute}",
    summary="Show schema attribute detail",
)
async def show_attribute(
    attribute: str,
    api_key: ApiKeyDep,
    H: Optional[str] = None,
) -> dict:
    """Show detailed information about a specific schema attribute."""
    try:
        cmd = build_samba_command_deep(["schema", "attribute", "show"], positionals=[attribute], args={"-H": H} if H else {})
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error("Failed to show schema attribute '%s': %s", attribute, exc)
        raise_classified_error(exc)


# NOTE: ``add_attribute`` endpoint REMOVED.
# ``samba-tool schema attribute add`` does NOT exist.
# Only ``show`` and ``modify`` sub-commands are available for
# ``samba-tool schema attribute``.  To create new attributes, use LDAP.


# ── Class endpoints ─────────────────────────────────────────────────────
# NOTE: The correct samba-tool sub-command is ``objectclass``, not ``class``.
# ``samba-tool schema objectclass`` does NOT have a ``list`` sub-command;
# only ``show`` is available.  To enumerate classes, use an LDAP query
# against CN=Schema,CN=Configuration,<base_dn>.


@router.get(
    "/classes/{classname}",
    summary="Show schema class detail",
)
async def show_class(
    classname: str,
    api_key: ApiKeyDep,
    H: Optional[str] = None,
) -> dict:
    """Show detailed information about a specific schema class.

    Note: The correct samba-tool invocation is
    ``samba-tool schema objectclass show <classname>``.
    """
    try:
        cmd = build_samba_command_deep(["schema", "objectclass", "show"], positionals=[classname], args={"-H": H} if H else {})
        result = await execute_samba_command(cmd)
        return {"status": "ok", "data": result}
    except RuntimeError as exc:
        logger.error("Failed to show schema class '%s': %s", classname, exc)
        raise_classified_error(exc)


# NOTE: ``add_class`` endpoint REMOVED.
# ``samba-tool schema objectclass add`` does NOT exist.
# Only ``show`` and ``modify`` sub-commands are available for
# ``samba-tool schema objectclass``.  To create new classes, use LDAP.
