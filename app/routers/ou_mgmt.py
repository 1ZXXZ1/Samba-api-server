"""
Extended Organizational Unit (OU) management router for the web interface.

Provides OU tree visualization, search, statistics, and sub-tree endpoints
that complement the basic CRUD operations in ``app.routers.ou``.

Every endpoint requires API-key authentication via ``ApiKeyDep``.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import (
    build_samba_command,
    execute_samba_command,
    raise_classified_error,
)
from app.models.user_mgmt import OUTreeNode, OUStats

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ous", tags=["OUs — Extended"])


# ── Helpers ──────────────────────────────────────────────────────────────

def _ensure_ou_dn(name: str) -> str:
    """Convert a simple OU name to a full DN if it isn't one already.

    Reuses the same logic from ``app.routers.ou._ensure_ou_dn``.
    """
    if "=" in name:
        return name
    base_dn = get_settings().DOMAIN_DN
    if not base_dn:
        server = get_settings().SERVER
        if server and "." in server:
            parts = server.split(".")
            domain_parts = parts[1:] if len(parts) > 1 else parts
            base_dn = ",".join(f"DC={p}" for p in domain_parts)
        else:
            return name
    return f"OU={name},{base_dn}"


def _get_domain_dn() -> str:
    """Return the domain base DN from settings, auto-detecting if needed."""
    settings = get_settings()
    if settings.DOMAIN_DN:
        return settings.DOMAIN_DN
    server = settings.SERVER
    if server and "." in server:
        parts = server.split(".")
        domain_parts = parts[1:] if len(parts) > 1 else parts
        return ",".join(f"DC={p}" for p in domain_parts)
    return ""


def _dn_parent(dn: str) -> str:
    """Return the parent DN of a given DN (the part after the first comma)."""
    parts = dn.split(",", 1)
    if len(parts) > 1:
        return parts[1]
    return ""


def _ou_name_from_dn(dn: str) -> str:
    """Extract the OU name (RDN value) from a DN like 'OU=Eng,DC=x'."""
    rdn = dn.split(",")[0]
    if "=" in rdn:
        return rdn.split("=", 1)[1]
    return rdn


def _is_sub_dn(child_dn: str, parent_dn: str) -> bool:
    """Return True if *child_dn* is a descendant of *parent_dn*.

    Case-insensitive comparison, matching by DN suffix.
    """
    return child_dn.lower().endswith(parent_dn.lower())


# ── Module-level SamDB query functions (Fix v1.6.2) ─────────────────────
# These functions were previously nested inside async wrappers, which
# caused pickle errors when passed to ProcessPoolExecutor via
# run_in_executor.  Moving them to module level makes them picklable.

def _do_ou_list_query(
    base_dn: Optional[str] = None,
    attributes: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Module-level SamDB OU list query (picklable for executor)."""
    from app.samdb_direct import _get_samdb, ldb_msg_to_dict

    samdb = _get_samdb(for_write=False)
    if samdb is None:
        return []

    import ldb as _ldb  # type: ignore[import-untyped]

    search_base = base_dn or _get_domain_dn() or None
    attrs = attributes or ["dn", "ou", "distinguishedName"]

    results = samdb.search(
        search_base,
        expression="(objectClass=organizationalUnit)",
        scope=_ldb.SCOPE_SUBTREE,
        attrs=attrs,
    )

    # Fix v1.6.3: Use ldb_msg_to_dict() instead of manual iteration
    # over msg keys.  Manual iteration includes the 'dn' key which
    # returns an ldb.Dn object that is not iterable, causing:
    #   TypeError: 'ldb.Dn' object is not iterable
    records = [ldb_msg_to_dict(msg) for msg in results]

    return records


def _do_ou_count_query(
    ou_dn: str,
    object_class: str,
) -> int:
    """Module-level SamDB object count query (picklable for executor)."""
    from app.samdb_direct import _get_samdb

    samdb = _get_samdb(for_write=False)
    if samdb is None:
        return 0

    import ldb as _ldb  # type: ignore[import-untyped]

    results = samdb.search(
        ou_dn,
        expression=f"(objectClass={object_class})",
        scope=_ldb.SCOPE_SUBTREE,
        attrs=["dn"],
    )
    return len(results)


def _do_ou_search_query(
    ldap_filter: str,
    attributes: Optional[str],
    offset: int,
    limit: int,
) -> tuple:
    """Module-level SamDB OU search query (picklable for executor)."""
    from app.samdb_direct import _get_samdb, ldb_msg_to_dict

    samdb = _get_samdb(for_write=False)
    if samdb is None:
        return [], 0

    import ldb as _ldb  # type: ignore[import-untyped]

    attrs = None
    if attributes:
        attrs = [a.strip() for a in attributes.split(",") if a.strip()]

    base_dn = _get_domain_dn() or None

    # Ensure objectClass filter is included
    if "objectClass" not in ldap_filter:
        full_filter = f"(&{ldap_filter}(objectClass=organizationalUnit))"
    else:
        full_filter = ldap_filter

    results = samdb.search(
        base_dn,
        expression=full_filter,
        scope=_ldb.SCOPE_SUBTREE,
        attrs=attrs,
    )

    # Fix v1.6.3: Use ldb_msg_to_dict() to avoid 'ldb.Dn' object
    # not iterable error when iterating over message keys.
    all_items = [ldb_msg_to_dict(msg) for msg in results]

    total = len(all_items)
    page = all_items[offset : offset + limit]
    return page, total


def _do_direct_children_count_query(ou_dn: str) -> int:
    """Module-level SamDB direct children count (picklable for executor)."""
    from app.samdb_direct import _get_samdb

    samdb = _get_samdb(for_write=False)
    if samdb is None:
        return 0

    import ldb as _ldb  # type: ignore[import-untyped]

    results = samdb.search(
        ou_dn,
        expression="(objectClass=*)",
        scope=_ldb.SCOPE_ONELEVEL,
        attrs=["dn"],
    )
    return len(results)


def _build_tree(
    ou_records: List[Dict[str, Any]],
    root_dn: Optional[str] = None,
) -> List[OUTreeNode]:
    """Build a hierarchical OU tree from a flat list of OU records.

    Each record must have a ``dn`` key.  The function resolves
    parent-child relationships based on DN structure.

    Parameters
    ----------
    ou_records:
        Flat list of dicts, each with at least ``dn``.
    root_dn:
        If provided, only OUs under this DN are included.

    Returns
    -------
    list[OUTreeNode]
        Top-level tree nodes (OUs directly under the domain root
        or the specified *root_dn*).
    """
    if not ou_records:
        return []

    # Build a set of all OU DNs for quick lookup
    dn_set: Dict[str, Dict[str, Any]] = {}
    for rec in ou_records:
        dn = rec.get("dn", "")
        if dn:
            dn_set[dn.lower()] = rec

    # Determine the root DN for the tree
    domain_dn = root_dn or _get_domain_dn()
    domain_dn_lower = domain_dn.lower()

    # Build nodes for each OU
    node_map: Dict[str, OUTreeNode] = {}  # lower-DN → node
    for dn_lower, rec in dn_set.items():
        dn = rec.get("dn", dn_lower)
        name = _ou_name_from_dn(dn)
        node_map[dn_lower] = OUTreeNode(name=name, dn=dn)

    # Link children to parents
    top_level: List[OUTreeNode] = []
    for dn_lower, node in node_map.items():
        parent_dn = _dn_parent(dn_lower).lower()

        if parent_dn == domain_dn_lower or parent_dn == "":
            # This OU is a direct child of the domain root
            top_level.append(node)
        elif parent_dn in node_map:
            # Parent is another OU in our list
            node_map[parent_dn].children.append(node)
        else:
            # Parent not in list — treat as top-level relative to root
            top_level.append(node)

    return top_level


async def _fetch_ou_list_samdb(
    base_dn: Optional[str] = None,
    attributes: Optional[List[str]] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Fetch OU records via direct SamDB LDAP query.

    Fix v1.6.2: Extracted nested _do_query to module-level
    _do_ou_list_query() to fix pickle error with ProcessPoolExecutor.
    """
    try:
        from app.worker import get_worker_pool

        loop = asyncio.get_running_loop()
        pool = get_worker_pool()

        func = functools.partial(
            _do_ou_list_query,
            base_dn=base_dn,
            attributes=attributes,
        )
        return await loop.run_in_executor(pool._executor, func)

    except Exception as exc:
        logger.warning("SamDB OU fetch error: %s", exc)
        return None


async def _fetch_ou_list_sambatool(
    base_dn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fallback: fetch OU list via samba-tool ou list."""
    args: Dict[str, Any] = {"--json": True, "--full-dn": True}
    if base_dn:
        args["--base-dn"] = base_dn

    cmd = build_samba_command("ou", "list", args)
    try:
        result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)
        return []  # unreachable, but helps type checker

    records: List[Dict[str, Any]] = []
    if isinstance(result, list):
        for entry in result:
            if isinstance(entry, dict):
                dn = entry.get("dn") or entry.get("distinguishedName") or entry.get("name", "")
                records.append({"dn": dn, "ou": entry.get("ou", entry.get("name", ""))})
            elif isinstance(entry, str):
                records.append({"dn": entry, "ou": _ou_name_from_dn(entry)})
    elif isinstance(result, dict):
        output = result.get("output", "")
        if output:
            for line in output.strip().splitlines():
                line = line.strip()
                if line:
                    records.append({"dn": line, "ou": _ou_name_from_dn(line)})

    return records


async def _count_objects_samdb(
    ou_dn: str,
    object_class: str,
) -> int:
    """Count objects of a given class under an OU via SamDB.

    Fix v1.6.2: Extracted nested _do_count to module-level
    _do_ou_count_query() to fix pickle error with ProcessPoolExecutor.
    """
    try:
        from app.worker import get_worker_pool

        loop = asyncio.get_running_loop()
        pool = get_worker_pool()

        func = functools.partial(
            _do_ou_count_query,
            ou_dn=ou_dn,
            object_class=object_class,
        )
        return await loop.run_in_executor(pool._executor, func)

    except Exception:
        return 0


async def _count_objects_sambatool(
    ou_dn: str,
    object_class: str,
) -> int:
    """Fallback: count objects using samba-tool list commands."""
    # Use the generic LDAP search approach: list objects and count
    domain = {
        "user": "user",
        "group": "group",
        "computer": "computer",
        "contact": "contact",
    }.get(object_class, "user")

    action = "list"
    args: Dict[str, Any] = {"--json": True, "--base-dn": ou_dn, "--full-dn": True}
    cmd = build_samba_command(domain, action, args)
    try:
        result = await execute_samba_command(cmd)
    except Exception:
        return 0

    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        output = result.get("output", "")
        if output:
            return len([l for l in output.strip().splitlines() if l.strip()])

    return 0


# ── Endpoint 1: OU tree ─────────────────────────────────────────────────

@router.get("/tree", summary="Get OU tree structure")
async def get_ou_tree(
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Return the full hierarchical OU tree for the domain.

    Each node contains:
    - ``name`` — OU name (RDN value)
    - ``dn`` — Full distinguished name
    - ``children`` — Nested list of child OU nodes
    - ``object_count`` — Number of direct child objects (non-recursive)

    Uses direct SamDB query for speed when available; otherwise falls
    back to ``samba-tool ou list``.
    """
    # Try SamDB first
    ou_records = await _fetch_ou_list_samdb()
    if ou_records is None:
        ou_records = await _fetch_ou_list_sambatool()

    tree = _build_tree(ou_records)

    # Count direct child objects for each node
    await _populate_object_counts(tree)

    return {
        "status": "ok",
        "message": "OU tree retrieved successfully",
        "tree": [node.model_dump() for node in tree],
        "total_ous": len(ou_records),
    }


async def _populate_object_counts(nodes: List[OUTreeNode]) -> None:
    """Populate object_count for each node in the tree.

    Uses SamDB for counting when available, otherwise samba-tool.
    Counts direct (one-level) children only, not recursive.
    """
    try:
        from app.samdb_direct import is_samba_available
        use_samdb = is_samba_available()
    except ImportError:
        use_samdb = False

    for node in nodes:
        if use_samdb:
            node.object_count = await _count_direct_children_samdb(node.dn)
        else:
            node.object_count = await _count_direct_children_sambatool(node.dn)
        # Recurse into children
        if node.children:
            await _populate_object_counts(node.children)


async def _count_direct_children_samdb(ou_dn: str) -> int:
    """Count direct (one-level) children under an OU via SamDB.

    Fix v1.6.2: Extracted nested _do_count to module-level
    _do_direct_children_count_query() to fix pickle error.
    """
    try:
        from app.worker import get_worker_pool

        loop = asyncio.get_running_loop()
        pool = get_worker_pool()

        func = functools.partial(_do_direct_children_count_query, ou_dn=ou_dn)
        return await loop.run_in_executor(pool._executor, func)

    except Exception:
        return 0


async def _count_direct_children_sambatool(ou_dn: str) -> int:
    """Fallback: count direct children using samba-tool ou list --base-dn."""
    args: Dict[str, Any] = {
        "--json": True,
        "--base-dn": ou_dn,
        "--full-dn": True,
    }
    cmd = build_samba_command("ou", "list", args)
    try:
        result = await execute_samba_command(cmd)
    except Exception:
        return 0

    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        output = result.get("output", "")
        if output:
            return len([l for l in output.strip().splitlines() if l.strip()])

    return 0


# ── Endpoint 2: Search OUs ──────────────────────────────────────────────

@router.get("/search", summary="Search OUs by filter")
async def search_ous(
    _: ApiKeyDep,
    search: Optional[str] = Query(
        default=None,
        description="Substring to match against OU name.",
    ),
    filter: Optional[str] = Query(
        default=None,
        alias="filter",
        description="Raw LDAP filter expression.",
    ),
    attributes: Optional[str] = Query(
        default=None,
        description="Comma-separated LDAP attributes to return.",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Zero-based offset for pagination.",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of results to return.",
    ),
) -> Dict[str, Any]:
    """Search OUs with substring or raw LDAP filter, returning paginated results.

    Uses direct SamDB LDAP query if available for speed; otherwise falls
    back to ``samba-tool ou list``.
    """
    # Build LDAP filter
    if filter:
        ldap_filter = filter
    elif search:
        escaped = (
            search.replace("\\", "\\5c")
            .replace("*", "\\2a")
            .replace("(", "\\28")
            .replace(")", "\\29")
        )
        ldap_filter = (
            f"(|(ou=*{escaped}*)(name=*{escaped}*)(description=*{escaped}*))"
        )
    else:
        ldap_filter = "(objectClass=organizationalUnit)"

    # Try SamDB first
    try:
        from app.samdb_direct import is_samba_available
        if is_samba_available():
            result = await _search_ous_samdb(ldap_filter, attributes, offset, limit)
            if result is not None:
                return result
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("Direct SamDB OU search failed, falling back: %s", exc)

    # Fallback: samba-tool ou list
    return await _search_ous_sambatool(search, attributes, offset, limit)


async def _search_ous_samdb(
    ldap_filter: str,
    attributes: Optional[str],
    offset: int,
    limit: int,
) -> Optional[Dict[str, Any]]:
    """Execute OU search via direct SamDB LDAP query.

    Fix v1.6.2: Extracted nested _do_search to module-level
    _do_ou_search_query() to fix pickle error with ProcessPoolExecutor.
    """
    try:
        from app.worker import get_worker_pool

        loop = asyncio.get_running_loop()
        pool = get_worker_pool()

        func = functools.partial(
            _do_ou_search_query,
            ldap_filter=ldap_filter,
            attributes=attributes,
            offset=offset,
            limit=limit,
        )
        page_items, total = await loop.run_in_executor(pool._executor, func)

        return {
            "status": "ok",
            "items": page_items,
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    except Exception as exc:
        logger.warning("SamDB OU search error: %s", exc)
        return None


async def _search_ous_sambatool(
    search: Optional[str],
    attributes: Optional[str],
    offset: int,
    limit: int,
) -> Dict[str, Any]:
    """Fallback: search OUs via samba-tool ou list."""
    ou_records = await _fetch_ou_list_sambatool()

    # Apply substring filter
    if search:
        search_lower = search.lower()
        ou_records = [
            rec for rec in ou_records
            if search_lower in rec.get("ou", "").lower()
            or search_lower in rec.get("dn", "").lower()
        ]

    total = len(ou_records)
    page = ou_records[offset : offset + limit]

    return {
        "status": "ok",
        "items": page,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


# ── Endpoint 3: OU statistics ───────────────────────────────────────────

@router.get("/{ou_dn}/stats", summary="Statistics for an OU")
async def get_ou_stats(
    ou_dn: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Return statistics for an OU and all its sub-OUs.

    Counts users, groups, computers, and contacts within the OU
    and any nested OUs (recursive).
    """
    resolved_dn = _ensure_ou_dn(ou_dn)

    # Determine counting method
    try:
        from app.samdb_direct import is_samba_available
        use_samdb = is_samba_available()
    except ImportError:
        use_samdb = False

    # Count each object type (potentially in parallel)
    if use_samdb:
        counts = await asyncio.gather(
            _count_objects_samdb(resolved_dn, "user"),
            _count_objects_samdb(resolved_dn, "group"),
            _count_objects_samdb(resolved_dn, "computer"),
            _count_objects_samdb(resolved_dn, "contact"),
            _count_objects_samdb(resolved_dn, "organizationalUnit"),
        )
    else:
        counts = await asyncio.gather(
            _count_objects_sambatool(resolved_dn, "user"),
            _count_objects_sambatool(resolved_dn, "group"),
            _count_objects_sambatool(resolved_dn, "computer"),
            _count_objects_sambatool(resolved_dn, "contact"),
            _count_sub_ous_sambatool(resolved_dn),
        )

    user_count, group_count, computer_count, contact_count, ou_count = counts

    # Subtract 1 from ou_count — the OU itself is counted
    if ou_count > 0:
        ou_count -= 1

    stats = OUStats(
        ou_dn=resolved_dn,
        user_count=user_count,
        group_count=group_count,
        computer_count=computer_count,
        contact_count=contact_count,
        ou_count=ou_count,
    )
    stats.total_objects = (
        stats.user_count
        + stats.group_count
        + stats.computer_count
        + stats.contact_count
        + stats.ou_count
    )

    return {
        "status": "ok",
        "message": f"Statistics for OU '{ou_dn}'",
        **stats.model_dump(),
    }


async def _count_sub_ous_sambatool(ou_dn: str) -> int:
    """Count sub-OUs using samba-tool ou list --base-dn."""
    args: Dict[str, Any] = {
        "--json": True,
        "--base-dn": ou_dn,
        "--full-dn": True,
    }
    cmd = build_samba_command("ou", "list", args)
    try:
        result = await execute_samba_command(cmd)
    except Exception:
        return 0

    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        output = result.get("output", "")
        if output:
            return len([l for l in output.strip().splitlines() if l.strip()])

    return 0


# ── Endpoint 4: Sub-tree under specific OU ───────────────────────────────

@router.get("/{ou_dn}/tree", summary="Sub-tree under a specific OU")
async def get_ou_subtree(
    ou_dn: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Return the OU tree starting from a specific OU.

    Same as ``GET /ous/tree`` but scoped to the specified OU as root.
    """
    resolved_dn = _ensure_ou_dn(ou_dn)

    # Try SamDB first
    ou_records = await _fetch_ou_list_samdb(base_dn=resolved_dn)
    if ou_records is None:
        ou_records = await _fetch_ou_list_sambatool(base_dn=resolved_dn)

    # Filter to only OUs under the specified DN
    filtered = [
        rec for rec in ou_records
        if _is_sub_dn(rec.get("dn", ""), resolved_dn)
    ]

    tree = _build_tree(filtered, root_dn=resolved_dn)

    # Populate object counts
    await _populate_object_counts(tree)

    # Build the root node for the specified OU itself
    root_name = _ou_name_from_dn(resolved_dn)
    root_node = OUTreeNode(
        name=root_name,
        dn=resolved_dn,
        children=tree,
    )

    # Count objects at the root OU level
    try:
        from app.samdb_direct import is_samba_available
        use_samdb = is_samba_available()
    except ImportError:
        use_samdb = False

    if use_samdb:
        root_node.object_count = await _count_direct_children_samdb(resolved_dn)
    else:
        root_node.object_count = await _count_direct_children_sambatool(resolved_dn)

    return {
        "status": "ok",
        "message": f"Sub-tree for OU '{ou_dn}' retrieved successfully",
        "tree": root_node.model_dump(),
        "total_ous": len(filtered) + 1,  # +1 for the root OU itself
    }
