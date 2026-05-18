"""
Fast LDB reader module for Samba AD DC Management API.

Executes ``sudo ldbsearch`` directly and returns parsed JSON.
Used by ALL read endpoints to retrieve AD data in one fast command,
bypassing the slower ``samba-tool`` interface.

v1.2.1_fix: Initial implementation with LDIF parser, TTLCache, and
async wrappers using ProcessPoolExecutor from app.worker.

v1.2.3_fix: Added single-object lookup methods (fetch_*_by_name),
specialized queries (fetch_user_groups, fetch_group_members,
fetch_ou_objects, fetch_domain_password_settings, fetch_domain_trusts,
fetch_kds_root_keys, fetch_domain_level, fetch_schema_objects,
fetch_sites, fetch_subnets, fetch_dns_zones, fetch_drs_replication),
and a generic ``search()`` helper.  All routers now use ldbsearch
instead of samba-tool for READ operations.

v1.2.4_fix: Rewrote ``fetch_domain_level()`` to use a combined LDAP
filter ``(|(objectClass=domain)(cn=Partitions)(objectClass=nTDSDSA))``
which correctly reads the forest functional level from the Partitions
container (``msDS-Behavior-Version`` on ``CN=Partitions,CN=Configuration``)
and the lowest DC level from nTDSDSA objects, instead of incorrectly
reading ``msDS-forestBehaviorVersion`` from the domain head object
(which does not have that attribute).  Also added level classification
by DN pattern and returns structured data with human-readable level names.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Optional

from cachetools import TTLCache

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────

LDB_PATH: str = "/var/lib/samba/private/sam.ldb"
LDBSEARCH_CMD: str = "ldbsearch"
DEFAULT_TIMEOUT: int = 30
CACHE_TTL: int = 3
CACHE_MAX_SIZE: int = 64

# ── Internal cache ────────────────────────────────────────────────────

_ldb_cache: TTLCache = TTLCache(maxsize=CACHE_MAX_SIZE, ttl=CACHE_TTL)


# ── LDIF Parser ───────────────────────────────────────────────────────

def _parse_ldif(text: str) -> list[dict[str, Any]]:
    """Parse LDIF output from ldbsearch into a list of dictionaries.

    Handles:
    - Lines starting with ``#`` or ``ref:`` are skipped.
    - Blank lines mark the end of an object.
    - Lines with ``attribute:: base64_value`` are base64-decoded.
    - Lines with ``attribute: value`` are stored as-is.
    - Objects without a ``dn`` attribute are ignored.

    Parameters
    ----------
    text:
        Raw LDIF text output from ldbsearch.

    Returns
    -------
    list[dict[str, Any]]
        List of parsed objects, each a dict mapping attribute names to values.
    """
    objects: list[dict[str, Any]] = []
    obj: dict[str, Any] = {}

    for line in text.splitlines():
        line = line.rstrip("\n")
        if line.startswith("#") or line.startswith("ref:"):
            continue
        if line == "":
            if obj.get("dn"):
                objects.append(obj)
            obj = {}
        elif ":: " in line:
            # base64-encoded value: "attribute:: base64value"
            idx = line.index(":: ")
            k = line[:idx]
            v = line[idx + 3:]
            try:
                obj[k] = base64.b64decode(v).decode("utf-8")
            except Exception:
                obj[k] = v
        elif ": " in line:
            # plain value: "attribute: value"
            idx = line.index(": ")
            k = line[:idx]
            v = line[idx + 2:]
            # Handle multi-valued attributes: if key already exists,
            # convert to list
            if k in obj:
                existing = obj[k]
                if isinstance(existing, list):
                    existing.append(v)
                else:
                    obj[k] = [existing, v]
            else:
                obj[k] = v

    # Handle last object if file doesn't end with blank line
    if obj.get("dn"):
        objects.append(obj)

    return objects


# ── Core ldbsearch runner (synchronous, for executor) ─────────────────

def _run_ldbsearch(
    base_dn: Optional[str],
    ldap_filter: str,
    attributes: Optional[list[str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    scope: Optional[str] = None,
) -> dict[str, Any]:
    """Execute ``sudo ldbsearch`` and return parsed results.

    This is a synchronous function designed to be submitted to a
    ``ProcessPoolExecutor``.  It must be a top-level (picklable)
    function, not a method.

    Parameters
    ----------
    base_dn:
        Optional base DN for the search (``-b`` flag).
    ldap_filter:
        LDAP search filter string.
    attributes:
        Optional list of attribute names to request.  If ``None``,
        all attributes (``*``) are requested.
    timeout:
        Maximum wall-time in seconds for the subprocess.
    scope:
        Optional search scope: ``"sub"``, ``"one"``, ``"base"``.
        Maps to ``-s`` flag.

    Returns
    -------
    dict[str, Any]
        ``{"objects": [...]}`` with parsed LDIF entries.

    Raises
    ------
    RuntimeError
        If ldbsearch returns a non-zero exit code or times out.
    """
    import os as _os

    cmd: list[str] = ["sudo", LDBSEARCH_CMD, "-H", LDB_PATH, "--cross-ncs"]

    if base_dn:
        cmd.extend(["-b", base_dn])

    if scope:
        cmd.extend(["-s", scope])

    cmd.append(ldap_filter)

    if attributes:
        cmd.extend(attributes)
    else:
        cmd.append("*")

    logger.debug("ldbsearch command: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env={
                **_os.environ,
                "LANG": "C",
            },
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"ldbsearch timed out after {timeout}s "
            f"(filter={ldap_filter!r})"
        )
    except FileNotFoundError:
        raise RuntimeError(
            f"ldbsearch executable not found: {LDBSEARCH_CMD}"
        )

    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        # ldbsearch returns 1 when no results found — that's not an error
        if proc.returncode == 1 and not proc.stdout.strip():
            return {"objects": []}
        if proc.returncode != 1:
            raise RuntimeError(
                f"ldbsearch failed (rc={proc.returncode}): {stderr}"
            )

    objects = _parse_ldif(proc.stdout)
    return {"objects": objects}


# ── Async wrapper ─────────────────────────────────────────────────────

async def run_ldbsearch(
    base_dn: Optional[str] = None,
    ldap_filter: str = "(objectClass=*)",
    attributes: Optional[list[str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    scope: Optional[str] = None,
) -> dict[str, Any]:
    """Async wrapper around :func:`_run_ldbsearch`.

    Executes the ldbsearch command in a process pool to avoid blocking
    the event loop.

    Parameters
    ----------
    base_dn:
        Optional base DN for the search.
    ldap_filter:
        LDAP search filter string.
    attributes:
        Optional list of attribute names to request.
    timeout:
        Maximum wall-time in seconds for the subprocess.
    scope:
        Optional search scope (``"sub"``, ``"one"``, ``"base"``).

    Returns
    -------
    dict[str, Any]
        ``{"objects": [...]}``
    """
    loop = asyncio.get_running_loop()

    # Try to use the app's worker pool executor if available
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()
        result = await loop.run_in_executor(
            pool._executor,
            _run_ldbsearch,
            base_dn,
            ldap_filter,
            attributes,
            timeout,
            scope,
        )
    except (ImportError, Exception):
        # Fallback: use a temporary executor
        result = await loop.run_in_executor(
            None,
            _run_ldbsearch,
            base_dn,
            ldap_filter,
            attributes,
            timeout,
            scope,
        )

    return result


# ── Generic search helper ─────────────────────────────────────────────

async def search(
    ldap_filter: str,
    base_dn: Optional[str] = None,
    attributes: Optional[list[str]] = None,
    scope: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Generic async search using ldbsearch.

    Convenience wrapper around :func:`run_ldbsearch` that returns
    just the list of parsed objects.

    Results are NOT cached — callers should use the typed fetch
    helpers (which have built-in caching) for frequently-accessed
    data, or implement their own caching.
    """
    result = await run_ldbsearch(
        base_dn=base_dn,
        ldap_filter=ldap_filter,
        attributes=attributes,
        scope=scope,
    )
    return result.get("objects", [])


# ── Cached fetch helpers (bulk) ──────────────────────────────────────

async def fetch_users() -> list[dict[str, Any]]:
    """Fetch all user objects via ldbsearch.

    Uses filter ``(&(objectClass=user)(objectCategory=person))``
    and requests all attributes.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_users"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(&(objectClass=user)(objectCategory=person))",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_groups() -> list[dict[str, Any]]:
    """Fetch all group objects via ldbsearch.

    Uses filter ``(objectClass=group)`` and requests all attributes.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_groups"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=group)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_computers() -> list[dict[str, Any]]:
    """Fetch all computer objects via ldbsearch.

    Uses filter ``(objectClass=computer)`` and requests all attributes.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_computers"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=computer)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_contacts() -> list[dict[str, Any]]:
    """Fetch all contact objects via ldbsearch.

    Uses filter ``(objectClass=contact)`` and requests all attributes.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_contacts"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=contact)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_ous() -> list[dict[str, Any]]:
    """Fetch all organizationalUnit objects via ldbsearch.

    Uses filter ``(objectClass=organizationalUnit)`` and requests
    all attributes.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_ous"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=organizationalUnit)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_gpos() -> list[dict[str, Any]]:
    """Fetch all groupPolicyContainer objects via ldbsearch.

    Uses filter ``(objectClass=groupPolicyContainer)`` and requests
    all attributes.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_gpos"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=groupPolicyContainer)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_domain_info() -> list[dict[str, Any]]:
    """Fetch domain information via ldbsearch.

    Uses filter ``(objectClass=domain)`` and requests specific
    attributes: objectSid, msDS-Behavior-Version, fSMORoleOwner,
    distinguishedName.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_domain_info"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=domain)",
        attributes=[
            "objectSid",
            "msDS-Behavior-Version",
            "fSMORoleOwner",
            "distinguishedName",
        ],
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_fsmo() -> list[dict[str, Any]]:
    """Fetch FSMO role owner information via ldbsearch.

    Uses filter ``(fSMORoleOwner=*)`` and requests attributes
    ``dn`` and ``fSMORoleOwner``.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_fsmo"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(fSMORoleOwner=*)",
        attributes=["dn", "fSMORoleOwner"],
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


# ── Single-object fetch helpers ───────────────────────────────────────

async def fetch_user_by_name(username: str) -> Optional[dict[str, Any]]:
    """Fetch a single user by sAMAccountName via ldbsearch.

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    Results are NOT cached (single-object lookups are fast).
    """
    result = await run_ldbsearch(
        ldap_filter=f"(&(objectClass=user)(objectCategory=person)(sAMAccountName={username}))",
    )
    objects = result.get("objects", [])
    return objects[0] if objects else None


async def fetch_group_by_name(groupname: str) -> Optional[dict[str, Any]]:
    """Fetch a single group by sAMAccountName via ldbsearch.

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    """
    result = await run_ldbsearch(
        ldap_filter=f"(&(objectClass=group)(sAMAccountName={groupname}))",
    )
    objects = result.get("objects", [])
    return objects[0] if objects else None


async def fetch_computer_by_name(computername: str) -> Optional[dict[str, Any]]:
    """Fetch a single computer by sAMAccountName via ldbsearch.

    Computer accounts typically have sAMAccountName ending with ``$``.
    This method tries both ``computername$`` and ``computername``.

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    """
    # Try with $ suffix first (standard for computer accounts)
    result = await run_ldbsearch(
        ldap_filter=f"(&(objectClass=computer)(sAMAccountName={computername}$))",
    )
    objects = result.get("objects", [])
    if objects:
        return objects[0]
    # Fallback: try without $
    result = await run_ldbsearch(
        ldap_filter=f"(&(objectClass=computer)(sAMAccountName={computername}))",
    )
    objects = result.get("objects", [])
    return objects[0] if objects else None


async def fetch_contact_by_name(contactname: str) -> Optional[dict[str, Any]]:
    """Fetch a single contact by CN via ldbsearch.

    Contacts are identified by their ``cn`` attribute (not sAMAccountName,
    since contacts don't have one).

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    """
    result = await run_ldbsearch(
        ldap_filter=f"(&(objectClass=contact)(cn={contactname}))",
    )
    objects = result.get("objects", [])
    return objects[0] if objects else None


async def fetch_ou_by_dn(ou_dn: str) -> Optional[dict[str, Any]]:
    """Fetch a single OU by its distinguishedName via ldbsearch.

    Uses base-DN search with scope ``base`` for maximum efficiency.

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    """
    result = await run_ldbsearch(
        base_dn=ou_dn,
        ldap_filter="(objectClass=organizationalUnit)",
        scope="base",
    )
    objects = result.get("objects", [])
    return objects[0] if objects else None


async def fetch_gpo_by_id(gpo_id: str) -> Optional[dict[str, Any]]:
    """Fetch a single GPO by its GUID (cn attribute) via ldbsearch.

    The *gpo_id* should be in the form ``{XXXXXXXX-...}``.

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    """
    result = await run_ldbsearch(
        ldap_filter=f"(&(objectClass=groupPolicyContainer)(cn={gpo_id}))",
    )
    objects = result.get("objects", [])
    return objects[0] if objects else None


async def fetch_object_by_dn(dn: str) -> Optional[dict[str, Any]]:
    """Fetch any LDAP object by its distinguishedName.

    Uses base-DN search with scope ``base`` for maximum efficiency.
    This is a generic method that can retrieve any object type.

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    """
    result = await run_ldbsearch(
        base_dn=dn,
        ldap_filter="(objectClass=*)",
        scope="base",
    )
    objects = result.get("objects", [])
    return objects[0] if objects else None


# ── Specialized query helpers ─────────────────────────────────────────

async def fetch_user_groups(username: str) -> list[str]:
    """Fetch the list of group DNs that a user belongs to.

    Reads the ``memberOf`` attribute from the user object.
    Returns a list of distinguished name strings.
    """
    user = await fetch_user_by_name(username)
    if not user:
        return []
    member_of = user.get("memberOf", [])
    if isinstance(member_of, str):
        member_of = [member_of]
    return member_of


async def fetch_group_members(groupname: str) -> list[str]:
    """Fetch the list of member DNs for a group.

    Reads the ``member`` attribute from the group object.
    Returns a list of distinguished name strings.
    """
    group = await fetch_group_by_name(groupname)
    if not group:
        return []
    members = group.get("member", [])
    if isinstance(members, str):
        members = [members]
    return members


async def fetch_ou_objects(ou_dn: str) -> list[dict[str, Any]]:
    """Fetch all direct child objects within a specific OU.

    Uses the OU DN as the base DN with scope ``one`` (one-level)
    to retrieve only direct children, not nested descendants.

    Returns a list of LDAP attribute dicts.
    """
    result = await run_ldbsearch(
        base_dn=ou_dn,
        ldap_filter="(objectClass=*)",
        scope="one",
    )
    return result.get("objects", [])


async def fetch_domain_password_settings() -> Optional[dict[str, Any]]:
    """Fetch password policy settings from the domain object.

    Reads attributes: minPwdLength, pwdHistoryLength, minPwdAge,
    maxPwdAge, pwdProperties, lockoutDuration, lockoutThreshold,
    lockOutObservationWindow.

    Fix v1.6.2: Uses explicit domain DN from settings as the search
    base with SCOPE_BASE, instead of searching with no base DN which
    can return the wrong object (e.g. DomainDnsZones partition instead
    of the domain head).  Also adds objectClass=domainDNS filter and
    SCOPE_BASE for a precise lookup that matches ``samba-tool domain
    passwordsettings show`` output.

    Returns the raw LDAP attribute dict, or ``None`` if not found.
    """
    cache_key = "fetch_domain_password_settings"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    # Fix v1.6.2: Use explicit domain DN to avoid picking up
    # DomainDnsZones or other application partitions.
    domain_dn = None
    try:
        from app.config import get_settings
        settings = get_settings()
        domain_dn = settings.DOMAIN_DN or None
    except Exception:
        pass

    result = await run_ldbsearch(
        base_dn=domain_dn,
        ldap_filter="(objectClass=domainDNS)",
        attributes=[
            "minPwdLength",
            "pwdHistoryLength",
            "minPwdAge",
            "maxPwdAge",
            "pwdProperties",
            "lockoutDuration",
            "lockoutThreshold",
            "lockOutObservationWindow",
            "distinguishedName",
        ],
        scope="base",
    )
    objects = result.get("objects", [])
    # If base DN search didn't find it, fall back to subtree search
    if not objects and domain_dn:
        result = await run_ldbsearch(
            base_dn=domain_dn,
            ldap_filter="(objectClass=domain)",
            attributes=[
                "minPwdLength",
                "pwdHistoryLength",
                "minPwdAge",
                "maxPwdAge",
                "pwdProperties",
                "lockoutDuration",
                "lockoutThreshold",
                "lockOutObservationWindow",
                "distinguishedName",
            ],
        )
        objects = result.get("objects", [])
    data = objects[0] if objects else None
    if data is not None:
        _ldb_cache[cache_key] = data
    return data


async def fetch_domain_trusts() -> list[dict[str, Any]]:
    """Fetch trust relationships from the directory.

    Uses filter ``(objectClass=trustedDomain)``.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_domain_trusts"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=trustedDomain)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_kds_root_keys() -> list[dict[str, Any]]:
    """Fetch KDS (Group Key Distribution Service) root keys.

    Uses filter ``(objectClass=msKds-ProvRootKey)``.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_kds_root_keys"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=msKds-ProvRootKey)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_domain_level() -> Optional[dict[str, Any]]:
    """Fetch domain, forest, and lowest-DC functional levels via ldbsearch.

    Uses a combined LDAP filter to fetch three types of objects in one
    query:

    - ``(objectClass=domain)`` → domain functional level
      (``msDS-Behavior-Version`` on the domain head object)
    - ``(cn=Partitions)`` → forest functional level
      (``msDS-Behavior-Version`` on ``CN=Partitions,CN=Configuration,…``)
    - ``(objectClass=nTDSDSA)`` → lowest DC functional level
      (``msDS-Behavior-Version`` on each NTDS DSA object; the minimum
      value across all DCs is the lowest DC level)

    The full filter is::

        (|(objectClass=domain)(cn=Partitions)(objectClass=nTDSDSA))

    Each returned object is classified by its DN:

    - If the DN contains ``CN=Partitions,CN=Configuration`` → forest
    - If the DN starts with ``DC=`` without ``CN=`` in the first RDN
      → domain
    - If the objectClass includes ``nTDSDSA`` → DC level

    Returns a dict with keys::

        domain_functional_level  – human-readable name (e.g. "2008 R2")
        forest_functional_level  – human-readable name
        lowest_dc_level          – human-readable name
        domain_version           – raw integer (e.g. "4")
        forest_version           – raw integer
        lowest_dc_version        – raw integer

    Results are cached for 30 seconds.

    v1.2.4_fix: Rewritten to use the combined filter approach (matching
    the working ``ldbsearch`` command), instead of querying only the
    domain object which missed ``msDS-forestBehaviorVersion`` (that
    attribute lives on the Partitions container, not the domain head).
    """
    cache_key = "fetch_domain_level"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    # Level mapping: msDS-Behavior-Version integer → human-readable name
    _LEVEL_MAP: dict[str, str] = {
        "0": "2000 Mixed/Native",
        "1": "2003 Interim",
        "2": "2003",
        "3": "2008",
        "4": "2008 R2",
        "5": "2012",
        "6": "2012 R2",
        "7": "2016",
    }

    result = await run_ldbsearch(
        ldap_filter="(|(objectClass=domain)(cn=Partitions)(objectClass=nTDSDSA))",
        attributes=["dn", "msDS-Behavior-Version", "objectClass"],
    )
    objects = result.get("objects", [])

    domain_ver: Optional[str] = None
    forest_ver: Optional[str] = None
    dc_versions: list[str] = []

    for obj in objects:
        dn = obj.get("dn", "")
        ver = obj.get("msDS-Behavior-Version", "")
        obj_classes = obj.get("objectClass", [])
        if isinstance(obj_classes, str):
            obj_classes = [obj_classes]

        # Classify by DN pattern (checked in priority order)
        if "CN=Partitions,CN=Configuration" in dn:
            # Forest functional level lives on the Partitions container
            forest_ver = str(ver) if ver else None
        elif any(cls == "nTDSDSA" for cls in obj_classes):
            # NTDS DSA object — represents a DC's functional capability
            if ver:
                dc_versions.append(str(ver))
        elif dn.upper().startswith("DC=") and "CN=" not in dn.split(",")[0]:
            # Domain head object (DN starts with DC=, first RDN has no CN=)
            domain_ver = str(ver) if ver else None

    # Determine lowest DC level (minimum across all DCs)
    lowest_dc_ver: Optional[str] = None
    if dc_versions:
        try:
            lowest_dc_ver = str(min(int(v) for v in dc_versions))
        except (ValueError, TypeError):
            lowest_dc_ver = dc_versions[0] if dc_versions else None

    # Map version numbers to human-readable names
    data = {
        "domain_functional_level": _LEVEL_MAP.get(str(domain_ver), f"Unknown ({domain_ver})") if domain_ver is not None else None,
        "forest_functional_level": _LEVEL_MAP.get(str(forest_ver), f"Unknown ({forest_ver})") if forest_ver is not None else None,
        "lowest_dc_level": _LEVEL_MAP.get(str(lowest_dc_ver), f"Unknown ({lowest_dc_ver})") if lowest_dc_ver is not None else None,
        "domain_version": domain_ver,
        "forest_version": forest_ver,
        "lowest_dc_version": lowest_dc_ver,
    }

    _ldb_cache[cache_key] = data
    return data


async def fetch_schema_objects() -> list[dict[str, Any]]:
    """Fetch schema classSchema and attributeSchema objects.

    Uses filter ``(objectClass=classSchema)`` by default.
    Results are cached for 60 seconds (schema changes are rare).
    """
    cache_key = "fetch_schema_classes"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=classSchema)",
        attributes=[
            "cn", "lDAPDisplayName", "objectClass",
            "subClassOf", "systemFlags", "schemaIDGUID",
        ],
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_sites() -> list[dict[str, Any]]:
    """Fetch site objects from the Sites container.

    Uses filter ``(objectClass=site)``.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_sites"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=site)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_subnets() -> list[dict[str, Any]]:
    """Fetch subnet objects from the Sites container.

    Uses filter ``(objectClass=subnet)``.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_subnets"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=subnet)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_dns_zones() -> list[dict[str, Any]]:
    """Fetch DNS zone objects from the directory.

    Uses filter ``(objectClass=dnsZone)``.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_dns_zones"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await run_ldbsearch(
        ldap_filter="(objectClass=dnsZone)",
    )
    data = result.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_delegations() -> list[dict[str, Any]]:
    """Fetch delegation objects from the directory.

    Uses filter ``(objectClass=msDS-AuthNPolicy)`` or
    ``(objectClass=msDS-AuthNPolicySilo)``.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_delegations"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    # Fetch both AuthN policies and silos
    result_policies = await run_ldbsearch(
        ldap_filter="(objectClass=msDS-AuthNPolicy)",
    )
    result_silos = await run_ldbsearch(
        ldap_filter="(objectClass=msDS-AuthNPolicySilo)",
    )
    data = result_policies.get("objects", []) + result_silos.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_service_accounts() -> list[dict[str, Any]]:
    """Fetch managed service accounts from the directory.

    Uses filter for both msDS-GroupManagedServiceAccount and
    msDS-ManagedServiceAccount object classes.

    Results are cached for 30 seconds.
    """
    cache_key = "fetch_service_accounts"
    cached = _ldb_cache.get(cache_key)
    if cached is not None:
        return cached

    result_gmsa = await run_ldbsearch(
        ldap_filter="(objectClass=msDS-GroupManagedServiceAccount)",
    )
    result_msa = await run_ldbsearch(
        ldap_filter="(objectClass=msDS-ManagedServiceAccount)",
    )
    data = result_gmsa.get("objects", []) + result_msa.get("objects", [])
    _ldb_cache[cache_key] = data
    return data


async def fetch_group_stats() -> dict[str, Any]:
    """Compute group statistics from the directory.

    Returns total group count, built-in groups, security groups,
    distribution groups, etc.  Derived from the cached group list.
    """
    groups = await fetch_groups()
    builtin = 0
    security = 0
    distribution = 0
    for g in groups:
        group_type = g.get("groupType", "")
        try:
            gt = int(group_type) if isinstance(group_type, str) else 0
        except (ValueError, TypeError):
            gt = 0
        if gt & 0x00000002:  # Builtin local group
            builtin += 1
        if gt & 0x80000000:  # Security group
            security += 1
        else:
            distribution += 1

    return {
        "total_groups": len(groups),
        "security_groups": security,
        "distribution_groups": distribution,
        "builtin_groups": builtin,
    }


# ── Cache invalidation ────────────────────────────────────────────────

def invalidate_cache() -> None:
    """Clear all cached ldbsearch results.

    Should be called after any write operation (POST/PUT/DELETE)
    to ensure subsequent reads return fresh data.
    """
    _ldb_cache.clear()
    logger.debug("ldb_reader cache invalidated")
