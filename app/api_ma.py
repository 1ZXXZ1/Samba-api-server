"""
API User & Key Management Module for the Samba AD DC Management API.

v2.8: Replaced sqlite3 with JSON-file-based storage to support systems
where Python was compiled without the sqlite3 module (e.g. ALT Linux).
Also adds granular role-based permission system with 140+ individual
permissions and full CRUD for custom roles.

Provides JSON-backed storage for API users, API keys, roles, and audit
logging, with an in-memory TTL cache to reduce file I/O on hot paths.

This module is **standalone** — it has no FastAPI dependency and can be
used from any Python context (CLI tools, background workers, tests, etc.).

Storage schema (JSON file)
--------------------------
* ``api_users``  — human accounts with bcrypt-hashed passwords
* ``api_keys``   — long-lived bearer tokens tied to a user
* ``roles``      — named roles with assigned permission sets
* ``audit_log``  — tamper-append log of every authenticated action

Quick start::

    from app.api_ma import init_db, create_user, create_api_key

    init_db()                         # creates DB file + default admin
    key = create_api_key(             # returns plaintext ONCE
        user_id=1, name="ci-token", role="operator", expires_days=90,
    )
    print(key)                        # store this securely!
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import bcrypt
from cachetools import TTLCache

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────

_DEFAULT_DB_PATH = "/var/lib/samba/api_mgmt.json"

DB_PATH: str = os.environ.get("SAMBA_API_MGMT_DB", _DEFAULT_DB_PATH)

# Cache TTLs
_API_KEY_CACHE_TTL: int = 60   # seconds — validated key result cache
_USER_CACHE_TTL: int = 30      # seconds — user lookup cache

# ── Thread-safety ────────────────────────────────────────────────────────

_db_lock = threading.Lock()

# ── In-memory caches ─────────────────────────────────────────────────────

_api_key_cache: TTLCache[str, Dict[str, Any]] = TTLCache(
    maxsize=512, ttl=_API_KEY_CACHE_TTL,
)
_user_cache: TTLCache[int, Dict[str, Any]] = TTLCache(
    maxsize=256, ttl=_USER_CACHE_TTL,
)
_user_name_cache: TTLCache[str, Dict[str, Any]] = TTLCache(
    maxsize=256, ttl=_USER_CACHE_TTL,
)
_role_cache: TTLCache[str, Dict[str, Any]] = TTLCache(
    maxsize=64, ttl=30,
)

# ── Valid roles & permissions ───────────────────────────────────────────

VALID_ROLES = {"admin", "operator", "auditor"}

# Will be extended dynamically via role CRUD
_builtin_roles: set = set(VALID_ROLES)


def _is_builtin_role(role_name: str) -> bool:
    """Return True if the role name is one of the built-in defaults."""
    return role_name in _builtin_roles


# ── Permission checking ─────────────────────────────────────────────────

def get_role_permissions(role_name: str) -> set[str]:
    """Return the set of permission strings assigned to *role_name*.

    Queries the JSON store and falls back to default permissions
    defined in ``app.permissions`` if the role exists there.
    """
    _ensure_db()

    # Check cache
    cached = _role_cache.get(role_name)
    if cached is not None:
        return set(cached.get("permissions", []))

    # Load from DB
    db = _read_db()
    roles = db.get("roles", [])
    for r in roles:
        if r.get("name") == role_name:
            perms = set(r.get("permissions", []))
            _role_cache[role_name] = r
            return perms

    # Fallback: default permissions from permissions module
    try:
        from app.permissions import DEFAULT_ROLE_PERMISSIONS
        if role_name in DEFAULT_ROLE_PERMISSIONS:
            return set(DEFAULT_ROLE_PERMISSIONS[role_name])
    except ImportError:
        pass

    return set()


def has_permission(role: str, method: str, endpoint: str) -> bool:
    """Check whether *role* is allowed to call *method* on *endpoint*.

    Uses the granular permission system from ``app.permissions`` to
    map (method, endpoint) to a specific permission string, then
    checks if the role has that permission.

    Parameters
    ----------
    role : str
        Role name (e.g. ``admin``, ``operator``, ``auditor``, or custom).
    method : str
        HTTP method in uppercase (``GET``, ``POST``, …).
    endpoint : str
        Request path, e.g. ``/api/v1/users``.

    Returns
    -------
    bool
        ``True`` if the role is permitted, ``False`` otherwise.
    """
    # Resolve the required permission for this request
    try:
        from app.permissions import resolve_permission
        required_perm = resolve_permission(method, endpoint)
    except ImportError:
        required_perm = None

    # If no specific permission is required, allow access
    if required_perm is None:
        return True

    # Check if the role has the required permission
    role_perms = get_role_permissions(role)
    if required_perm in role_perms:
        return True

    # Admin role always has all permissions (safety net)
    if role == "admin":
        return True

    return False


def has_specific_permission(role: str, permission: str) -> bool:
    """Check whether *role* has a specific named permission.

    Parameters
    ----------
    role : str
        Role name.
    permission : str
        Permission string (e.g. ``user.create``, ``gpo.delete``).

    Returns
    -------
    bool
    """
    role_perms = get_role_permissions(role)
    return permission in role_perms


# ── JSON file helpers ────────────────────────────────────────────────────

_db_initialized = False


def _default_db() -> Dict[str, Any]:
    """Return a blank database structure with seeded default data."""
    now = _now_iso()
    hashed = bcrypt.hashpw("admin".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Import default role permissions
    try:
        from app.permissions import DEFAULT_ROLE_PERMISSIONS
        default_perms = DEFAULT_ROLE_PERMISSIONS
    except ImportError:
        default_perms = {
            "admin": set(),
            "operator": set(),
            "auditor": set(),
        }

    roles = []
    for rname, perms in default_perms.items():
        roles.append({
            "name": rname,
            "description": f"Built-in {rname} role",
            "permissions": sorted(perms),
            "is_builtin": True,
            "created_at": now,
            "updated_at": now,
        })

    return {
        "version": 1,
        "api_users": [
            {
                "id": 1,
                "username": "admin",
                "password_hash": hashed,
                "full_name": "Default Administrator",
                "email": "",
                "role": "admin",
                "is_active": 1,
                "created_at": now,
                "updated_at": now,
            }
        ],
        "api_keys": [],
        "roles": roles,
        "audit_log": [],
        "_next_user_id": 2,
        "_next_key_id": 1,
    }


def _read_db() -> Dict[str, Any]:
    """Read the JSON database file and return its contents as a dict."""
    try:
        with open(DB_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return _default_db()


def _write_db(data: Dict[str, Any]) -> None:
    """Write the full database dict to the JSON file atomically."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    # Write to a temp file first, then rename for atomicity
    tmp_path = DB_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, default=str)
    # Atomic rename
    try:
        os.replace(tmp_path, DB_PATH)
    except OSError:
        # Fallback: non-atomic write if rename fails (e.g. cross-device)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        with open(DB_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, default=str)


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ── Initialisation ──────────────────────────────────────────────────────

def init_db(db_path: Optional[str] = None) -> None:
    """Create the JSON database file if it does not exist and seed defaults.

    On first run, creates an ``admin`` user with username ``admin`` and
    password ``admin``.  **Change this password immediately in production.**

    Also seeds three built-in roles (admin, operator, auditor) with their
    default permission sets from ``app.permissions``.

    Parameters
    ----------
    db_path : str, optional
        Override the database file path for this call only.
    """
    global DB_PATH, _db_initialized  # noqa: PLW0603
    if db_path is not None:
        DB_PATH = db_path

    with _db_lock:
        db_dir = os.path.dirname(DB_PATH)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        # If DB doesn't exist, create with defaults
        if not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0:
            data = _default_db()
            _write_db(data)
            logger.info("Created management database at %s with default admin user", DB_PATH)
        else:
            # Ensure roles exist in existing DB
            data = _read_db()
            _ensure_roles(data)

        _db_initialized = True


def _ensure_roles(data: Dict[str, Any]) -> None:
    """Ensure built-in roles exist in the database, adding them if missing."""
    try:
        from app.permissions import DEFAULT_ROLE_PERMISSIONS
    except ImportError:
        return

    roles = data.get("roles", [])
    existing_names = {r.get("name") for r in roles}
    now = _now_iso()
    changed = False

    for rname, perms in DEFAULT_ROLE_PERMISSIONS.items():
        if rname not in existing_names:
            roles.append({
                "name": rname,
                "description": f"Built-in {rname} role",
                "permissions": sorted(perms),
                "is_builtin": True,
                "created_at": now,
                "updated_at": now,
            })
            changed = True
            logger.info("Added missing built-in role '%s' to database", rname)
        else:
            # Update built-in role permissions if they've changed
            for r in roles:
                if r.get("name") == rname and r.get("is_builtin"):
                    new_perms = sorted(perms)
                    if r.get("permissions") != new_perms:
                        r["permissions"] = new_perms
                        r["updated_at"] = now
                        changed = True
                        logger.info("Updated built-in role '%s' permissions (%d perms)", rname, len(new_perms))

    if changed:
        data["roles"] = roles
        _write_db(data)


def _ensure_db() -> None:
    """Initialise the database on first use if not already done."""
    if not _db_initialized:
        init_db()


# ── Cache invalidation helpers ──────────────────────────────────────────

def _invalidate_user_cache(user_id: int, username: Optional[str] = None) -> None:
    """Remove cached entries for the given user."""
    _user_cache.pop(user_id, None)
    if username:
        _user_name_cache.pop(username, None)


def _invalidate_api_key_cache(key_hash: Optional[str] = None) -> None:
    """Remove cached API-key validation entries."""
    _api_key_cache.clear()


def _invalidate_role_cache(role_name: Optional[str] = None) -> None:
    """Remove cached role entries."""
    if role_name:
        _role_cache.pop(role_name, None)
    else:
        _role_cache.clear()


# ── User management ─────────────────────────────────────────────────────

def create_user(
    username: str,
    password: str,
    role: str = "operator",
    full_name: str = "",
    email: str = "",
) -> Dict[str, Any]:
    """Create a new API user.

    Parameters
    ----------
    username : str
        Unique login name.
    password : str
        Plaintext password — will be bcrypt-hashed before storage.
    role : str
        Role name (must exist in the roles table).
    full_name : str
        Human-readable display name.
    email : str
        Contact e-mail address.

    Returns
    -------
    dict
        The newly created user record (without ``password_hash``).

    Raises
    ------
    ValueError
        If *role* is invalid or *username* already exists.
    """
    _ensure_db()

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now = _now_iso()

    with _db_lock:
        data = _read_db()

        # Check username uniqueness
        for u in data["api_users"]:
            if u["username"] == username:
                raise ValueError(f"Username '{username}' already exists")

        # Validate role
        valid_roles = {r["name"] for r in data.get("roles", [])}
        if role not in valid_roles:
            raise ValueError(f"Invalid role '{role}'; must be one of {valid_roles}")

        user_id = data.get("_next_user_id", len(data["api_users"]) + 1)
        user = {
            "id": user_id,
            "username": username,
            "password_hash": hashed,
            "full_name": full_name,
            "email": email,
            "role": role,
            "is_active": 1,
            "created_at": now,
            "updated_at": now,
        }
        data["api_users"].append(user)
        data["_next_user_id"] = user_id + 1
        _write_db(data)

    _invalidate_user_cache(user_id, username)
    result = dict(user)
    result.pop("password_hash", None)
    return result


def delete_user(user_id: int) -> bool:
    """Soft-delete a user (set ``is_active=0``) and deactivate all their API keys.

    Parameters
    ----------
    user_id : int
        The user to deactivate.

    Returns
    -------
    bool
        ``True`` if the user was found and deactivated, ``False`` otherwise.
    """
    _ensure_db()
    now = _now_iso()

    with _db_lock:
        data = _read_db()
        found = False
        for u in data["api_users"]:
            if u["id"] == user_id and u["is_active"] == 1:
                u["is_active"] = 0
                u["updated_at"] = now
                found = True
                break
        if not found:
            return False

        # Deactivate all API keys owned by this user
        for k in data["api_keys"]:
            if k["user_id"] == user_id and k["is_active"] == 1:
                k["is_active"] = 0

        _write_db(data)

    _invalidate_user_cache(user_id)
    _invalidate_api_key_cache()
    return True


def update_user(user_id: int, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Update arbitrary fields on an existing user.

    Accepted keyword arguments: ``username``, ``password``, ``full_name``,
    ``email``, ``role``, ``is_active``.

    If ``password`` is supplied it will be bcrypt-hashed before storage.
    The key ``password_hash`` is **not** accepted directly.

    Parameters
    ----------
    user_id : int
        The user to update.
    **kwargs
        Fields to update.

    Returns
    -------
    dict or None
        Updated user record (without ``password_hash``), or ``None`` if
        the user was not found.
    """
    _ensure_db()
    allowed = {"username", "full_name", "email", "role", "is_active"}
    updates: Dict[str, Any] = {}
    for key in allowed:
        if key in kwargs:
            updates[key] = kwargs[key]

    # Handle password separately — hash before storage
    if "password" in kwargs:
        updates["password_hash"] = bcrypt.hashpw(
            kwargs["password"].encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    if not updates:
        return get_user(user_id)

    with _db_lock:
        data = _read_db()
        user = None
        for u in data["api_users"]:
            if u["id"] == user_id:
                user = u
                break

        if user is None:
            return None

        # Check role validity
        if "role" in updates:
            valid_roles = {r["name"] for r in data.get("roles", [])}
            if updates["role"] not in valid_roles:
                raise ValueError(f"Invalid role '{updates['role']}'; must be one of {valid_roles}")

        # Check username uniqueness
        if "username" in updates and updates["username"] != user.get("username"):
            for u in data["api_users"]:
                if u["username"] == updates["username"] and u["id"] != user_id:
                    raise ValueError(f"Username '{updates['username']}' already exists")

        user.update(updates)
        user["updated_at"] = _now_iso()
        _write_db(data)

    # Invalidate caches
    old_user = get_user(user_id)
    _invalidate_user_cache(user_id)
    if old_user and old_user.get("username"):
        _invalidate_user_cache(user_id, old_user["username"])

    result = get_user(user_id)
    if result:
        result.pop("password_hash", None)
    return result


def get_user(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a user by primary key."""
    _ensure_db()

    cached = _user_cache.get(user_id)
    if cached is not None:
        return dict(cached)

    with _db_lock:
        data = _read_db()
        for u in data["api_users"]:
            if u["id"] == user_id:
                _user_cache[user_id] = u
                return dict(u)
    return None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve a user by username."""
    _ensure_db()

    cached = _user_name_cache.get(username)
    if cached is not None:
        return dict(cached)

    with _db_lock:
        data = _read_db()
        for u in data["api_users"]:
            if u["username"] == username:
                _user_name_cache[username] = u
                _user_cache[u["id"]] = u
                return dict(u)
    return None


def list_users(
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    offset: int = 0,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List users with optional filtering and pagination."""
    _ensure_db()

    with _db_lock:
        data = _read_db()

    results = []
    for u in data["api_users"]:
        if role is not None and u["role"] != role:
            continue
        if is_active is not None and u["is_active"] != (1 if is_active else 0):
            continue
        d = dict(u)
        d.pop("password_hash", None)
        results.append(d)

    return results[offset:offset + limit]


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify a username/password pair."""
    _ensure_db()
    user = get_user_by_username(username)
    if user is None:
        return None
    if not user["is_active"]:
        return None

    try:
        if bcrypt.checkpw(
            password.encode("utf-8"), user["password_hash"].encode("utf-8")
        ):
            result = dict(user)
            result.pop("password_hash", None)
            return result
    except Exception:
        logger.warning("bcrypt check failed for user '%s'", username, exc_info=True)
    return None


# ── API Key management ──────────────────────────────────────────────────

def _hash_key(key: str) -> str:
    """Return the SHA-256 hex digest of *key* for storage."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def create_api_key(
    user_id: int,
    name: str = "",
    role: str = "operator",
    expires_days: Optional[int] = None,
    description: str = "",
) -> str:
    """Generate a new API key for the given user.

    The **plaintext** key is returned exactly once.  It cannot be
    retrieved later — store it securely.

    Parameters
    ----------
    user_id : int
        Owner of the new key.
    name : str
        Human-readable label for the key.
    role : str
        Permission role for this key.
    expires_days : int, optional
        Number of days until the key expires.  ``None`` means no expiry.
    description : str
        Optional longer description.

    Returns
    -------
    str
        The plaintext API key (shown once).

    Raises
    ------
    ValueError
        If *role* is invalid or *user_id* does not exist / is inactive.
    """
    _ensure_db()

    # Verify the user exists and is active.
    user = get_user(user_id)
    if user is None:
        raise ValueError(f"User {user_id} does not exist")
    if not user["is_active"]:
        raise ValueError(f"User {user_id} is not active")

    plaintext_key: str = secrets.token_urlsafe(48)
    key_hash = _hash_key(plaintext_key)
    key_prefix = plaintext_key[:8]
    now = _now_iso()
    expires_at: Optional[str] = None
    if expires_days is not None:
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=expires_days)
        ).isoformat()

    with _db_lock:
        data = _read_db()

        # Validate role
        valid_roles = {r["name"] for r in data.get("roles", [])}
        if role not in valid_roles:
            raise ValueError(f"Invalid role '{role}'; must be one of {valid_roles}")

        key_id = data.get("_next_key_id", len(data["api_keys"]) + 1)
        key_record = {
            "id": key_id,
            "key_hash": key_hash,
            "key_prefix": key_prefix,
            "user_id": user_id,
            "name": name,
            "description": description,
            "role": role,
            "is_active": 1,
            "expires_at": expires_at,
            "created_at": now,
            "last_used_at": None,
        }
        data["api_keys"].append(key_record)
        data["_next_key_id"] = key_id + 1
        _write_db(data)

    _invalidate_api_key_cache()
    return plaintext_key


def delete_api_key(key_id: int) -> bool:
    """Deactivate an API key."""
    _ensure_db()

    with _db_lock:
        data = _read_db()
        found = False
        for k in data["api_keys"]:
            if k["id"] == key_id and k["is_active"] == 1:
                k["is_active"] = 0
                found = True
                break
        if not found:
            return False
        _write_db(data)

    _invalidate_api_key_cache()
    return found


def update_api_key(key_id: int, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Update fields on an existing API key.

    Accepted keyword arguments: ``name``, ``description``, ``role``,
    ``is_active``, ``expires_at``.
    """
    _ensure_db()
    allowed = {"name", "description", "role", "is_active", "expires_at"}
    updates: Dict[str, Any] = {}
    for key in allowed:
        if key in kwargs:
            updates[key] = kwargs[key]

    if not updates:
        return get_api_key(key_id)

    with _db_lock:
        data = _read_db()
        key_record = None
        for k in data["api_keys"]:
            if k["id"] == key_id:
                key_record = k
                break

        if key_record is None:
            return None

        # Validate role
        if "role" in updates:
            valid_roles = {r["name"] for r in data.get("roles", [])}
            if updates["role"] not in valid_roles:
                raise ValueError(f"Invalid role '{updates['role']}'; must be one of {valid_roles}")

        key_record.update(updates)
        _write_db(data)

    _invalidate_api_key_cache()
    return get_api_key(key_id)


def get_api_key(key_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve an API key record by ID."""
    _ensure_db()

    with _db_lock:
        data = _read_db()
        for k in data["api_keys"]:
            if k["id"] == key_id:
                return dict(k)
    return None


def validate_api_key(key_plaintext: str) -> Optional[Dict[str, Any]]:
    """Validate a plaintext API key and return enriched information.

    Performs a constant-time comparison against stored hashes, checks
    that the key is active and not expired, and returns the key record
    merged with its owner's username and the key's role.

    Results are cached for 60 seconds to avoid a DB hit on every request.
    """
    _ensure_db()

    # Check the cache first.
    cached = _api_key_cache.get(key_plaintext)
    if cached is not None:
        # Re-check expiry from cached data
        expires_at = cached.get("expires_at")
        if expires_at:
            try:
                exp = datetime.fromisoformat(expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp:
                    _api_key_cache.pop(key_plaintext, None)
                    return None
            except (ValueError, TypeError):
                pass
        return dict(cached)

    key_hash = _hash_key(key_plaintext)
    key_prefix = key_plaintext[:8]

    with _db_lock:
        data = _read_db()

        key_data = None
        for k in data["api_keys"]:
            if k["key_prefix"] == key_prefix and k["is_active"] == 1:
                # Constant-time comparison of the hash
                if secrets.compare_digest(k["key_hash"], key_hash):
                    key_data = k
                    break

        if key_data is None:
            return None

        # Check expiry
        if key_data["expires_at"]:
            try:
                exp = datetime.fromisoformat(key_data["expires_at"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp:
                    return None
            except (ValueError, TypeError):
                pass

        # Update last_used_at (best-effort)
        now = _now_iso()
        try:
            for k in data["api_keys"]:
                if k["id"] == key_data["id"]:
                    k["last_used_at"] = now
                    break
            _write_db(data)
        except Exception:
            logger.debug("Failed to update last_used_at for key %d", key_data["id"])

        # Fetch the owning user
        user_data = None
        for u in data["api_users"]:
            if u["id"] == key_data["user_id"]:
                user_data = u
                break

    result: Dict[str, Any] = {
        "key_id": key_data["id"],
        "user_id": key_data["user_id"],
        "username": user_data["username"] if user_data else None,
        "role": key_data["role"],
        "key_prefix": key_data["key_prefix"],
        "expires_at": key_data["expires_at"],
    }

    # Cache the successful validation
    _api_key_cache[key_plaintext] = result
    return result


def list_api_keys(
    user_id: Optional[int] = None,
    is_active: Optional[bool] = None,
    offset: int = 0,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List API keys with optional filtering and pagination."""
    _ensure_db()

    with _db_lock:
        data = _read_db()

    results = []
    for k in data["api_keys"]:
        if user_id is not None and k["user_id"] != user_id:
            continue
        if is_active is not None and k["is_active"] != (1 if is_active else 0):
            continue
        d = dict(k)
        d.pop("key_hash", None)  # never expose the hash
        results.append(d)

    return results[offset:offset + limit]


def rotate_api_key(key_id: int) -> Optional[str]:
    """Deactivate an existing key and create a new one with the same settings."""
    _ensure_db()
    old_key = get_api_key(key_id)
    if old_key is None:
        return None

    # Deactivate the old key
    delete_api_key(key_id)

    # Determine remaining expiry (if any)
    expires_days: Optional[int] = None
    if old_key["expires_at"]:
        try:
            exp = datetime.fromisoformat(old_key["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            remaining = exp - datetime.now(timezone.utc)
            if remaining.total_seconds() > 0:
                expires_days = max(1, int(remaining.total_seconds() / 86400))
        except (ValueError, TypeError):
            pass

    # Create the replacement key
    new_key = create_api_key(
        user_id=old_key["user_id"],
        name=old_key["name"],
        role=old_key["role"],
        expires_days=expires_days,
        description=old_key.get("description", ""),
    )
    return new_key


# ── Role management ─────────────────────────────────────────────────────

def list_roles() -> List[Dict[str, Any]]:
    """List all defined roles with their permissions."""
    _ensure_db()

    with _db_lock:
        data = _read_db()

    return [
        {
            "name": r["name"],
            "description": r.get("description", ""),
            "permissions": r.get("permissions", []),
            "is_builtin": r.get("is_builtin", False),
            "created_at": r.get("created_at", ""),
            "updated_at": r.get("updated_at", ""),
        }
        for r in data.get("roles", [])
    ]


def get_role(name: str) -> Optional[Dict[str, Any]]:
    """Retrieve a role by name."""
    _ensure_db()

    with _db_lock:
        data = _read_db()

    for r in data.get("roles", []):
        if r["name"] == name:
            return {
                "name": r["name"],
                "description": r.get("description", ""),
                "permissions": r.get("permissions", []),
                "is_builtin": r.get("is_builtin", False),
                "created_at": r.get("created_at", ""),
                "updated_at": r.get("updated_at", ""),
            }
    return None


def create_role(
    name: str,
    permissions: List[str],
    description: str = "",
) -> Dict[str, Any]:
    """Create a new custom role with specified permissions.

    Parameters
    ----------
    name : str
        Unique role name.
    permissions : list[str]
        List of permission strings (e.g. ``["user.list", "user.show"]``).
    description : str
        Human-readable description.

    Returns
    -------
    dict
        The newly created role record.

    Raises
    ------
    ValueError
        If *name* already exists or permissions are invalid.
    """
    _ensure_db()

    # Validate permissions
    try:
        from app.permissions import ALL_PERMISSIONS
        invalid = set(permissions) - ALL_PERMISSIONS
        if invalid:
            raise ValueError(f"Invalid permissions: {sorted(invalid)}")
    except ImportError:
        pass  # Cannot validate without permissions module

    now = _now_iso()

    with _db_lock:
        data = _read_db()

        # Check uniqueness
        for r in data.get("roles", []):
            if r["name"] == name:
                raise ValueError(f"Role '{name}' already exists")

        role = {
            "name": name,
            "description": description,
            "permissions": sorted(set(permissions)),
            "is_builtin": False,
            "created_at": now,
            "updated_at": now,
        }
        data.setdefault("roles", []).append(role)
        _write_db(data)

    _invalidate_role_cache(name)
    return role


def update_role(name: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Update a role's attributes.

    Accepted keyword arguments: ``description``, ``permissions``, ``name``.

    Built-in roles can only have their permissions updated.
    """
    _ensure_db()

    with _db_lock:
        data = _read_db()
        role = None
        for r in data.get("roles", []):
            if r["name"] == name:
                role = r
                break

        if role is None:
            return None

        # Validate new permissions if provided
        if "permissions" in kwargs:
            try:
                from app.permissions import ALL_PERMISSIONS
                invalid = set(kwargs["permissions"]) - ALL_PERMISSIONS
                if invalid:
                    raise ValueError(f"Invalid permissions: {sorted(invalid)}")
            except ImportError:
                pass
            role["permissions"] = sorted(set(kwargs["permissions"]))

        if "description" in kwargs:
            role["description"] = kwargs["description"]

        # Handle rename
        new_name = kwargs.get("name")
        if new_name and new_name != name:
            # Check uniqueness
            for r in data.get("roles", []):
                if r["name"] == new_name:
                    raise ValueError(f"Role '{new_name}' already exists")
            old_name = role["name"]
            role["name"] = new_name
            # Update all users with this role
            for u in data["api_users"]:
                if u["role"] == old_name:
                    u["role"] = new_name
            # Update all API keys with this role
            for k in data["api_keys"]:
                if k["role"] == old_name:
                    k["role"] = new_name

        role["updated_at"] = _now_iso()
        _write_db(data)

    # Invalidate caches
    _invalidate_role_cache()
    if new_name and new_name != name:
        _invalidate_role_cache(new_name)
    else:
        _invalidate_role_cache(name)

    # Also invalidate user/key caches since role assignments may have changed
    _invalidate_user_cache(0)  # Clear all user caches
    _invalidate_api_key_cache()

    return {
        "name": role["name"],
        "description": role.get("description", ""),
        "permissions": role.get("permissions", []),
        "is_builtin": role.get("is_builtin", False),
    }


def delete_role(name: str) -> bool:
    """Delete a custom (non-built-in) role.

    Returns ``False`` if the role is built-in or not found.
    """
    _ensure_db()

    with _db_lock:
        data = _read_db()
        roles = data.get("roles", [])
        new_roles = []
        found = False
        for r in roles:
            if r["name"] == name:
                if r.get("is_builtin", False):
                    return False  # Cannot delete built-in roles
                found = True
                continue
            new_roles.append(r)

        if not found:
            return False

        data["roles"] = new_roles
        _write_db(data)

    _invalidate_role_cache(name)
    return True


# ── Audit logging ───────────────────────────────────────────────────────

def log_action(
    user_id: Optional[int],
    api_key_id: Optional[int],
    action: str,
    endpoint: str = "",
    ip_address: str = "",
    details: Optional[str] = None,
) -> None:
    """Append an entry to the audit log."""
    _ensure_db()
    now = _now_iso()

    with _db_lock:
        data = _read_db()
        entry = {
            "id": len(data.get("audit_log", [])) + 1,
            "user_id": user_id,
            "api_key_id": api_key_id,
            "action": action,
            "endpoint": endpoint,
            "ip_address": ip_address,
            "timestamp": now,
            "details": details,
        }
        data.setdefault("audit_log", []).append(entry)
        # Keep only last 10000 audit entries to prevent unbounded growth
        if len(data["audit_log"]) > 10000:
            data["audit_log"] = data["audit_log"][-10000:]
        _write_db(data)


def list_audit_log(
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    endpoint: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List audit log entries with optional filtering and pagination."""
    _ensure_db()

    with _db_lock:
        data = _read_db()

    results = []
    for entry in reversed(data.get("audit_log", [])):
        if user_id is not None and entry.get("user_id") != user_id:
            continue
        if action is not None and entry.get("action") != action:
            continue
        if endpoint is not None and not entry.get("endpoint", "").startswith(endpoint):
            continue
        results.append(entry)

    return results[offset:offset + limit]
