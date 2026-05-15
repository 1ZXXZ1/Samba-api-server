"""
Management API router — CRUD operations for API users, API keys, roles, and permissions.

Provides endpoints for managing users, API keys, roles (with granular permissions),
and viewing audit logs. These endpoints are used by the web frontend's admin panel.

All endpoints require admin-level authentication.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth import ApiKeyDep
from app.models.common import ErrorResponse, SuccessResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mgmt",
    tags=["Management"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
    },
)


# ── Request models ──────────────────────────────────────────────────────

class RoleCreateRequest(BaseModel):
    """Request body for creating a new role."""
    name: str = Field(..., description="Unique role name", min_length=1, max_length=64)
    description: str = Field(default="", description="Human-readable description")
    permissions: List[str] = Field(..., description="List of permission strings")


class RoleUpdateRequest(BaseModel):
    """Request body for updating a role."""
    name: Optional[str] = Field(default=None, description="New role name (rename)")
    description: Optional[str] = Field(default=None, description="Updated description")
    permissions: Optional[List[str]] = Field(default=None, description="Updated permission list")


class PermissionAssignRequest(BaseModel):
    """Request body for assigning permissions to a role."""
    role_name: str = Field(..., description="Role name to assign permissions to")
    permissions: List[str] = Field(..., description="List of permission strings to add")


class PermissionRevokeRequest(BaseModel):
    """Request body for revoking permissions from a role."""
    role_name: str = Field(..., description="Role name to revoke permissions from")
    permissions: List[str] = Field(..., description="List of permission strings to remove")


# ── User Management ────────────────────────────────────────────────────

@router.get("/users", summary="List management users")
async def list_users(
    _: ApiKeyDep,
    role: Optional[str] = Query(default=None, description="Filter by role"),
    is_active: Optional[bool] = Query(default=None, description="Filter by active status"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=100, ge=1, le=500, description="Page size"),
) -> Dict[str, Any]:
    """List all management users with optional filtering and pagination."""
    from app.api_ma import list_users as _list_users
    result = _list_users(role=role, is_active=is_active, offset=offset, limit=limit)
    return {"status": "ok", "data": result}


@router.post("/users", summary="Create management user", status_code=status.HTTP_201_CREATED)
async def create_user(
    username: str = Query(..., description="Username"),
    password: str = Query(..., description="Password"),
    role: str = Query(default="operator", description="Role name"),
    full_name: Optional[str] = Query(default=None, description="Full name"),
    email: Optional[str] = Query(default=None, description="Email address"),
    _: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Create a new management user."""
    from app.api_ma import create_user as _create_user
    try:
        result = _create_user(username=username, password=password, role=role,
                              full_name=full_name or "", email=email or "")
        return {"status": "ok", "data": result}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/users/{user_id}", summary="Get management user")
async def get_user(
    user_id: int,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Get a specific management user by ID."""
    from app.api_ma import get_user as _get_user
    result = _get_user(user_id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "data": result}


@router.put("/users/{user_id}", summary="Update management user")
async def update_user(
    user_id: int,
    _: ApiKeyDep,
    username: Optional[str] = Query(default=None),
    password: Optional[str] = Query(default=None),
    role: Optional[str] = Query(default=None),
    full_name: Optional[str] = Query(default=None),
    email: Optional[str] = Query(default=None),
    is_active: Optional[bool] = Query(default=None),
) -> Dict[str, Any]:
    """Update a management user's attributes."""
    from app.api_ma import update_user as _update_user
    kwargs = {k: v for k, v in {
        "username": username, "password": password, "role": role,
        "full_name": full_name, "email": email, "is_active": is_active,
    }.items() if v is not None}
    if not kwargs:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        result = _update_user(user_id, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "data": result}


@router.delete("/users/{user_id}", summary="Delete management user")
async def delete_user(
    user_id: int,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Soft-delete a management user (deactivates user and all their API keys)."""
    from app.api_ma import delete_user as _delete_user
    result = _delete_user(user_id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "message": f"User {user_id} deactivated"}


# ── API Key Management ─────────────────────────────────────────────────

@router.get("/keys", summary="List API keys")
async def list_api_keys(
    _: ApiKeyDep,
    user_id: Optional[int] = Query(default=None, description="Filter by user ID"),
    is_active: Optional[bool] = Query(default=None, description="Filter by active status"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=100, ge=1, le=500, description="Page size"),
) -> Dict[str, Any]:
    """List API keys with optional filtering and pagination."""
    from app.api_ma import list_api_keys as _list_api_keys
    result = _list_api_keys(user_id=user_id, is_active=is_active, offset=offset, limit=limit)
    return {"status": "ok", "data": result}


@router.post("/keys", summary="Create API key", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    user_id: int = Query(..., description="User ID to associate key with"),
    name: str = Query(..., description="Key name/description"),
    role: str = Query(default="operator", description="Role name"),
    expires_days: Optional[int] = Query(default=None, description="Days until expiry (None = no expiry)"),
    _: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Create a new API key. The plaintext key is returned ONLY once."""
    from app.api_ma import create_api_key as _create_api_key
    try:
        result = _create_api_key(user_id=user_id, name=name, role=role,
                                 expires_days=expires_days)
        return {"status": "ok", "data": {"key": result}}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/keys/{key_id}", summary="Get API key details")
async def get_api_key(
    key_id: int,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Get details of a specific API key."""
    from app.api_ma import get_api_key as _get_api_key
    result = _get_api_key(key_id)
    if not result:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"status": "ok", "data": result}


@router.put("/keys/{key_id}", summary="Update API key")
async def update_api_key(
    key_id: int,
    _: ApiKeyDep,
    name: Optional[str] = Query(default=None),
    role: Optional[str] = Query(default=None),
    is_active: Optional[bool] = Query(default=None),
    expires_days: Optional[int] = Query(default=None, description="Reset expiry to N days from now"),
) -> Dict[str, Any]:
    """Update an API key's attributes."""
    from app.api_ma import update_api_key as _update_api_key
    kwargs = {k: v for k, v in {
        "name": name, "role": role, "is_active": is_active,
    }.items() if v is not None}
    if expires_days is not None:
        from datetime import datetime, timedelta, timezone
        kwargs["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
    if not kwargs:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        result = _update_api_key(key_id, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not result:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"status": "ok", "data": result}


@router.delete("/keys/{key_id}", summary="Delete API key")
async def delete_api_key(
    key_id: int,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Deactivate an API key."""
    from app.api_ma import delete_api_key as _delete_api_key
    result = _delete_api_key(key_id)
    if not result:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"status": "ok", "message": f"API key {key_id} deactivated"}


@router.post("/keys/{key_id}/rotate", summary="Rotate API key")
async def rotate_api_key(
    key_id: int,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Rotate an API key: deactivate old key and create new one with same settings."""
    from app.api_ma import rotate_api_key as _rotate_api_key
    try:
        result = _rotate_api_key(key_id)
        if result is None:
            raise HTTPException(status_code=404, detail="API key not found")
        return {"status": "ok", "data": {"key": result}}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ── Role Management ────────────────────────────────────────────────────

@router.get("/roles", summary="List all roles")
async def list_roles(
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """List all defined roles with their permission sets."""
    from app.api_ma import list_roles as _list_roles
    result = _list_roles()
    return {"status": "ok", "data": result}


@router.get("/roles/{role_name}", summary="Get role details")
async def get_role(
    role_name: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Get details of a specific role including its permissions."""
    from app.api_ma import get_role as _get_role
    result = _get_role(role_name)
    if not result:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")
    return {"status": "ok", "data": result}


@router.post("/roles", summary="Create custom role", status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleCreateRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Create a new custom role with specified permissions.

    Permission strings use the format ``resource.action`` (e.g. ``user.create``,
    ``gpo.delete``, ``dns.recordcreate``).  See ``/api/v1/mgmt/permissions`` for
    the full list of available permissions.
    """
    from app.api_ma import create_role as _create_role
    try:
        result = _create_role(
            name=body.name,
            permissions=body.permissions,
            description=body.description,
        )
        return {"status": "ok", "data": result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put("/roles/{role_name}", summary="Update role")
async def update_role(
    role_name: str,
    body: RoleUpdateRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Update a role's attributes (description, permissions, or rename).

    Built-in roles (admin, operator, auditor) can have their permissions
    updated but cannot be renamed or deleted.
    """
    from app.api_ma import update_role as _update_role
    kwargs = {k: v for k, v in {
        "name": body.name, "description": body.description,
        "permissions": body.permissions,
    }.items() if v is not None}
    if not kwargs:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        result = _update_role(role_name, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not result:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")
    return {"status": "ok", "data": result}


@router.delete("/roles/{role_name}", summary="Delete custom role")
async def delete_role(
    role_name: str,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Delete a custom (non-built-in) role.

    Built-in roles (admin, operator, auditor) cannot be deleted.
    """
    from app.api_ma import delete_role as _delete_role
    result = _delete_role(role_name)
    if not result:
        raise HTTPException(
            status_code=400,
            detail=f"Role '{role_name}' not found or is a built-in role that cannot be deleted",
        )
    return {"status": "ok", "message": f"Role '{role_name}' deleted"}


# ── Permission Management ──────────────────────────────────────────────

@router.get("/permissions", summary="List all available permissions")
async def list_permissions(
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """List all available permissions grouped by category.

    Returns a dictionary mapping resource categories (e.g. 'user', 'group',
    'dns') to lists of permission strings.
    """
    try:
        from app.permissions import get_permissions_by_category, ALL_PERMISSIONS
        return {
            "status": "ok",
            "total": len(ALL_PERMISSIONS),
            "categories": get_permissions_by_category(),
        }
    except ImportError:
        return {"status": "ok", "total": 0, "categories": {}}


@router.post("/permissions/assign", summary="Assign permissions to a role")
async def assign_permissions(
    body: PermissionAssignRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Add one or more permissions to an existing role.

    This appends permissions to the role's current set — it does NOT
    replace existing permissions.
    """
    from app.api_ma import get_role, update_role
    role = get_role(body.role_name)
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{body.role_name}' not found")

    # Merge: current + new
    current = set(role.get("permissions", []))
    new_perms = current | set(body.permissions)

    # Validate permissions
    try:
        from app.permissions import ALL_PERMISSIONS
        invalid = set(body.permissions) - ALL_PERMISSIONS
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid permission strings: {sorted(invalid)}",
            )
    except ImportError:
        pass

    try:
        result = update_role(body.role_name, permissions=sorted(new_perms))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "ok", "data": result}


@router.post("/permissions/revoke", summary="Revoke permissions from a role")
async def revoke_permissions(
    body: PermissionRevokeRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Remove one or more permissions from an existing role."""
    from app.api_ma import get_role, update_role
    role = get_role(body.role_name)
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{body.role_name}' not found")

    # Subtract
    current = set(role.get("permissions", []))
    new_perms = current - set(body.permissions)

    try:
        result = update_role(body.role_name, permissions=sorted(new_perms))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "ok", "data": result}


# ── Audit Log ──────────────────────────────────────────────────────────

@router.get("/audit", summary="View audit log")
async def list_audit_log(
    _: ApiKeyDep,
    user_id: Optional[int] = Query(default=None, description="Filter by user ID"),
    action: Optional[str] = Query(default=None, description="Filter by action"),
    endpoint: Optional[str] = Query(default=None, description="Filter by endpoint"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=100, ge=1, le=500, description="Page size"),
) -> Dict[str, Any]:
    """View audit log entries."""
    try:
        from app.api_ma import list_audit_log as _list_audit_log
        result = _list_audit_log(user_id=user_id, action=action, endpoint=endpoint,
                                 offset=offset, limit=limit)
        return {"status": "ok", "data": result}
    except Exception:
        # Audit log may not be available if api_ma is not initialized
        return {"status": "ok", "data": []}
