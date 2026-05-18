"""
Authentication module for the Samba AD DC Management API.

v2.8: Supports both static API key (legacy) and management DB API keys
(with granular permission-based access control). JWT authentication
is handled separately in auth_jwt.py and validated in the combined
auth middleware in main.py.

Every request (except public paths) must include either:
- ``X-API-Key`` header matching a configured key, OR
- ``Authorization: Bearer <jwt>`` header with valid JWT token
"""

from __future__ import annotations

import secrets
from typing import Annotated, Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.config import Settings, get_settings

# ── Header definition ───────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _extract_api_key(
    request: Request,
    api_key: Annotated[str | None, Security(api_key_header)] = None,
) -> str | None:
    """Return the raw API key from the request header, or *None*."""
    return api_key


def verify_api_key(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    api_key: Annotated[str | None, Depends(_extract_api_key)],
) -> str:
    """FastAPI dependency that validates the ``X-API-Key`` header.

    v2.9: Also accepts requests already authenticated via JWT by the
    combined auth middleware (``request.state.auth_method == "jwt"``).
    This allows JWT-bearing clients to access management endpoints
    (users, keys, roles, audit) without an API key.

    Returns
    -------
    str
        The validated API key value, or ``"jwt"`` for JWT-authenticated
        requests.

    Raises
    ------
    HTTPException
        401 if the key is missing or does not match any valid key and
        the request was not authenticated via JWT.
    """
    # v2.9: If the combined auth middleware already authenticated this
    # request via JWT, honour that and skip the API-key requirement.
    auth_method = getattr(request.state, "auth_method", None)
    if auth_method == "jwt":
        return "jwt"

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": "Missing X-API-Key header or Authorization Bearer token",
            },
        )

    # v2.8: Check management DB first
    try:
        from app.api_ma import validate_api_key
        result = validate_api_key(api_key)
        if result:
            return api_key
    except Exception:
        pass  # api_ma not available, fall back to static key

    # Use constant-time comparison to prevent timing attacks.
    if not secrets.compare_digest(api_key, settings.API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": "Invalid API key",
            },
        )

    return api_key


# Convenient type alias for injection into route handlers.
ApiKeyDep = Annotated[str, Depends(verify_api_key)]


# ── v2.8: Permission-based dependencies ────────────────────────────────

def require_permission(permission: str):
    """Dependency factory that checks the authenticated user's permissions.

    Parameters
    ----------
    permission : str
        The required permission string (e.g. ``user.create``, ``gpo.delete``).

    Returns
    -------
    Callable
        A FastAPI dependency that raises 403 if the user lacks the permission.

    Example::

        @router.post("/", dependencies=[Depends(require_permission("user.create"))])
        async def create_user(...):
            ...
    """
    async def _check_permission(request: Request) -> Dict[str, Any]:
        # Get role from request state (set by auth middleware)
        role = getattr(request.state, "role", None)

        # If no role in state, try JWT payload
        if role is None:
            user = getattr(request.state, "user", None)
            if user and isinstance(user, dict):
                role = user.get("role")

        if role is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "status": "error",
                    "message": f"Permission '{permission}' required but no role found",
                },
            )

        # Check permission via api_ma
        try:
            from app.api_ma import has_specific_permission
            if has_specific_permission(role, permission):
                return {"role": role, "permission": permission}
        except Exception:
            pass

        # Admin always has all permissions
        if role == "admin":
            return {"role": role, "permission": permission}

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "status": "error",
                "message": (
                    f"Role '{role}' does not have permission '{permission}'. "
                    f"Required: {permission}"
                ),
            },
        )

    return _check_permission
