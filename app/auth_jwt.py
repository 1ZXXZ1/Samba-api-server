"""
JWT / OAuth2 authentication for the Samba AD DC Management API.

Provides JWT-based authentication alongside the existing API key auth
(``app.auth``).  Tokens are signed with HS256 using python-jose and
contain the standard claims ``sub`` (username), ``role``, ``exp``,
``iat``, and ``type`` (access / refresh).

Usage in route handlers::

    from app.auth_jwt import AuthDep, AdminDep

    @router.get("/me")
    async def me(user: AuthDep):
        return {"username": user["username"], "role": user["role"]}

    @router.delete("/dangerous")
    async def dangerous(user: AdminDep):
        ...

Settings additions (to be added to ``app/config.py``)::

    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

If ``JWT_SECRET_KEY`` is empty, a secret is auto-generated on first run
and persisted in a simple file (``~/.samba-api-jwt-secret``) so that
server restarts do not invalidate existing tokens.
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from jose import JWTError, jwt

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

# ── JWT Settings defaults ──────────────────────────────────────────────

_JWT_ALGORITHM_DEFAULT = "HS256"
_JWT_ACCESS_EXPIRE_MINUTES_DEFAULT = 30
_JWT_REFRESH_EXPIRE_DAYS_DEFAULT = 7
_JWT_SECRET_FILE = os.path.join(
    os.environ.get("HOME", "/tmp"), ".samba-api-jwt-secret"
)

# ── In-memory user database (mirrors api_ma) ──────────────────────────
# NOTE: In production this should query the real Samba AD / api_ma DB.
# For now we provide a small in-memory mapping that can be replaced.
# Roles: admin, operator, auditor, viewer

_USER_DB: dict[str, dict[str, Any]] = {
    # Populated on startup / first authenticate call from config
}


def _ensure_user_db(settings: Settings) -> dict[str, dict[str, Any]]:
    """Populate the in-memory user DB from settings if not yet done.

    At minimum, create an ``admin`` user from the configured API key
    credentials so that the login endpoint works out of the box.
    """
    if _USER_DB:
        return _USER_DB
    # Default admin user – password matches API key by convention.
    _USER_DB["admin"] = {
        "username": "admin",
        "password": settings.API_KEY,  # initial password = API key
        "role": "admin",
        "disabled": False,
    }
    return _USER_DB


# ── Secret key management ─────────────────────────────────────────────

def _get_jwt_secret(settings: Settings) -> str:
    """Return the JWT signing secret, generating one if needed.

    Priority:
    1. ``settings.JWT_SECRET_KEY`` (env ``SAMBA_JWT_SECRET_KEY``)
    2. Auto-generated key persisted to ``_JWT_SECRET_FILE``
    """
    configured = getattr(settings, "JWT_SECRET_KEY", "")
    if configured:
        return configured

    # Try to load persisted secret
    try:
        if os.path.isfile(_JWT_SECRET_FILE):
            with open(_JWT_SECRET_FILE, "r") as fh:
                persisted = fh.read().strip()
                if persisted:
                    return persisted
    except OSError:
        pass

    # Generate and persist
    new_secret = secrets.token_urlsafe(48)
    try:
        with open(_JWT_SECRET_FILE, "w") as fh:
            fh.write(new_secret)
        os.chmod(_JWT_SECRET_FILE, 0o600)
        logger.info("Generated new JWT secret key and saved to %s", _JWT_SECRET_FILE)
    except OSError as exc:
        logger.warning(
            "Could not persist JWT secret to %s: %s. "
            "Tokens will be invalidated on restart.",
            _JWT_SECRET_FILE,
            exc,
        )
    return new_secret


# ── Token creation / decoding ─────────────────────────────────────────

def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token.

    Parameters
    ----------
    data : dict
        Payload claims.  Must contain ``sub`` (username) and ``role``.
    expires_delta : timedelta | None
        Custom expiry delta.  Falls back to
        ``JWT_ACCESS_TOKEN_EXPIRE_MINUTES`` from settings.

    Returns
    -------
    str
        Encoded JWT string.
    """
    settings = get_settings()
    algorithm = getattr(settings, "JWT_ALGORITHM", _JWT_ALGORITHM_DEFAULT)
    expire_minutes = getattr(
        settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", _JWT_ACCESS_EXPIRE_MINUTES_DEFAULT
    )
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=expire_minutes)
    )
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    })
    return jwt.encode(to_encode, _get_jwt_secret(settings), algorithm=algorithm)


def create_refresh_token(data: dict[str, Any]) -> str:
    """Create a signed JWT refresh token (longer expiry).

    Parameters
    ----------
    data : dict
        Payload claims.  Must contain ``sub`` (username) and ``role``.

    Returns
    -------
    str
        Encoded JWT string.
    """
    settings = get_settings()
    algorithm = getattr(settings, "JWT_ALGORITHM", _JWT_ALGORITHM_DEFAULT)
    expire_days = getattr(
        settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", _JWT_REFRESH_EXPIRE_DAYS_DEFAULT
    )
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=expire_days)
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
    })
    return jwt.encode(to_encode, _get_jwt_secret(settings), algorithm=algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token.

    Parameters
    ----------
    token : str
        Encoded JWT string.

    Returns
    -------
    dict
        Decoded claims.

    Raises
    ------
    JWTError
        If the token is invalid, expired, or the signature does not match.
    """
    settings = get_settings()
    algorithm = getattr(settings, "JWT_ALGORITHM", _JWT_ALGORITHM_DEFAULT)
    return jwt.decode(token, _get_jwt_secret(settings), algorithms=[algorithm])


# ── Login authentication ──────────────────────────────────────────────

def authenticate_login(username: str, password: str) -> dict[str, Any] | None:
    """Validate username/password against the user DB and return token pair.

    v2.8: Uses api_ma.authenticate_user() for the actual credential check
    so that JWT login goes through the same bcrypt-verified path as
    API-key creation.  Falls back to the in-memory user DB if api_ma
    is unavailable.

    Parameters
    ----------
    username : str
        The username to authenticate.
    password : str
        The plaintext password to verify.

    Returns
    -------
    dict | None
        Token response dict on success, ``None`` on failure.
    """
    settings = get_settings()

    # v2.8: Try api_ma first (authoritative source)
    user_info = None
    try:
        from app.api_ma import authenticate_user
        user_info = authenticate_user(username, password)
    except Exception:
        pass  # api_ma unavailable

    if user_info is None:
        # Fallback to in-memory user DB
        users = _ensure_user_db(settings)
        user = users.get(username)
        if user is None:
            return None
        if user.get("disabled"):
            return None

        # Timing-safe comparison for password
        if not secrets.compare_digest(password, user["password"]):
            return None

        user_info = {"username": username, "role": user["role"]}

    # Build tokens with role and permissions
    role = user_info.get("role", "operator")

    # v2.8: Include role permissions in the token for fast permission checks
    permissions = []
    try:
        from app.api_ma import get_role_permissions
        permissions = sorted(get_role_permissions(role))
    except Exception:
        pass

    token_data = {
        "sub": username,
        "role": role,
        "permissions": permissions,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    expire_minutes = getattr(
        settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", _JWT_ACCESS_EXPIRE_MINUTES_DEFAULT
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": expire_minutes * 60,  # seconds
        "role": role,
        "permissions": permissions,
    }


# ── Pydantic models ───────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """Request body for the login endpoint."""

    username: str = Field(..., description="Username for authentication.")
    password: str = Field(..., description="Plaintext password.")


class TokenResponse(BaseModel):
    """Response body containing JWT tokens."""

    access_token: str = Field(..., description="Short-lived access token.")
    refresh_token: str = Field(..., description="Long-lived refresh token.")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer').")
    expires_in: int = Field(..., description="Access token TTL in seconds.")
    role: str = Field(..., description="User role (admin, operator, auditor, viewer).")
    permissions: list[str] = Field(
        default_factory=list,
        description="List of permission strings assigned to the role.",
    )


class RefreshRequest(BaseModel):
    """Request body for the token-refresh endpoint."""

    refresh_token: str = Field(..., description="A valid refresh token.")


class MeResponse(BaseModel):
    """Response body for the /me and /auth/check endpoints.

    Returns the authenticated user's role, permissions, and token/key
    expiry information.
    """

    status: str = Field(default="ok", description="Response status.")
    auth_method: str = Field(
        ...,
        description="Authentication method used: 'jwt', 'api_key', or 'credentials'.",
    )
    username: str = Field(default="", description="Authenticated username.")
    role: str = Field(..., description="User role (admin, operator, auditor, or custom).")
    permissions: list[str] = Field(
        default_factory=list,
        description="List of permission strings assigned to the role.",
    )
    expires_at: str = Field(
        default="",
        description=(
            "ISO-8601 expiry timestamp of the token/key. "
            "Empty string if the token/key does not expire."
        ),
    )


class CheckCredentialsRequest(BaseModel):
    """Request body for the /auth/check endpoint.

    Both fields are optional — the endpoint also accepts X-API-Key
    header or Authorization: Bearer token as alternative authentication
    methods.  At least one authentication method must be provided.
    """

    username: Optional[str] = Field(default=None, description="Username to verify (optional if X-API-Key or Bearer token is provided).")
    password: Optional[str] = Field(default=None, description="Plaintext password to verify (optional if X-API-Key or Bearer token is provided).")


# ── OAuth2 scheme ─────────────────────────────────────────────────────

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


# ── FastAPI dependencies ──────────────────────────────────────────────

async def get_current_user(
    token: Annotated[str | None, Depends(oauth2_scheme)] = None,
) -> dict[str, Any]:
    """Validate JWT from ``Authorization: Bearer`` header.

    Returns
    -------
    dict
        User info: ``{"username": ..., "role": ...}``.

    Raises
    ------
    HTTPException
        401 if the token is missing, invalid, or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"status": "error", "message": "Could not validate credentials"},
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token is None:
        raise credentials_exception

    try:
        payload = decode_token(token)
    except JWTError:
        raise credentials_exception

    # Verify it's an access token, not a refresh token
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"status": "error", "message": "Invalid token type; access token required"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    username: str | None = payload.get("sub")
    role: str | None = payload.get("role")

    if username is None or role is None:
        raise credentials_exception

    # v2.8: Verify user still exists and is active via api_ma
    try:
        from app.api_ma import get_user_by_username
        user = get_user_by_username(username)
        if user is None or not user.get("is_active"):
            raise credentials_exception
    except Exception:
        # Fallback to in-memory user DB
        settings = get_settings()
        users = _ensure_user_db(settings)
        user = users.get(username)
        if user is None or user.get("disabled"):
            raise credentials_exception

    # v2.8: Include permissions in the returned user info
    return {
        "username": username,
        "role": role,
        "permissions": payload.get("permissions", []),
    }


def require_role(*roles: str):
    """Dependency factory that checks the authenticated user's role.

    Parameters
    ----------
    *roles : str
        One or more allowed role names.  The user must have at least one.

    Returns
    -------
    Callable
        A FastAPI dependency that raises 403 if the role does not match.

    Example::

        @router.delete("/", dependencies=[Depends(require_role("admin"))])
        async def dangerous():
            ...
    """
    async def _check_role(
        user: Annotated[dict[str, Any], Depends(get_current_user)],
    ) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "status": "error",
                    "message": (
                        f"Role '{user['role']}' not permitted. "
                        f"Required: one of {list(roles)}."
                    ),
                },
            )
        return user

    return _check_role


# ── Convenience type aliases ──────────────────────────────────────────

#: Authenticated user – any valid JWT bearer.
AuthDep = Annotated[dict[str, Any], Depends(get_current_user)]

#: Admin-only dependency.
AdminDep = Annotated[dict[str, Any], Depends(require_role("admin"))]

#: Operator or admin dependency.
OperatorDep = Annotated[
    dict[str, Any], Depends(require_role("operator", "admin"))
]

#: Auditor, operator, or admin dependency.
AuditorDep = Annotated[
    dict[str, Any], Depends(require_role("auditor", "operator", "admin"))
]
