"""
FastAPI application entry-point for the Samba AD DC Management API.

Creates the application instance, registers middleware, exception
handlers, startup/shutdown hooks, and mounts all API routers.

v1.4.3: Added shell router for bash/python3 command execution.
v2.8:   Added batch router for multi-step sequential operations.
v2.7:   Major upgrade — JWT auth, rate limiting, caching, pagination,
        WebSocket task notifications, Prometheus metrics, structured
        logging, extended user/OU management, CSV import/export,
        OU tree, system stats, Dockerfile, config.yaml support.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.executor import SambaToolError, classify_samba_error
from app.models.common import ErrorResponse
from app.worker import shutdown_worker_pool

# Import Pydantic models at module level so that FastAPI/Pydantic can resolve
# them even when ``from __future__ import annotations`` is active.
# (Annotations become strings and are evaluated in the *module* global namespace,
# so names imported inside a function are invisible to Pydantic.)
from app.auth_jwt import LoginRequest, TokenResponse, RefreshRequest, MeResponse, CheckCredentialsRequest

logger = logging.getLogger(__name__)


# ── Lifespan (startup / shutdown) ──────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage resources that live for the duration of the application."""
    settings = get_settings()

    # ---- Startup ----
    _tmpdir = os.environ.get("TMPDIR", "")
    if not _tmpdir or _tmpdir == "/tmp":
        os.environ["TMPDIR"] = "/var/tmp"
        os.environ["TMP"] = "/var/tmp"
        os.environ["TEMP"] = "/var/tmp"
        logger.info("Set TMPDIR=/var/tmp in server process environment")

    # v2.7: Structured logging setup
    from app.logging_config import setup_logging
    log_format_json = os.environ.get("SAMBA_LOG_FORMAT", "standard").lower() == "json"
    setup_logging(settings.LOG_LEVEL, json_format=log_format_json)

    logger.info(
        "Samba API Server starting – host=%s port=%d workers=%d",
        settings.API_HOST,
        settings.API_PORT,
        settings.WORKER_POOL_SIZE,
    )

    from app.worker import get_worker_pool  # noqa: WPS433
    get_worker_pool()

    # v2.7: Initialize management database (api_ma)
    try:
        from app.api_ma import init_db
        init_db()
        logger.info("Management database initialized")
    except Exception as exc:
        logger.warning("Failed to initialize management database: %s", exc)

    # v2.7: Initialize cache
    try:
        from app.cache import get_cache
        cache = get_cache()
        stats = cache.stats()
        logger.info("Response cache initialized (max_size=%d, default_ttl=%ds)",
                     stats["maxsize"], cache._default_ttl)
    except Exception as exc:
        logger.warning("Failed to initialize cache: %s", exc)

    # v2.7: Install WebSocket hooks on TaskManager
    try:
        from app.tasks import get_task_manager
        from app.ws import get_ws_manager, install_task_hooks
        tm = get_task_manager()
        wsm = get_ws_manager()
        install_task_hooks(tm, wsm)
        logger.info("WebSocket task hooks installed")
    except Exception as exc:
        logger.warning("Failed to install WebSocket task hooks: %s", exc)

    logger.info("Registered API routes:")
    for route in app.routes:
        if hasattr(route, "methods") and hasattr(route, "path"):
            methods = ",".join(route.methods - {"HEAD", "OPTIONS"})  # type: ignore[operator]
            logger.info("  %s %s", methods, route.path)

    yield  # <- application is running

    # ---- Shutdown ----
    logger.info("Samba API Server shutting down")

    # v1.6.8-2: Call projet graceful shutdown from lifespan (not atexit/signal)
    try:
        from app.routers.shell_projet import graceful_shutdown_projet
        graceful_shutdown_projet()
    except Exception as exc:
        logger.warning("Error during projet shutdown: %s", exc)

    try:
        from app.samdb_direct import reset_all_samdb_connections
        reset_all_samdb_connections()
    except ImportError:
        pass

    # v2.7: Cleanup WebSocket connections
    try:
        from app.ws import get_ws_manager
        wsm = get_ws_manager()
        # Close all active WebSocket connections
        for task_id, connections in list(wsm._task_connections.items()):
            for ws in list(connections):
                try:
                    await ws.close(code=1001, reason="Server shutting down")
                except Exception:
                    pass
        for ws in list(wsm._global_connections):
            try:
                await ws.close(code=1001, reason="Server shutting down")
            except Exception:
                pass
        logger.info("WebSocket connections closed")
    except Exception as exc:
        logger.warning("Error closing WebSocket connections: %s", exc)

    # v2.7: Cleanup cache
    try:
        from app.cache import get_cache
        cache = get_cache()
        cache.invalidate_all()
    except Exception:
        pass

    shutdown_worker_pool(wait=True)


# ── Application factory ────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Build and return the fully configured :class:`FastAPI` instance."""

    app = FastAPI(
        title="Samba AD DC Management API",
        version="pr-a.1.1",
        description=(
            "REST API for administering Samba AD DC via samba-tool.\n\n"
            "## Authentication\n"
            "Supports both **API Key** (``X-API-Key`` header) and "
            "**JWT Bearer** (``Authorization: Bearer <token>``) authentication.\n\n"
            "## Versions\n"
            "- v1.2.1_fix: Added fast ldbsearch-based /full endpoints and dashboard\n"
            "- v1.2.2_fix: Fixed cache AttributeError, replaced TTLCache internals\n"
            "- v1.2.3_fix: ALL read endpoints now use ldbsearch instead of samba-tool\n"
            "- v1.4.3: Shell execution router\n"
            "- v2.8: Batch operations with rollback\n"
            "- v2.7: JWT auth, rate limiting, caching, pagination, WebSocket, "
            "Prometheus metrics, structured logging, CSV import/export, OU tree, "
            "system stats, user/API-key management\n"
            "- v3.7: Added ``/api/v1/auth/me`` and ``/api/v1/auth/check``\n"
            "- v3.8: ``/auth/check`` now also accepts X-API-Key and JWT Bearer (not only login/password)\n"
            "- v3.9: Fixed contact add ``--ou`` (was ``--contactou``), fixed contact show/move/delete name resolution, added missing contact fields\n"
            "- v1.6.7: Shell Project — fixed async run race, config from settings, concurrent run protection, WS client compat\n"
            "- v1.6.6: Shell Project /list routing fix, separate rate limit category, debug delays\n"
        ),
        lifespan=lifespan,
    )

    # ── CORS ───────────────────────────────────────────────────────
    # v2.7: Configurable CORS origins
    from app.middleware import get_cors_config
    cors_config = get_cors_config(settings=None)  # Will read from env
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_config.get("allow_origins", ["*"]),
        allow_credentials=cors_config.get("allow_credentials", True),
        allow_methods=cors_config.get("allow_methods", ["*"]),
        allow_headers=cors_config.get("allow_headers", ["*"]),
    )

    # ── v2.7: Request ID middleware ────────────────────────────────
    from app.logging_config import RequestIDMiddleware
    app.add_middleware(RequestIDMiddleware)

    # ── v2.7: Prometheus metrics middleware ─────────────────────────
    from app.middleware import PrometheusMiddleware
    app.add_middleware(PrometheusMiddleware)

    # ── v2.7: Rate limiting middleware ──────────────────────────────
    from app.middleware import RateLimitMiddleware
    _rate_settings = get_settings()
    app.add_middleware(
        RateLimitMiddleware,
        auth_limit=_rate_settings.RATE_LIMIT_AUTH_PER_MIN,
        read_limit=_rate_settings.RATE_LIMIT_READ_PER_MIN,
        write_limit=_rate_settings.RATE_LIMIT_WRITE_PER_MIN,
        shell_projet_limit=getattr(_rate_settings, 'RATE_LIMIT_SHELL_PROJET_PER_MIN', 120),
        window_seconds=getattr(_rate_settings, 'RATE_LIMIT_WINDOW_SECONDS', 60),
    )

    # ── Combined Auth middleware (API Key + JWT) ──────────────────
    _PUBLIC_PATHS: frozenset[str] = frozenset({
        "/health",
        "/health/detailed",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/api/v1/auth/login",      # v2.7: Login endpoint
        "/api/v1/auth/refresh",    # v2.7: Refresh token endpoint
        "/api/v1/auth/check",      # v3.7: Credentials check endpoint
    })

    _PUBLIC_PREFIXES: tuple[str, ...] = (
        "/docs",
        "/ws/",                     # v2.7: WebSocket endpoints
    )

    @app.middleware("http")
    async def combined_auth_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Enforce API-key or JWT authentication on every non-public path.

        v2.7: Supports both X-API-Key header and Bearer JWT tokens.
        Checks API key against both the static SAMBA_API_KEY and the
        management database (api_ma), and also validates JWT tokens.
        """
        path = request.url.path

        # Skip auth for public paths
        if path in _PUBLIC_PATHS:
            return await call_next(request)
        if any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES):
            return await call_next(request)
        if request.method == "OPTIONS":
            return await call_next(request)

        settings = get_settings()

        # Try JWT Bearer token first
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                from app.auth_jwt import decode_token
                payload = decode_token(token)
                if payload and payload.get("type") == "access":
                    # v2.8: Permission check for JWT tokens
                    jwt_role = payload.get("role", "operator")
                    try:
                        from app.api_ma import has_permission
                        if not has_permission(jwt_role, request.method, path):
                            # Try to resolve the specific permission for better error msg
                            try:
                                from app.permissions import resolve_permission
                                req_perm = resolve_permission(request.method, path)
                                perm_msg = f" (requires: {req_perm})" if req_perm else ""
                            except Exception:
                                perm_msg = ""
                            return JSONResponse(
                                status_code=403,
                                content=ErrorResponse(
                                    status="error",
                                    message=f"Role '{jwt_role}' does not have permission for {request.method} {path}{perm_msg}",
                                ).model_dump(),
                            )
                    except Exception:
                        pass  # Permission system not available, allow
                    # Store user info in request state for downstream use
                    request.state.user = payload
                    request.state.auth_method = "jwt"
                    request.state.role = jwt_role
                    return await call_next(request)
            except Exception as exc:
                logger.debug("JWT validation failed: %s", exc)
                return JSONResponse(
                    status_code=401,
                    content=ErrorResponse(
                        status="error",
                        message=f"Invalid or expired JWT token: {exc}",
                    ).model_dump(),
                )

        # Try API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # v2.7: Check against management DB first, then static key
            validated = False
            role = "admin"

            # Check management DB (api_ma)
            try:
                from app.api_ma import validate_api_key
                result = validate_api_key(api_key)
                if result:
                    validated = True
                    role = result.get("role", "operator")
                    request.state.api_key_info = result
                    request.state.auth_method = "api_key"
            except Exception:
                pass  # api_ma not available, fall back to static key

            # Fallback: check static API key from settings
            if not validated:
                import secrets
                if secrets.compare_digest(api_key, settings.API_KEY):
                    validated = True
                    request.state.auth_method = "static_api_key"

            if validated:
                request.state.role = role
                # v2.8: Granular permission-based access control
                from app.api_ma import has_permission
                if not has_permission(role, request.method, path):
                    # Try to resolve the specific permission for better error msg
                    perm_msg = ""
                    try:
                        from app.permissions import resolve_permission
                        req_perm = resolve_permission(request.method, path)
                        if req_perm:
                            perm_msg = f" (requires: {req_perm})"
                    except Exception:
                        pass
                    return JSONResponse(
                        status_code=403,
                        content=ErrorResponse(
                            status="error",
                            message=f"Role '{role}' does not have permission for {request.method} {path}{perm_msg}",
                        ).model_dump(),
                    )
                # Audit log the authenticated action
                try:
                    from app.api_ma import log_action
                    key_info = getattr(request.state, 'api_key_info', None)
                    log_action(
                        user_id=key_info.get('user_id') if key_info else None,
                        api_key_id=key_info.get('key_id') if key_info else None,
                        action=f"{request.method} {path}",
                        endpoint=path,
                        ip_address=request.client.host if request.client else "",
                    )
                except Exception:
                    pass  # Audit logging is best-effort
                return await call_next(request)

            return JSONResponse(
                status_code=401,
                content=ErrorResponse(
                    status="error",
                    message="Invalid API key",
                ).model_dump(),
            )

        # No authentication provided
        return JSONResponse(
            status_code=401,
            content=ErrorResponse(
                status="error",
                message="Missing authentication. Provide X-API-Key header or Authorization: Bearer token",
            ).model_dump(),
        )

    # ── v2.7: Cache invalidation middleware ─────────────────────────
    # v1.2.1_fix: Also invalidates ldb_reader cache on write ops.
    @app.middleware("http")
    async def cache_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Invalidate cache on write operations.

        On POST/PUT/DELETE/PATCH requests, invalidates both the
        response cache (``app.cache``) and the ldb_reader internal
        cache so that subsequent ``/full`` endpoint reads return
        fresh data from ldbsearch.
        """
        response = await call_next(request)

        # Invalidate cache on write operations
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            try:
                from app.cache import get_cache
                cache = get_cache()
                cache.invalidate_for_write(request.url.path)
            except Exception:
                pass
            # v1.2.1_fix: Also invalidate ldb_reader cache
            try:
                from app.ldb_reader import invalidate_cache
                invalidate_cache()
            except Exception:
                pass

        return response

    # ── Custom exception handlers ──────────────────────────────────

    @app.exception_handler(SambaToolError)
    async def samba_tool_error_handler(  # type: ignore[no-untyped-def]
        request: Request,
        exc: SambaToolError,
    ):
        http_status = exc.http_status
        if http_status == 500:
            http_status = classify_samba_error(exc)
        logger.error(
            "SambaToolError on %s (HTTP %d): %s",
            request.url.path, http_status, exc,
        )
        return JSONResponse(
            status_code=http_status,
            content=ErrorResponse(
                status="error",
                message=str(exc),
            ).model_dump(),
        )

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(  # type: ignore[no-untyped-def]
        request: Request,
        exc: RuntimeError,
    ):
        http_status = classify_samba_error(exc)
        logger.error("RuntimeError on %s (HTTP %d): %s", request.url.path, http_status, exc)
        return JSONResponse(
            status_code=http_status,
            content=ErrorResponse(
                status="error",
                message=str(exc),
            ).model_dump(),
        )

    @app.exception_handler(TimeoutError)
    async def timeout_error_handler(  # type: ignore[no-untyped-def]
        request: Request,
        exc: TimeoutError,
    ):
        logger.error("TimeoutError on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=504,
            content=ErrorResponse(
                status="error",
                message="Operation timed out",
                details=str(exc),
            ).model_dump(),
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(  # type: ignore[no-untyped-def]
        request: Request,
        exc: ValueError,
    ):
        logger.warning("ValueError on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                status="error",
                message=str(exc),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(  # type: ignore[no-untyped-def]
        request: Request,
        exc: Exception,
    ):
        logger.exception("Unhandled exception on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                status="error",
                message="Internal server error",
                details=str(exc) if logger.isEnabledFor(logging.DEBUG) else None,
            ).model_dump(),
        )

    # ── Health check ───────────────────────────────────────────────

    @app.get("/health", tags=["system"])
    async def health_check() -> dict[str, str]:
        settings = get_settings()
        role = settings.ensure_server_role()
        return {
            "status": "ok",
            "service": "samba-api-server",
            "server_role": role,
            "version": "pr-a.1.1",
        }

    # v2.7: Detailed health check
    @app.get("/health/detailed", tags=["system"])
    async def health_check_detailed() -> dict:
        from app.monitoring import get_health_detailed
        return get_health_detailed()

    # v2.7: Prometheus metrics endpoint
    @app.get("/metrics", tags=["system"])
    async def prometheus_metrics():
        from app.monitoring import get_metrics
        from app.middleware import get_prometheus_metrics
        metrics = get_metrics()
        # Merge middleware HTTP metrics
        mw_metrics = get_prometheus_metrics()
        return {**metrics.get_stats(), **mw_metrics}

    # v2.7: System stats endpoint
    @app.get("/api/v1/system/stats", tags=["system"])
    async def system_stats():
        from app.monitoring import get_system_stats, get_samba_stats
        return {
            "status": "ok",
            "system": get_system_stats(),
            "samba": get_samba_stats(),
        }

    # v2.7: Management API endpoints (api_ma router)
    from app.routers import mgmt  # Management API router
    app.include_router(mgmt.router)

    # ── Auth endpoints ─────────────────────────────────────────────
    from app.auth_jwt import authenticate_login, create_access_token, create_refresh_token, decode_token

    @app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Authentication"])
    async def login(body: LoginRequest):
        """Authenticate with username/password and get JWT tokens."""
        from app.api_ma import authenticate_user
        user = authenticate_user(body.username, body.password)
        if not user:
            raise HTTPException(
                status_code=401,
                detail={"status": "error", "message": "Invalid username or password"},
            )
        token_data = {"sub": user["username"], "role": user["role"]}
        # v2.8: Include permissions in the token
        try:
            from app.api_ma import get_role_permissions
            perms = sorted(get_role_permissions(user["role"]))
            token_data["permissions"] = perms
        except Exception:
            perms = []
        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token(token_data)
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=1800,
            role=user["role"],
            permissions=perms,
        )

    @app.post("/api/v1/auth/refresh", tags=["Authentication"])
    async def refresh(body: RefreshRequest):
        """Refresh an access token using a refresh token."""
        try:
            payload = decode_token(body.refresh_token)
            if not payload or payload.get("type") != "refresh":
                raise HTTPException(status_code=401, detail="Invalid refresh token")
            token_data = {"sub": payload["sub"], "role": payload["role"]}
            # v2.8: Re-fetch permissions from current role definition
            try:
                from app.api_ma import get_role_permissions
                perms = sorted(get_role_permissions(payload["role"]))
                token_data["permissions"] = perms
            except Exception:
                perms = payload.get("permissions", [])
                token_data["permissions"] = perms
            access_token = create_access_token(token_data)
            new_refresh = create_refresh_token(token_data)
            return TokenResponse(
                access_token=access_token,
                refresh_token=new_refresh,
                token_type="bearer",
                expires_in=1800,
                role=payload["role"],
                permissions=perms,
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"Token refresh failed: {exc}")

    # ── /me endpoint — current user info ───────────────────────────
    @app.get("/api/v1/auth/me", response_model=MeResponse, tags=["Authentication"])
    async def me(request: Request):
        """Return the authenticated user's role, permissions, and expiry info.

        Works with **both** authentication methods:

        * **API Key** — provide the ``X-API-Key`` header.
        * **JWT Bearer** — provide the ``Authorization: Bearer <token>`` header.

        The response includes the user's role, the full list of permissions
        assigned to that role, and the token/key expiry timestamp (if any).
        """
        auth_method = getattr(request.state, "auth_method", None)

        if auth_method == "jwt":
            # JWT Bearer token authentication
            user_payload = getattr(request.state, "user", {})
            role = user_payload.get("role", "unknown")
            permissions = user_payload.get("permissions", [])

            # Re-fetch permissions from the role definition in case
            # they were updated after the token was issued.
            try:
                from app.api_ma import get_role_permissions
                fresh_perms = sorted(get_role_permissions(role))
                if fresh_perms:
                    permissions = fresh_perms
            except Exception:
                pass

            # JWT expiry from token payload
            expires_at = ""
            try:
                exp_ts = user_payload.get("exp")
                if exp_ts:
                    from datetime import datetime, timezone
                    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
            except Exception:
                pass

            username = user_payload.get("sub", "")

            return MeResponse(
                status="ok",
                auth_method="jwt",
                username=username,
                role=role,
                permissions=permissions,
                expires_at=expires_at,
            )

        elif auth_method in ("api_key", "static_api_key"):
            # API Key authentication
            role = getattr(request.state, "role", "unknown")
            key_info = getattr(request.state, "api_key_info", {})

            # Fetch permissions for the role
            permissions = []
            try:
                from app.api_ma import get_role_permissions
                permissions = sorted(get_role_permissions(role))
            except Exception:
                pass

            # API key expiry
            expires_at = key_info.get("expires_at", "") or ""

            username = key_info.get("username", "")

            return MeResponse(
                status="ok",
                auth_method="api_key",
                username=username,
                role=role,
                permissions=permissions,
                expires_at=expires_at or "",
            )

        else:
            raise HTTPException(
                status_code=401,
                detail={"status": "error", "message": "Not authenticated"},
            )

    # ── /auth/check — check credentials (login/password OR X-API-Key OR JWT) ─
    @app.post("/api/v1/auth/check", response_model=MeResponse, tags=["Authentication"])
    async def check_credentials(request: Request, body: CheckCredentialsRequest = None):
        """Verify credentials and return role & permissions.

        Accepts **three** authentication methods (at least one required):

        1. **X-API-Key** header — validates the API key and returns its
           role, permissions, and expiry.
        2. **Authorization: Bearer <token>** — validates a JWT access
           token and returns the embedded role & permissions.
        3. **Username + password** in the request body — validates the
           login/password pair and returns the account's role &
           permissions.

        You can combine methods (e.g. send an API key *and* a body), but
        only the first successfully validated method is used.  Priority:
        API key → JWT → username/password.
        """
        # ── Method 1: X-API-Key header ───────────────────────────────
        api_key = request.headers.get("X-API-Key")
        if api_key:
            settings = get_settings()
            validated = False
            role = "admin"
            key_info = {}

            # Check management DB (api_ma)
            try:
                from app.api_ma import validate_api_key
                result = validate_api_key(api_key)
                if result:
                    validated = True
                    role = result.get("role", "operator")
                    key_info = result
            except Exception:
                pass

            # Fallback: check static API key
            if not validated:
                import secrets as _secrets
                if _secrets.compare_digest(api_key, settings.API_KEY):
                    validated = True
                    role = "admin"

            if validated:
                permissions = []
                try:
                    from app.api_ma import get_role_permissions
                    permissions = sorted(get_role_permissions(role))
                except Exception:
                    pass

                return MeResponse(
                    status="ok",
                    auth_method="api_key",
                    username=key_info.get("username", ""),
                    role=role,
                    permissions=permissions,
                    expires_at=key_info.get("expires_at", "") or "",
                )

        # ── Method 2: JWT Bearer token ───────────────────────────────
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                from app.auth_jwt import decode_token
                payload = decode_token(token)
                if payload and payload.get("type") == "access":
                    jwt_role = payload.get("role", "unknown")
                    permissions = payload.get("permissions", [])

                    # Re-fetch fresh permissions from role definition
                    try:
                        from app.api_ma import get_role_permissions
                        fresh_perms = sorted(get_role_permissions(jwt_role))
                        if fresh_perms:
                            permissions = fresh_perms
                    except Exception:
                        pass

                    # JWT expiry
                    expires_at = ""
                    try:
                        exp_ts = payload.get("exp")
                        if exp_ts:
                            from datetime import datetime, timezone
                            expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
                    except Exception:
                        pass

                    return MeResponse(
                        status="ok",
                        auth_method="jwt",
                        username=payload.get("sub", ""),
                        role=jwt_role,
                        permissions=permissions,
                        expires_at=expires_at,
                    )
            except Exception:
                pass  # Invalid JWT, fall through to next method

        # ── Method 3: Username + password in body ────────────────────
        if body and body.username and body.password:
            from app.api_ma import authenticate_user
            user = authenticate_user(body.username, body.password)
            if not user:
                raise HTTPException(
                    status_code=401,
                    detail={"status": "error", "message": "Invalid username or password"},
                )

            role = user.get("role", "unknown")
            permissions = []
            try:
                from app.api_ma import get_role_permissions
                permissions = sorted(get_role_permissions(role))
            except Exception:
                pass

            return MeResponse(
                status="ok",
                auth_method="credentials",
                username=user.get("username", body.username),
                role=role,
                permissions=permissions,
                expires_at="",
            )

        # ── No valid authentication provided ─────────────────────────
        raise HTTPException(
            status_code=401,
            detail={
                "status": "error",
                "message": "No valid authentication provided. Send X-API-Key header, Authorization: Bearer token, or username/password in body.",
            },
        )

    # ── Routers ────────────────────────────────────────────────────
    from app.routers import (
        user,
        group,
        computer,
        contact,
        ou,
        domain,
        dns,
        sites,
        fsmo,
        drs,
        gpo,
        schema,
        delegation,
        service_account,
        auth_policy,
        misc,
        shell,             # v1.4.3: Shell execution router
        batch,             # v2.8: Batch execution router
        user_mgmt,         # v2.7: Extended user management (search, import/export, batch)
        ou_mgmt,           # v2.7: Extended OU management (tree, stats, search)
        dashboard,         # v1.2.1_fix: Full AD dashboard via ldbsearch
        shell_projet,      # v1.6.4: Shell Project router (workspace + WebSocket)
        ai,                # v1.6.8-1: AI Assistant router (OpenRouter + Task Builder)
    )

    api_prefix = "/api/v1"
    app.include_router(user.router, prefix=api_prefix)
    app.include_router(group.router, prefix=api_prefix)
    app.include_router(computer.router, prefix=api_prefix)
    app.include_router(contact.router, prefix=api_prefix)
    app.include_router(ou.router, prefix=api_prefix)
    app.include_router(domain.router, prefix=api_prefix)
    app.include_router(dns.router, prefix=api_prefix)
    app.include_router(sites.router, prefix=api_prefix)
    app.include_router(fsmo.router, prefix=api_prefix)
    app.include_router(drs.router, prefix=api_prefix)
    app.include_router(gpo.router, prefix=api_prefix)
    app.include_router(schema.router, prefix=api_prefix)
    app.include_router(delegation.router, prefix=api_prefix)
    app.include_router(service_account.router, prefix=api_prefix)
    app.include_router(auth_policy.router, prefix=api_prefix)
    app.include_router(misc.router, prefix=api_prefix)
    app.include_router(shell.router, prefix=api_prefix)           # v1.4.3
    app.include_router(batch.router, prefix=api_prefix)           # v2.8
    app.include_router(user_mgmt.router, prefix=api_prefix)       # v2.7
    app.include_router(ou_mgmt.router, prefix=api_prefix)         # v2.7
    app.include_router(dashboard.router, prefix=api_prefix)       # v1.2.1_fix
    app.include_router(shell_projet.router, prefix=api_prefix)    # v1.6.4
    app.include_router(ai.router, prefix=api_prefix)               # v1.6.8-1

    # v1.6.8-3 fix #1: Register app reference for in-memory OpenAPI access
    # This allows the AI service to get /openapi.json without making an HTTP
    # self-request (which caused a deadlock with single-worker uvicorn).
    try:
        from app.services.ai_service import register_app
        register_app(app)
    except Exception as exc:
        logger.warning("Failed to register app for AI service: %s", exc)

    # ── Task status endpoint ────────────────────────────────────────
    from app.tasks import get_task_manager

    @app.get("/api/v1/tasks/{task_id}")
    async def get_task(task_id: str):
        tm = get_task_manager()
        task_status = tm.get_task_status(task_id)
        if task_status is None:
            raise HTTPException(status_code=404, detail="Task not found")
        return task_status

    # v2.7: List all tasks
    @app.get("/api/v1/tasks", tags=["Tasks"])
    async def list_tasks():
        tm = get_task_manager()
        return {"status": "ok", "tasks": tm.list_tasks()}

    # v2.7: WebSocket endpoints for task notifications
    from app.ws import get_ws_manager

    @app.websocket("/ws/tasks/{task_id}")
    async def ws_task_status(websocket: WebSocket, task_id: str):
        """WebSocket endpoint for real-time task status updates."""
        wsm = get_ws_manager()
        tm = get_task_manager()

        # Check if task exists
        task_status = tm.get_task_status(task_id)
        if task_status is None:
            await websocket.close(code=1008, reason="Task not found")
            return

        await wsm.connect(websocket, task_id)
        try:
            # Send current status immediately
            await websocket.send_json(task_status)
            # Keep connection alive, wait for disconnect
            while True:
                try:
                    data = await websocket.receive_text()
                    # Client can send "ping" to keep alive
                    if data == "ping":
                        await websocket.send_json({"type": "pong"})
                except WebSocketDisconnect:
                    break
        finally:
            wsm.disconnect(websocket, task_id)

    @app.websocket("/ws/tasks")
    async def ws_all_tasks(websocket: WebSocket):
        """WebSocket endpoint for monitoring all task updates (dashboard)."""
        wsm = get_ws_manager()
        tm = get_task_manager()

        await wsm.connect(websocket)
        try:
            # Send snapshot of all current tasks
            await websocket.send_json({
                "type": "tasks_snapshot",
                "tasks": tm.list_tasks(),
            })
            while True:
                try:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_json({"type": "pong"})
                except WebSocketDisconnect:
                    break
        finally:
            wsm.disconnect(websocket)

    # ── v1.6.4: WebSocket endpoints for Shell Project ──────────────────
    from app.shell_projet_ws import get_projet_ws_manager
    from app.routers.shell_projet import _projects as _projet_registry

    @app.websocket("/ws/projet/{projet_id}")
    async def ws_projet_output(websocket: WebSocket, projet_id: str):
        """WebSocket endpoint for real-time project execution output.

        Connect to this endpoint to receive real-time stdout/stderr
        output as a project's command executes. Also receives status
        changes (creating, running, completed, failed) and archive
        extraction events.

        Messages are JSON objects with a ``type`` field:
        - ``output`` — stdout/stderr data chunk
        - ``status`` — project status change
        - ``command_result`` — final result of command execution
        - ``extract_result`` — archive extraction result
        """
        pws_mgr = get_projet_ws_manager()

        # Check if project exists
        record = _projet_registry.get(projet_id)

        await pws_mgr.connect(websocket, projet_id=projet_id)
        try:
            # Send current project status immediately
            if record:
                import json as _json
                await websocket.send_text(_json.dumps({
                    "type": "status",
                    "projet_id": projet_id,
                    "status": record.status,
                    "workspace": record.workspace_path,
                    "ts": time.time(),
                }))
            else:
                import json as _json
                await websocket.send_text(_json.dumps({
                    "type": "error",
                    "projet_id": projet_id,
                    "message": f"Project '{projet_id}' not found in registry",
                }))

            # Keep connection alive
            while True:
                try:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_json({"type": "pong"})
                except WebSocketDisconnect:
                    break
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.warning("WebSocket error for projet %s: %s", projet_id, exc)
        finally:
            await pws_mgr.disconnect(websocket, projet_id=projet_id)

    @app.websocket("/ws/projet")
    async def ws_all_projets(websocket: WebSocket):
        """WebSocket endpoint for monitoring all project events (dashboard).

        Receives every project event across the system: status changes,
        output chunks, extraction results, and command results.
        """
        pws_mgr = get_projet_ws_manager()

        await pws_mgr.connect(websocket, projet_id=None)
        try:
            # Send snapshot of current projects
            import json as _json
            await websocket.send_text(_json.dumps({
                "type": "projets_snapshot",
                "count": len(_projet_registry),
                "projects": [
                    p.to_workspace_info().model_dump()
                    for p in _projet_registry.values()
                ],
            }))

            while True:
                try:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_json({"type": "pong"})
                except WebSocketDisconnect:
                    break
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.warning("WebSocket error on global projet channel: %s", exc)
        finally:
            await pws_mgr.disconnect(websocket, projet_id=None)

    return app


# ── Module-level app instance ──────────────────────────────────────────
app = create_app()
