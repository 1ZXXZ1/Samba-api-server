"""
Middleware collection for the Samba AD DC Management API.

Provides rate limiting, CORS configuration, request logging, and
lightweight Prometheus-style metrics — all without external dependencies
beyond the standard library and Starlette/FastAPI.

Usage in ``app/main.py``::

    from app.middleware import (
        RateLimitMiddleware,
        get_cors_config,
        RequestLoggingMiddleware,
        PrometheusMiddleware,
    )

    app.add_middleware(PrometheusMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, settings=get_settings())

    cors_cfg = get_cors_config(get_settings())
    app.add_middleware(CORSMiddleware, **cors_cfg)
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# 1. RateLimitMiddleware
# ═══════════════════════════════════════════════════════════════════════

# Endpoint group classification
_AUTH_PREFIXES = ("/api/v1/auth/",)
_SHELL_PROJET_PREFIXES = ("/api/v1/shell/projet",)
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class _SlidingWindowCounter:
    """In-memory sliding-window rate counter.

    Tracks request counts per key within a sliding time window.
    Uses a simple dict of ``{key: [(timestamp, ...), ...]}`` and prunes
    entries older than the window on every check.
    """

    def __init__(self, window_seconds: int = 60) -> None:
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def _prune(self, key: str, now: float) -> None:
        """Remove timestamps outside the window."""
        cutoff = now - self.window
        self._buckets[key] = [ts for ts in self._buckets[key] if ts > cutoff]

    def count(self, key: str) -> int:
        """Return the current count for *key* within the window."""
        now = time.monotonic()
        self._prune(key, now)
        return len(self._buckets[key])

    def increment(self, key: str) -> int:
        """Record a hit and return the new count."""
        now = time.monotonic()
        self._prune(key, now)
        self._buckets[key].append(now)
        return len(self._buckets[key])

    def reset(self, key: str) -> None:
        """Clear the counter for *key*."""
        self._buckets.pop(key, None)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limiting middleware using in-memory sliding window counters.

    Configurable limits per endpoint group:

    * **Auth endpoints** (``/api/v1/auth/*``): configurable per IP
    * **Shell Project endpoints** (``/api/v1/shell/projet/*``): configurable per user
    * **Read endpoints** (GET): configurable per user
    * **Write endpoints** (POST/PUT/PATCH/DELETE): configurable per user

    Returns HTTP 429 with a ``Retry-After`` header when the limit is
    exceeded.  Uses ``X-Forwarded-For`` for IP detection (first entry).

    v1.6.7: Shell projet concurrent run protection — the /run endpoint now
    checks running status synchronously before executing, preventing race
    conditions.
    All limits are now configurable via environment variables:
    - SAMBA_RATE_LIMIT_AUTH_PER_MIN
    - SAMBA_RATE_LIMIT_READ_PER_MIN
    - SAMBA_RATE_LIMIT_WRITE_PER_MIN
    - SAMBA_RATE_LIMIT_SHELL_PROJET_PER_MIN
    - SAMBA_RATE_LIMIT_WINDOW_SECONDS

    Parameters
    ----------
    app : ASGIApp
        The wrapped ASGI application.
    auth_limit : int
        Max requests per minute for auth endpoints (default 10).
    read_limit : int
        Max requests per minute for read endpoints (default 100).
    write_limit : int
        Max requests per minute for write endpoints (default 30).
    shell_projet_limit : int
        Max requests per minute for shell projet endpoints (default 120).
        Shell projet has higher limits because project workflows involve
        multiple sequential API calls (create → upload → run → show).
    window_seconds : int
        Sliding window size in seconds (default 60).
    """

    # Paths that bypass rate limiting entirely
    _EXEMPT_PATHS: frozenset[str] = frozenset({
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
    })

    def __init__(
        self,
        app: Any,
        auth_limit: int = 10,
        read_limit: int = 100,
        write_limit: int = 30,
        shell_projet_limit: int = 120,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)
        self.auth_limit = auth_limit
        self.read_limit = read_limit
        self.write_limit = write_limit
        self.shell_projet_limit = shell_projet_limit
        self._counter = _SlidingWindowCounter(window_seconds=window_seconds)
        self._window = window_seconds

    def _client_ip(self, request: Request) -> str:
        """Extract client IP, honouring X-Forwarded-For."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # First entry is the original client
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def _user_id(self, request: Request) -> str:
        """Best-effort user identification for rate-limit keying.

        Checks for a Bearer token or X-API-Key header; falls back to IP.
        """
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            # Use a hash of the token as the key to avoid storing raw tokens
            token_part = auth_header[7:27]  # first 20 chars is unique enough
            return f"bearer:{token_part}"
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"apikey:{api_key[:8]}"
        return f"ip:{self._client_ip(request)}"

    def _classify(self, request: Request) -> tuple[str, int]:
        """Classify the request and return (key_prefix, limit)."""
        path = request.url.path
        # Check auth endpoints first
        for prefix in _AUTH_PREFIXES:
            if path.startswith(prefix):
                return "auth", self.auth_limit
        # v1.6.6: Shell projet endpoints get their own rate limit
        for prefix in _SHELL_PROJET_PREFIXES:
            if path.startswith(prefix):
                return "shell_projet", self.shell_projet_limit
        if request.method in _WRITE_METHODS:
            return "write", self.write_limit
        return "read", self.read_limit

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # Exempt paths (health, docs, etc.)
        if path in self._EXEMPT_PATHS or path.startswith("/docs"):
            return await call_next(request)

        # OPTIONS preflight — no rate limit
        if request.method == "OPTIONS":
            return await call_next(request)

        group, limit = self._classify(request)

        # Auth endpoints are rate-limited per IP; others per user
        if group == "auth":
            identifier = self._client_ip(request)
        else:
            identifier = self._user_id(request)

        key = f"{group}:{identifier}"
        current = self._counter.increment(key)

        if current > limit:
            retry_after = self._window
            logger.warning(
                "Rate limit exceeded: group=%s identifier=%s count=%d limit=%d",
                group, identifier, current, limit,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "status": "error",
                    "message": (
                        f"Rate limit exceeded for {group} endpoints. "
                        f"Limit: {limit} requests per {self._window}s."
                    ),
                },
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)


# ═══════════════════════════════════════════════════════════════════════
# 2. CORS configuration helper
# ═══════════════════════════════════════════════════════════════════════

def get_cors_config(settings: Any) -> dict[str, Any]:
    """Return keyword arguments for ``CORSMiddleware``.

    Reads ``SAMBA_CORS_ORIGINS`` (comma-separated) from the environment.
    If set, uses specific origins; if not, falls back to ``["*"]``
    (backward compatible with the current wildcard configuration).

    Parameters
    ----------
    settings : Settings
        The application settings instance (used for env access).

    Returns
    -------
    dict
        Keyword arguments suitable for ``app.add_middleware(CORSMiddleware, **...)``.
    """
    origins_str = os.environ.get("SAMBA_CORS_ORIGINS", "").strip()

    if origins_str:
        origins = [o.strip() for o in origins_str.split(",") if o.strip()]
    else:
        origins = ["*"]

    return {
        "allow_origins": origins,
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }


# ═══════════════════════════════════════════════════════════════════════
# 3. RequestLoggingMiddleware
# ═══════════════════════════════════════════════════════════════════════

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs every request in a structured format.

    Logs the HTTP method, path, status code, and duration.  Includes
    the user/API key identifier when available.  Output is suitable
    for JSON log aggregation (use a JSON formatter in logging config).
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start = time.monotonic()
        start_utc = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

        # Best-effort user identification
        user_id = self._identify_user(request)

        # Process the request
        response = await call_next(request)

        duration_ms = (time.monotonic() - start) * 1000

        logger.info(
            "request_completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "query": str(request.query_params) if request.query_params else "",
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "user_id": user_id,
                "client_ip": self._client_ip(request),
                "timestamp": start_utc,
            },
        )

        # Also emit a human-readable line for non-JSON log setups
        logger.info(
            "%s %s → %d (%.1fms) user=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            user_id,
        )

        return response

    @staticmethod
    def _identify_user(request: Request) -> str:
        """Return a best-effort user identifier for log entries."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return f"bearer:{auth_header[7:27]}"
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"apikey:{api_key[:8]}"
        return "anonymous"

    @staticmethod
    def _client_ip(request: Request) -> str:
        """Extract client IP, honouring X-Forwarded-For."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "-"


# ═══════════════════════════════════════════════════════════════════════
# 4. PrometheusMiddleware (lightweight, no prometheus_client dependency)
# ═══════════════════════════════════════════════════════════════════════

class PrometheusMiddleware(BaseHTTPMiddleware):
    """Lightweight request metrics middleware.

    Tracks:
    * Request counts by method, endpoint, and status code
    * Request duration histogram (bucketed)

    All data is stored in-memory.  Expose via :func:`get_metrics()` for
    scraping.  Does **not** depend on ``prometheus_client``.
    """

    # Duration histogram buckets in milliseconds
    _BUCKETS: tuple[float, ...] = (
        5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
    )

    def __init__(self, app: Any) -> None:
        super().__init__(app)
        # {("GET", "/api/v1/users", 200): 42, ...}
        self._counters: dict[tuple[str, str, int], int] = defaultdict(int)
        # {("GET", "/api/v1/users"): {5: 0, 10: 3, 25: 7, ...}, ...}
        self._histograms: dict[tuple[str, str], dict[float, int]] = defaultdict(
            lambda: {b: 0 for b in self._BUCKETS}
        )
        self._total_requests: int = 0

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # v1.6.7-4: Store start time so PrometheusMiddleware can read it
        request.state._start_time = time.monotonic()

        response = await call_next(request)

        method = request.method
        path = self._normalize_path(request.url.path)
        status_code = response.status_code
        duration_ms = 0.0

        # Read duration from _start_time set by this middleware
        if hasattr(request.state, "_start_time"):
            duration_ms = (time.monotonic() - request.state._start_time) * 1000

        # Update counters
        self._counters[(method, path, status_code)] += 1
        self._total_requests += 1

        # Update histogram
        hist = self._histograms[(method, path)]
        for bucket in self._BUCKETS:
            if duration_ms <= bucket:
                hist[bucket] += 1

        return response

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a URL path for metrics grouping.

        Replaces UUID/path-parameter-like segments with placeholders
        to avoid cardinality explosion.
        """
        import re
        # Replace UUIDs
        path = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ":id",
            path,
            flags=re.IGNORECASE,
        )
        # Replace numeric IDs
        path = re.sub(r"/\d+", "/:id", path)
        return path


# ── Prometheus metrics accessors ──────────────────────────────────────

# Module-level reference so get_metrics() works even before middleware is added
_prometheus_instance: PrometheusMiddleware | None = None


def register_prometheus(middleware: PrometheusMiddleware) -> None:
    """Register the Prometheus middleware instance for metrics access."""
    global _prometheus_instance
    _prometheus_instance = middleware


def get_metrics() -> dict[str, Any]:
    """Return current metrics as a dict suitable for serialization.

    Example output::

        {
            "total_requests": 1234,
            "counters": [
                {"method": "GET", "endpoint": "/api/v1/users", "status": 200, "count": 42},
                ...
            ],
            "histograms": [
                {"method": "GET", "endpoint": "/api/v1/users", "buckets": {"5": 0, "10": 3, ...}},
                ...
            ]
        }
    """
    if _prometheus_instance is None:
        return {"total_requests": 0, "counters": [], "histograms": []}

    inst = _prometheus_instance

    counters = [
        {
            "method": key[0],
            "endpoint": key[1],
            "status": key[2],
            "count": count,
        }
        for key, count in sorted(inst._counters.items())
    ]

    histograms = [
        {
            "method": key[0],
            "endpoint": key[1],
            "buckets": {str(b): c for b, c in sorted(buckets.items())},
        }
        for key, buckets in sorted(inst._histograms.items())
    ]

    return {
        "total_requests": inst._total_requests,
        "counters": counters,
        "histograms": histograms,
    }
