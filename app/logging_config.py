"""
Structured JSON logging and request-ID middleware for the
Samba AD DC Management API server.

Features
--------
* **JsonFormatter** — formats every log record as a single-line JSON
  object, making logs trivially parseable by log aggregators (ELK,
  Loki, CloudWatch Logs Insights, etc.).
* **setup_logging()** — one-call configuration of the root logger.
  When the ``SAMBA_LOG_FORMAT`` environment variable is set to ``json``,
  logs are emitted as JSON; otherwise the standard human-readable
  formatter is used (backward-compatible).
* **Request ID middleware** — generates a unique ``request_id`` per
  incoming HTTP request, injects it into the logging context, and
  returns it in the ``X-Request-ID`` response header.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import traceback
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# ── Context variables for structured logging ──────────────────────────

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
task_id_ctx: ContextVar[str] = ContextVar("task_id", default="")
user_id_ctx: ContextVar[str] = ContextVar("user_id", default="")
api_key_id_ctx: ContextVar[str] = ContextVar("api_key_id", default="")
endpoint_ctx: ContextVar[str] = ContextVar("endpoint", default="")


# =====================================================================
# JsonFormatter
# =====================================================================

class JsonFormatter(logging.Formatter):
    """Format a :class:`logging.LogRecord` as a single-line JSON object.

    Standard fields emitted for every record:
        timestamp, level, logger, message, module, function, line

    Extra fields (pulled from the record and/or context variables):
        task_id, duration, user_id, api_key_id, endpoint, request_id

    If the record carries exception info (``exc_info``), the formatted
    traceback is added under the ``traceback`` key.
    """

    # Extra attribute names to promote to top-level JSON fields.
    _EXTRA_FIELDS = (
        "task_id",
        "duration",
        "user_id",
        "api_key_id",
        "endpoint",
        "request_id",
    )

    def format(self, record: logging.LogRecord) -> str:
        # Build the base object
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Promote recognised extra fields from the record
        for field in self._EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is None:
                # Fall back to context variable
                cv_map = {
                    "task_id": task_id_ctx,
                    "user_id": user_id_ctx,
                    "api_key_id": api_key_id_ctx,
                    "endpoint": endpoint_ctx,
                    "request_id": request_id_ctx,
                }
                if field in cv_map:
                    try:
                        value = cv_map[field].get("")
                    except Exception:
                        value = None
            if value:
                log_obj[field] = value

        # Handle any *additional* extra fields that the caller passed
        # via logger.info("msg", extra={...}) — but skip internal ones.
        _internal_attrs = {
            "name", "msg", "args", "created", "relativeCreated",
            "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "pathname", "filename", "module", "thread", "threadName",
            "process", "processName", "levelno", "levelname", "message",
            "msecs", "taskName",
        }
        for key, value in record.__dict__.items():
            if key not in _internal_attrs and key not in self._EXTRA_FIELDS:
                if key.startswith("_"):
                    continue
                log_obj[key] = value

        # Exception / traceback
        if record.exc_info and record.exc_info[0] is not None:
            log_obj["traceback"] = self.formatException(record.exc_info)

        try:
            return json.dumps(log_obj, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            # Last resort — emit what we can
            return json.dumps(
                {"message": str(log_obj.get("message", ""))},
                ensure_ascii=False,
            )


# =====================================================================
# Standard (human-readable) formatter
# =====================================================================

class StandardFormatter(logging.Formatter):
    """Standard coloured formatter with request-id support.

    Falls back to the classic ``asctime level name  message`` pattern
    when no request context is available.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Inject request_id if available from context
        rid = request_id_ctx.get("")
        if rid:
            record.request_id_display = f"[{rid[:8]}] "
        else:
            record.request_id_display = ""

        fmt = (
            "%(asctime)s %(levelname)-8s %(name)s  "
            "%(request_id_display)s%(message)s"
        )
        self._style._fmt = fmt  # type: ignore[attr-defined]
        return super().format(record)


# =====================================================================
# setup_logging()
# =====================================================================

def setup_logging(
    log_level: str = "INFO",
    json_format: bool = False,
) -> None:
    """Configure the root logger for the application.

    Parameters
    ----------
    log_level:
        One of DEBUG, INFO, WARNING, ERROR, CRITICAL.
    json_format:
        If *True*, use :class:`JsonFormatter`; otherwise use the
        human-readable :class:`StandardFormatter`.  When *json_format*
        is not given, the ``SAMBA_LOG_FORMAT`` environment variable is
        consulted (``json`` enables JSON output).
    """
    # Determine format mode
    if not json_format:
        env_fmt = os.environ.get("SAMBA_LOG_FORMAT", "").lower().strip()
        json_format = env_fmt == "json"

    level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove any existing handlers (avoid duplicate output)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(StandardFormatter())

    root_logger.addHandler(handler)

    # Quiet down noisy third-party loggers
    for noisy in ("uvicorn.access", "uvicorn.error", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    mode = "JSON" if json_format else "standard"
    root_logger.info(
        "Logging configured: level=%s format=%s", log_level, mode,
    )


# =====================================================================
# Request ID middleware
# =====================================================================

class RequestIDMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that:

    1. Generates a unique ``request_id`` (UUID4) for each request.
    2. Stores it in a :class:`contextvars.ContextVar` so that log
       messages emitted during the request automatically include it.
    3. Propagates an incoming ``X-Request-ID`` header if present
       (useful for distributed tracing).
    4. Adds ``X-Request-ID`` to the response headers.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Use the caller-provided ID or generate a new one
        req_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex

        # Set context variables for this request
        rid_token = request_id_ctx.set(req_id)
        ep_token = endpoint_ctx.set(request.url.path)

        # Also store api_key_id if present (masked for security)
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # Only store a truncated hint — never log the full key
            api_key_id_ctx.set(f"key_{api_key[:4]}***")

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            # Reset context variables
            request_id_ctx.reset(rid_token)
            endpoint_ctx.reset(ep_token)
            try:
                api_key_id_ctx.set("")
            except Exception:
                pass
