"""
AI Assistant service for the Task Builder (v1.6.8-5).

Integrates with OpenRouter (https://openrouter.ai) to provide an AI agent
that translates natural-language requests into structured API call sequences
for the Samba AD Management Task Builder (ETL Constructor).

Key features:
    - OpenRouter integration via the ``openai`` Python SDK
    - Automatic OpenAPI schema compression and caching
    - **Progressive schema compression** with configurable max size
    - Safe Mode: strips real data values, keeps only keys and types
    - Server-side validation of AI responses against real OpenAPI schema
    - Permission-aware action filtering
    - Audit logging of all AI interactions
    - 429 rate-limit retry with Retry-After header respect
    - 402 / connection-error → skip to next fallback model immediately
    - Fallback model chain when primary model is rate-limited

v1.6.8-3 fixes:
    #1  OpenAPI schema self-deadlock
    #2  model=string bug

v1.6.8-4 fix:
    429 Rate Limit retry with Retry-After header respect + fallback model chain

v1.6.8-5 fixes:
    **Prompt too large** — 217 endpoints × full detail = 55,356 chars ≈ 38,860
    prompt tokens.  This causes:
    - 402 "insufficient credits" on paid models (prompt + max_tokens > balance)
    - Slow/expensive requests even when they succeed
    - Connection timeouts on long-running retries

    Fixes:
    1. **Progressive schema compression** — if the compressed schema exceeds
       ``AI_MAX_SCHEMA_CHARS`` (default 12000), it is progressively stripped:
         - Level 1 (full): paths + methods + operationId + summary + params + body_fields
         - Level 2: paths + methods + operationId + summary (strip params, body_fields)
         - Level 3: paths + methods + operationId (strip summary too)
         - Level 4: paths + methods only (minimal)
    2. **402 → immediate fallback** — 402 means "insufficient credits", retrying
       the same model is pointless. Skip to next fallback model immediately.
    3. **Connection errors → retry** — DNS failures / connection resets are
       transient. Retry up to 2 times with exponential backoff before failing.
    4. **Prompt token estimation logging** — log estimated prompt tokens before
       sending so the admin can tune ``AI_MAX_SCHEMA_CHARS``.

    New config:
      ``SAMBA_AI_MAX_SCHEMA_CHARS`` — max compressed schema size in chars (default: 12000)

Configuration (via environment variables with SAMBA_ prefix):
    SAMBA_AI_OPENROUTER_API_KEY   — OpenRouter API key (required)
    SAMBA_AI_DEFAULT_MODEL        — Default LLM model (default: openrouter/free)
    SAMBA_AI_TEMPERATURE          — LLM temperature (default: 0.7)
    SAMBA_AI_MAX_TOKENS           — Max completion tokens (default: 2046)
    SAMBA_AI_API_BASE             — Base URL of this API server (default: http://127.0.0.1:8099)
    SAMBA_AI_RATE_LIMIT_RETRIES   — Max 429 retries per model (default: 3)
    SAMBA_AI_RATE_LIMIT_MAX_WAIT  — Max wait seconds per 429 retry (default: 30)
    SAMBA_AI_FALLBACK_MODELS      — Fallback models if primary is rate-limited
    SAMBA_AI_MAX_SCHEMA_CHARS     — Max compressed schema size in chars (default: 12000)
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from app.config import get_settings
from app.models.ai import AIAction, AIRequest, AIResponse

logger = logging.getLogger(__name__)

# ── Module-level state ──────────────────────────────────────────────────

_openapi_compressed: Optional[str] = None
_openapi_raw: Optional[Dict[str, Any]] = None
_openapi_loaded_at: float = 0.0
_OPENAPI_CACHE_TTL = 300  # seconds — refresh schema every 5 minutes

# v1.6.8-3 fix #1: Store reference to FastAPI app for in-memory OpenAPI access
_fastapi_app: Optional[Any] = None

# v1.6.8-3 fix #2: Known-invalid model names that should be rejected
_INVALID_MODEL_NAMES = {"string", "str", "int", "float", "bool", "none", "null", ""}


def register_app(app: Any) -> None:
    """Store a reference to the FastAPI app instance for in-memory OpenAPI access.

    Called once from main.py during app creation. This avoids the need
    for HTTP self-requests to fetch /openapi.json.
    """
    global _fastapi_app
    _fastapi_app = app
    logger.info("[AI] FastAPI app reference registered for in-memory OpenAPI access")


# ═══════════════════════════════════════════════════════════════════════
#  OpenAPI Schema Loading & Compression
# ═══════════════════════════════════════════════════════════════════════


def _compress_schema_raw(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Compress raw OpenAPI schema to Level 1 (full detail).

    Keeps: paths, methods, operationId, summary, params, body_fields.
    This is the most detailed compression level.
    """
    compressed: Dict[str, Any] = {}
    for path, methods in raw.get("paths", {}).items():
        compressed[path] = {}
        for method, details in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            entry: Dict[str, Any] = {}
            op_id = details.get("operationId", "")
            if op_id:
                entry["operationId"] = op_id
            summary = details.get("summary", "")
            if summary:
                entry["summary"] = summary

            # Parameters
            params = []
            for p in details.get("parameters", []):
                pname = p.get("name", "")
                if pname:
                    prequired = p.get("required", False)
                    pin = p.get("in", "")
                    params.append({
                        "name": pname,
                        "in": pin,
                        "required": prequired,
                    })
            if params:
                entry["params"] = params

            # Request body fields
            request_body = details.get("requestBody")
            if request_body:
                content = request_body.get("content", {})
                for _ct, ct_details in content.items():
                    schema_ref = ct_details.get("schema", {})
                    props = schema_ref.get("properties", {})
                    if props:
                        body_fields = list(props.keys())
                        required_body = schema_ref.get("required", [])
                        entry["body_fields"] = body_fields
                        entry["body_required"] = required_body
                    break  # Only first content type

            compressed[path][method.upper()] = entry
    return compressed


def _strip_to_level(compressed: Dict[str, Any], level: int) -> Dict[str, Any]:
    """Progressively strip schema detail to reduce token count.

    Levels:
        1 — Full: paths + methods + operationId + summary + params + body_fields
        2 — Medium: paths + methods + operationId + summary (strip params, body_fields)
        3 — Compact: paths + methods + operationId (strip summary too)
        4 — Minimal: paths + methods only
    """
    result: Dict[str, Any] = {}
    for path, methods in compressed.items():
        result[path] = {}
        for method, details in methods.items():
            if not isinstance(details, dict):
                # level 4 might have simplified to just method: True
                result[path][method] = details
                continue

            if level >= 4:
                # Minimal: just path + method, no detail at all
                result[path][method] = True
            elif level >= 3:
                # Compact: operationId only
                entry: Dict[str, Any] = {}
                if "operationId" in details:
                    entry["operationId"] = details["operationId"]
                result[path][method] = entry
            elif level >= 2:
                # Medium: operationId + summary (no params/body)
                entry = {}
                if "operationId" in details:
                    entry["operationId"] = details["operationId"]
                if "summary" in details:
                    entry["summary"] = details["summary"]
                result[path][method] = entry
            else:
                # Level 1: full detail (as-is)
                result[path][method] = details
    return result


def load_openapi_schema() -> Tuple[str, Dict[str, Any]]:
    """Load and compress the OpenAPI schema from the running server.

    v1.6.8-5: Uses progressive schema compression. If the compressed schema
    exceeds ``AI_MAX_SCHEMA_CHARS`` (default 12000), it is progressively
    stripped to reduce token count:
        - Level 1 (full): all details
        - Level 2: strip params + body_fields
        - Level 3: strip summary too
        - Level 4: keep only paths + methods

    The schema is cached for 5 minutes.
    """
    global _openapi_compressed, _openapi_raw, _openapi_loaded_at

    now = time.time()
    if _openapi_compressed is not None and (now - _openapi_loaded_at) < _OPENAPI_CACHE_TTL:
        return _openapi_compressed, _openapi_raw or {}

    raw: Dict[str, Any] = {}

    # v1.6.8-3 fix #1: Use in-memory app.openapi() instead of HTTP self-request
    if _fastapi_app is not None:
        try:
            logger.info("[AI] Fetching OpenAPI schema from app (in-memory)")
            raw = _fastapi_app.openapi()
            if not raw or not isinstance(raw, dict):
                raise ValueError("app.openapi() returned empty or invalid data")
        except Exception as exc:
            logger.error("[AI] Failed to get OpenAPI schema from app: %s", exc)
            raw = {}
    else:
        # Fallback: HTTP request (only if app reference not registered)
        logger.warning("[AI] FastAPI app reference not registered, falling back to HTTP fetch")
        settings = get_settings()
        openapi_url = f"{settings.AI_API_BASE.rstrip('/')}/openapi.json"
        try:
            import httpx
            logger.info("[AI] Fetching OpenAPI schema from %s (HTTP fallback)", openapi_url)
            resp = httpx.get(openapi_url, timeout=15)
            resp.raise_for_status()
            raw = resp.json()
        except Exception as exc:
            logger.error("[AI] Failed to load OpenAPI schema via HTTP: %s", exc)
            if _openapi_compressed is None:
                _openapi_compressed = "{}"
                _openapi_raw = {}
            return _openapi_compressed, _openapi_raw or {}

    if not raw:
        if _openapi_compressed is None:
            _openapi_compressed = "{}"
            _openapi_raw = {}
        return _openapi_compressed, _openapi_raw or {}

    # Compress to Level 1 (full detail) first
    compressed = _compress_schema_raw(raw)

    # v1.6.8-5: Progressive compression to fit within AI_MAX_SCHEMA_CHARS
    settings = get_settings()
    max_schema_chars = getattr(settings, "AI_MAX_SCHEMA_CHARS", 12000)

    total_endpoints = sum(len(v) for v in compressed.values())
    level_names = {1: "full", 2: "medium", 3: "compact", 4: "minimal"}

    for level in range(1, 5):
        if level == 1:
            candidate = compressed
        else:
            candidate = _strip_to_level(compressed, level)

        candidate_str = json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))

        if len(candidate_str) <= max_schema_chars:
            _openapi_compressed = candidate_str
            if level > 1:
                logger.info(
                    "[AI] Schema compressed to level %d (%s): %d endpoints, %d chars "
                    "(target: %d chars)",
                    level, level_names.get(level, "?"),
                    total_endpoints, len(candidate_str), max_schema_chars,
                )
            break
    else:
        # Even level 4 (minimal) exceeds the limit — truncate paths
        logger.warning(
            "[AI] Schema exceeds max_schema_chars even at minimal level 4 "
            "(%d chars > %d). Using minimal schema anyway.",
            len(candidate_str), max_schema_chars,
        )
        _openapi_compressed = candidate_str

    _openapi_raw = raw
    _openapi_loaded_at = now

    logger.info(
        "[AI] OpenAPI schema loaded: %d endpoints, compressed size: %d chars "
        "(max_schema_chars=%d)",
        total_endpoints, len(_openapi_compressed), max_schema_chars,
    )

    return _openapi_compressed, _openapi_raw or {}


def get_schema_endpoints() -> List[Dict[str, Any]]:
    """Return a flat list of endpoint info from the compressed schema."""
    compressed_str, _ = load_openapi_schema()
    try:
        schema = json.loads(compressed_str)
    except json.JSONDecodeError:
        return []

    endpoints = []
    for path, methods in schema.items():
        for method, details in methods.items():
            if isinstance(details, dict):
                endpoints.append({
                    "method": method,
                    "path": path,
                    "operation_id": details.get("operationId", ""),
                    "summary": details.get("summary", ""),
                    "parameters": [p.get("name", "") for p in details.get("params", [])],
                })
            else:
                # Level 4: details is just True
                endpoints.append({
                    "method": method,
                    "path": path,
                    "operation_id": "",
                    "summary": "",
                    "parameters": [],
                })
    return endpoints


# ═══════════════════════════════════════════════════════════════════════
#  Safe Mode — Context Sanitization
# ═══════════════════════════════════════════════════════════════════════


def sanitize_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Strip real data values from a task graph context, keeping only structure.

    This ensures that PII (usernames, passwords, IPs, group names) is never
    sent to the external LLM. Only keys and value types are preserved.

    Special keys (``node_id``, ``type``, ``id``) are preserved as-is because
    they are structural identifiers, not sensitive data.
    """
    if not context:
        return {}

    # Keys that are structural and should be preserved
    STRUCTURAL_KEYS = {"node_id", "type", "id", "operationId", "method", "path", "label"}

    sanitized: Dict[str, Any] = {}
    for key, value in context.items():
        if key in STRUCTURAL_KEYS:
            sanitized[key] = value
        elif isinstance(value, dict):
            sanitized[key] = sanitize_context(value)
        elif isinstance(value, list):
            if len(value) > 0 and isinstance(value[0], dict):
                sanitized[key] = [sanitize_context(value[0])]
            else:
                sanitized[key] = f"<list[{len(value)}]>"
        elif isinstance(value, bool):
            sanitized[key] = value  # booleans are safe (True/False)
        elif value is None:
            sanitized[key] = None
        elif isinstance(value, (int, float)):
            sanitized[key] = f"<{type(value).__name__}>"
        else:
            sanitized[key] = f"<{type(value).__name__}>"

    return sanitized


# ═══════════════════════════════════════════════════════════════════════
#  AI Response Validation
# ═══════════════════════════════════════════════════════════════════════


def _validate_action_against_schema(
    action: AIAction,
    valid_paths: Dict[str, Set[str]],
) -> Optional[str]:
    """Validate a single AI action against the real OpenAPI schema.

    Returns an error message if the action is invalid, or None if valid.
    """
    if action.type == "add_api_node":
        payload = action.payload
        method = payload.get("method", "").upper()
        path = payload.get("path", "")

        if not method or not path:
            return f"add_api_node missing method or path: {payload}"

        if path not in valid_paths:
            return f"AI suggested unknown path: {path}"

        if method not in valid_paths[path]:
            return f"AI suggested {method} {path} but only {valid_paths[path]} exist"

    elif action.type == "connect_nodes":
        payload = action.payload
        if "from_node_id" not in payload or "to_node_id" not in payload:
            return f"connect_nodes missing from_node_id or to_node_id: {payload}"

    elif action.type == "set_param":
        payload = action.payload
        if "node_id" not in payload or "key" not in payload:
            return f"set_param missing node_id or key: {payload}"

    return None


def _build_valid_paths_map(compressed_str: str) -> Dict[str, Set[str]]:
    """Build a map of path -> set of valid HTTP methods from the compressed schema."""
    try:
        schema = json.loads(compressed_str)
    except json.JSONDecodeError:
        return {}

    result: Dict[str, Set[str]] = {}
    for path, methods in schema.items():
        result[path] = set()
        for method in methods.keys():
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                result[path].add(method.upper())
    return result


# ═══════════════════════════════════════════════════════════════════════
#  Model Name Validation (v1.6.8-3 fix #2)
# ═══════════════════════════════════════════════════════════════════════


def _validate_model_name(model: str) -> str:
    """Validate and return a proper model name.

    Rejects obviously invalid values like "string", "str", etc.
    which can happen when:
    - Pydantic type annotations are misinterpreted as values
    - Frontend sends the type name instead of an actual model ID
    - The env var is set to a type name by mistake

    Returns the validated model name, or the configured default if invalid.
    """
    if not model or model.lower().strip() in _INVALID_MODEL_NAMES:
        settings = get_settings()
        default = settings.AI_DEFAULT_MODEL
        logger.warning(
            "[AI] Invalid model name '%s' rejected, falling back to '%s'",
            model, default,
        )
        return default
    return model


# ═══════════════════════════════════════════════════════════════════════
#  Token Estimation (v1.6.8-5)
# ═══════════════════════════════════════════════════════════════════════


def _estimate_tokens(text: str) -> int:
    """Rough token count estimation.

    Uses the heuristic of ~4 characters per token for English/mixed content.
    This is an approximation — actual token count depends on the model's
    tokenizer, but it's good enough for budget checks.
    """
    return max(1, len(text) // 4)


# ═══════════════════════════════════════════════════════════════════════
#  429 Rate-Limit Retry + Fallback Model Chain (v1.6.8-4)
#  + 402/connection-error handling (v1.6.8-5)
# ═══════════════════════════════════════════════════════════════════════


def _extract_retry_after(exc: Exception) -> Optional[float]:
    """Extract retry_after_seconds from an OpenRouter 429 error.

    OpenRouter 429 errors include ``retry_after_seconds`` in the error
    metadata.  The openai Python SDK wraps this in
    ``exc.response.json()['error']['metadata']['retry_after_seconds']``.

    Returns the wait time in seconds (float), or None if not parseable.
    """
    try:
        resp = getattr(exc, "response", None)
        if resp is not None:
            try:
                body = resp.json()
            except Exception:
                body = {}
            retry_val = (
                body.get("error", {})
                .get("metadata", {})
                .get("retry_after_seconds")
            )
            if retry_val is not None:
                return float(retry_val)

            retry_header = resp.headers.get("Retry-After")
            if retry_header:
                return float(retry_header)
    except Exception as parse_exc:
        logger.debug("[AI] Could not parse Retry-After from 429: %s", parse_exc)

    # Fallback: parse from error message string
    try:
        msg = str(exc)
        match = re.search(r"retry_after_seconds[\"']?\s*[:=]\s*([0-9.]+)", msg)
        if match:
            return float(match.group(1))
    except Exception:
        pass

    return None


def _classify_error(exc: Exception) -> str:
    """Classify an LLM API error into a category for retry/skip decisions.

    Returns one of:
        "rate_limit"   — 429 Too Many Requests (retry with backoff)
        "insufficient" — 402 Payment Required (skip to next fallback immediately)
        "connection"   — Network/DNS error (retry with short backoff)
        "fatal"        — Other error (skip to next fallback immediately)
    """
    exc_class_name = type(exc).__name__
    exc_msg = str(exc)

    # 429 Rate Limit
    if exc_class_name == "RateLimitError" or "429" in exc_msg:
        return "rate_limit"

    # 402 Insufficient Credits / Payment Required
    if "402" in exc_msg or "insufficient" in exc_msg.lower() or "credits" in exc_msg.lower():
        return "insufficient"

    # 400 Bad Request — usually model-specific issue
    if "400" in exc_msg:
        return "fatal"

    # 404 Model Not Found — e.g. "No endpoints found for poolside/laguna-xs.2"
    # v1.6.8-7: Must be classified as fatal so the agent skips to next
    # fallback model immediately instead of retrying a non-existent model.
    if "404" in exc_msg or "no endpoints found" in exc_msg.lower():
        return "fatal"

    # 401/403 Auth errors
    if "401" in exc_msg or "403" in exc_msg:
        return "fatal"

    # Connection errors (DNS, timeout, network)
    if exc_class_name in ("APIConnectionError", "ConnectError", "TimeoutError"):
        return "connection"
    if "connection" in exc_msg.lower() or "temporary failure" in exc_msg.lower():
        return "connection"
    if "timed out" in exc_msg.lower() or "timeout" in exc_msg.lower():
        return "connection"

    # 500/502/503 server errors — might be transient
    if "500" in exc_msg or "502" in exc_msg or "503" in exc_msg:
        return "connection"

    return "fatal"


def _build_model_chain(primary_model: str, settings: Any) -> List[str]:
    """Build the ordered list of models to try.

    Starts with the primary model, then appends each model from
    ``AI_FALLBACK_MODELS`` that is not the same as the primary.
    Duplicates are removed while preserving order.
    """
    chain = [primary_model]
    fallback_str = getattr(settings, "AI_FALLBACK_MODELS", "")
    if fallback_str:
        for m in fallback_str.split(","):
            m = m.strip()
            if m and m not in chain:
                chain.append(m)
    return chain


def _call_llm_with_retry(
    model: str,
    system_prompt: str,
    user_message: str,
    settings: Any,
) -> Union[Dict[str, Any], str]:
    """Call the LLM with retry logic for 429 and connection errors.

    Returns a dict with ``content`` and ``tokens_used`` on success,
    or an error message string on failure.

    v1.6.8-5 error handling:
    - 429 (rate limit): retry with Retry-After backoff
    - 402 (insufficient credits): skip to next fallback immediately (no retry)
    - Connection errors: retry up to 2 times with short backoff
    - Other errors: skip to next fallback immediately (no retry)
    """
    try:
        from openai import OpenAI
    except ImportError:
        return "openai package not installed. Run: pip install openai"

    max_rate_retries = getattr(settings, "AI_RATE_LIMIT_RETRIES", 3)
    max_wait = getattr(settings, "AI_RATE_LIMIT_MAX_WAIT", 30)
    max_conn_retries = 2  # Connection errors: max 2 retries

    # Disable SDK built-in retries — we handle retries ourselves
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=settings.AI_OPENROUTER_API_KEY,
        max_retries=0,
    )

    rate_retries_done = 0
    conn_retries_done = 0
    total_waited = 0.0

    # Cap on total attempts to prevent infinite loops
    max_total_attempts = max_rate_retries + max_conn_retries + 1

    for attempt in range(max_total_attempts):
        try:
            if attempt == 0:
                est_tokens = _estimate_tokens(system_prompt + user_message)
                logger.info(
                    "[AI] Sending request to model=%s, user_prompt_len=%d, "
                    "est_total_tokens~%d, max_tokens=%d",
                    model, len(user_message), est_tokens, settings.AI_MAX_TOKENS,
                )
            else:
                logger.info(
                    "[AI] Retry for model=%s (attempt %d, rate_retries=%d, "
                    "conn_retries=%d, waited %.1fs)",
                    model, attempt + 1, rate_retries_done, conn_retries_done, total_waited,
                )

            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                temperature=settings.AI_TEMPERATURE,
                max_tokens=settings.AI_MAX_TOKENS,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content
            tokens_used = 0
            prompt_tokens = 0
            if response.usage:
                tokens_used = response.usage.total_tokens or 0
                prompt_tokens = response.usage.prompt_tokens or 0

            logger.info(
                "[AI] Response received: %d chars, prompt=%d tokens, total=%d tokens "
                "(model=%s, retries=%d)",
                len(content or ""), prompt_tokens, tokens_used, model,
                rate_retries_done + conn_retries_done,
            )

            return {
                "content": content,
                "tokens_used": tokens_used,
                "prompt_tokens": prompt_tokens,
                "retries": rate_retries_done + conn_retries_done,
                "total_waited": total_waited,
            }

        except ImportError:
            return "openai package not installed. Run: pip install openai"

        except Exception as exc:
            error_type = _classify_error(exc)

            # ── 402 Insufficient Credits → skip immediately ──
            if error_type == "insufficient":
                logger.warning(
                    "[AI] 402 insufficient credits for model=%s, skipping to next fallback: %s",
                    model, str(exc)[:200],
                )
                return (
                    f"Model '{model}' requires more credits: {exc}"
                )

            # ── 429 Rate Limit → retry with backoff ──
            if error_type == "rate_limit" and rate_retries_done < max_rate_retries:
                retry_after = _extract_retry_after(exc)
                if retry_after is not None:
                    wait_time = min(retry_after, max_wait)
                else:
                    wait_time = min(2 ** (rate_retries_done + 1), max_wait)

                rate_retries_done += 1
                total_waited += wait_time
                logger.warning(
                    "[AI] 429 rate limit on model=%s, waiting %.1fs (rate retry %d/%d, "
                    "retry_after=%.1fs). Error: %s",
                    model, wait_time, rate_retries_done, max_rate_retries,
                    retry_after or 0, str(exc)[:200],
                )

                time.sleep(wait_time)
                continue

            # ── Connection error → retry with short backoff ──
            if error_type == "connection" and conn_retries_done < max_conn_retries:
                wait_time = min(2 ** (conn_retries_done + 1), 10)  # 2s, 4s
                conn_retries_done += 1
                total_waited += wait_time
                logger.warning(
                    "[AI] Connection error for model=%s, waiting %.1fs (conn retry %d/%d): %s",
                    model, wait_time, conn_retries_done, max_conn_retries,
                    str(exc)[:200],
                )

                time.sleep(wait_time)
                continue

            # ── Rate limit retries exhausted ──
            if error_type == "rate_limit":
                logger.error(
                    "[AI] 429 rate limit exhausted for model=%s after %d retries (%.1fs waited): %s",
                    model, max_rate_retries, total_waited, str(exc)[:300],
                )
                return (
                    f"Model '{model}' rate-limited after {max_rate_retries} retries "
                    f"({total_waited:.0f}s waited): {exc}"
                )

            # ── Connection retries exhausted ──
            if error_type == "connection":
                logger.error(
                    "[AI] Connection error exhausted for model=%s after %d retries: %s",
                    model, max_conn_retries, str(exc)[:300],
                )
                return f"Model '{model}' connection failed after {max_conn_retries} retries: {exc}"

            # ── Fatal error → skip immediately ──
            logger.error(
                "[AI] Fatal error for model=%s (no retry): %s",
                model, exc, exc_info=True,
            )
            return f"LLM request failed (model={model}): {exc}"

    # Should not reach here
    return f"LLM request failed after all retries for model={model}"


# ═══════════════════════════════════════════════════════════════════════
#  System Prompt
# ═══════════════════════════════════════════════════════════════════════


SYSTEM_PROMPT = """You are an expert AI agent integrated into a Task Builder (ETL Constructor) \
for a Samba Active Directory Domain Controller management API.

Your job is to translate user requests in natural language into a sequence \
of API call nodes for the visual task constructor.

### AVAILABLE API SCHEMA
Below is the compressed schema of available API operations. You MUST only \
use endpoints from this schema — never invent endpoints.

{api_schema}

### SECURITY: SAFE MODE
You are operating in Safe Mode{safe_mode_note}.
- You CANNOT see real data values (usernames, passwords, IPs, group names, etc.).
- Instead of real values, you see only types like `<string>`, `<integer>`, `<list>`.
- When you need a specific value that the user mentioned (e.g., "disable user ivanov"), \
you MUST use the placeholder `{{USER_INPUT}}` as the value and tell the user to fill it in.
- Your job is to build the LOGIC and STRUCTURE of the task. Real data is filled by the user.

### RESPONSE FORMAT
You MUST respond ONLY in valid JSON. No text outside JSON.
Structure:
{{
  "message": "Brief explanation for the user (mention {{USER_INPUT}} placeholders)",
  "actions": [
    {{
      "type": "add_api_node",
      "payload": {{
        "node_id": "unique_id_like_node_1",
        "method": "HTTP_METHOD",
        "path": "/api/v1/...",
        "operationId": "from_schema",
        "label": "Human-readable node title",
        "params": {{ "param_name": "value_or_{{USER_INPUT}}" }}
      }}
    }},
    {{
      "type": "connect_nodes",
      "payload": {{ "from_node_id": "node_1", "to_node_id": "node_2" }}
    }},
    {{
      "type": "set_param",
      "payload": {{ "node_id": "node_1", "key": "param_name", "value": "value_or_{{USER_INPUT}}" }}
    }}
  ]
}}

### RULES
1. Only use paths and methods from the provided API schema.
2. Build logical ETL chains: GET data -> transform -> POST/PUT/DELETE.
3. Use `{{USER_INPUT}}` for any sensitive or user-specific values.
4. Provide clear labels for each node so the UI is understandable.
5. If the request is unclear, ask for clarification in the message.
6. Keep node IDs sequential: node_1, node_2, node_3, etc.
7. For POST/PUT/PATCH requests, include the body_fields from the schema as params.
"""


# ═══════════════════════════════════════════════════════════════════════
#  Main Processing Function
# ═══════════════════════════════════════════════════════════════════════


async def process_ai_request(request: AIRequest) -> AIResponse:
    """Process an AI assistant request and return structured actions.

    Pipeline:
        1. Load and compress OpenAPI schema (with progressive size reduction)
        2. Sanitize context (Safe Mode)
        3. Build prompt with schema + context + user request
        4. Validate and resolve model name
        5. Call OpenRouter LLM with 429 retry + 402 skip + fallback chain
        6. Parse and validate the LLM response
        7. Filter actions by OpenAPI schema validity
        8. Return structured AIResponse
    """
    settings = get_settings()

    if not settings.AI_OPENROUTER_API_KEY:
        return AIResponse(
            status="error",
            error="AI is not configured: OPENROUTER_API_KEY is empty. "
                  "Set SAMBA_AI_OPENROUTER_API_KEY in .env",
        )

    # 1. Load schema (in-memory, progressive compression)
    compressed_schema, _ = load_openapi_schema()

    # 2. Sanitize context
    user_context = request.context or {}
    if request.safe_mode:
        user_context = sanitize_context(user_context)

    # 3. Build system prompt
    safe_mode_note = " (ACTIVE — data values hidden)" if request.safe_mode else " (OFF — data visible)"
    system_prompt = SYSTEM_PROMPT.format(
        api_schema=compressed_schema,
        safe_mode_note=safe_mode_note,
    )

    # v1.6.8-5: Log estimated prompt tokens
    est_prompt_tokens = _estimate_tokens(system_prompt)
    logger.info(
        "[AI] System prompt: %d chars, ~%d est tokens. Schema: %d chars. "
        "max_tokens=%d, est_total~%d",
        len(system_prompt), est_prompt_tokens, len(compressed_schema),
        settings.AI_MAX_TOKENS, est_prompt_tokens + settings.AI_MAX_TOKENS,
    )

    # 4. Build user message
    user_message_parts = [
        f"[USER PROMPT]:\n{request.prompt}",
    ]
    if user_context:
        user_message_parts.append(
            f"\n[CURRENT TASK CONTEXT (Safe Mode: {request.safe_mode})]:\n"
            + json.dumps(user_context, ensure_ascii=False, indent=2)
        )
    user_message = "\n".join(user_message_parts)

    # v1.6.8-3 fix #2: Validate model name, reject "string" and similar
    raw_model = request.model_override or settings.AI_DEFAULT_MODEL
    model = _validate_model_name(raw_model)

    # 5. Call OpenRouter with 429 retry + 402 skip + fallback model chain (v1.6.8-5)
    models_to_try = _build_model_chain(model, settings)
    last_error: Optional[str] = None
    total_retries = 0
    total_waited = 0.0

    for attempt_model in models_to_try:
        result = _call_llm_with_retry(
            model=attempt_model,
            system_prompt=system_prompt,
            user_message=user_message,
            settings=settings,
        )

        if isinstance(result, dict):
            # Success
            content = result["content"]
            tokens_used = result["tokens_used"]
            total_retries = result.get("retries", 0)
            total_waited = result.get("total_waited", 0.0)
            model = attempt_model  # record which model actually responded
            break
        elif isinstance(result, str):
            # Error message — try next fallback model
            last_error = result
            logger.warning(
                "[AI] Model %s failed, trying next fallback if available",
                attempt_model,
            )
            continue
    else:
        # All models exhausted
        logger.error("[AI] All models exhausted. Last error: %s", last_error)
        return AIResponse(
            status="error",
            error=last_error or "All LLM models exhausted after rate-limit retries",
        )

    if total_retries > 0:
        logger.info(
            "[AI] Request succeeded after %d retries, %.1fs total wait (model=%s)",
            total_retries, total_waited, model,
        )

    # 6. Parse LLM response
    if not content:
        return AIResponse(status="error", error="LLM returned empty response")

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        logger.error("[AI] LLM returned invalid JSON: %s", content[:500])
        return AIResponse(
            status="error",
            error=f"LLM returned invalid JSON: {exc}",
        )

    # 7. Validate actions against OpenAPI schema
    valid_paths = _build_valid_paths_map(compressed_schema)
    raw_actions = parsed.get("actions", [])
    actions: List[AIAction] = []
    rejected: List[str] = []

    for act in raw_actions:
        if not isinstance(act, dict):
            continue
        act_type = act.get("type", "")
        act_payload = act.get("payload", {})
        if not act_type or not isinstance(act_payload, dict):
            continue

        ai_action = AIAction(type=act_type, payload=act_payload)

        # Validate against schema
        validation_error = _validate_action_against_schema(ai_action, valid_paths)
        if validation_error:
            rejected.append(validation_error)
            logger.warning("[AI] Rejected action: %s", validation_error)
        else:
            actions.append(ai_action)

    if rejected:
        logger.warning("[AI] %d actions rejected by schema validation", len(rejected))

    return AIResponse(
        status="success",
        message=parsed.get("message"),
        actions=actions if actions else None,
        model_used=model,
        tokens_used=tokens_used,
        retries=total_retries if total_retries > 0 else None,
    )
