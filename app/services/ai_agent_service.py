"""
AI Agent service for direct execution mode (v1.8.5-2).

Unlike the Task Builder AI (ai_service.py) which returns structured
suggestions for the frontend constructor, the Agent mode **executes
actions directly** on the server using Polza.ai tool calling.

The AI has access to four tools:
    - ``execute_samba_api``  — Call any Samba AD API endpoint
    - ``execute_shell_command`` — Run shell commands on the server
    - ``save_file``  — Save data to local files (CSV, JSON, XLSX, TXT)
    - ``read_file``  — Read files from the server

Agent loop:
    1. Build system prompt with API schema + rules
    2. Send messages + tools to Polza.ai
    3. If LLM returns tool_calls → execute them → feed results back
    4. If LLM returns text → done, return final answer
    5. Repeat up to AI_AGENT_MAX_STEPS (default: 10)

Safety:
    - Shell commands are checked against blocked patterns
    - Shell execution can be disabled entirely via AI_AGENT_SHELL_ENABLED
    - File operations are sandboxed to AI_AGENT_EXPORT_DIR
    - All tool calls are audit-logged
    - API calls use the server's own API key
    - Tool results are truncated to prevent token overflow

v1.6.8-7 fixes:
    #1  Invalid port '8099api' — path normalization
    #2  API call deadlock — sync httpx → async httpx.AsyncClient
    #3  404 model not found — fallback model chain

v1.6.8-8 fixes:
    #4  402 insufficient credits — API menu was generated from the raw
        (uncompressed) OpenAPI schema, producing a ~20K char menu.
        Combined with the system prompt, this caused "You requested up
        to 80593 tokens, but can only afford 24407" errors.
        Fix: use the compressed schema for the agent menu, with
        progressive compression (3 levels) and a configurable
        ``AI_AGENT_MAX_MENU_CHARS`` (default: 8000).
    #5  Tool result truncation reduced from 4000 to 3000 chars to
        save ~250 tokens per tool call.

v1.6.8-9 fix:
    #6  TypeError: 'NoneType' object is not subscriptable — the LLM
        API can return a response object with choices=None or choices=[]
        (content moderation, context window overflow after 3+ tool steps,
        Polza.ai internal errors). The code only checked for string
        errors from _agent_llm_call but did not validate the response
        object's structure. Now:
        - response.choices is checked for None/empty before access
        - response.choices[0].message is checked for None
        - Invalid responses are treated as model errors and trigger
          fallback model chain
        - The agent loop no longer crashes with an unhandled TypeError

Configuration (via environment variables with SAMBA_ prefix):
    SAMBA_AI_AGENT_MAX_STEPS          — Max agent loop iterations (default: 10)
    SAMBA_AI_AGENT_EXPORT_DIR         — Directory for file exports
    SAMBA_AI_AGENT_SHELL_ENABLED      — Enable shell command execution (default: true)
    SAMBA_AI_AGENT_SHELL_TIMEOUT      — Shell command timeout in seconds (default: 30)
    SAMBA_AI_AGENT_SHELL_BLOCKED_CMDS — Blocked command patterns (comma-separated)
    SAMBA_AI_AGENT_API_TIMEOUT        — HTTP timeout for API calls in seconds (default: 60)
    SAMBA_AI_AGENT_MAX_MENU_CHARS     — Max API menu chars in system prompt (default: 8000)
"""

from __future__ import annotations

import asyncio
import ast
import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from app.config import get_settings
from app.models.ai import AIAgentRequest, AIAgentResponse, AIAgentStep, AIUsageInfo
from app.services.data_masker import DataMasker, create_masker_from_config
from app.services.ai_service import (
    _build_model_chain,
    _classify_error,
    _estimate_tokens,
    _extract_retry_after,
    _validate_model_name,
    load_openapi_schema,
)

# Module-level async httpx client (reused across requests)
_api_http_client: Optional[Any] = None

# v1.8.6: Cache of models that don't support tool/function calling.
# When a model returns "No endpoints found that support tool use",
# we add it here so subsequent agent requests skip it immediately
# instead of wasting time/money on a guaranteed failure.
#
# v1.8.6-1: Pre-populate with known non-tool-use models so we skip
# them from the very first request instead of wasting 8-13 seconds
# on a guaranteed 400 BAD_REQUEST before fallback.
#
# v1.9.12: Also includes models that return "Модель не найдена" /
# "model not found" 400 errors — they are guaranteed to fail every
# time, so skipping them avoids 5-10s wasted per request on each
# fallback hop.
_NO_TOOL_SUPPORT_MODELS: set = {
    "liquid/lfm-2-24b-a2b",          # Known: "No endpoints found that support tool use"
    "deepseek/deepseek-v4-flashy",    # 400: "Модель не найдена" on Polza.ai (typo? use deepseek-v4-flash)
    "inception/mercury-2",            # 400: "Модель не найдена" on Polza.ai
    "#inception/mercury-2",           # Same model with '#' prefix (chat CLI convention)
}

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  AI Debug Logging Helper (v1.9.12)
# ═══════════════════════════════════════════════════════════════════════

def _ai_debug_enabled() -> bool:
    """Check if AI debug logging is enabled via SAMBA_AI_DEBUG."""
    try:
        from app.config import get_settings
        return getattr(get_settings(), "AI_DEBUG", False)
    except Exception:
        return False


def _ai_debug_max_content() -> int:
    """Get max content length for AI debug log entries."""
    try:
        from app.config import get_settings
        return getattr(get_settings(), "AI_DEBUG_MAX_CONTENT", 2000)
    except Exception:
        return 2000


def _truncate_for_debug(text: str, max_len: int = 0) -> str:
    """Truncate text for debug logging, showing start and end with truncation notice."""
    if not max_len:
        max_len = _ai_debug_max_content()
    if max_len <= 0 or len(text) <= max_len:
        return text
    half = max_len // 2 - 20
    return f"{text[:half]}...[{len(text) - max_len + 40} chars truncated]...{text[-half:]}"


def _ai_debug_log(direction: str, data: dict) -> None:
    """Log AI request/response data when AI_DEBUG is enabled.

    Args:
        direction: "REQUEST" or "RESPONSE" or "TOOL_RESULT"
        data: Dict of key-value pairs to log
    """
    if not _ai_debug_enabled():
        return
    max_len = _ai_debug_max_content()
    separator = "=" * 60
    lines = [f"[AI-DEBUG] {separator}"]
    lines.append(f"[AI-DEBUG]  {direction}")
    lines.append(f"[AI-DEBUG] {separator}")
    for key, value in data.items():
        if isinstance(value, str):
            display = _truncate_for_debug(value, max_len)
        elif isinstance(value, (dict, list)):
            display = _truncate_for_debug(
                json.dumps(value, ensure_ascii=False, default=str), max_len
            )
        else:
            display = str(value)
        lines.append(f"[AI-DEBUG]  {key}: {display}")
    lines.append(f"[AI-DEBUG] {separator}")
    for line in lines:
        logger.info(line)


# ═══════════════════════════════════════════════════════════════════════
#  Safe Tool Arguments Parser (v1.9.1)
# ═══════════════════════════════════════════════════════════════════════


def _safe_parse_tool_args(raw_arguments: str) -> Dict[str, Any]:
    """Safely parse tool call arguments from LLM output.

    Handles common issues:
    - JSON with JavaScript-style booleans (true/false) and null
    - Python-style dicts with single quotes
    - Falls back to ast.literal_eval after JS→Python token replacement

    v1.9.1: Fixed ``NameError: name 'false' is not defined`` which occurred
    when AI models returned tool call arguments containing JavaScript-style
    booleans (true/false) or null. ``ast.literal_eval`` only accepts Python
    tokens (True/False/None), so we replace JS tokens before calling it.
    """
    if not raw_arguments or not raw_arguments.strip():
        return {}

    # 1. Try standard JSON parsing first (most common case)
    try:
        result = json.loads(raw_arguments)
        if isinstance(result, dict):
            return result
        return {}
    except json.JSONDecodeError:
        pass

    # 2. Replace JavaScript-style tokens with Python equivalents before ast.literal_eval
    sanitized = raw_arguments
    # Replace JS booleans/null with Python equivalents
    # Use word-boundary-aware replacement to avoid replacing inside strings
    sanitized = re.sub(r'\btrue\b', 'True', sanitized)
    sanitized = re.sub(r'\bfalse\b', 'False', sanitized)
    sanitized = re.sub(r'\bnull\b', 'None', sanitized)

    try:
        result = ast.literal_eval(sanitized)
        if isinstance(result, dict):
            return result
        return {}
    except Exception:
        pass

    # 3. Last resort: try original raw_arguments with ast.literal_eval
    try:
        result = ast.literal_eval(raw_arguments)
        if isinstance(result, dict):
            return result
        return {}
    except Exception:
        logger.warning(
            "[AI-AGENT] Failed to parse tool arguments: %s",
            raw_arguments[:200],
        )
        return {}


# ═══════════════════════════════════════════════════════════════════════
#  Agent Tool Definitions (OpenAI-compatible function calling format)
# ═══════════════════════════════════════════════════════════════════════

AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "execute_samba_api",
            "description": (
                "Call a Samba AD Management API endpoint on the local server. "
                "Use this to list users, create groups, manage DNS, run commands, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                        "description": "HTTP method",
                    },
                    "path": {
                        "type": "string",
                        "description": "API endpoint path, e.g. /api/v1/users/",
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Query string parameters (key-value pairs)",
                        "additionalProperties": {"type": "string"},
                    },
                    "body_params": {
                        "type": "object",
                        "description": "JSON body for POST/PUT/PATCH requests",
                        "additionalProperties": True,
                    },
                },
                "required": ["method", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_shell_command",
            "description": (
                "Execute a shell command on the server. Use for system administration "
                "tasks that are not available through the API: checking logs, running "
                "samba-tool commands directly, network diagnostics, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 30, max: 300)",
                        "default": 30,
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_file",
            "description": (
                "Save data to a local file. Supports CSV, JSON, XLSX (if pandas "
                "installed), TXT, and MD formats. Files are saved in the export "
                "directory. Use when the user asks to export, download, or save data."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "File name, e.g. users.csv or report.json",
                    },
                    "content": {
                        "type": "string",
                        "description": (
                            "Data to save. For JSON/XLSX use a JSON array string. "
                            "For CSV use comma-separated values."
                        ),
                    },
                },
                "required": ["filename", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a file from the server. Supports text files, JSON, CSV, and "
                "config files. Maximum file size: 1MB."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Absolute or relative path to the file",
                    },
                },
                "required": ["filepath"],
            },
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════
#  API Menu Generator for Agent System Prompt
# ═══════════════════════════════════════════════════════════════════════


def _generate_api_menu_for_agent() -> str:
    """Generate a human-readable API endpoint menu for the agent system prompt.

    v1.6.8-8: Uses the compressed schema instead of the raw schema.
    The raw schema produces a ~20K char menu which causes 402 insufficient
    credits errors ("You requested up to 80593 tokens, but can only afford
    24407"). The compressed schema is ~8K chars and fits within token budgets.

    The menu is progressively stripped to fit within AI_AGENT_MAX_MENU_CHARS
    (default: 8000 chars):
      Level 1 — full detail: method + path + summary + params + body_fields
      Level 2 — method + path + summary (strip params, body_fields)
      Level 3 — method + path only (strip summary)
    """
    compressed_str, _ = load_openapi_schema()
    if not compressed_str or compressed_str == "{}":
        return "API schema not available."

    try:
        schema = json.loads(compressed_str)
    except json.JSONDecodeError:
        return "API schema not available."

    settings = get_settings()
    max_menu_chars = getattr(settings, "AI_AGENT_MAX_MENU_CHARS", 8000)

    # Try progressively simpler menu levels until it fits
    for level in (1, 2, 3):
        menu_lines: List[str] = []
        paths = schema if isinstance(schema, dict) else {}

        for path, methods in paths.items():
            for method, details in methods.items():
                if not isinstance(method, str) or method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    continue
                method_upper = method.upper()

                if level == 1 and isinstance(details, dict):
                    # Full detail: method + path + summary + params + body
                    summary = details.get("summary", "")
                    if summary:
                        menu_lines.append(f"- {method_upper} {path}: {summary}")
                    else:
                        menu_lines.append(f"- {method_upper} {path}")

                    # Parameters
                    for p in details.get("params", []):
                        pname = p.get("name", "") if isinstance(p, dict) else str(p)
                        prequired = "REQ" if (isinstance(p, dict) and p.get("required")) else "opt"
                        menu_lines.append(f"    [{prequired}] {pname}")

                    # Body fields
                    body_fields = details.get("body_fields", [])
                    body_required = details.get("body_required", [])
                    for bf in body_fields:
                        req_mark = "REQ" if bf in body_required else "opt"
                        menu_lines.append(f"    [{req_mark}] body:{bf}")

                    # operationId (if present)
                    op_id = details.get("operationId", "")
                    if op_id and not summary:
                        menu_lines.append(f"    id: {op_id}")

                elif level == 2 and isinstance(details, dict):
                    # Medium: method + path + summary
                    summary = details.get("summary", "")
                    op_id = details.get("operationId", "")
                    if summary:
                        menu_lines.append(f"- {method_upper} {path}: {summary}")
                    elif op_id:
                        menu_lines.append(f"- {method_upper} {path} ({op_id})")
                    else:
                        menu_lines.append(f"- {method_upper} {path}")

                else:
                    # Level 3: method + path only
                    menu_lines.append(f"- {method_upper} {path}")

        menu_text = "\n".join(menu_lines)
        if len(menu_text) <= max_menu_chars:
            if level > 1:
                logger.info(
                    "[AI-AGENT] API menu compressed to level %d: %d chars (target: %d)",
                    level, len(menu_text), max_menu_chars,
                )
            return menu_text

    # Even level 3 exceeds limit — truncate
    menu_text = "\n".join(menu_lines)
    logger.warning(
        "[AI-AGENT] API menu exceeds max_menu_chars even at minimal level 3 "
        "(%d chars > %d). Truncating.",
        len(menu_text), max_menu_chars,
    )
    return menu_text[:max_menu_chars] + "\n... [MENU TRUNCATED]"


# ═══════════════════════════════════════════════════════════════════════
#  Tool Execution Functions
# ═══════════════════════════════════════════════════════════════════════

# Max chars for tool results (prevent token overflow)
# v1.6.8-8: Reduced from 4000 to 3000 to save tokens.
# API responses can be 38K+ chars; truncating to 3K saves ~250 tokens per
# tool call while still providing enough context for the AI to work with.
_MAX_TOOL_RESULT_CHARS = 3000


def _truncate_result(result: str, max_chars: int = _MAX_TOOL_RESULT_CHARS) -> str:
    """Truncate a tool result string to prevent token overflow."""
    if len(result) <= max_chars:
        return result
    return result[:max_chars] + f"\n... [TRUNCATED: {len(result)} chars total, showing first {max_chars}]"


async def _get_api_http_client() -> Any:
    """Get or create a reusable async httpx client for API calls.

    Using a persistent client avoids the overhead of creating a new
    connection pool on every request and supports HTTP keep-alive.
    """
    global _api_http_client
    if _api_http_client is None or _api_http_client.is_closed:
        import httpx
        _api_http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _api_http_client


async def _execute_samba_api_call(
    method: str,
    path: str,
    query_params: Optional[Dict[str, str]] = None,
    body_params: Optional[Dict[str, Any]] = None,
) -> str:
    """Execute an API call to the local Samba AD Management API.

    Uses httpx.AsyncClient to avoid blocking the event loop.
    This is critical because the API server calls itself — a synchronous
    httpx call would block the event loop and cause a deadlock/timeout.

    v1.6.8-7 fixes:
    - Path normalization: ensures path starts with ``/`` to prevent
      ``http://127.0.0.1:8099api/...`` (Invalid port '8099api').
    - Async HTTP client: prevents event loop blocking.
    - Configurable timeout: uses AI_AGENT_API_TIMEOUT (default: 60s).
    """
    settings = get_settings()

    # v1.6.8-7 fix #1: Ensure path starts with '/'
    # The AI sometimes returns paths like "api/v1/groups/" without a
    # leading slash, which concatenates into "http://127.0.0.1:8099api/..."
    # and httpx parses as port "8099api".
    if not path.startswith('/'):
        path = '/' + path

    url = f"{settings.AI_API_BASE.rstrip('/')}{path}"
    headers = {
        "X-API-Key": settings.API_KEY,
        "Accept": "application/json",
    }

    # Configurable API timeout (default: 60s)
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    logger.info("[AI-AGENT] API call: %s %s (timeout=%ds)", method, url, int(api_timeout))

    try:
        client = await _get_api_http_client()

        # v1.6.8-7 fix #2: Use async httpx to avoid blocking the event loop.
        # The previous sync httpx call blocked the event loop, causing
        # self-request deadlocks because FastAPI couldn't accept new
        # connections while the loop was blocked.
        resp = await client.request(
            method=method.upper(),
            url=url,
            headers=headers,
            params=query_params,
            json=body_params,
            timeout=api_timeout,
        )
        try:
            result = json.dumps(resp.json(), ensure_ascii=False)
        except Exception:
            result = json.dumps({"status_code": resp.status_code, "text": resp.text})

        logger.info("[AI-AGENT] API response: %d chars, status=%d", len(result), resp.status_code)
        return _truncate_result(result)

    except Exception as exc:
        logger.error("[AI-AGENT] API call failed: %s", exc)
        return json.dumps({"error": str(exc)})


def _execute_shell_command(command: str, timeout: int = 30) -> str:
    """Execute a shell command on the server with safety checks.

    Safety measures:
    - Blocked command patterns (configurable via AI_AGENT_SHELL_BLOCKED_CMDS)
    - Timeout (configurable via AI_AGENT_SHELL_TIMEOUT, max 300s)
    - Output truncation
    - Shell execution can be disabled entirely via AI_AGENT_SHELL_ENABLED
    """
    settings = get_settings()

    # Check if shell execution is enabled
    shell_enabled = getattr(settings, "AI_AGENT_SHELL_ENABLED", True)
    if not shell_enabled:
        return json.dumps({
            "error": "Shell command execution is disabled by administrator. "
                     "Set SAMBA_AI_AGENT_SHELL_ENABLED=true to enable.",
        })

    # Check blocked commands
    blocked_str = getattr(settings, "AI_AGENT_SHELL_BLOCKED_CMDS",
                          "rm -rf /,mkfs.,dd if=,:(){ :|:& };:,fork bomb,format ")
    blocked_patterns = [p.strip() for p in blocked_str.split(",") if p.strip()]

    for pattern in blocked_patterns:
        if pattern.lower() in command.lower():
            logger.warning("[AI-AGENT] Blocked shell command (matches '%s'): %s", pattern, command[:200])
            return json.dumps({
                "error": f"Command blocked by safety policy (matches pattern: '{pattern}'). "
                         f"If you need to run this command, ask the administrator to adjust "
                         f"SAMBA_AI_AGENT_SHELL_BLOCKED_CMDS.",
            })

    # Cap timeout
    max_timeout = getattr(settings, "AI_AGENT_SHELL_TIMEOUT", 30)
    timeout = min(timeout, max_timeout, 300)

    logger.info("[AI-AGENT] Shell command: %s (timeout=%ds)", command[:200], timeout)

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output_parts = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            output_parts.append(f"[STDERR]: {result.stderr}")
        if result.returncode != 0:
            output_parts.append(f"[EXIT CODE]: {result.returncode}")

        output = "\n".join(output_parts) if output_parts else "(no output)"

        logger.info(
            "[AI-AGENT] Shell result: exit=%d, stdout=%d chars, stderr=%d chars",
            result.returncode, len(result.stdout or ""), len(result.stderr or ""),
        )

        return _truncate_result(output)

    except subprocess.TimeoutExpired:
        logger.warning("[AI-AGENT] Shell command timed out after %ds: %s", timeout, command[:200])
        return json.dumps({"error": f"Command timed out after {timeout} seconds"})
    except Exception as exc:
        logger.error("[AI-AGENT] Shell command failed: %s", exc)
        return json.dumps({"error": str(exc)})


def _save_file_agent(filename: str, content: str) -> str:
    """Save data to a file in the export directory.

    Supports:
    - .json — pretty-printed JSON
    - .csv — comma-separated values (with BOM for Excel compatibility)
    - .xlsx — requires pandas (optional)
    - .txt, .md — plain text
    """
    settings = get_settings()
    export_dir = getattr(settings, "AI_AGENT_EXPORT_DIR", "/home/AD-API-USER/ai-exports")
    os.makedirs(export_dir, exist_ok=True)

    # Sanitize filename — prevent directory traversal
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        return json.dumps({"error": f"Invalid filename '{filename}'. Only simple filenames allowed (no path separators)."})

    filepath = os.path.join(export_dir, safe_filename)
    ext = os.path.splitext(safe_filename)[1].lower()

    logger.info("[AI-AGENT] Saving file: %s (format: %s)", filepath, ext)

    try:
        if ext == ".json":
            try:
                data = json.loads(content)
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)

        elif ext == ".csv":
            with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
                f.write(content)

        elif ext in (".xlsx", ".xls"):
            # Try pandas for Excel support
            try:
                import io as _io
                import pandas as pd
                try:
                    data = json.loads(content)
                    df = pd.DataFrame(data)
                except (json.JSONDecodeError, ValueError):
                    df = pd.read_csv(_io.StringIO(content))
                df.to_excel(filepath, index=False)
            except ImportError:
                return json.dumps({
                    "error": "XLSX export requires pandas. Install with: pip install pandas openpyxl. "
                             "Alternatively, save as .csv or .json format.",
                })

        elif ext in (".txt", ".md", ".log", ".sh", ".conf", ".yaml", ".yml", ".ini"):
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

        else:
            return json.dumps({
                "error": f"Unsupported file format '{ext}'. Use .csv, .json, .xlsx, .txt, or .md",
            })

        full_path = os.path.abspath(filepath)
        size = os.path.getsize(filepath)
        logger.info("[AI-AGENT] File saved: %s (%d bytes)", full_path, size)
        return json.dumps({"success": True, "path": full_path, "size_bytes": size})

    except Exception as exc:
        logger.error("[AI-AGENT] File save failed: %s", exc)
        return json.dumps({"error": f"Failed to save file: {exc}"})


def _read_file_agent(filepath: str) -> str:
    """Read a file from the server.

    Safety:
    - Maximum file size: 1MB
    - Only text-based formats are supported
    - Path traversal is blocked
    """
    # Block path traversal
    if ".." in filepath:
        return json.dumps({"error": "Path traversal not allowed (.. in path)"})

    if not os.path.exists(filepath):
        return json.dumps({"error": f"File not found: {filepath}"})

    if os.path.getsize(filepath) > 1 * 1024 * 1024:
        return json.dumps({"error": f"File too large (max 1MB): {filepath}"})

    ext = os.path.splitext(filepath)[1].lower()
    supported_exts = {
        ".json", ".csv", ".tsv", ".txt", ".md", ".log", ".py",
        ".yaml", ".yml", ".ini", ".conf", ".sh", ".cfg", ".env",
        ".xml", ".html", ".css", ".js", ".ts",
    }

    if ext not in supported_exts:
        return json.dumps({"error": f"Unsupported file format '{ext}'. Supported: {sorted(supported_exts)}"})

    logger.info("[AI-AGENT] Reading file: %s", filepath)

    try:
        if ext == ".json":
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            return _truncate_result(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return _truncate_result(content)

    except Exception as exc:
        logger.error("[AI-AGENT] File read failed: %s", exc)
        return json.dumps({"error": f"Failed to read file: {exc}"})


async def _dispatch_tool_call(
    function_name: str,
    function_args: Dict[str, Any],
    user_permissions: Optional[set] = None,
) -> str:
    """Route a tool call to the appropriate execution function.

    v1.6.8-7: Made async because _execute_samba_api_call is now async.
    v1.8: Added extended tools (shares, config, system, network, skills, permissions).
    Shell commands are run in a thread pool to avoid blocking the event loop.
    """
    # Original 4 tools
    if function_name == "execute_samba_api":
        return await _execute_samba_api_call(
            method=function_args.get("method", "GET"),
            path=function_args.get("path", "/"),
            query_params=function_args.get("query_params"),
            body_params=function_args.get("body_params"),
        )
    elif function_name == "execute_shell_command":
        return await asyncio.to_thread(
            _execute_shell_command,
            command=function_args.get("command", ""),
            timeout=function_args.get("timeout", 30),
        )
    elif function_name == "save_file":
        return _save_file_agent(
            filename=function_args.get("filename", "export.txt"),
            content=function_args.get("content", ""),
        )
    elif function_name == "read_file":
        return _read_file_agent(
            filepath=function_args.get("filepath", ""),
        )
    else:
        # v1.8: Extended tools (shares, config, system, network, skills, permissions)
        from app.services.ai_extended_tools import dispatch_extended_tool_call
        result = await dispatch_extended_tool_call(function_name, function_args, user_permissions)
        if isinstance(result, str):
            return result
        return json.dumps({"error": f"Unknown tool: {function_name}"})


# ═══════════════════════════════════════════════════════════════════════
#  Agent System Prompt
# ═══════════════════════════════════════════════════════════════════════

AGENT_SYSTEM_PROMPT_TEMPLATE = """You are an expert AI administrator for a Samba Active Directory Domain Controller.

You have FULL ACCESS to the server through these tools:
1. `execute_samba_api` — Call any Samba AD Management API endpoint (list users, create groups, manage DNS, GPO, OUs, etc.)
2. `execute_samba_api_as` — Call API on behalf of a SPECIFIC USER by username or ID. Creates a JWT token for that user and makes the request. Use this for RBAC testing — verify what a user CAN and CANNOT do. Example: `execute_samba_api_as(method="DELETE", path="/api/v1/users/testuser", as_user="junior_admin")` → should return 403 if junior_admin lacks user.delete permission.
3. `execute_shell_command` — Execute shell commands directly on the server (samba-tool, system administration, diagnostics)
4. `save_file` — Save/export data to files (CSV, JSON, XLSX, TXT)
5. `read_file` — Read files from the server (text files only, NOT .xlsx/.png)
6. `manage_postgresql` — Manage PostgreSQL databases: list databases/tables, read/write/update/delete records, execute SQL queries
7. `ldbsearch_ad` — FAST direct AD database queries via ldbsearch. ONE step to count users, search objects, list groups, etc.
   **v2.0 ONE-STEP EXPORT**: `export_xlsx='report.xlsx'` — auto-export to XLSX without separate data_export call!
   **v2.0 `include_groups=true`** — automatically add 'groups' column to results!
   **v2.0 `exclude='Admin,Guest,krbtgt'`** — filter out system accounts inline!
   **`groups_bulk` action** — gets groups for ALL users in ONE step instead of calling groups_of N times!
8. `data_import` — Auto-import data from API endpoints, files, or JSON. Auto-detects fields/columns. Returns column names.
   **`from_ad_users`** — ONE-STEP import: fetches users from API + groups via ldbsearch, merged with 'groups' column!
9. `data_export` — Export data to XLSX (with optional chart on 2nd sheet!), CSV, JSON, TSV. Returns download link.
   **KEY**: Use `columns='col1,col2,...'` to select only specific columns during export — no need for a separate data_transform select step!
   **KEY**: Use `chart_type='bar'`, `chart_x='Column'`, `chart_y='Value'` to add chart on 2nd sheet — no need for a separate data_diagram step!
10. `data_transform` — Filter, sort, aggregate, pivot, merge, deduplicate, select columns. Supports AND/OR, NOT_IN.
   **`enrich_with_groups`** or **`enrich`** — adds groups column to user data in ONE step! Works automatically after ldbsearch_ad groups_bulk or data_import from_ad_users!
   **`select_columns`** or **`select`** — select specific columns from snapshot
   **`add_column`** or **`derive`** — add a computed column
10. `data_diagram` — Create charts/diagrams: bar, line, pie, scatter, histogram, table. Saves as PNG.

### ★★★ FASTEST WORKFLOW: ldbsearch_ad ONE-STEP EXPORT (v2.0) ★★★
For "export AD users to XLSX" type tasks, use ldbsearch_ad with export_xlsx parameter — DONE IN 1 STEP!

**ONE-STEP** (1 call ≈ 0.10₽):
```
ldbsearch_ad(action='list', object_type='user', attributes='sAMAccountName,cn,department', include_groups=true, exclude='Administrator,Guest,krbtgt,default', export_xlsx='users_report.xlsx', export_columns='sAMAccountName,cn,department,groups', chart_type='bar', chart_x='department')
```

**TWO-STEP** (2 calls ≈ 0.15₽):
```
1. ldbsearch_ad(action='list', object_type='user', attributes='sAMAccountName,cn,department', include_groups=true, exclude='Administrator,Guest,krbtgt,default', snapshot_name='users')
2. data_export(action='to_xlsx', snapshot_name='users', columns='sAMAccountName,cn,department,groups', filename='report.xlsx', chart_type='bar', chart_x='department')
```

### ldbsearch_ad NEW PARAMETERS (v2.0)
| Parameter | Description | Example |
|-----------|-------------|---------|
| `snapshot_name` | Save parsed tabular data as snapshot for data_export | `'users'` |
| `include_groups` | Auto-add 'groups' column (runs groups_bulk internally) | `true` |
| `exclude` | Comma-separated sAMAccountNames to exclude | `'Administrator,Guest,krbtgt,default'` |
| `export_xlsx` | Filename to auto-export XLSX (one-step!) | `'report.xlsx'` |
| `export_columns` | Columns to include in XLSX (with export_xlsx) | `'sAMAccountName,cn,groups'` |
| `chart_type` | Chart type for XLSX 2nd sheet | `'bar'` |
| `chart_x` | Column for chart X axis | `'department'` |
| `chart_y` | Column for chart Y axis | `'count'` |
| `chart_title` | Chart title | `'Users by Department'` |

### EFFICIENCY RULES (CRITICAL — follow these to minimize steps and cost)
1. **MINIMIZE STEPS** — Every step costs money and time. Aim for 1-2 steps for data tasks, not 10+.
2. **NEVER repeat a tool call** with the same parameters — if a step succeeded, use its result.
3. **ldbsearch_ad auto-saves snapshot** — You do NOT need to call ldbsearch_ad twice. The first call already saves data to a snapshot (name shown in result). Use that snapshot_name for subsequent data_export/data_transform if needed.
4. **Do NOT call data_transform select after ldbsearch_ad** — ldbsearch_ad already returns the right columns. The 'dn' column is NOT in preview. Just use the data directly.
5. **For simple queries like "show users and departments"**: Call ldbsearch_ad ONCE and immediately answer from the result. Do NOT call any other tools!
6. **Use ldbsearch_ad with export_xlsx for ONE-STEP data export** — no need for data_import + data_transform + data_export!
7. **Use include_groups=true** instead of separate groups_bulk + enrich steps!
8. **Use exclude='...' parameter** instead of separate data_transform filter step!
9. **NEVER call ldbsearch_ad groups_of multiple times** — use `groups_bulk` to get ALL user groups in ONE step.
10. **Do NOT call request_api_access before data_import** — data_import(action='from_api') already knows the API. Skip the discovery step!
11. **Use data_export columns= parameter** instead of a separate data_transform select step.
12. **Use data_export chart_type= parameter** instead of a separate data_diagram step.
13. **Use data_import from_ad_users** instead of separate from_api + groups_bulk + enrich steps — ONE call does it all!

### COMMON MISTAKES TO AVOID (these waste steps and money!)
1. WRONG: `ldbsearch_ad list` then again with snapshot_name → RIGHT: First call auto-saves snapshot! Use data directly!
2. WRONG: `ldbsearch_ad` + `data_transform select` → RIGHT: ldbsearch_ad already returns clean columns (no 'dn' in preview)!
3. WRONG: `request_api_access` before `data_import` → RIGHT: Use `data_import(action='from_api')` directly!
4. WRONG: 5-step pipeline → RIGHT: `ldbsearch_ad(..., include_groups=true, exclude='...', export_xlsx='report.xlsx')` (1 step!)
5. WRONG: Separate `data_diagram` call → RIGHT: Use `data_export(chart_type='bar', chart_x='...')` inline
6. WRONG: Separate `data_transform select_columns` → RIGHT: Use `data_export(columns='...')` inline
7. WRONG: `ldbsearch_ad groups_of` N times → RIGHT: Use `groups_bulk` ONCE or `include_groups=true`
8. WRONG: Using `save_file` for export → RIGHT: Use `data_export(action='to_xlsx')`

WRONG (wastes 8-10 steps!):
  ✗ request_api_access → execute_samba_api → data_import → filter → enrich → select_columns → export → diagram (9 steps!)
  ✗ ldbsearch_ad groups_of(user1) → groups_of(user2) → ... → 10+ calls!
  ✗ data_import → filter → select_columns → enrich → export (5 steps) → should be: ldbsearch_ad + export_xlsx (1 step!)

### QUICK REFERENCE: Filter Conditions
| Task | Condition |
|------|-----------|
| Exclude system accounts | `sAMAccountName NOT_IN Administrator,Guest,krbtgt,default` or `exclude='Administrator,Guest,krbtgt,default'` |
| Active users only | `status = active` or `userAccountControl != 66050` |
| Name contains text | `cn CONTAINS Иванов` |
| Non-empty field | `givenName NOT_EMPTY` |
| Multiple conditions | `sAMAccountName NOT_IN Administrator,Guest AND sn NOT_EMPTY` |

### QUICK REFERENCE: Tool Action Names
| Tool | Correct Action | Wrong Action (common mistake) |
|------|---------------|-------------------------------|
| ldbsearch_ad | 'list' + include_groups=true + export_xlsx='...' | separate groups_bulk + data_import + data_export calls |
| ldbsearch_ad | 'export' (alias for 'list' + auto-export) | — |
| data_transform | 'select_columns' or 'select' | both work, use with columns param |
| data_transform | 'add_column' or 'derive' | both work, use with expression param |
| data_transform | 'enrich_with_groups' or 'enrich' | both work, enrich auto-finds groups_bulk result |
| data_import | 'from_json' or 'from_raw' | both work now |
| data_import | 'from_ad_users' | ONE step for users+groups, replaces from_api+groups_bulk+enrich |
| data_import | 'from_file', source='path' | both source and file_path work now |
| data_export | 'to_xlsx' + chart_type='bar' + columns='...' | separate data_diagram or select_columns calls |

### AVAILABLE API ENDPOINTS
{api_menu}

### RBAC TESTING with `execute_samba_api_as` (v1.9.6-4)
Use `execute_samba_api_as` to test what a specific user CAN and CANNOT do.
This is essential for verifying role-based access control (RBAC).

**Workflow for RBAC testing:**
1. Create a role with specific permissions (use execute_samba_api POST /api/v1/mgmt/roles)
2. Create a user with that role (use execute_samba_api POST /api/v1/mgmt/users)
3. Create an API key for the user (use execute_samba_api POST /api/v1/mgmt/keys)
4. Test ALLOWED actions → should return 200 (use execute_samba_api_as with as_user="username")
5. Test DENIED actions → should return 403 (use execute_samba_api_as with as_user="username")

**Examples:**
- Test that junior_admin can LIST users: `execute_samba_api_as(method="GET", path="/api/v1/users", as_user="junior_admin")`
- Test that junior_admin CANNOT delete users: `execute_samba_api_as(method="DELETE", path="/api/v1/users/testuser", as_user="junior_admin")`
- Test that junior_admin can create users: `execute_samba_api_as(method="POST", path="/api/v1/users", as_user="junior_admin", body_params={"username": "test", "password": "Pass123!"})`
- Compare with admin: `execute_samba_api_as(method="DELETE", path="/api/v1/users/testuser", as_user="admin")`

**Key difference from execute_samba_api:**
- `execute_samba_api` → always uses the admin API key (full access)
- `execute_samba_api_as` → creates a JWT token for the specified user (respects RBAC permissions)

The response includes `executed_as` (who the request was made as), `response` (the API response), and `http_status`.
If http_status is 403, the user's role doesn't have the required permission — this is EXPECTED for RBAC testing.

### ★★★ READ/WRITE STRATEGY (CRITICAL — saves tokens and money!) ★★★
**READ** operations (list, search, count, export) → **ALWAYS use `ldbsearch_ad`** — it's FAST, direct, and cheap.
**WRITE** operations (create, update, delete, manage) → **ALWAYS use `execute_samba_api`** — it has validation and error handling.

NEVER use `execute_samba_api` for GET/read operations when `ldbsearch_ad` can do it!
- WRONG: `execute_samba_api(method="GET", path="/api/v1/users/")` → 18K+ chars, wastes tokens!
- RIGHT: `ldbsearch_ad(action='list', object_type='user', attributes='sAMAccountName,cn,department')` → compact, fast, cheap!

NEVER use `request_api_access` before ldbsearch_ad — ldbsearch_ad doesn't need API discovery!

### RULES
1. **ONE-STEP ANSWERS**: For simple queries like "show users", "list departments", "how many groups" — call ldbsearch_ad ONCE and answer immediately from the result. Do NOT call any other tools after ldbsearch_ad for simple display queries!
2. **ldbsearch_ad auto-saves data**: Every ldbsearch_ad call saves a snapshot automatically. You do NOT need to call ldbsearch_ad again with snapshot_name. The snapshot_name is in the result.
3. **No data_transform select after ldbsearch_ad**: ldbsearch_ad already returns clean columns without 'dn'. Do NOT call data_transform to select/reorder columns after ldbsearch_ad.
4. **For AD data READ/export tasks**: PREFER `ldbsearch_ad` with `export_xlsx` parameter — it does query + parse + groups + exclude + export in ONE step!
5. **For AD WRITE/management**: Use `execute_samba_api` (create users, manage groups, DNS, GPO) — POST/PUT/DELETE only!
6. **NEVER use execute_samba_api for GET/read operations** — use `ldbsearch_ad` instead! It's faster and uses fewer tokens.
7. **NEVER call request_api_access** — it's unnecessary overhead. Use ldbsearch_ad directly for reads, execute_samba_api directly for writes.
8. **For user+groups tasks**: Use `ldbsearch_ad(include_groups=true)` or `data_import(from_ad_users)` for ONE-STEP import.
9. **For AD queries that need export**: Use `ldbsearch_ad` with `export_xlsx` — no need for data_import first!
10. **For shell tasks**: Use `execute_shell_command` ONLY for tasks that have no API or data tool equivalent.
11. **Always use exclude='...'** for excluding system accounts — it's built into ldbsearch_ad now!
12. **Always use column names from ldbsearch_ad result** — check the `preview_columns` list in the result.
13. **Verify destructive operations** (delete, disable, DROP) before executing.
14. **Respond in the same language** the user writes in.
15. **For XLSX with chart**: Use data_export(chart_type=..., chart_x=..., chart_y=...) or ldbsearch_ad(export_xlsx=..., chart_type=...).
16. **For column selection during export**: Use data_export(columns='...') or ldbsearch_ad(export_columns='...').
17. **For users+groups export**: Use `ldbsearch_ad(action='list', include_groups=true, export_xlsx='report.xlsx')` — ONE step!

### ★★★ DATA MASKING (PII Protection — v3.0) ★★★
Tool results contain MASKED data for privacy (GDPR/ФЗ-152 compliance).
- Sensitive values (logins, names, emails) are replaced with tokens: [P1], [P2], [P3]...
- JSON field names (cn, displayName, department) tell you what each token represents
- Tokens will be auto-replaced with real values before the user sees your response

**RULES:**
1. Copy tokens EXACTLY as shown: [P1] not [P_1] or [P01]
2. NEVER guess or invent real values behind tokens
3. Different tokens [P1] vs [P2] = different values, even for same field

### ★★★ RESULT VALIDATION (v2.2) ★★★
ldbsearch_ad results include a `validation` field:
- `approved: true` — result is valid, data is correct
- `approved: false` — result is REJECTED, do NOT trust the data
- `errors` — list of error descriptions (why rejected)
- `warnings` — list of warnings (informational)
- `validation_note` — human-readable summary

If `approved: false`, explain the error to the user and suggest corrections.

### ★★★ SCHEMA-BASED ATTRIBUTE WEIGHTS (from SKILL) ★★★
Each AD object_type has attributes with weights from the SKILL schema:
- W5 = always request (key identifiers like sAMAccountName, cn, objectSid)
- W3 = commonly needed (department, mail, userAccountControl, etc.)
- W1 = rare/special (only request when specifically needed)

**When querying, prefer W5+W3 attributes.** Only add W1 attributes if the user specifically asks.

**computer (objectClass=computer) SUP user:**
Computer inherits ALL user attributes, plus computer-specific:
- W5: cn, sAMAccountName, dNSHostName, objectClass, objectSid, userAccountControl
- W3: operatingSystem, operatingSystemVersion, managedBy, servicePrincipalName, pwdLastSet, lastLogonTimestamp, msDS-isRODC
- W1: operatingSystemServicePack, operatingSystemHotfix, location, networkAddress, rIDSetReferences, msDS-isGC, msDS-SiteName, msDS-GenerationId, etc.

### SHELL COMMANDS
- You can run shell commands on the server
- BUT: prefer ldbsearch_ad + data_export over shell commands for data tasks
- For samba-tool commands: use `sudo samba-tool <command>` if needed
- Dangerous commands (rm -rf /, mkfs, etc.) are blocked for safety

### POSTGRESQL DATABASE
- Use `manage_postgresql` to interact with the PostgreSQL database
- Actions: list_databases, list_tables, describe_table, select, insert, update, delete, execute_query
- Always preview data before making changes (SELECT before UPDATE/DELETE)
- Be cautious with DROP and TRUNCATE operations
"""


# ═══════════════════════════════════════════════════════════════════════
#  Main Agent Processing Function
# ═══════════════════════════════════════════════════════════════════════


async def process_ai_agent_request(
    request: AIAgentRequest,
    user_permissions: Optional[set] = None,
    user_info: Optional[Dict[str, str]] = None,
) -> AIAgentResponse:
    """Process an AI agent request using tool calling (function calling).

    The agent has direct access to:
    - Samba AD API (execute_samba_api)
    - Shell commands (execute_shell_command)
    - File I/O (save_file, read_file)
    - Samba Share management (manage_samba_share) — v1.8
    - Samba Config management (manage_samba_config) — v1.8
    - System administration (system_admin) — v1.8
    - Network administration (network_admin) — v1.8
    - AI Skills (ai_skill_execute) — v1.8
    - Permission-based API access (request_api_access) — v1.8

    Supports Polza.ai as AI provider

    The agent loop runs up to AI_AGENT_MAX_STEPS iterations:
    1. Send messages + tools to LLM
    2. If LLM returns tool_calls → execute → feed results back
    3. If LLM returns text → done
    """
    settings = get_settings()

    # v1.8.5-2: Use Polza.ai only
    from app.services.ai_polza_provider import get_effective_ai_provider, create_ai_client, build_polza_extra_body
    provider_info = get_effective_ai_provider()

    # v1.8.5-2: Build Polza.ai extra body params
    # IMPORTANT: When using tools, do NOT restrict provider to Novita
    # because Novita doesn't support tool use (returns 400 BAD_REQUEST).
    # For tool-calling requests, we remove provider.only restriction.
    polza_extra_body = build_polza_extra_body(for_tool_use=True)
    if polza_extra_body:
        logger.info("[AI-AGENT] Using Polza.ai extra_body (for_tool_use=True): %s", polza_extra_body)

    if not provider_info["api_key"]:
        return AIAgentResponse(
            status="error",
            error="AI is not configured. Set SAMBA_POLZA_AI_URL and SAMBA_POLZA_AI_KEY in .env",
        )

    # 1. Generate API menu for system prompt
    api_menu = _generate_api_menu_for_agent()
    system_prompt = AGENT_SYSTEM_PROMPT_TEMPLATE.format(api_menu=api_menu)

    # v2.2: Add masking context to system prompt so AI understands tokens
    masker = create_masker_from_config()
    if masker.token_count == 0 and hasattr(masker, 'get_ai_context_block'):
        # Pre-add masking explanation to system prompt
        mask_context = masker.get_ai_context_block()
        if mask_context:
            system_prompt += "\n\n" + mask_context

    est_tokens = _estimate_tokens(system_prompt)
    logger.info(
        "[AI-AGENT] System prompt: %d chars, ~%d est tokens, API menu: %d chars",
        len(system_prompt), est_tokens, len(api_menu),
    )

    # 2. Build initial messages
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
    ]

    # Add context if provided
    if request.context:
        context_str = json.dumps(request.context, ensure_ascii=False, indent=2)
        messages.append({
            "role": "user",
            "content": f"[CONTEXT DATA]:\n{context_str}",
        })

    # Add user prompt
    messages.append({"role": "user", "content": request.prompt})

    # 3. Validate model name and build fallback chain
    raw_model = request.model_override or provider_info["default_model"]
    primary_model = _validate_model_name(raw_model)

    # v1.6.8-7 fix #3: Build fallback model chain
    models_to_try = _build_model_chain(primary_model, settings)

    # v1.8.6: Skip models known to not support tool calling.
    # This avoids wasting time/money on API calls that are guaranteed
    # to fail with "No endpoints found that support tool use".
    if _NO_TOOL_SUPPORT_MODELS:
        before = len(models_to_try)
        models_to_try = [m for m in models_to_try if m not in _NO_TOOL_SUPPORT_MODELS]
        skipped = before - len(models_to_try)
        if skipped:
            logger.info(
                "[AI-AGENT] Skipped %d model(s) known to not support tool use: %s",
                skipped, _NO_TOOL_SUPPORT_MODELS,
            )
        if not models_to_try:
            return AIAgentResponse(
                status="error",
                error=f"All models in fallback chain don't support tool use: {_NO_TOOL_SUPPORT_MODELS}. "
                      f"Change SAMBA_POLZA_AI_MODEL or SAMBA_AI_FALLBACK_MODELS in .env",
            )
        # Update primary model if the original was skipped
        primary_model = models_to_try[0]

    # 4. Create AI client (Polza.ai)
    try:
        client = create_ai_client()
    except ValueError as exc:
        return AIAgentResponse(status="error", error=str(exc))
    except ImportError:
        return AIAgentResponse(
            status="error",
            error="openai package not installed. Run: pip install openai",
        )

    # 5. Build tools list (original + extended + data) — v1.8.7
    from app.services.ai_extended_tools import get_all_extended_tools
    all_tools = AGENT_TOOLS + get_all_extended_tools()

    # 6. Agent loop
    max_steps = request.max_steps or getattr(settings, "AI_AGENT_MAX_STEPS", 10)
    max_rate_retries = getattr(settings, "AI_RATE_LIMIT_RETRIES", 3)
    max_wait = getattr(settings, "AI_RATE_LIMIT_MAX_WAIT", 30)

    steps: List[AIAgentStep] = []
    total_tokens = 0
    total_cost_rub: float = 0.0  # v1.8.4: cumulative cost
    last_usage_info: Optional[Dict[str, Any]] = None  # v1.8.4
    final_answer: Optional[str] = None
    step_num = 0
    model = primary_model  # Will be updated if fallback is used
    last_model_error: Optional[str] = None

    # v2.2: DataMasker already created above (before system prompt)
    # It is reused for the entire request lifecycle.

    for iteration in range(max_steps):
        # -- Call LLM with retry --
        llm_result = await asyncio.to_thread(
            _agent_llm_call,
            client=client,
            model=model,
            messages=messages,
            tools=all_tools,
            temperature=settings.AI_TEMPERATURE,
            max_tokens=settings.AI_MAX_TOKENS,
            max_rate_retries=max_rate_retries,
            max_wait=max_wait,
            extra_body=polza_extra_body,
        )

        if isinstance(llm_result, str):
            # v1.6.8-7 fix #3: Try fallback models on fatal errors
            # (404 model not found, 402 insufficient credits, etc.)
            last_model_error = llm_result

            # Find next model in the fallback chain
            current_idx = -1
            for i, m in enumerate(models_to_try):
                if m == model:
                    current_idx = i
                    break

            next_idx = current_idx + 1
            if next_idx < len(models_to_try):
                next_model = models_to_try[next_idx]
                logger.warning(
                    "[AI-AGENT] Model '%s' failed, trying fallback '%s'",
                    model, next_model,
                )
                model = next_model
                continue  # Retry with next model

            # All models exhausted
            return AIAgentResponse(
                status="error",
                error=last_model_error,
                steps=steps,
                total_steps=step_num,
                model_used=model,
            )

        response = llm_result

        # v1.6.8-9 fix #6: Validate LLM response structure.
        # Polza.ai can return a response with choices=None or choices=[]
        # (content moderation, context overflow, internal errors).
        # Previously this caused: TypeError: 'NoneType' object is not
        # subscriptable at response.choices[0].message.
        if not response or not response.choices:
            logger.warning(
                "[AI-AGENT] LLM returned empty/None choices for model=%s "
                "(response type=%s, choices=%s)",
                model, type(response).__name__, repr(response.choices),
            )
            # Treat as a model error and try next fallback
            current_idx = -1
            for i, m in enumerate(models_to_try):
                if m == model:
                    current_idx = i
                    break
            next_idx = current_idx + 1
            if next_idx < len(models_to_try):
                next_model = models_to_try[next_idx]
                logger.warning(
                    "[AI-AGENT] Model '%s' returned empty choices, trying fallback '%s'",
                    model, next_model,
                )
                model = next_model
                continue
            # All fallbacks exhausted
            return AIAgentResponse(
                status="error",
                error=(
                    f"LLM returned empty response (no choices) for all models. "
                    f"This may be caused by content moderation or context window overflow. "
                    f"Try reducing AI_AGENT_MAX_MENU_CHARS or AI_MAX_TOKENS."
                ),
                steps=steps,
                total_steps=step_num,
                model_used=model,
            )

        if response.usage:
            total_tokens += (response.usage.total_tokens or 0)

        # v1.8.4: Extract detailed usage/cost info from Polza.ai response
        from app.services.ai_polza_provider import extract_usage_info, format_usage_log
        step_usage = extract_usage_info(response)
        last_usage_info = step_usage
        if step_usage.get("cost_rub") is not None:
            try:
                total_cost_rub += float(step_usage["cost_rub"])
            except (ValueError, TypeError):
                pass
        logger.info("[AI-AGENT] Step usage: %s", format_usage_log(step_usage))

        assistant_message = response.choices[0].message

        # v1.6.8-9 fix #6: message can also be None in rare cases
        if assistant_message is None:
            logger.warning(
                "[AI-AGENT] LLM returned choices[0].message=None for model=%s",
                model,
            )
            current_idx = -1
            for i, m in enumerate(models_to_try):
                if m == model:
                    current_idx = i
                    break
            next_idx = current_idx + 1
            if next_idx < len(models_to_try):
                next_model = models_to_try[next_idx]
                logger.warning(
                    "[AI-AGENT] Model '%s' returned None message, trying fallback '%s'",
                    model, next_model,
                )
                model = next_model
                continue
            return AIAgentResponse(
                status="error",
                error=f"LLM returned None message for all models (model={model}). "
                      f"This may be caused by content filtering.",
                steps=steps,
                total_steps=step_num,
                model_used=model,
            )

        content = assistant_message.content or ""

        # v1.9.12: Debug log — what we RECEIVED from the AI
        _ai_debug_log("RESPONSE ← AI", {
            "model": model,
            "content": content,
            "content_length": len(content),
            "has_tool_calls": bool(assistant_message.tool_calls),
            "tool_calls_count": len(assistant_message.tool_calls) if assistant_message.tool_calls else 0,
            "tool_calls": [
                {
                    "id": tc.id,
                    "function_name": tc.function.name,
                    "function_arguments": tc.function.arguments,
                }
                for tc in (assistant_message.tool_calls or [])
            ],
            "finish_reason": response.choices[0].finish_reason if response.choices else "?",
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens if response.usage else "?",
                "completion_tokens": response.usage.completion_tokens if response.usage else "?",
                "total_tokens": response.usage.total_tokens if response.usage else "?",
            } if response.usage else "(no usage data)",
        })

        # -- Check if LLM wants to call tools --
        if not assistant_message.tool_calls:
            # No tool calls — LLM is done, return final answer
            final_answer = content
            break

        # -- Process tool calls --
        step_num += 1

        # Build assistant message for conversation history
        tool_calls_for_history = []
        for tc in assistant_message.tool_calls:
            tool_calls_for_history.append({
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            })

        messages.append({
            "role": "assistant",
            "content": content,
            "tool_calls": tool_calls_for_history,
        })

        # Execute each tool call
        for tc in assistant_message.tool_calls:
            function_name = tc.function.name
            raw_arguments = tc.function.arguments

            # Parse arguments (v1.9.1: use _safe_parse_tool_args)
            function_args = _safe_parse_tool_args(raw_arguments)

            logger.info(
                "[AI-AGENT] Step %d: tool=%s, args=%s",
                step_num, function_name, json.dumps(function_args, ensure_ascii=False)[:200],
            )

            # Execute the tool (async because API calls use httpx.AsyncClient)
            tool_result = await _dispatch_tool_call(function_name, function_args, user_permissions)

            # v1.9.12: Debug log — tool execution result (ORIGINAL, before masking)
            _ai_debug_log("TOOL_RESULT (original, before masking)", {
                "step": step_num,
                "tool": function_name,
                "args": function_args,
                "result_length": len(tool_result),
                "result": tool_result,
            })

            # v3.0: PII masking ENABLED for tool results sent to AI.
            # Real PII (names, logins, emails, etc.) is replaced with tokens
            # like [P1], [P2], etc. The AI works with these tokens,
            # and unmasking is applied to the AI's final response before
            # it reaches the user. This ensures GDPR/ФЗ-152 compliance.
            masked_tool_result = masker.mask_json_string(tool_result)
            if masked_tool_result != tool_result:
                logger.info(
                    "[AI-AGENT] PII detected in tool result for %s "
                    "(original: %d chars, masked: %d chars) — "
                    "sending MASKED data to AI",
                    function_name, len(tool_result), len(masked_tool_result),
                )
                _ai_debug_log("TOOL_RESULT (masked, sent to AI)", {
                    "step": step_num,
                    "tool": function_name,
                    "original_length": len(tool_result),
                    "masked_length": len(masked_tool_result),
                    "masker_tokens": masker.token_count,
                })
                # Send MASKED data to AI
                tool_result_for_ai = masked_tool_result
            else:
                # No PII detected — send as-is
                tool_result_for_ai = tool_result

            # Record step (use original unmasked result for audit)
            result_preview = tool_result[:500]
            steps.append(AIAgentStep(
                step=step_num,
                tool_name=function_name,
                tool_args=function_args,
                result_preview=result_preview,
                success="error" not in tool_result.lower()[:100],
            ))

            # v2.1: Add ORIGINAL (unmasked) tool result to conversation
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": tool_result_for_ai,
            })

    else:
        # Agent hit max steps
        final_answer = (
            f"Agent reached maximum step limit ({max_steps}). "
            f"Completed {step_num} steps. Last step results are included."
        )
        logger.warning("[AI-AGENT] Reached max steps: %d", max_steps)

    # v3.0: Unmask AI response — replace [P1],[P2]... tokens with real values
    # so the user sees real data in the final answer.
    if final_answer and masker.token_count > 0:
        unmasked_answer = masker.unmask_text(final_answer)
        if unmasked_answer != final_answer:
            logger.info(
                "[AI-AGENT] Unmasked %d tokens in final answer",
                masker.token_count,
            )
            final_answer = unmasked_answer

    # 6. Return response
    # v1.8.4: Build usage info from last step
    from app.models.ai import AIUsageInfo
    usage_obj = None
    if last_usage_info:
        usage_obj = AIUsageInfo(
            prompt_tokens=last_usage_info.get("prompt_tokens"),
            completion_tokens=last_usage_info.get("completion_tokens"),
            total_tokens=last_usage_info.get("total_tokens"),
            reasoning_tokens=last_usage_info.get("reasoning_tokens"),
            cached_tokens=last_usage_info.get("cached_tokens"),
            cost_rub=last_usage_info.get("cost_rub"),
            provider=last_usage_info.get("provider"),
        )

    return AIAgentResponse(
        status="success" if final_answer else "partial",
        message=final_answer or "Agent completed with no final answer",
        steps=steps,
        total_steps=step_num,
        model_used=model,
        tokens_used=total_tokens if total_tokens > 0 else None,
        cost_rub=total_cost_rub if total_cost_rub > 0 else None,
        usage=usage_obj,
    )


def _agent_llm_call(
    client: Any,
    model: str,
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    temperature: float,
    max_tokens: int,
    max_rate_retries: int = 3,
    max_wait: int = 30,
    extra_body: Optional[Dict[str, Any]] = None,
) -> Any:
    """Call the LLM for agent mode with 429 retry logic.

    v1.8.2: Added extra_body parameter for Polza.ai-specific request fields
    (provider, reasoning, top_k, repetition_penalty, top_p).
    The OpenAI SDK passes extra_body fields directly in the JSON request body.

    Returns the OpenAI response object on success, or an error string on failure.
    """
    rate_retries_done = 0
    conn_retries_done = 0
    total_waited = 0.0
    max_total_attempts = max_rate_retries + 3 + 1  # rate + connection + initial

    for attempt in range(max_total_attempts):
        try:
            logger.debug("[AI-AGENT] LLM call attempt %d, model=%s", attempt + 1, model)

            # v1.8.2: Build create kwargs, adding extra_body for Polza.ai
            create_kwargs: Dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            # v2.4: Only include tools if non-empty (empty list causes API errors)
            if tools:
                create_kwargs["tools"] = tools
            # Add Polza.ai-specific extra body parameters if configured
            if extra_body:
                create_kwargs["extra_body"] = extra_body

            # v1.9.12: Debug log — what we're SENDING to the AI
            _ai_debug_log("REQUEST → AI", {
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "attempt": f"{attempt + 1}/{max_total_attempts}",
                "messages_count": len(messages),
                "messages_roles": [m.get("role", "?") for m in messages],
                "messages_summary": [
                    {
                        "role": m.get("role", "?"),
                        "content_len": len(m.get("content", "")) if m.get("content") else 0,
                        "content_preview": (m.get("content", "") or "")[:200],
                        "tool_calls_count": len(m.get("tool_calls", [])) if m.get("tool_calls") else 0,
                    }
                    for m in messages
                ],
                "tools_count": len(tools),
                "tools_names": [t.get("function", {}).get("name", "?") for t in tools],
                "extra_body": extra_body or "(none)",
            })

            response = client.chat.completions.create(**create_kwargs)

            return response

        except Exception as exc:
            error_type = _classify_error(exc)

            # v1.8.6: "No tool support" — model provider doesn't support
            # function/tool calling. Add to cache and skip immediately.
            if error_type == "no_tool_support":
                _NO_TOOL_SUPPORT_MODELS.add(model)
                logger.warning(
                    "[AI-AGENT] Model '%s' doesn't support tool use (added to skip cache). "
                    "Error: %s",
                    model, str(exc)[:200],
                )
                return f"Model '{model}' doesn't support tool use: {exc}"

            # 402 Insufficient Credits → skip immediately
            if error_type == "insufficient":
                logger.warning("[AI-AGENT] 402 insufficient credits for model=%s: %s", model, str(exc)[:200])
                return f"Model '{model}' requires more credits: {exc}"

            # 429 Rate Limit → retry with backoff
            if error_type == "rate_limit" and rate_retries_done < max_rate_retries:
                retry_after = _extract_retry_after(exc)
                if retry_after is not None:
                    wait_time = min(retry_after, max_wait)
                else:
                    wait_time = min(2 ** (rate_retries_done + 1), max_wait)

                rate_retries_done += 1
                total_waited += wait_time
                logger.warning(
                    "[AI-AGENT] 429 rate limit, waiting %.1fs (retry %d/%d)",
                    wait_time, rate_retries_done, max_rate_retries,
                )
                time.sleep(wait_time)
                continue

            # Connection error → retry
            if error_type == "connection" and conn_retries_done < 2:
                wait_time = min(2 ** (conn_retries_done + 1), 10)
                conn_retries_done += 1
                total_waited += wait_time
                logger.warning(
                    "[AI-AGENT] Connection error, waiting %.1fs (retry %d/2)",
                    wait_time, conn_retries_done,
                )
                time.sleep(wait_time)
                continue

            # Fatal or retries exhausted
            if error_type == "rate_limit":
                return f"Model '{model}' rate-limited after {max_rate_retries} retries: {exc}"
            if error_type == "connection":
                return f"Model '{model}' connection failed after 2 retries: {exc}"

            logger.error("[AI-AGENT] LLM call failed: %s", exc, exc_info=True)
            return f"LLM call failed (model={model}): {exc}"

    return f"LLM call failed after all retries for model={model}"


# ═══════════════════════════════════════════════════════════════════════
#  Chat Agent Processing Function (v1.8)
# ═══════════════════════════════════════════════════════════════════════


async def process_chat_agent_request(
    chat_id: str,
    user_message: str,
    chat_system_prompt: str = "",
    chat_context: Optional[Dict[str, Any]] = None,
    max_steps: Optional[int] = None,
    user_permissions: Optional[set] = None,
    user_info: Optional[Dict[str, str]] = None,
) -> AIAgentResponse:
    """Process a chat message using the AI agent with conversation history.

    Unlike process_ai_agent_request which is a one-shot interaction,
    this function loads the chat's conversation history and continues
    the dialogue. This enables persistent multi-turn conversations.

    The function:
        1. Loads chat history from the management DB
        2. Builds a system prompt with chat context + permission info
        3. Runs the agent loop with conversation history
        4. Returns the AI's response
    """
    from app.services.ai_chat_service import get_chat_messages_for_agent
    from app.services.ai_polza_provider import get_effective_ai_provider, create_ai_client, build_polza_extra_body

    settings = get_settings()
    provider_info = get_effective_ai_provider()

    # v1.8.2: Build Polza.ai extra body params if using Polza.ai
    # v1.8-2 fix: Must use for_tool_use=True because chat agent uses
    # tool calling. Without it, provider.only (e.g. Novita) is sent,
    # which may not support tool use and causes 400 BAD_REQUEST.
    polza_extra_body = None
    if provider_info["provider"] == "polza":
        polza_extra_body = build_polza_extra_body(for_tool_use=True)
        if polza_extra_body:
            logger.info("[AI-CHAT-AGENT] Using Polza.ai extra_body (for_tool_use=True): %s", polza_extra_body)

    if not provider_info["api_key"]:
        return AIAgentResponse(
            status="error",
            error="AI is not configured. Set SAMBA_POLZA_AI_URL and SAMBA_POLZA_AI_KEY in .env",
        )

    # Build system prompt for chat mode
    permission_mode = getattr(settings, "AI_PERMISSION_MODE", True)

    if permission_mode and user_permissions:
        from app.permissions import get_permissions_by_category
        perms_by_cat = get_permissions_by_category()
        user_perms_by_cat = {
            cat: [p for p in perms if p in user_permissions]
            for cat, perms in perms_by_cat.items()
        }
        user_perms_by_cat = {k: v for k, v in user_perms_by_cat.items() if v}
        perm_str = json.dumps(user_perms_by_cat, ensure_ascii=False)
        api_context = f"Your current user has these permissions:\n{perm_str}\n\nUse `request_api_access` tool to discover available endpoints."
    else:
        api_menu = _generate_api_menu_for_agent()
        api_context = f"Available API endpoints:\n{api_menu}"

    chat_system = f"""You are an expert AI administrator for a Samba Active Directory Domain Controller.

You are in a persistent chat session. The user can ask multiple questions and you maintain conversation context.

{api_context}

You have access to these tools:
1. `execute_samba_api` — Call any Samba AD Management API endpoint
2. `execute_samba_api_as` — Call API on behalf of a SPECIFIC USER by username or ID. Use for RBAC testing — verify what a user can/cannot do. Example: `execute_samba_api_as(method="DELETE", path="/api/v1/users/testuser", as_user="junior_admin")`
3. `execute_shell_command` — Execute shell commands on the server
4. `save_file` — Save/export data to files (CSV, JSON, XLSX, TXT)
5. `read_file` — Read files from the server
6. `manage_samba_share` — Create, edit, delete Samba file shares
7. `manage_samba_config` — Read and modify Samba configuration (smb.conf)
8. `system_admin` — System administration (services, logs, backups, disk/memory usage)
9. `network_admin` — Network diagnostics and administration
10. `ai_skill_execute` — Execute AI skills from the SKILL directory
11. `request_api_access` — Discover available API endpoints by your permissions
12. `data_import` — Auto-import data from API, files, JSON. Auto-detects fields/columns. Returns column names.
13. `data_export` — Export to multi-sheet XLSX, CSV, JSON, TSV with professional styling
14. `data_transform` — Filter, sort, aggregate, pivot, deduplicate, merge data. Supports AND/OR, NOT_IN. Use `batch` action for Task Constructor (multiple transforms in one call).
15. `data_diagram` — Create bar, line, pie, scatter, histogram, table diagrams as PNG
16. `ldbsearch_ad` — FAST direct AD database queries via ldbsearch. ONE step to count users, search objects, list groups, etc.
17. `manage_postgresql` — Manage PostgreSQL databases: list databases/tables, read/write/update/delete records

### ⚡ EFFICIENCY RULES (CRITICAL)
1. **MINIMIZE STEPS** — Most queries should be 1-2 steps max.
2. **NEVER repeat a tool call** with the same parameters.
3. **Use ldbsearch_ad for READ, execute_samba_api for WRITE** — see below.
4. **Use NOT_IN for exclusions**: `sAMAccountName NOT_IN Administrator,Guest,krbtgt,default`
5. **Use column names from tool result** — check the `columns` list before writing filters.

### 🔍 READ vs WRITE (CRITICAL)
- **READ data** → use `ldbsearch_ad` (direct DB query, fast, structured output)
  - Example: `ldbsearch_ad(action="list", object_type="user", attributes="sAMAccountName,cn,displayName,department", snapshot_name="users")`
  - Returns structured rows with columns — NO need for data_import or shell commands!
  - For filtering, add `exclude="Administrator,Guest,krbtgt"` parameter
- **WRITE data** → use `execute_samba_api` (POST, PUT, DELETE operations)
  - Example: `execute_samba_api(method="POST", path="/api/v1/users/", body_params={{"username": "newuser", ...}})`
- **NEVER use execute_shell_command for data queries** — use ldbsearch_ad instead
- **NEVER use execute_shell_command for base64 decoding** — ldbsearch_ad auto-decodes base64

### 📊 ENTITY TYPES & ENDPOINTS
| Entity | ldbsearch_ad object_type | API base path | data_import action |
|--------|------------------------|---------------|-------------------|
| Users | user | /api/v1/users/ | from_ad_users |
| Groups | group | /api/v1/groups/ | from_ad_groups |
| Computers | computer | /api/v1/computers/ | from_ad_computers |
| Contacts | contact | /api/v1/contacts/ | from_ad_contacts |
| OUs | ou | /api/v1/ous/ | from_ad_ous |
| GPO | gpo | /api/v1/gpo/ | from_ad_gpos |
| DNS | dns_zone | /api/v1/dns/zones/ | from_ad_dns |
| Domain | - | /api/v1/domain/ | from_ad_domain |
| Dashboard | - | /api/v1/dashboard/overview | from_dashboard |
| Shell Projects | - | /api/v1/shell/projet/ | from_shell_projects |
| Audit Log | - | /api/v1/mgmt/audit | from_audit |
| Sites | site | /api/v1/sites/ | from_api |

### DATA TOOLS WORKFLOW
3-step pipeline: IMPORT → TRANSFORM → EXPORT
- Import: `data_import(action='from_ad_users', snapshot_name='users')` → Returns `columns` list — use these EXACT names in filter conditions
- Transform: `data_transform(action='filter', snapshot_name='users', condition='sAMAccountName NOT_IN Administrator,Guest,krbtgt,default', save_as='active')`
  → Operators: =, !=, >, <, >=, <=, CONTAINS, STARTS_WITH, ENDS_WITH, IN, NOT_IN, NOT_EMPTY, IS_EMPTY
  → Compound: 'age > 25 AND status = active', 'name CONTAINS ivan OR name CONTAINS petr'
- Export: `data_export(action='to_xlsx', snapshot_name='active', filename='report.xlsx')`
- Diagram: `data_diagram(action='bar', snapshot_name='users', x_column='dept', y_column='count')`

### TASK CONSTRUCTOR (batch action)
Execute multiple transforms in ONE call:
```
data_transform(action='batch', snapshot_name='users', batch_steps=[
  {{"action": "filter", "condition": "sAMAccountName NOT_IN Administrator,Guest,krbtgt"}},
  {{"action": "sort", "sort_by": "cn"}},
  {{"action": "select", "columns": "sAMAccountName,cn,department"}}
], save_as='clean_users')
```

### ldbsearch_ad ONE-STEP EXPORT
For "export AD users to XLSX" type tasks, use ldbsearch_ad with export_xlsx parameter — DONE IN 1 STEP!
```
ldbsearch_ad(action='list', object_type='user', attributes='sAMAccountName,cn,department', include_groups=true, exclude='Administrator,Guest,krbtgt,default', export_xlsx='users_report.xlsx')
```

### RULES
1. **For data/export tasks**: ALWAYS use data_import → data_transform → data_export pipeline.
2. Use `execute_samba_api` for all AD management tasks (users, groups, DNS, GPO, etc.)
3. Use `execute_samba_api_as` for RBAC testing — to verify what a specific user can/cannot do.
4. Use `manage_samba_share` for creating/editing/deleting Samba file shares
5. Use `manage_samba_config` for reading and modifying smb.conf
6. Use `system_admin` for service management, logs, backups, and system monitoring
7. Use `network_admin` for network diagnostics (ping, DNS, connections)
8. Use `data_import` to quickly fetch API data — auto-detects all fields
9. Use `data_export` for professional multi-sheet XLSX/CSV/JSON exports
10. Use `data_transform` with NOT_IN for exclusions — ONE condition instead of many
11. Use `data_transform` with `batch` action for Task Constructor — multiple transforms in ONE call
12. Always verify destructive operations (delete, disable) before executing
13. Respond in the same language the user writes in
"""

    # Add custom system prompt if provided
    if chat_system_prompt:
        chat_system += f"\n### ADDITIONAL INSTRUCTIONS\n{chat_system_prompt}\n"

    # Build messages with history
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": chat_system},
    ]

    # Add context if provided
    if chat_context:
        context_str = json.dumps(chat_context, ensure_ascii=False, indent=2)
        messages.append({
            "role": "user",
            "content": f"[SESSION CONTEXT]:\n{context_str}",
        })

    # Load chat history (EXCLUDE the current user message to avoid duplication)
    # The current message is already saved to DB before this function is called,
    # so get_chat_messages_for_agent() returns it as the last entry.
    # We must skip the last user message if it matches our current user_message.
    try:
        history = get_chat_messages_for_agent(chat_id)
        # Add conversation history (skip system messages)
        for msg in history:
            if msg["role"] in ("user", "assistant"):
                messages.append({"role": msg["role"], "content": msg["content"]})
    except Exception as exc:
        logger.warning("[AI-CHAT-AGENT] Failed to load chat history: %s", exc)

    # Add the new user message ONLY if it's not already in history
    # (prevents duplicate "user" messages in the conversation)
    last_msg_content = ""
    if messages and messages[-1].get("role") == "user":
        last_msg_content = messages[-1].get("content", "")
    if last_msg_content != user_message:
        messages.append({"role": "user", "content": user_message})
    else:
        logger.debug("[AI-CHAT-AGENT] Skipping duplicate user message (already in history)")

    # Build tools list (original + extended)
    from app.services.ai_extended_tools import EXTENDED_AGENT_TOOLS
    all_tools = AGENT_TOOLS + EXTENDED_AGENT_TOOLS

    # Validate model
    raw_model = provider_info["default_model"]
    primary_model = _validate_model_name(raw_model)
    models_to_try = _build_model_chain(primary_model, settings)

    # v1.8.6: Skip models known to not support tool calling
    if _NO_TOOL_SUPPORT_MODELS:
        before = len(models_to_try)
        models_to_try = [m for m in models_to_try if m not in _NO_TOOL_SUPPORT_MODELS]
        skipped = before - len(models_to_try)
        if skipped:
            logger.info(
                "[AI-CHAT-AGENT] Skipped %d model(s) known to not support tool use: %s",
                skipped, _NO_TOOL_SUPPORT_MODELS,
            )
        if not models_to_try:
            return AIAgentResponse(
                status="error",
                error=f"All models in fallback chain don't support tool use: {_NO_TOOL_SUPPORT_MODELS}. "
                      f"Change SAMBA_POLZA_AI_MODEL or SAMBA_AI_FALLBACK_MODELS in .env",
            )
        primary_model = models_to_try[0]

    # Create AI client
    try:
        client = create_ai_client()
    except (ValueError, ImportError) as exc:
        return AIAgentResponse(status="error", error=str(exc))

    # Agent loop
    effective_max_steps = max_steps or getattr(settings, "AI_AGENT_MAX_STEPS", 10)
    max_rate_retries = getattr(settings, "AI_RATE_LIMIT_RETRIES", 3)
    max_wait = getattr(settings, "AI_RATE_LIMIT_MAX_WAIT", 30)

    steps: List[AIAgentStep] = []
    total_tokens = 0
    total_cost_rub: float = 0.0  # v1.8.4: cumulative cost
    last_usage_info: Optional[Dict[str, Any]] = None  # v1.8.4
    final_answer: Optional[str] = None
    step_num = 0
    model = primary_model

    # v1.10: Create DataMasker for this chat request
    masker = create_masker_from_config()

    for iteration in range(effective_max_steps):
        llm_result = await asyncio.to_thread(
            _agent_llm_call,
            client=client,
            model=model,
            messages=messages,
            tools=all_tools,
            temperature=settings.AI_TEMPERATURE,
            max_tokens=settings.AI_MAX_TOKENS,
            max_rate_retries=max_rate_retries,
            max_wait=max_wait,
            extra_body=polza_extra_body,
        )

        if isinstance(llm_result, str):
            last_model_error = llm_result
            current_idx = -1
            for i, m in enumerate(models_to_try):
                if m == model:
                    current_idx = i
                    break
            next_idx = current_idx + 1
            if next_idx < len(models_to_try):
                model = models_to_try[next_idx]
                continue
            return AIAgentResponse(
                status="error",
                error=last_model_error,
                steps=steps,
                total_steps=step_num,
                model_used=model,
            )

        response = llm_result

        if not response or not response.choices:
            current_idx = -1
            for i, m in enumerate(models_to_try):
                if m == model:
                    current_idx = i
                    break
            next_idx = current_idx + 1
            if next_idx < len(models_to_try):
                model = models_to_try[next_idx]
                continue
            return AIAgentResponse(
                status="error",
                error="LLM returned empty response for all models",
                steps=steps,
                total_steps=step_num,
                model_used=model,
            )

        if response.usage:
            total_tokens += (response.usage.total_tokens or 0)

        # v1.8.4: Extract detailed usage/cost info
        from app.services.ai_polza_provider import extract_usage_info, format_usage_log
        chat_step_usage = extract_usage_info(response)
        last_usage_info = chat_step_usage
        if chat_step_usage.get("cost_rub") is not None:
            try:
                total_cost_rub += float(chat_step_usage["cost_rub"])
            except (ValueError, TypeError):
                pass
        logger.info("[AI-CHAT-AGENT] Step usage: %s", format_usage_log(chat_step_usage))

        assistant_message = response.choices[0].message

        if assistant_message is None:
            current_idx = -1
            for i, m in enumerate(models_to_try):
                if m == model:
                    current_idx = i
                    break
            next_idx = current_idx + 1
            if next_idx < len(models_to_try):
                model = models_to_try[next_idx]
                continue
            return AIAgentResponse(
                status="error",
                error=f"LLM returned None message for all models",
                steps=steps,
                total_steps=step_num,
                model_used=model,
            )

        content = assistant_message.content or ""

        if not assistant_message.tool_calls:
            final_answer = content
            break

        step_num += 1

        tool_calls_for_history = []
        for tc in assistant_message.tool_calls:
            tool_calls_for_history.append({
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            })

        messages.append({
            "role": "assistant",
            "content": content,
            "tool_calls": tool_calls_for_history,
        })

        for tc in assistant_message.tool_calls:
            function_name = tc.function.name
            raw_arguments = tc.function.arguments

            function_args: Dict[str, Any] = _safe_parse_tool_args(raw_arguments)

            logger.info(
                "[AI-CHAT-AGENT] Step %d: tool=%s, args=%s",
                step_num, function_name, json.dumps(function_args, ensure_ascii=False)[:200],
            )

            tool_result = await _dispatch_tool_call(function_name, function_args, user_permissions)

            # v2.2: PII masking ENABLED — AI receives masked data with tokens
            masked_tool_result = masker.mask_json_string(tool_result)
            if masked_tool_result != tool_result:
                logger.info(
                    "[AI-CHAT-AGENT] PII detected in tool result for %s "
                    "(original: %d chars, masked: %d chars) — "
                    "sending MASKED data to AI",
                    function_name, len(tool_result), len(masked_tool_result),
                )
                # Send MASKED data to AI
                tool_result_for_ai = masked_tool_result
            else:
                # No PII detected — send as-is
                tool_result_for_ai = tool_result

            result_preview = tool_result[:500]
            steps.append(AIAgentStep(
                step=step_num,
                tool_name=function_name,
                tool_args=function_args,
                result_preview=result_preview,
                success="error" not in tool_result.lower()[:100],
            ))

            # v2.1: Add ORIGINAL (unmasked) tool result to conversation
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": tool_result_for_ai,
            })

    else:
        final_answer = (
            f"Agent reached maximum step limit ({effective_max_steps}). "
            f"Completed {step_num} steps."
        )
        logger.warning("[AI-CHAT-AGENT] Reached max steps: %d", effective_max_steps)

    # v2.2: Unmask AI response — replace tokens with real values
    if final_answer and masker.token_count > 0:
        unmasked_answer = masker.unmask_text(final_answer)
        if unmasked_answer != final_answer:
            logger.info(
                "[AI-CHAT-AGENT] Unmasked %d tokens in final answer",
                masker.token_count,
            )
            final_answer = unmasked_answer

    return AIAgentResponse(
        status="success" if final_answer else "partial",
        message=final_answer or "Agent completed with no final answer",
        steps=steps,
        total_steps=step_num,
        model_used=model,
        tokens_used=total_tokens if total_tokens > 0 else None,
        cost_rub=total_cost_rub if total_cost_rub > 0 else None,
        usage=AIUsageInfo(
            prompt_tokens=last_usage_info.get("prompt_tokens") if last_usage_info else None,
            completion_tokens=last_usage_info.get("completion_tokens") if last_usage_info else None,
            total_tokens=last_usage_info.get("total_tokens") if last_usage_info else None,
            reasoning_tokens=last_usage_info.get("reasoning_tokens") if last_usage_info else None,
            cached_tokens=last_usage_info.get("cached_tokens") if last_usage_info else None,
            cost_rub=last_usage_info.get("cost_rub") if last_usage_info else None,
            provider=last_usage_info.get("provider") if last_usage_info else None,
        ) if last_usage_info else None,
    )
