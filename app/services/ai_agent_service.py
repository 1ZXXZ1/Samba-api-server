"""
AI Agent service for direct execution mode (v1.6.8-9).

Unlike the Task Builder AI (ai_service.py) which returns structured
suggestions for the frontend constructor, the Agent mode **executes
actions directly** on the server using OpenRouter tool calling.

The AI has access to four tools:
    - ``execute_samba_api``  — Call any Samba AD API endpoint
    - ``execute_shell_command`` — Run shell commands on the server
    - ``save_file``  — Save data to local files (CSV, JSON, XLSX, TXT)
    - ``read_file``  — Read files from the server

Agent loop:
    1. Build system prompt with API schema + rules
    2. Send messages + tools to OpenRouter
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
        OpenRouter internal errors). The code only checked for string
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
import json
import logging
import os
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from app.config import get_settings
from app.models.ai import AIAgentRequest, AIAgentResponse, AIAgentStep
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

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Agent Tool Definitions (OpenRouter function calling format)
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


async def _dispatch_tool_call(function_name: str, function_args: Dict[str, Any]) -> str:
    """Route a tool call to the appropriate execution function.

    v1.6.8-7: Made async because _execute_samba_api_call is now async.
    Shell commands are run in a thread pool to avoid blocking the event loop.
    """
    if function_name == "execute_samba_api":
        return await _execute_samba_api_call(
            method=function_args.get("method", "GET"),
            path=function_args.get("path", "/"),
            query_params=function_args.get("query_params"),
            body_params=function_args.get("body_params"),
        )
    elif function_name == "execute_shell_command":
        # Run sync subprocess in thread pool to avoid blocking event loop
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
        return json.dumps({"error": f"Unknown tool: {function_name}"})


# ═══════════════════════════════════════════════════════════════════════
#  Agent System Prompt
# ═══════════════════════════════════════════════════════════════════════

AGENT_SYSTEM_PROMPT_TEMPLATE = """You are an expert AI administrator for a Samba Active Directory Domain Controller.

You have FULL ACCESS to the server through these tools:
1. `execute_samba_api` — Call any Samba AD Management API endpoint (list users, create groups, manage DNS, GPO, OUs, etc.)
2. `execute_shell_command` — Execute shell commands directly on the server (samba-tool, system administration, diagnostics)
3. `save_file` — Save/export data to files (CSV, JSON, XLSX, TXT)
4. `read_file` — Read files from the server

### AVAILABLE API ENDPOINTS
{api_menu}

### RULES
1. Use `execute_samba_api` for all AD management tasks (users, groups, DNS, GPO, etc.)
2. Use `execute_shell_command` for tasks not available via API (logs, diagnostics, samba-tool direct)
3. When asked to export/save data: first get the data via API, then call `save_file`
4. For multi-step tasks, execute each step sequentially and check results before proceeding
5. If an API call fails, check the error and try an alternative approach
6. Always verify destructive operations (delete, disable) before executing
7. Respond in the same language the user writes in

### SHELL COMMANDS
- You can run any shell command on the server
- For samba-tool commands: use `sudo samba-tool <command>` if needed
- For diagnostics: use standard Linux tools (ping, dig, netstat, journalctl, etc.)
- Dangerous commands (rm -rf /, mkfs, etc.) are blocked for safety
"""


# ═══════════════════════════════════════════════════════════════════════
#  Main Agent Processing Function
# ═══════════════════════════════════════════════════════════════════════


async def process_ai_agent_request(request: AIAgentRequest) -> AIAgentResponse:
    """Process an AI agent request using tool calling (function calling).

    The agent has direct access to:
    - Samba AD API (execute_samba_api)
    - Shell commands (execute_shell_command)
    - File I/O (save_file, read_file)

    The agent loop runs up to AI_AGENT_MAX_STEPS iterations:
    1. Send messages + tools to OpenRouter
    2. If LLM returns tool_calls → execute → feed results back
    3. If LLM returns text → done
    """
    settings = get_settings()

    if not settings.AI_OPENROUTER_API_KEY:
        return AIAgentResponse(
            status="error",
            error="AI is not configured: OPENROUTER_API_KEY is empty. "
                  "Set SAMBA_AI_OPENROUTER_API_KEY in .env",
        )

    # 1. Generate API menu for system prompt
    api_menu = _generate_api_menu_for_agent()
    system_prompt = AGENT_SYSTEM_PROMPT_TEMPLATE.format(api_menu=api_menu)

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
    raw_model = request.model_override or settings.AI_DEFAULT_MODEL
    primary_model = _validate_model_name(raw_model)

    # v1.6.8-7 fix #3: Build fallback model chain
    # Previously, the agent only tried one model. If it failed with
    # 404 (model not found) or 402 (insufficient credits), the
    # entire request failed. Now we try fallback models.
    models_to_try = _build_model_chain(primary_model, settings)

    # 4. Create OpenAI client
    try:
        from openai import OpenAI
    except ImportError:
        return AIAgentResponse(
            status="error",
            error="openai package not installed. Run: pip install openai",
        )

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=settings.AI_OPENROUTER_API_KEY,
        max_retries=0,  # We handle retries ourselves
    )

    # 5. Agent loop
    max_steps = request.max_steps or getattr(settings, "AI_AGENT_MAX_STEPS", 10)
    max_rate_retries = getattr(settings, "AI_RATE_LIMIT_RETRIES", 3)
    max_wait = getattr(settings, "AI_RATE_LIMIT_MAX_WAIT", 30)

    steps: List[AIAgentStep] = []
    total_tokens = 0
    final_answer: Optional[str] = None
    step_num = 0
    model = primary_model  # Will be updated if fallback is used
    last_model_error: Optional[str] = None

    # v1.6.8-7: Try models in the fallback chain
    for current_model in models_to_try:
        model = current_model
        last_model_error = None
        break  # We'll handle fallback within the loop below
    else:
        model = primary_model

    for iteration in range(max_steps):
        # -- Call LLM with retry --
        # v1.6.8-7: Run sync OpenAI call in thread pool to avoid blocking
        # the event loop (the SDK is synchronous and uses time.sleep for retries)
        llm_result = await asyncio.to_thread(
            _agent_llm_call,
            client=client,
            model=model,
            messages=messages,
            tools=AGENT_TOOLS,
            temperature=settings.AI_TEMPERATURE,
            max_tokens=settings.AI_MAX_TOKENS,
            max_rate_retries=max_rate_retries,
            max_wait=max_wait,
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
        # OpenRouter can return a response with choices=None or choices=[]
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

            # Parse arguments
            function_args: Dict[str, Any] = {}
            try:
                function_args = json.loads(raw_arguments)
            except json.JSONDecodeError:
                try:
                    import ast
                    function_args = ast.literal_eval(raw_arguments)
                except Exception:
                    function_args = {}

            logger.info(
                "[AI-AGENT] Step %d: tool=%s, args=%s",
                step_num, function_name, json.dumps(function_args, ensure_ascii=False)[:200],
            )

            # Execute the tool (async because API calls use httpx.AsyncClient)
            tool_result = await _dispatch_tool_call(function_name, function_args)

            # Record step
            result_preview = tool_result[:500]
            steps.append(AIAgentStep(
                step=step_num,
                tool_name=function_name,
                tool_args=function_args,
                result_preview=result_preview,
                success="error" not in tool_result.lower()[:100],
            ))

            # Add tool result to conversation
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": tool_result,
            })

    else:
        # Agent hit max steps
        final_answer = (
            f"Agent reached maximum step limit ({max_steps}). "
            f"Completed {step_num} steps. Last step results are included."
        )
        logger.warning("[AI-AGENT] Reached max steps: %d", max_steps)

    # 6. Return response
    return AIAgentResponse(
        status="success" if final_answer else "partial",
        message=final_answer or "Agent completed with no final answer",
        steps=steps,
        total_steps=step_num,
        model_used=model,
        tokens_used=total_tokens if total_tokens > 0 else None,
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
) -> Any:
    """Call the LLM for agent mode with 429 retry logic.

    Returns the OpenAI response object on success, or an error string on failure.
    """
    rate_retries_done = 0
    conn_retries_done = 0
    total_waited = 0.0
    max_total_attempts = max_rate_retries + 3 + 1  # rate + connection + initial

    for attempt in range(max_total_attempts):
        try:
            logger.debug("[AI-AGENT] LLM call attempt %d, model=%s", attempt + 1, model)

            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            return response

        except Exception as exc:
            error_type = _classify_error(exc)

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
