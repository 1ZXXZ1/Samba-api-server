"""
AI Assistant router for the Task Builder (v1.8).

v2.4: Quick-path optimization — intent detection skips 1st AI call for
common queries (~40-60% token savings). Two-phase prompt+tools for 2-call mode.

Provides REST endpoints for:
    - /ai/assistant  — Task Builder AI: translates natural-language
      requests into structured task builder actions.
    - /ai/agent      — Agent AI: executes actions directly on the server
      (API calls, shell commands, file I/O) using tool calling.
    - /ai/schema     — Returns a compressed summary of the OpenAPI schema.
    - /ai/config     — Returns the current AI configuration (non-sensitive).
    - /ai/chat/      — AI Chat system: create, list, delete, connect to
      chat sessions with user isolation.
    - /ai/chat/send  — Send a message in a chat session.
    - /ai/chat/history — Get chat message history.

All AI interactions are audit-logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from app.auth import ApiKeyDep
from app.models.ai import (
    AIConfigResponse,
    AIRequest,
    AIResponse,
    AISchemaResponse,
    AIEndpointInfo,
    AIAgentRequest,
    AIAgentResponse,
    AIBalanceResponse,
    AIInfoResponse,
)
from app.models.ai_chat import (
    ChatCreateRequest,
    ChatUpdateRequest,
    ChatSessionResponse,
    ChatListResponse,
    ChatMessageSend,
    ChatMessageResponse,
    ChatMessageUsageInfo,
    ChatHistoryResponse,
    ChatConnectInfo,
    ChatInfoResponse,
)
from app.services import ai_service
from app.services import ai_agent_service
from app.services.data_masker import DataMasker, create_masker_from_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["AI Assistant"])


# ═══════════════════════════════════════════════════════════════════════
#  Quick-Path Intent Detection (v2.4)
# ═══════════════════════════════════════════════════════════════════════

# For common queries like "show users", "list groups", we can pre-execute
# the ldbsearch_ad tool and skip the 1st AI call entirely. This reduces
# 2 AI calls → 1 AI call, saving ~50% tokens and ~40% cost.
#
# Pattern format: (regex, tool_function, default_args)
# The regex is checked against the user message (case-insensitive).
_QUICK_INTENT_PATTERNS: List[Tuple[str, str, Dict[str, Any]]] = [
    # ── User queries ──────────────────────────────────────────────────
    (
        r"(?:показ|покажи|список|сколько|вывед|выведи|вс[её]|list|show|count|get|отобраз|дай).*(?:user|пользовател|уч[её]тн)",
        "ldbsearch_ad",
        {"action": "list", "object_type": "user", "attributes": "sAMAccountName,cn,displayName,department,title", "exclude": "Administrator,Guest,krbtgt,default"},
    ),
    # ── Group queries ─────────────────────────────────────────────────
    (
        r"(?:показ|покажи|список|сколько|вывед|выведи|вс[её]|list|show|count|get|отобраз|дай).*(?:group|групп)",
        "ldbsearch_ad",
        {"action": "list", "object_type": "group", "attributes": "sAMAccountName,cn,description"},
    ),
    # ── Computer queries ──────────────────────────────────────────────
    (
        r"(?:показ|покажи|список|сколько|вывед|выведи|вс[её]|list|show|count|get|отобраз|дай).*(?:computer|компьютер|pc|рабоч|станци)",
        "ldbsearch_ad",
        {"action": "list", "object_type": "computer", "attributes": "sAMAccountName,cn,operatingSystem,dNSHostName"},
    ),
    # ── Count queries (very common) ──────────────────────────────────
    (
        r"(?:сколько|how many|count|число|количеств).*(?:user|пользовател|уч[её]тн)",
        "ldbsearch_ad",
        {"action": "count", "object_type": "user"},
    ),
    (
        r"(?:сколько|how many|count|число|количеств).*(?:group|групп)",
        "ldbsearch_ad",
        {"action": "count", "object_type": "group"},
    ),
    (
        r"(?:сколько|how many|count|число|количеств).*(?:computer|компьютер|pc|станци)",
        "ldbsearch_ad",
        {"action": "count", "object_type": "computer"},
    ),
    # ── OU queries ──────────────────────────────────────────────────
    (
        r"(?:показ|покажи|список|сколько|вывед|выведи|вс[её]|list|show|count|get|отобраз|дай).*(?:ou|подразделен|orgunit)",
        "ldbsearch_ad",
        {"action": "list", "object_type": "ou", "attributes": "ou,description"},
    ),
]


def _detect_quick_intent(user_message: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Detect if the user message matches a known intent for quick-path execution.

    Returns (tool_function, tool_args) if matched, None otherwise.
    Only matches simple, unambiguous queries where we can predict the exact
    tool call. Complex queries fall back to the normal 2-call flow.
    """
    msg_lower = user_message.lower().strip()

    # Skip very long messages — likely complex queries
    if len(msg_lower) > 150:
        return None

    # Skip messages with complex qualifiers (filters, specific names, etc.)
    # These need the AI to determine the right parameters
    complex_indicators = [
        " где ", "where", " фильтр", "filter",
        " создать", "create", " добавить", "add", " удалить", "delete", "remove",
        " изменить", "modify", "change", " обновить", "update",
        " пароль", "password", " право", "permission", " роль", "role",
        " экспорт", "export", " xlsx", " csv", " диаграмм", "chart", " график",
        " сценарий", "script", "backup", " бэкап",
    ]
    for indicator in complex_indicators:
        if indicator in msg_lower:
            return None

    for pattern, tool_name, default_args in _QUICK_INTENT_PATTERNS:
        if re.search(pattern, msg_lower, re.IGNORECASE):
            return (tool_name, dict(default_args))  # Return a copy

    return None


def _build_quick_path_system_prompt(mask_context: str = "") -> str:
    """Build a short system prompt for the quick-path (answer-only) mode.

    This is ~60% shorter than the full chat system prompt, saving
    ~3000 tokens per request. The AI just needs to format the answer
    from pre-fetched data — it doesn't need tool descriptions or
    efficiency rules.
    """
    prompt = """You are a helpful AD administrator AI. The user asked a question, and the relevant data has ALREADY been fetched from the AD database.

Your ONLY task: answer the user's question based on the data provided. Format data as tables when appropriate. Respond in the user's language.

Rules:
1. Use the EXACT data from the results — do not invent or guess values
2. For empty/missing fields, show "—" (dash)
3. Keep responses concise — just the data the user asked for
4. If the user asks for more, tell them to ask a follow-up question
"""
    if mask_context:
        prompt += "\n" + mask_context
    return prompt


def _build_answer_phase_system_prompt(mask_context: str = "") -> str:
    """Build a shorter system prompt for the 2nd+ AI call (answer phase).

    Removes verbose sections (entity table, data tools workflow, examples)
    that are only needed for tool selection, not for answer generation.
    Saves ~2500 tokens vs the full prompt.
    """
    prompt = """You are an expert AI administrator for a Samba Active Directory Domain Controller.

You are in a persistent chat session. The user can ask multiple questions and you maintain conversation context.

### EFFICIENCY RULES
1. **MINIMIZE STEPS** — Most queries should be 1-2 steps max.
2. **NEVER repeat a tool call** with the same parameters.
3. **Use ldbsearch_ad for READ, execute_samba_api for WRITE**.
4. **Use NOT_IN for exclusions**: `sAMAccountName NOT_IN Administrator,Guest,krbtgt,default`

### RULES
1. Use `execute_samba_api` for all AD management tasks
2. Use `ldbsearch_ad` for fast AD data queries
3. Always verify destructive operations (delete, disable) before executing
4. Respond in the same language the user writes in
"""
    if mask_context:
        prompt += "\n" + mask_context
    return prompt


def _slim_tool_result(tool_result: str) -> str:
    """Strip unnecessary metadata from tool results before sending to AI.

    Removes fields that the AI doesn't need: rows_parsed, excluded_count,
    rows_after_exclude, snapshot_saved, snapshot_name, validation details,
    preview_filtered, preview_columns, computer_accounts_filtered.

    Saves ~200-400 tokens per tool call.
    """
    try:
        data = json.loads(tool_result)
    except (json.JSONDecodeError, TypeError):
        return tool_result

    if not isinstance(data, dict):
        return tool_result

    # Fields to remove (metadata the AI doesn't need)
    fields_to_remove = [
        "rows_parsed", "excluded_count", "rows_after_exclude",
        "snapshot_saved", "snapshot_name",
        "preview_filtered", "preview_columns",
        "computer_accounts_filtered", "groups_added", "groups_error",
        "post_process_note", "rejected",
    ]
    for field in fields_to_remove:
        data.pop(field, None)

    # Slim down validation object
    validation = data.get("validation")
    if isinstance(validation, dict):
        # Keep only approved + present_attrs
        slim_validation = {}
        if "approved" in validation:
            slim_validation["approved"] = validation["approved"]
        if "present_attrs" in validation:
            slim_validation["present_attrs"] = validation["present_attrs"]
        if not validation.get("approved", True):
            # If rejected, keep the note
            slim_validation["validation_note"] = validation.get("validation_note", "")
        data["validation"] = slim_validation

    # Slim down export result
    export = data.get("export")
    if isinstance(export, dict):
        # Keep only success + path + url
        slim_export = {}
        for k in ("success", "path", "url", "filename", "error"):
            if k in export:
                slim_export[k] = export[k]
        data["export"] = slim_export

    return json.dumps(data, ensure_ascii=False, default=str)


# ── Helper: get user info from request ──────────────────────────────────


def _get_user_info(request: Request) -> Dict[str, str]:
    """Extract user_id, username, and role from request state."""
    auth_method = getattr(request.state, "auth_method", "api_key")
    user_id = ""
    username = ""
    role = "operator"

    if auth_method == "jwt":
        user_payload = getattr(request.state, "user", {})
        user_id = user_payload.get("sub", "jwt-user")
        username = user_payload.get("sub", "")
        role = user_payload.get("role", "operator")
    elif auth_method in ("api_key", "static_api_key"):
        key_info = getattr(request.state, "api_key_info", {})
        user_id = key_info.get("user_id", "api-key-user")
        username = key_info.get("username", "")
        role = getattr(request.state, "role", "admin")

    return {"user_id": user_id or "anonymous", "username": username, "role": role}


def _get_user_permissions(request: Request) -> set:
    """Get the current user's permissions set."""
    role = _get_user_info(request).get("role", "operator")
    try:
        from app.api_ma import get_role_permissions
        return get_role_permissions(role)
    except Exception:
        return set()


# ── Main AI Assistant ───────────────────────────────────────────────────


@router.post(
    "/assistant",
    response_model=AIResponse,
    summary="AI Assistant for Task Builder",
    description=(
        "Generates task builder actions from a natural-language prompt. "
        "Uses LLM (Polza.ai) and the server's own OpenAPI specification. "
        "In Safe Mode (default), real data values are hidden from the LLM "
        "and replaced with {{USER_INPUT}} placeholders."
    ),
)
async def ai_assistant(
    request: Request,
    body: AIRequest,
    api_key: ApiKeyDep,
) -> AIResponse:
    """Process an AI assistant request."""
    _log_ai_action(
        request=request,
        action="ai_assistant",
        detail=f"safe={body.safe_mode} model_override={body.model_override} "
               f"prompt_len={len(body.prompt)}",
    )

    result = await ai_service.process_ai_request(body)
    return result


# ── OpenAPI Schema Summary ──────────────────────────────────────────────


@router.get(
    "/schema",
    response_model=AISchemaResponse,
    summary="Compressed OpenAPI schema for AI",
)
async def get_ai_schema(
    request: Request,
    api_key: ApiKeyDep,
) -> AISchemaResponse:
    """Return the compressed OpenAPI schema used by the AI."""
    _log_ai_action(request=request, action="ai_schema_view", detail="view")

    endpoints = ai_service.get_schema_endpoints()
    compressed_str, raw = ai_service.load_openapi_schema()

    return AISchemaResponse(
        total_endpoints=len(endpoints),
        schema_version=raw.get("info", {}).get("version") if raw else None,
        endpoints=[
            AIEndpointInfo(
                method=e["method"],
                path=e["path"],
                operation_id=e.get("operation_id"),
                summary=e.get("summary"),
                parameters=e.get("parameters", []),
            )
            for e in endpoints
        ],
    )


# ── AI Configuration ────────────────────────────────────────────────────


@router.get(
    "/config",
    response_model=AIConfigResponse,
    summary="Current AI configuration",
)
async def get_ai_config(
    request: Request,
    api_key: ApiKeyDep,
) -> AIConfigResponse:
    """Return the current AI configuration (non-sensitive)."""
    from app.config import get_settings

    settings = get_settings()
    endpoints = ai_service.get_schema_endpoints()
    compressed_str, _ = ai_service.load_openapi_schema()
    schema_loaded = compressed_str != "{}"

    # Determine active provider + Polza.ai details
    from app.services.ai_polza_provider import (
        is_polza_configured, get_effective_ai_provider, get_polza_config_summary
    )
    provider_info = get_effective_ai_provider()
    polza_summary = get_polza_config_summary()

    fallback_str = getattr(settings, "AI_FALLBACK_MODELS", "")
    fallback_list = [m.strip() for m in fallback_str.split(",") if m.strip()] if fallback_str else []

    return AIConfigResponse(
        enabled=bool(provider_info["api_key"]),
        default_model=provider_info["default_model"],
        safe_mode_default=True,
        temperature=settings.AI_TEMPERATURE,
        max_tokens=settings.AI_MAX_TOKENS,
        schema_loaded=schema_loaded,
        schema_endpoints=len(endpoints),
        rate_limit_retries=getattr(settings, "AI_RATE_LIMIT_RETRIES", 3),
        rate_limit_max_wait=getattr(settings, "AI_RATE_LIMIT_MAX_WAIT", 30),
        fallback_models=fallback_list,
        max_schema_chars=getattr(settings, "AI_MAX_SCHEMA_CHARS", 12000),
        # v1.8.3: Polza.ai provider info (structured)
        active_provider=polza_summary.get("active_provider", "polza"),
        polza_configured=polza_summary.get("polza_configured", False),
        polza_url=polza_summary.get("polza_url"),
        polza_model=polza_summary.get("polza_model"),
        polza_provider=polza_summary.get("polza_provider"),
        polza_reasoning=polza_summary.get("polza_reasoning"),
        polza_sampling=polza_summary.get("polza_sampling"),
        polza_web_search=polza_summary.get("polza_web_search"),
        polza_extra_body=polza_summary.get("polza_extra_body"),
        # v1.8.4: Polza.ai balance info
        polza_balance=polza_summary.get("polza_balance"),
    )


# ── AI Balance (v1.8.4) ────────────────────────────────────────────────


@router.get(
    "/balance",
    response_model=AIBalanceResponse,
    summary="AI provider account balance",
    description=(
        "Get the current account balance for the active AI provider. "
        "For Polza.ai, returns amount, reserved, and spent amounts in RUB."
    ),
)
async def get_ai_balance(
    request: Request,
    api_key: ApiKeyDep,
) -> AIBalanceResponse:
    """Return the current AI provider account balance."""
    _log_ai_action(request=request, action="ai_balance_view", detail="view")

    from app.services.ai_polza_provider import (
        is_polza_configured, get_polza_balance, get_effective_ai_provider,
    )

    provider_info = get_effective_ai_provider()

    if provider_info["provider"] == "polza" and is_polza_configured():
        balance_data = get_polza_balance()
        error = balance_data.get("error")
        return AIBalanceResponse(
            provider="polza",
            balance=balance_data if not error else None,
            configured=True,
            error=error,
        )
    else:
        return AIBalanceResponse(
            provider=provider_info["provider"],
            balance=None,
            configured=bool(provider_info["api_key"]),
            error="Balance API is only available for Polza.ai provider",
        )


# ── AI Agent (Direct Execution) ────────────────────────────────────────


@router.post(
    "/agent",
    response_model=AIAgentResponse,
    summary="AI Agent with direct execution",
    description=(
        "AI agent that executes actions directly on the server using "
        "tool calling. The AI has access to: "
        "1) execute_samba_api — call any Samba AD API endpoint, "
        "2) execute_samba_api_as — call API on behalf of a specific user (RBAC testing), "
        "3) execute_shell_command — run shell commands on the server, "
        "4) save_file — export data to CSV/JSON/XLSX, "
        "5) read_file — read files from the server, "
        "6) manage_samba_share — create/edit/delete Samba shares, "
        "7) manage_samba_config — read/modify smb.conf, "
        "8) system_admin — system administration tools, "
        "9) network_admin — network diagnostics, "
        "10) ai_skill_execute — execute AI skills, "
        "11) request_api_access — discover available endpoints by permission. "
        "The agent uses Polza.ai for AI inference."
    ),
)
async def ai_agent(
    request: Request,
    body: AIAgentRequest,
    api_key: ApiKeyDep,
) -> AIAgentResponse:
    """Process an AI agent request with direct tool execution."""
    _log_ai_action(
        request=request,
        action="ai_agent",
        detail=f"model_override={body.model_override} max_steps={body.max_steps} "
               f"prompt_len={len(body.prompt)}",
    )

    # Pass user permissions to the agent for permission-based mode
    user_perms = _get_user_permissions(request)
    user_info = _get_user_info(request)

    result = await ai_agent_service.process_ai_agent_request(
        body,
        user_permissions=user_perms,
        user_info=user_info,
    )

    # v1.8.4: Fetch current balance after the request
    from app.services.ai_polza_provider import is_polza_configured, get_polza_balance
    if is_polza_configured() and result.status == "success":
        balance_data = get_polza_balance()
        if "error" not in balance_data:
            result.balance = balance_data

    return result


# ═══════════════════════════════════════════════════════════════════════
#  AI Chat Endpoints (v1.8)
# ═══════════════════════════════════════════════════════════════════════


@router.post(
    "/chat/",
    response_model=ChatSessionResponse,
    summary="Create a new AI chat session",
    description=(
        "Create a new AI chat session. Each user has their own isolated "
        "chats. Admin users can see all chats."
    ),
)
async def create_chat(
    request: Request,
    body: ChatCreateRequest,
    api_key: ApiKeyDep,
) -> ChatSessionResponse:
    """Create a new AI chat session."""
    from app.config import get_settings
    settings = get_settings()

    if not getattr(settings, "AI_CHAT_ENABLED", True):
        raise HTTPException(status_code=503, detail="AI chat is disabled")

    user_info = _get_user_info(request)

    try:
        from app.services.ai_chat_service import create_chat as _create_chat
        chat = _create_chat(
            owner_id=user_info["user_id"],
            owner_username=user_info["username"],
            title=body.title,
            model_override=body.model_override,
            system_prompt=body.system_prompt,
            context=body.context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _log_ai_action(
        request=request,
        action="ai_chat_create",
        detail=f"chat_id={chat['id']} title={body.title}",
    )

    return ChatSessionResponse(**chat)


@router.get(
    "/chat/list",
    response_model=ChatListResponse,
    summary="List AI chat sessions",
    description=(
        "List chat sessions for the current user. Regular users see only "
        "their own chats. Admin users can see all chats."
    ),
)
async def list_chats(
    request: Request,
    api_key: ApiKeyDep,
    include_archived: bool = False,
) -> ChatListResponse:
    """List chat sessions."""
    user_info = _get_user_info(request)

    from app.services.ai_chat_service import list_chats as _list_chats
    chats = _list_chats(
        user_id=user_info["user_id"],
        role=user_info["role"],
        include_archived=include_archived,
    )

    # v1.8.4: Add cost summary per chat
    from app.services.ai_chat_service import get_chat_cost_summary
    chat_responses = []
    for c in chats:
        cost_summary = get_chat_cost_summary(c["id"])
        chat_responses.append(ChatSessionResponse(
            **{k: v for k, v in c.items() if k != "system_prompt" and k != "context"},
            total_cost_rub=cost_summary["total_cost_rub"] if cost_summary["total_cost_rub"] > 0 else None,
            total_tokens=cost_summary["total_tokens"] if cost_summary["total_tokens"] > 0 else None,
        ))

    return ChatListResponse(
        chats=chat_responses,
        total=len(chat_responses),
    )


@router.get(
    "/chat/{chat_id}",
    response_model=ChatSessionResponse,
    summary="Get chat session details",
)
async def get_chat(
    request: Request,
    chat_id: str,
    api_key: ApiKeyDep,
) -> ChatSessionResponse:
    """Get a specific chat session."""
    user_info = _get_user_info(request)

    from app.services.ai_chat_service import get_chat as _get_chat
    chat = _get_chat(chat_id, user_info["user_id"], user_info["role"])

    if not chat:
        raise HTTPException(status_code=404, detail=f"Chat '{chat_id}' not found or no access")

    return ChatSessionResponse(**chat)


@router.put(
    "/chat/{chat_id}",
    response_model=ChatSessionResponse,
    summary="Update chat session",
)
async def update_chat(
    request: Request,
    chat_id: str,
    body: ChatUpdateRequest,
    api_key: ApiKeyDep,
) -> ChatSessionResponse:
    """Update a chat session (title, system prompt, archive)."""
    user_info = _get_user_info(request)

    from app.services.ai_chat_service import update_chat as _update_chat
    chat = _update_chat(
        chat_id=chat_id,
        user_id=user_info["user_id"],
        role=user_info["role"],
        title=body.title,
        system_prompt=body.system_prompt,
    )

    if not chat:
        raise HTTPException(status_code=404, detail=f"Chat '{chat_id}' not found or no access")

    return ChatSessionResponse(**chat)


@router.delete(
    "/chat/{chat_id}",
    summary="Delete a chat session",
)
async def delete_chat(
    request: Request,
    chat_id: str,
    api_key: ApiKeyDep,
) -> dict:
    """Delete a chat session and all its messages."""
    user_info = _get_user_info(request)

    from app.services.ai_chat_service import delete_chat as _delete_chat
    deleted = _delete_chat(chat_id, user_info["user_id"], user_info["role"])

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Chat '{chat_id}' not found or no access")

    _log_ai_action(
        request=request,
        action="ai_chat_delete",
        detail=f"chat_id={chat_id}",
    )

    return {"status": "ok", "message": f"Chat '{chat_id}' deleted"}


@router.post(
    "/chat/{chat_id}/send",
    response_model=ChatMessageResponse,
    summary="Send a message in a chat session",
    description=(
        "Send a message to the AI in a chat session. The AI will respond "
        "using the agent mode (tool calling) or assistant mode. "
        "The conversation history is preserved across messages."
    ),
)
async def send_chat_message(
    request: Request,
    chat_id: str,
    body: ChatMessageSend,
    api_key: ApiKeyDep,
) -> ChatMessageResponse:
    """Send a message in a chat session and get AI response."""
    from app.config import get_settings
    settings = get_settings()

    if not getattr(settings, "AI_CHAT_ENABLED", True):
        raise HTTPException(status_code=503, detail="AI chat is disabled")

    user_info = _get_user_info(request)
    user_perms = _get_user_permissions(request)

    from app.services.ai_chat_service import get_chat, add_message, get_chat_messages_for_agent

    # Verify access
    chat = get_chat(chat_id, user_info["user_id"], user_info["role"])
    if not chat:
        raise HTTPException(status_code=404, detail=f"Chat '{chat_id}' not found or no access")

    # Save user message
    user_msg = add_message(
        chat_id=chat_id,
        role="user",
        content=body.message,
    )

    _log_ai_action(
        request=request,
        action="ai_chat_send",
        detail=f"chat_id={chat_id} use_agent={body.use_agent} msg_len={len(body.message)}",
    )

    # Process with AI
    try:
        if body.use_agent:
            # Agent mode — tool calling with conversation history
            result = await ai_agent_service.process_chat_agent_request(
                chat_id=chat_id,
                user_message=body.message,
                chat_system_prompt=chat.get("system_prompt", ""),
                chat_context=chat.get("context", {}),
                max_steps=body.max_steps,
                user_permissions=user_perms,
                user_info=user_info,
            )

            # v1.8.4: Extract usage/cost info from agent response
            agent_cost_rub = result.cost_rub
            agent_usage = result.usage
            agent_usage_dict = None
            if agent_usage:
                agent_usage_dict = {
                    "prompt_tokens": agent_usage.prompt_tokens,
                    "completion_tokens": agent_usage.completion_tokens,
                    "total_tokens": agent_usage.total_tokens,
                    "reasoning_tokens": agent_usage.reasoning_tokens,
                    "cached_tokens": agent_usage.cached_tokens,
                    "cost_rub": agent_usage.cost_rub,
                    "provider": agent_usage.provider,
                }

            # Save assistant response with cost info
            assistant_msg = add_message(
                chat_id=chat_id,
                role="assistant",
                content=result.message or "",
                model_used=result.model_used,
                tokens_used=result.tokens_used,
                cost_rub=agent_cost_rub,
                usage_info=agent_usage_dict,
                tool_steps=[
                    {"step": s.step, "tool": s.tool_name, "args": s.tool_args, "success": s.success}
                    for s in result.steps
                ] if result.steps else None,
            )

            # v1.8.4: Fetch current balance after the request
            from app.services.ai_polza_provider import is_polza_configured, get_polza_balance
            balance_after = None
            if is_polza_configured():
                balance_data = get_polza_balance()
                if "error" not in balance_data:
                    balance_after = balance_data

            return ChatMessageResponse(
                id=assistant_msg["id"],
                role="assistant",
                content=result.message or "",
                timestamp=assistant_msg["timestamp"],
                model_used=result.model_used,
                tokens_used=result.tokens_used,
                cost_rub=agent_cost_rub,
                usage=ChatMessageUsageInfo(
                    prompt_tokens=agent_usage_dict.get("prompt_tokens") if agent_usage_dict else None,
                    completion_tokens=agent_usage_dict.get("completion_tokens") if agent_usage_dict else None,
                    total_tokens=agent_usage_dict.get("total_tokens") if agent_usage_dict else None,
                    reasoning_tokens=agent_usage_dict.get("reasoning_tokens") if agent_usage_dict else None,
                    cached_tokens=agent_usage_dict.get("cached_tokens") if agent_usage_dict else None,
                    cost_rub=agent_cost_rub,
                    provider=agent_usage_dict.get("provider") if agent_usage_dict else None,
                ) if agent_usage_dict else None,
                tool_steps=[
                    {"step": s.step, "tool": s.tool_name, "args": s.tool_args, "success": s.success}
                    for s in result.steps
                ] if result.steps else None,
            )
        else:
            # Assistant mode — Task Builder suggestions only
            ai_req = AIRequest(
                prompt=body.message,
                context=chat.get("context"),
                safe_mode=True,
            )
            result = await ai_service.process_ai_request(ai_req)

            # v1.8.4: Extract usage/cost info from assistant response
            asst_cost_rub = None
            asst_usage_dict = None
            if result.usage:
                asst_cost_rub = result.usage.cost_rub
                asst_usage_dict = {
                    "prompt_tokens": result.usage.prompt_tokens,
                    "completion_tokens": result.usage.completion_tokens,
                    "total_tokens": result.usage.total_tokens,
                    "reasoning_tokens": result.usage.reasoning_tokens,
                    "cached_tokens": result.usage.cached_tokens,
                    "cost_rub": result.usage.cost_rub,
                    "provider": result.usage.provider,
                }

            content = result.message or json.dumps({"actions": [a.model_dump() for a in (result.actions or [])]})
            assistant_msg = add_message(
                chat_id=chat_id,
                role="assistant",
                content=content,
                model_used=result.model_used,
                tokens_used=result.tokens_used,
                cost_rub=asst_cost_rub,
                usage_info=asst_usage_dict,
            )

            return ChatMessageResponse(
                id=assistant_msg["id"],
                role="assistant",
                content=content,
                timestamp=assistant_msg["timestamp"],
                model_used=result.model_used,
                tokens_used=result.tokens_used,
                cost_rub=asst_cost_rub,
                usage=ChatMessageUsageInfo(
                    prompt_tokens=asst_usage_dict.get("prompt_tokens") if asst_usage_dict else None,
                    completion_tokens=asst_usage_dict.get("completion_tokens") if asst_usage_dict else None,
                    total_tokens=asst_usage_dict.get("total_tokens") if asst_usage_dict else None,
                    reasoning_tokens=asst_usage_dict.get("reasoning_tokens") if asst_usage_dict else None,
                    cached_tokens=asst_usage_dict.get("cached_tokens") if asst_usage_dict else None,
                    cost_rub=asst_cost_rub,
                    provider=asst_usage_dict.get("provider") if asst_usage_dict else None,
                ) if asst_usage_dict else None,
            )

    except Exception as exc:
        logger.error("[AI-CHAT] Failed to process message: %s", exc)
        # Save error message — but wrap in try/except in case the chat
        # session was deleted while the agent was processing (FK violation)
        try:
            error_msg = add_message(
                chat_id=chat_id,
                role="assistant",
                content=f"Error: {exc}",
            )
            return ChatMessageResponse(
                id=error_msg["id"],
                role="assistant",
                content=f"Error processing message: {exc}",
                timestamp=error_msg["timestamp"],
            )
        except Exception:
            logger.warning("[AI-CHAT] Could not save error message to chat %s (session may have been deleted)", chat_id)
            from datetime import datetime, timezone
            return ChatMessageResponse(
                id="error",
                role="assistant",
                content=f"Error processing message: {exc}",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )


@router.post(
    "/chat/{chat_id}/stream",
    summary="Send chat message with SSE streaming (real-time steps)",
    description=(
        "Send a message in a chat session and receive real-time updates "
        "via Server-Sent Events (SSE). Each tool step, partial content, "
        "and the final answer are sent as separate SSE events so the "
        "client can display progress in real-time instead of waiting "
        "for the full response. v1.8.5-4."
    ),
)
async def stream_chat_message(
    request: Request,
    chat_id: str,
    body: ChatMessageSend,
    api_key: ApiKeyDep,
) -> StreamingResponse:
    """Stream a chat message response with real-time tool step updates."""
    from app.config import get_settings
    from app.services.ai_chat_service import get_chat, add_message, get_chat_messages_for_agent
    from app.services.ai_agent_service import (
        _validate_model_name, _build_model_chain,
        _agent_llm_call, _dispatch_tool_call, AGENT_TOOLS,
        _safe_parse_tool_args, _ai_debug_log,
    )
    from app.services.ai_polza_provider import (
        get_effective_ai_provider, create_ai_client, build_polza_extra_body,
        extract_usage_info, format_usage_log,
    )
    from app.models.ai import AIAgentStep

    settings = get_settings()

    if not getattr(settings, "AI_CHAT_ENABLED", True):
        raise HTTPException(status_code=503, detail="AI chat is disabled")

    user_info = _get_user_info(request)
    user_perms = _get_user_permissions(request)

    # Verify access
    chat = get_chat(chat_id, user_info["user_id"], user_info["role"])
    if not chat:
        raise HTTPException(status_code=404, detail=f"Chat '{chat_id}' not found or no access")

    # Save user message
    add_message(chat_id=chat_id, role="user", content=body.message)

    _log_ai_action(
        request=request,
        action="ai_chat_stream",
        detail=f"chat_id={chat_id} use_agent={body.use_agent} msg_len={len(body.message)}",
    )

    async def sse_generator():
        """Generate SSE events as the agent processes."""
        try:
            if not body.use_agent:
                # Assistant mode — no streaming, just return result
                ai_req = ai_service.AIRequest(
                    prompt=body.message,
                    context=chat.get("context"),
                    safe_mode=True,
                )
                result = await ai_service.process_ai_request(ai_req)

                # Save and send
                try:
                    assistant_msg = add_message(
                        chat_id=chat_id,
                        role="assistant",
                        content=result.message or "",
                    )
                except Exception:
                    assistant_msg = {"id": "stream", "timestamp": ""}

                yield f"data: {json.dumps({'type': 'content', 'content': result.message or ''}, ensure_ascii=False)}\n\n"
                yield f"data: {json.dumps({'type': 'done', 'message_id': assistant_msg.get('id', '')}, ensure_ascii=False)}\n\n"
                return

            # Agent mode — stream tool steps in real-time
            provider_info = get_effective_ai_provider()

            # Build extra body
            polza_extra_body = None
            if provider_info["provider"] == "polza":
                polza_extra_body = build_polza_extra_body(for_tool_use=True)

            # Build system prompt (same as process_chat_agent_request)
            from app.services.ai_agent_service import _generate_api_menu_for_agent

            permission_mode = getattr(settings, "AI_PERMISSION_MODE", True)
            if permission_mode and user_perms:
                from app.permissions import get_permissions_by_category
                perms_by_cat = get_permissions_by_category()
                user_perms_by_cat = {
                    cat: [p for p in perms if p in user_perms]
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
  - Example: `execute_samba_api(method="POST", path="/api/v1/users/", body={{"username": "newuser", ...}})`
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

### EXAMPLE: "Export all users except default to XLSX" (2 steps with batch):
  1. data_import(action='from_ad_users', snapshot_name='users')
  2. data_transform(action='batch', snapshot_name='users', batch_steps=[
       {{"action": "filter", "condition": "sAMAccountName NOT_IN Administrator,Guest,krbtgt,default"}},
       {{"action": "select", "columns": "sAMAccountName,cn,department"}}
     ], save_as='clean')
  3. data_export(action='to_xlsx', snapshot_name='clean', filename='users.xlsx')

### RULES
1. **For data/export tasks**: ALWAYS use data_import → data_transform → data_export pipeline.
2. Use `execute_samba_api` for all AD management tasks (users, groups, DNS, GPO, etc.) — this uses the admin API key with full access.
3. Use `execute_samba_api_as` for RBAC testing — to verify what a specific user can/cannot do. Example: `execute_samba_api_as(method="DELETE", path="/api/v1/users/test", as_user="junior_admin")` → should return 403 if junior_admin lacks permission.
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

            chat_system_prompt = chat.get("system_prompt", "") or ""
            if chat_system_prompt:
                chat_system += f"\n### ADDITIONAL INSTRUCTIONS\n{chat_system_prompt}\n"

            # v2.2: Add masking context to system prompt so AI understands tokens
            masker = create_masker_from_config()
            if hasattr(masker, 'get_ai_context_block'):
                mask_context = masker.get_ai_context_block()
                if mask_context:
                    chat_system += "\n\n" + mask_context

            # Build messages
            messages = [{"role": "system", "content": chat_system}]

            chat_context = chat.get("context")
            if chat_context:
                messages.append({
                    "role": "user",
                    "content": f"[SESSION CONTEXT]:\n{json.dumps(chat_context, ensure_ascii=False, indent=2)}",
                })

            try:
                history = get_chat_messages_for_agent(chat_id)
                for msg in history:
                    if msg["role"] in ("user", "assistant"):
                        messages.append({"role": msg["role"], "content": msg["content"]})
            except Exception:
                pass

            # Add user message only if not already in history (prevent duplicate)
            last_msg_content = ""
            if messages and messages[-1].get("role") == "user":
                last_msg_content = messages[-1].get("content", "")
            if last_msg_content != body.message:
                messages.append({"role": "user", "content": body.message})
            else:
                logger.debug("[AI-CHAT-STREAM] Skipping duplicate user message (already in history)")

            # Tools
            from app.services.ai_extended_tools import EXTENDED_AGENT_TOOLS
            all_tools = AGENT_TOOLS + EXTENDED_AGENT_TOOLS

            # Initialize variables shared between quick-path and normal flow
            total_tokens = 0
            total_cost_rub = 0.0
            last_usage_info = None
            step_num = 0
            model = provider_info["default_model"]
            final_answer = None
            all_steps = []
            max_rate_retries = getattr(settings, "AI_RATE_LIMIT_RETRIES", 3)
            max_wait = getattr(settings, "AI_RATE_LIMIT_MAX_WAIT", 30)

            # v2.4: Phase 2 tools — minimal set for answer generation
            # Only include ldbsearch_ad + execute_samba_api for follow-up queries
            # Saves ~3600 tokens vs sending all 14 tools on 2nd call
            _phase2_tools = [
                t for t in all_tools
                if t.get("function", {}).get("name") in ("ldbsearch_ad", "execute_samba_api")
            ]

            # v2.4: Quick-path intent detection — skip 1st AI call for common queries
            quick_intent = _detect_quick_intent(body.message)
            quick_path_taken = False

            if quick_intent:
                tool_name, tool_args = quick_intent
                logger.info(
                    "[AI-CHAT-STREAM] Quick-path intent detected: %s(%s) — skipping 1st AI call",
                    tool_name, json.dumps(tool_args, ensure_ascii=False)[:100],
                )

                # Pre-execute the tool (same as AI would do in step 1)
                step_num = 1
                try:
                    tool_result = await _dispatch_tool_call(tool_name, tool_args, user_perms)
                except Exception as exc:
                    logger.warning("[AI-CHAT-STREAM] Quick-path tool execution failed: %s — falling back to normal flow", exc)
                    quick_intent = None  # Fall back to normal flow
                    tool_result = None

                if quick_intent and tool_result:
                    # Send step event to client (shows what was pre-executed)
                    yield f"data: {json.dumps({'type': 'step_start', 'step': step_num, 'tool': tool_name, 'args': tool_args}, ensure_ascii=False)}\n\n"

                    # Debug log: original tool result
                    _ai_debug_log("QUICK-PATH TOOL_RESULT (original, before masking)", {
                        "step": step_num,
                        "tool": tool_name,
                        "args": tool_args,
                        "result_length": len(tool_result),
                        "result": tool_result,
                    })

                    # Apply PII masking + slim
                    tool_result_slim = _slim_tool_result(tool_result)
                    masked_tool_result = masker.mask_json_string(tool_result_slim)
                    if masked_tool_result != tool_result_slim:
                        logger.info(
                            "[AI-CHAT-STREAM] Quick-path: PII detected in tool result for %s "
                            "(original: %d chars, slim: %d, masked: %d chars)",
                            tool_name, len(tool_result), len(tool_result_slim), len(masked_tool_result),
                        )
                        tool_result_for_ai = masked_tool_result
                    else:
                        tool_result_for_ai = tool_result_slim

                    # Build simplified quick-path system prompt
                    mask_context = masker.get_ai_context_block() if hasattr(masker, 'get_ai_context_block') else ""
                    quick_prompt = _build_quick_path_system_prompt(mask_context)

                    # Build messages for 1-call mode: [system] + [user + data context]
                    user_content_with_data = (
                        f"{body.message}\n\n"
                        f"=== FETCHED DATA ===\n{tool_result_for_ai}\n=== END DATA ==="
                    )
                    quick_messages = [
                        {"role": "system", "content": quick_prompt},
                        {"role": "user", "content": user_content_with_data},
                    ]

                    # Send step_result event to client (original unmasked preview)
                    success = "error" not in tool_result.lower()[:100]
                    all_steps.append({"step": step_num, "tool": tool_name, "args": tool_args, "success": success})
                    result_preview = tool_result[:800]
                    yield f"data: {json.dumps({'type': 'step_result', 'step': step_num, 'tool': tool_name, 'success': success, 'result_preview': result_preview}, ensure_ascii=False)}\n\n"

                    # Make 1 AI call (answer-only, no tools)
                    try:
                        client = create_ai_client()
                    except (ValueError, ImportError) as exc:
                        yield f"data: {json.dumps({'type': 'error', 'error': str(exc)}, ensure_ascii=False)}\n\n"
                        return

                    raw_model = provider_info["default_model"]
                    primary_model = _validate_model_name(raw_model)
                    models_to_try = _build_model_chain(primary_model, settings)
                    model = primary_model

                    # Build extra body for non-tool-use call (simpler)
                    quick_extra_body = None
                    if provider_info["provider"] == "polza":
                        quick_extra_body = build_polza_extra_body(for_tool_use=False)

                    _ai_debug_log("REQUEST → AI (quick-path, answer-only)", {
                        "model": model,
                        "temperature": settings.AI_TEMPERATURE,
                        "messages_count": len(quick_messages),
                        "messages_roles": [m["role"] for m in quick_messages],
                        "tools_count": 0,
                        "mode": "QUICK_PATH_NO_TOOLS",
                    })

                    llm_result = await asyncio.to_thread(
                        _agent_llm_call,
                        client=client,
                        model=model,
                        messages=quick_messages,
                        tools=[],  # No tools — just answer generation
                        temperature=settings.AI_TEMPERATURE,
                        max_tokens=settings.AI_MAX_TOKENS,
                        max_rate_retries=max_rate_retries,
                        max_wait=max_wait,
                        extra_body=quick_extra_body,
                    )

                    if isinstance(llm_result, str):
                        # Error — fall back to normal flow
                        logger.warning("[AI-CHAT-STREAM] Quick-path AI call failed: %s — falling back", llm_result[:200])
                        quick_intent = None  # Fall through to normal flow
                    elif llm_result and llm_result.choices and llm_result.choices[0].message:
                        response = llm_result
                        content = response.choices[0].message.content or ""

                        if response.usage:
                            total_tokens += (response.usage.total_tokens or 0)
                        step_usage = extract_usage_info(response)
                        if step_usage.get("cost_rub") is not None:
                            try:
                                total_cost_rub += float(step_usage["cost_rub"])
                            except (ValueError, TypeError):
                                pass

                        _ai_debug_log("RESPONSE ← AI (quick-path)", {
                            "model": model,
                            "content": content,
                            "content_length": len(content),
                            "has_tool_calls": False,
                            "usage": {
                                "prompt_tokens": response.usage.prompt_tokens if response.usage else "?",
                                "completion_tokens": response.usage.completion_tokens if response.usage else "?",
                                "total_tokens": response.usage.total_tokens if response.usage else "?",
                            } if response.usage else "(no usage data)",
                        })

                        final_answer = content
                        quick_path_taken = True
                    else:
                        logger.warning("[AI-CHAT-STREAM] Quick-path AI returned empty response — falling back")
                        quick_intent = None  # Fall through to normal flow

            if not quick_path_taken:
                # ── Normal flow: 2+ AI calls with tool calling ─────────
                # Client
                try:
                    client = create_ai_client()
                except (ValueError, ImportError) as exc:
                    yield f"data: {json.dumps({'type': 'error', 'error': str(exc)}, ensure_ascii=False)}\n\n"
                    return

                raw_model = provider_info["default_model"]
                primary_model = _validate_model_name(raw_model)
                models_to_try = _build_model_chain(primary_model, settings)

                # v1.8.6: Skip models known to not support tool calling
                from app.services.ai_agent_service import _NO_TOOL_SUPPORT_MODELS
                if _NO_TOOL_SUPPORT_MODELS:
                    before = len(models_to_try)
                    models_to_try = [m for m in models_to_try if m not in _NO_TOOL_SUPPORT_MODELS]
                    skipped = before - len(models_to_try)
                    if skipped:
                        logger.info(
                            "[AI-CHAT-STREAM] Skipped %d model(s) known to not support tool use: %s",
                            skipped, _NO_TOOL_SUPPORT_MODELS,
                        )
                    if not models_to_try:
                        yield f"data: {json.dumps({'type': 'error', 'error': f'All models dont support tool use: {_NO_TOOL_SUPPORT_MODELS}'}, ensure_ascii=False)}\n\n"
                        return
                    primary_model = models_to_try[0]

                effective_max_steps = body.max_steps or getattr(settings, "AI_AGENT_MAX_STEPS", 10)


                # Send start event
                yield f"data: {json.dumps({'type': 'start', 'model': primary_model}, ensure_ascii=False)}\n\n"

                for iteration in range(effective_max_steps):
                    # v2.4: Phase-based optimization — after 1st tool call,
                    # use simplified prompt + minimal tools to save tokens
                    if step_num > 0:
                        current_tools = _phase2_tools
                        mask_context = masker.get_ai_context_block() if hasattr(masker, 'get_ai_context_block') else ""
                        # Replace system prompt with shorter version for answer phase
                        if messages and messages[0].get("role") == "system":
                            messages[0]["content"] = _build_answer_phase_system_prompt(mask_context)
                    else:
                        current_tools = all_tools

                    llm_result = await asyncio.to_thread(
                        _agent_llm_call,
                        client=client,
                        model=model,
                        messages=messages,
                        tools=current_tools,
                        temperature=settings.AI_TEMPERATURE,
                        max_tokens=settings.AI_MAX_TOKENS,
                        max_rate_retries=max_rate_retries,
                        max_wait=max_wait,
                        extra_body=polza_extra_body,
                    )

                    if isinstance(llm_result, str):
                        # Model error — try fallback
                        fallback_reason = ""
                        if "doesn't support tool use" in llm_result or "support tool use" in llm_result.lower():
                            fallback_reason = "no tool support"
                        elif "insufficient credits" in llm_result.lower() or "402" in llm_result:
                            fallback_reason = "insufficient credits"
                        elif "rate-limited" in llm_result.lower():
                            fallback_reason = "rate limited"

                        current_idx = -1
                        for i, m in enumerate(models_to_try):
                            if m == model:
                                current_idx = i
                                break
                        next_idx = current_idx + 1
                        if next_idx < len(models_to_try):
                            model = models_to_try[next_idx]
                            yield f"data: {json.dumps({'type': 'fallback', 'model': model, 'reason': fallback_reason}, ensure_ascii=False)}\n\n"
                            continue
                        yield f"data: {json.dumps({'type': 'error', 'error': llm_result}, ensure_ascii=False)}\n\n"
                        return

                    response = llm_result

                    if not response or not response.choices or response.choices[0].message is None:
                        current_idx = -1
                        for i, m in enumerate(models_to_try):
                            if m == model:
                                current_idx = i
                                break
                        next_idx = current_idx + 1
                        if next_idx < len(models_to_try):
                            model = models_to_try[next_idx]
                            yield f"data: {json.dumps({'type': 'fallback', 'model': model, 'reason': 'empty response'}, ensure_ascii=False)}\n\n"
                            continue
                        yield f"data: {json.dumps({'type': 'error', 'error': 'LLM returned empty response'}, ensure_ascii=False)}\n\n"
                        return

                    if response.usage:
                        total_tokens += (response.usage.total_tokens or 0)

                    step_usage = extract_usage_info(response)
                    last_usage_info = step_usage
                    if step_usage.get("cost_rub") is not None:
                        try:
                            total_cost_rub += float(step_usage["cost_rub"])
                        except (ValueError, TypeError):
                            pass

                    assistant_message = response.choices[0].message
                    content = assistant_message.content or ""

                    _ai_debug_log("RESPONSE ← AI (stream)", {
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
                        "phase": "answer" if step_num > 0 else "tool_selection",
                        "tools_count": len(current_tools),
                    })

                    if not assistant_message.tool_calls:
                        final_answer = content
                        break

                    step_num += 1

                    # Build tool_calls for history
                    tool_calls_for_history = []
                    for tc in assistant_message.tool_calls:
                        tool_calls_for_history.append({
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                        })

                    messages.append({
                        "role": "assistant",
                        "content": content,
                        "tool_calls": tool_calls_for_history,
                    })

                    # Execute each tool call and stream step events
                    for tc in assistant_message.tool_calls:
                        function_name = tc.function.name
                        raw_arguments = tc.function.arguments

                        function_args = _safe_parse_tool_args(raw_arguments)

                        # Send step_start event
                        yield f"data: {json.dumps({'type': 'step_start', 'step': step_num, 'tool': function_name, 'args': function_args}, ensure_ascii=False)}\n\n"

                        tool_result = await _dispatch_tool_call(function_name, function_args, user_perms)

                        _ai_debug_log("TOOL_RESULT (original, before masking)", {
                            "step": step_num,
                            "tool": function_name,
                            "args": function_args,
                            "result_length": len(tool_result),
                            "result": tool_result,
                        })

                        # v2.4: Slim tool result before masking (strip metadata)
                        tool_result_slim = _slim_tool_result(tool_result)

                        # PII masking
                        masked_tool_result = masker.mask_json_string(tool_result_slim)
                        if masked_tool_result != tool_result_slim:
                            logger.info(
                                "[AI-CHAT-STREAM] PII detected in tool result for %s "
                                "(original: %d chars, slim: %d, masked: %d chars) — "
                                "sending MASKED data to AI",
                                function_name, len(tool_result), len(tool_result_slim), len(masked_tool_result),
                            )
                            _ai_debug_log("TOOL_RESULT (masked, sent to AI)", {
                                "step": step_num,
                                "tool": function_name,
                                "original_length": len(tool_result),
                                "masked_length": len(masked_tool_result),
                                "masker_tokens": masker.token_count,
                            })
                            tool_result_for_ai = masked_tool_result
                        else:
                            tool_result_for_ai = tool_result_slim

                        success = "error" not in tool_result.lower()[:100]
                        all_steps.append({
                            "step": step_num,
                            "tool": function_name,
                            "args": function_args,
                            "success": success,
                        })

                        # Send step_result event — show ORIGINAL (unmasked) preview
                        result_preview = tool_result[:800]
                        yield f"data: {json.dumps({'type': 'step_result', 'step': step_num, 'tool': function_name, 'success': success, 'result_preview': result_preview}, ensure_ascii=False)}\n\n"

                        # Add masked tool result to conversation history
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": tool_result_for_ai,
                        })
                else:
                    final_answer = f"Agent reached maximum step limit ({effective_max_steps}). Completed {step_num} steps."

            # v3.0: Unmask AI response — replace [P1],[P2]... tokens with real values
            # so the user sees real data in the final answer.
            if final_answer and masker.token_count > 0:
                unmasked_answer = masker.unmask_text(final_answer)
                if unmasked_answer != final_answer:
                    logger.info(
                        "[AI-CHAT-STREAM] Unmasked %d tokens in final answer",
                        masker.token_count,
                    )
                    final_answer = unmasked_answer
            elif final_answer:
                _ai_debug_log("FINAL ANSWER (no masking needed)", {
                    "answer": final_answer,
                })

            # Save assistant message (with unmasked content for the user)
            try:
                assistant_msg = add_message(
                    chat_id=chat_id,
                    role="assistant",
                    content=final_answer or "",
                    model_used=model,
                    tokens_used=total_tokens,
                    cost_rub=total_cost_rub,
                    usage_info=last_usage_info,
                    tool_steps=all_steps if all_steps else None,
                )
            except Exception:
                assistant_msg = {"id": "stream", "timestamp": ""}

            # Send final content + done events
            yield f"data: {json.dumps({'type': 'content', 'content': final_answer or ''}, ensure_ascii=False)}\n\n"
            yield f"data: {json.dumps({
                'type': 'done',
                'message_id': assistant_msg.get('id', ''),
                'model': model,
                'tokens': total_tokens,
                'cost_rub': total_cost_rub,
                'steps': step_num,
            }, ensure_ascii=False)}\n\n"

        except Exception as exc:
            logger.error("[AI-CHAT-STREAM] Error: %s", exc)
            yield f"data: {json.dumps({'type': 'error', 'error': str(exc)}, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/chat/{chat_id}/history",
    response_model=ChatHistoryResponse,
    summary="Get chat message history",
)
async def get_chat_history(
    request: Request,
    chat_id: str,
    api_key: ApiKeyDep,
    limit: int = 50,
    before: Optional[str] = None,
) -> ChatHistoryResponse:
    """Get chat message history."""
    user_info = _get_user_info(request)

    from app.services.ai_chat_service import get_chat_history as _get_history
    messages, has_more = _get_history(
        chat_id=chat_id,
        user_id=user_info["user_id"],
        role=user_info["role"],
        limit=limit,
        before=before,
    )

    return ChatHistoryResponse(
        chat_id=chat_id,
        messages=[
            ChatMessageResponse(
                id=m["id"],
                role=m["role"],
                content=m["content"],
                timestamp=m["timestamp"],
                model_used=m.get("model_used"),
                tokens_used=m.get("tokens_used"),
                cost_rub=m.get("cost_rub"),
                usage=ChatMessageUsageInfo(
                    prompt_tokens=m.get("usage", {}).get("prompt_tokens") if m.get("usage") else None,
                    completion_tokens=m.get("usage", {}).get("completion_tokens") if m.get("usage") else None,
                    total_tokens=m.get("usage", {}).get("total_tokens") if m.get("usage") else None,
                    reasoning_tokens=m.get("usage", {}).get("reasoning_tokens") if m.get("usage") else None,
                    cached_tokens=m.get("usage", {}).get("cached_tokens") if m.get("usage") else None,
                    cost_rub=m.get("usage", {}).get("cost_rub") if m.get("usage") else None,
                    provider=m.get("usage", {}).get("provider") if m.get("usage") else None,
                ) if m.get("usage") else None,
                tool_steps=m.get("tool_steps"),
            )
            for m in messages
        ],
        total=len(messages),
        has_more=has_more,
    )


# ── AI Info (v1.8.4) — Dashboard with balance + costs ───────────────────


@router.get(
    "/info",
    response_model=AIInfoResponse,
    summary="AI usage dashboard",
    description=(
        "Get a comprehensive overview of AI usage: provider, balance, "
        "total costs across all chats, and per-chat cost breakdown. "
        "This is the main 'dashboard' endpoint to see how much AI costs."
    ),
)
async def get_ai_info(
    request: Request,
    api_key: ApiKeyDep,
) -> AIInfoResponse:
    """Return AI usage info dashboard with balance and costs."""
    _log_ai_action(request=request, action="ai_info_view", detail="view")

    from app.services.ai_polza_provider import (
        is_polza_configured, get_polza_balance, get_effective_ai_provider,
    )
    from app.services.ai_chat_service import get_all_chats_cost_summary

    provider_info = get_effective_ai_provider()
    all_costs = get_all_chats_cost_summary()

    # Get balance
    balance = None
    if provider_info["provider"] == "polza" and is_polza_configured():
        balance_data = get_polza_balance()
        if "error" not in balance_data:
            balance = balance_data

    return AIInfoResponse(
        provider=provider_info["provider"],
        configured=bool(provider_info["api_key"]),
        default_model=provider_info["default_model"],
        balance=balance,
        total_chats=all_costs["total_chats"],
        total_cost_rub=all_costs["total_cost_rub"],
        total_tokens=all_costs["total_tokens"],
        chat_costs=all_costs["chat_costs"],
    )


# ── Chat Info (v1.8.4) — Per-chat cost summary ────────────────────────


@router.get(
    "/chat/{chat_id}/info",
    response_model=ChatInfoResponse,
    summary="Chat session cost/usage summary",
    description=(
        "Get detailed cost and usage summary for a specific chat session. "
        "Includes total cost, token usage, balance, and per-message cost "
        "breakdown so you can see exactly what each request cost."
    ),
)
async def get_chat_info(
    request: Request,
    chat_id: str,
    api_key: ApiKeyDep,
) -> ChatInfoResponse:
    """Return chat session cost/usage info with balance."""
    user_info = _get_user_info(request)

    from app.services.ai_chat_service import get_chat, get_chat_cost_summary
    from app.services.ai_polza_provider import (
        is_polza_configured, get_polza_balance, get_effective_ai_provider,
    )

    chat = get_chat(chat_id, user_info["user_id"], user_info["role"])
    if not chat:
        raise HTTPException(status_code=404, detail=f"Chat '{chat_id}' not found or no access")

    cost_summary = get_chat_cost_summary(chat_id)

    # Get balance
    balance = None
    provider_info = get_effective_ai_provider()
    if provider_info["provider"] == "polza" and is_polza_configured():
        balance_data = get_polza_balance()
        if "error" not in balance_data:
            balance = balance_data

    return ChatInfoResponse(
        chat_id=chat_id,
        title=chat["title"],
        owner_id=chat["owner_id"],
        model=chat.get("model", ""),
        message_count=chat["message_count"],
        assistant_message_count=cost_summary["assistant_message_count"],
        total_cost_rub=cost_summary["total_cost_rub"],
        total_tokens=cost_summary["total_tokens"],
        total_prompt_tokens=cost_summary["total_prompt_tokens"],
        total_completion_tokens=cost_summary["total_completion_tokens"],
        total_reasoning_tokens=cost_summary["total_reasoning_tokens"],
        balance=balance,
        provider=provider_info["provider"],
        messages=cost_summary["messages"],
    )


# ── Export File Downloads (v1.9.1) ─────────────────────────────────────


@router.get(
    "/exports",
    summary="List all exported files with download links",
    description=(
        "List all files in the AI export directory with download URLs. "
        "Each file includes a download_url that can be used to retrieve the file."
    ),
)
async def list_export_files(
    request: Request,
    api_key: ApiKeyDep,
) -> dict:
    """List all exported files with download links."""
    from app.config import get_settings
    settings = get_settings()
    export_dir = getattr(settings, "AI_AGENT_EXPORT_DIR", "/home/AD-API-USER/ai-exports")

    _log_ai_action(request=request, action="ai_exports_list", detail="list")

    if not os.path.isdir(export_dir):
        return {"files": [], "total": 0, "export_dir": export_dir}

    files = []
    try:
        for fname in sorted(os.listdir(export_dir)):
            fpath = os.path.join(export_dir, fname)
            if os.path.isfile(fpath):
                stat = os.stat(fpath)
                files.append({
                    "filename": fname,
                    "size_bytes": stat.st_size,
                    "modified": stat.st_mtime,
                    "download_url": f"/api/v1/ai/exports/{fname}",
                })
    except Exception as exc:
        logger.error("[AI-EXPORTS] Failed to list export dir: %s", exc)
        return {"files": [], "total": 0, "error": str(exc)}

    return {"files": files, "total": len(files), "export_dir": export_dir}


@router.get(
    "/exports/{filename}",
    summary="Download an exported file",
    description=(
        "Download a file from the AI export directory. "
        "Files are created by data_export, ldbsearch_ad export_xlsx, "
        "and save_file tools."
    ),
)
async def download_export_file(
    request: Request,
    filename: str,
    api_key: ApiKeyDep,
):
    """Download an exported file by filename."""
    import os as _os
    from fastapi.responses import FileResponse
    from app.config import get_settings

    settings = get_settings()
    export_dir = getattr(settings, "AI_AGENT_EXPORT_DIR", "/home/AD-API-USER/ai-exports")

    # Sanitize filename — prevent directory traversal
    safe_filename = _os.path.basename(filename)
    if safe_filename != filename:
        raise HTTPException(status_code=400, detail="Invalid filename (path separators not allowed)")

    filepath = _os.path.join(export_dir, safe_filename)

    if not _os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"File '{safe_filename}' not found")

    if not _os.path.isfile(filepath):
        raise HTTPException(status_code=400, detail=f"'{safe_filename}' is not a file")

    _log_ai_action(
        request=request,
        action="ai_export_download",
        detail=f"file={safe_filename}",
    )

    # Determine media type based on extension
    ext = _os.path.splitext(safe_filename)[1].lower()
    media_types = {
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xls": "application/vnd.ms-excel",
        ".csv": "text/csv",
        ".json": "application/json",
        ".tsv": "text/tab-separated-values",
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".png": "image/png",
        ".pdf": "application/pdf",
    }
    media_type = media_types.get(ext, "application/octet-stream")

    return FileResponse(
        path=filepath,
        filename=safe_filename,
        media_type=media_type,
    )


# ── Helper: Audit logging ───────────────────────────────────────────────


def _log_ai_action(request: Request, action: str, detail: str = "") -> None:
    """Log an AI action to the audit trail."""
    try:
        from app.api_ma import log_action

        user_id = getattr(request.state, "user_id", None)
        api_key_id = getattr(request.state, "api_key_id", None)
        ip_address = request.client.host if request.client else ""

        log_action(
            user_id=user_id,
            api_key_id=api_key_id,
            action=action,
            endpoint="/api/v1/ai/" + action,
            ip_address=ip_address,
            details=detail,
        )
    except Exception as exc:
        logger.debug("[AI] Audit log failed (non-fatal): %s", exc)

