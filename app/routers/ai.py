"""
AI Assistant router for the Task Builder (v1.6.8-6).

Provides REST endpoints for:
    - /ai/assistant  — Task Builder AI: translates natural-language
      requests into structured task builder actions.
    - /ai/agent      — Agent AI: executes actions directly on the server
      (API calls, shell commands, file I/O) using tool calling.
    - /ai/schema     — Returns a compressed summary of the OpenAPI schema.
    - /ai/config     — Returns the current AI configuration (non-sensitive).

All AI interactions are audit-logged.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth import ApiKeyDep
from app.models.ai import (
    AIConfigResponse,
    AIRequest,
    AIResponse,
    AISchemaResponse,
    AIEndpointInfo,
    AIAgentRequest,
    AIAgentResponse,
)
from app.services import ai_service
from app.services import ai_agent_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["AI Assistant"])


# ── Main AI Assistant ───────────────────────────────────────────────────


@router.post(
    "/assistant",
    response_model=AIResponse,
    summary="AI Assistant for Task Builder",
    description=(
        "Generates task builder actions from a natural-language prompt. "
        "Uses OpenRouter LLM and the server's own OpenAPI specification. "
        "In Safe Mode (default), real data values are hidden from the LLM "
        "and replaced with {{USER_INPUT}} placeholders."
    ),
)
async def ai_assistant(
    request: Request,
    body: AIRequest,
    api_key: ApiKeyDep,
) -> AIResponse:
    """Process an AI assistant request.

    The AI translates the user's natural-language prompt into a sequence
    of API call nodes for the visual Task Builder constructor.
    """
    # Audit log
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
    description=(
        "Returns a compressed summary of the server's OpenAPI specification. "
        "This is the same schema that is fed to the AI assistant. Useful for "
        "debugging and frontend integration."
    ),
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
    description="Returns the current AI configuration (non-sensitive fields only).",
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

    # Parse fallback models list
    fallback_str = getattr(settings, "AI_FALLBACK_MODELS", "")
    fallback_list = [m.strip() for m in fallback_str.split(",") if m.strip()] if fallback_str else []

    return AIConfigResponse(
        enabled=bool(settings.AI_OPENROUTER_API_KEY),
        default_model=settings.AI_DEFAULT_MODEL,
        safe_mode_default=True,
        temperature=settings.AI_TEMPERATURE,
        max_tokens=settings.AI_MAX_TOKENS,
        schema_loaded=schema_loaded,
        schema_endpoints=len(endpoints),
        rate_limit_retries=getattr(settings, "AI_RATE_LIMIT_RETRIES", 3),
        rate_limit_max_wait=getattr(settings, "AI_RATE_LIMIT_MAX_WAIT", 30),
        fallback_models=fallback_list,
        max_schema_chars=getattr(settings, "AI_MAX_SCHEMA_CHARS", 12000),
    )


# ── AI Agent (Direct Execution) (v1.6.8-6) ─────────────────────────────


@router.post(
    "/agent",
    response_model=AIAgentResponse,
    summary="AI Agent with direct execution",
    description=(
        "AI agent that executes actions directly on the server using "
        "tool calling. The AI has access to: "
        "1) execute_samba_api — call any Samba AD API endpoint, "
        "2) execute_shell_command — run shell commands on the server, "
        "3) save_file — export data to CSV/JSON/XLSX, "
        "4) read_file — read files from the server. "
        "The agent runs in a loop: call LLM → execute tools → feed results "
        "back → repeat until done (up to AI_AGENT_MAX_STEPS iterations)."
    ),
)
async def ai_agent(
    request: Request,
    body: AIAgentRequest,
    api_key: ApiKeyDep,
) -> AIAgentResponse:
    """Process an AI agent request with direct tool execution.

    Unlike /ai/assistant which returns structured suggestions for the
    Task Builder UI, this endpoint executes actions directly on the server.
    The AI uses OpenRouter tool calling to:
    - Call API endpoints (list users, create groups, etc.)
    - Execute shell commands (samba-tool, diagnostics, etc.)
    - Save/read files (export data, read configs, etc.)
    """
    # Audit log
    _log_ai_action(
        request=request,
        action="ai_agent",
        detail=f"model_override={body.model_override} max_steps={body.max_steps} "
               f"prompt_len={len(body.prompt)}",
    )

    result = await ai_agent_service.process_ai_agent_request(body)
    return result


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
