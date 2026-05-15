"""
Pydantic models for the AI Assistant API (v1.6.8-6).

Provides structured request/response models for:
    - Task Builder AI (AIRequest/AIResponse) — returns structured actions
    - Agent AI (AIAgentRequest/AIAgentResponse) — executes actions directly

Safe Mode: When enabled, real data values are stripped from the context
sent to the LLM — only keys and types are visible. The AI uses
``{{USER_INPUT}}`` placeholders for values that must be filled in manually.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── Request ──────────────────────────────────────────────────────────────


class AIRequest(BaseModel):
    """User request to the AI assistant."""

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description=(
            "Natural-language request from the user. "
            "Example: 'Disable user ivanov and remove from group admins'"
        ),
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Current task graph from the frontend constructor. "
            "In Safe Mode, all values are replaced with type placeholders "
            "before sending to the LLM."
        ),
    )
    safe_mode: bool = Field(
        True,
        description=(
            "When True (default), real data values are stripped from the "
            "context. The AI only sees keys and types, and must use "
            "{{USER_INPUT}} placeholders for any specific values."
        ),
    )
    model_override: Optional[str] = Field(
        None,
        description=(
            "Override the default LLM model for this request. "
            "Example: 'openai/gpt-4o-mini', 'anthropic/claude-3-haiku'. "
            "If None, uses the server default (DEFAULT_MODEL). "
            "NOTE: Do NOT send type names like 'string' as the value — "
            "they will be rejected and the default model will be used."
        ),
    )

    # v1.6.8-3 fix #2: Reject type-name strings like "string" in model_override
    @field_validator("model_override", mode="before")
    @classmethod
    def _validate_model_override(cls, v: Any) -> Any:
        """Reject obviously invalid model names like 'string', 'str', etc.

        These can appear when the OpenAPI schema type hint 'string' is
        mistakenly used as the actual value by frontend code generators.
        """
        if v is not None and isinstance(v, str):
            invalid_names = {"string", "str", "int", "float", "bool", "none", "null", ""}
            if v.lower().strip() in invalid_names:
                # Return None so the server default model is used instead
                return None
        return v


# ── Actions (returned by AI) ────────────────────────────────────────────


class AIAction(BaseModel):
    """A single action suggested by the AI assistant.

    Supported action types:

    - ``add_api_node``: Add a new API call node to the task graph.
      Payload: ``{"node_id", "method", "path", "operationId", "label", "params"}``

    - ``connect_nodes``: Connect two nodes in sequence.
      Payload: ``{"from_node_id", "to_node_id"}``

    - ``set_param``: Set a parameter value on an existing node.
      Payload: ``{"node_id", "key", "value"}``

    - ``add_comment``: Add a comment/annotation node.
      Payload: ``{"node_id", "text"}``

    - ``add_condition``: Add a conditional branch node.
      Payload: ``{"node_id", "condition", "true_node_id", "false_node_id"}``
    """

    type: str = Field(
        ...,
        description=(
            "Action type: add_api_node, connect_nodes, set_param, "
            "add_comment, add_condition"
        ),
    )
    payload: Dict[str, Any] = Field(
        ...,
        description="Action-specific data (see AIAction docstring for details).",
    )


# ── Response ─────────────────────────────────────────────────────────────


class AIResponse(BaseModel):
    """Structured response from the AI assistant."""

    status: str = Field(
        default="success",
        description="Response status: 'success' or 'error'.",
    )
    message: Optional[str] = Field(
        None,
        description=(
            "Human-readable message from the AI explaining what it did. "
            "Mentions {{USER_INPUT}} placeholders when Safe Mode is active."
        ),
    )
    actions: Optional[List[AIAction]] = Field(
        None,
        description="List of suggested actions for the frontend constructor.",
    )
    model_used: Optional[str] = Field(
        None,
        description="The LLM model that was actually used for this request.",
    )
    tokens_used: Optional[int] = Field(
        None,
        description="Total tokens consumed by this request (prompt + completion).",
    )
    error: Optional[str] = Field(
        None,
        description="Error message if status is 'error'.",
    )
    retries: Optional[int] = Field(
        None,
        description=(
            "Number of 429 rate-limit retries that were needed before "
            "getting a successful response. None if no retries occurred. "
            "(v1.6.8-4)"
        ),
    )


# ── OpenAPI Schema Info ─────────────────────────────────────────────────


class AIEndpointInfo(BaseModel):
    """Brief info about a single API endpoint (for /ai/schema)."""

    method: str
    path: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)


class AISchemaResponse(BaseModel):
    """Response for the /ai/schema endpoint — compressed OpenAPI summary."""

    total_endpoints: int
    schema_version: Optional[str] = None
    endpoints: List[AIEndpointInfo]


# ── AI Config ────────────────────────────────────────────────────────────


class AIConfigResponse(BaseModel):
    """Current AI configuration (non-sensitive)."""

    enabled: bool
    default_model: str
    safe_mode_default: bool
    temperature: float
    max_tokens: int
    schema_loaded: bool
    schema_endpoints: int
    rate_limit_retries: int = Field(
        default=3,
        description="Max retry attempts on 429 rate limit per model.",
    )
    rate_limit_max_wait: int = Field(
        default=30,
        description="Max wait seconds per 429 retry.",
    )
    fallback_models: List[str] = Field(
        default_factory=list,
        description="List of fallback model IDs if primary is rate-limited.",
    )
    max_schema_chars: int = Field(
        default=12000,
        description="Max compressed schema size in chars sent to LLM.",
    )


# ── Agent Mode (v1.6.8-6) ───────────────────────────────────────────────


class AIAgentRequest(BaseModel):
    """Request for the AI Agent mode (direct execution with tool calling).

    Unlike AIRequest (Task Builder) which returns structured suggestions,
    the Agent mode executes actions directly on the server using OpenRouter
    tool calling. The AI has access to:
    - execute_samba_api — call any API endpoint
    - execute_shell_command — run shell commands
    - save_file — save/export data to files
    - read_file — read files from server
    """

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=8000,
        description=(
            "Natural-language request. The AI will execute the necessary "
            "actions to fulfill it. Example: 'List all domain users and "
            "export to CSV'"
        ),
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Optional context data to include in the AI's conversation. "
            "For example, previously loaded file contents."
        ),
    )
    model_override: Optional[str] = Field(
        None,
        description=(
            "Override the default LLM model for this request. "
            "Agent mode works best with models that support tool calling: "
            "'openai/gpt-4o-mini', 'anthropic/claude-3-haiku', "
            "'meta-llama/llama-3.1-8b-instruct:free'."
        ),
    )
    max_steps: Optional[int] = Field(
        None,
        description=(
            "Override the max agent loop iterations for this request. "
            "If None, uses the server default (AI_AGENT_MAX_STEPS)."
        ),
    )

    @field_validator("model_override", mode="before")
    @classmethod
    def _validate_model_override(cls, v: Any) -> Any:
        """Reject obviously invalid model names."""
        if v is not None and isinstance(v, str):
            invalid_names = {"string", "str", "int", "float", "bool", "none", "null", ""}
            if v.lower().strip() in invalid_names:
                return None
        return v


class AIAgentStep(BaseModel):
    """A single step in the agent execution chain.

    Each step represents one tool call by the AI agent, including
    the tool name, arguments, and a preview of the result.
    """

    step: int = Field(description="Step number (1-based).")
    tool_name: str = Field(description="Name of the tool that was called.")
    tool_args: Dict[str, Any] = Field(description="Arguments passed to the tool.")
    result_preview: str = Field(
        description="First 500 chars of the tool execution result.",
    )
    success: bool = Field(
        default=True,
        description="Whether the tool call succeeded.",
    )


class AIAgentResponse(BaseModel):
    """Response from the AI Agent mode."""

    status: str = Field(
        default="success",
        description=(
            "Response status: 'success' (completed), 'partial' (hit max steps), "
            "or 'error'."
        ),
    )
    message: Optional[str] = Field(
        None,
        description="Final answer from the AI agent.",
    )
    steps: List[AIAgentStep] = Field(
        default_factory=list,
        description="List of tool call steps executed by the agent.",
    )
    total_steps: int = Field(
        default=0,
        description="Total number of tool calls executed.",
    )
    model_used: Optional[str] = Field(
        None,
        description="The LLM model that was used for this request.",
    )
    tokens_used: Optional[int] = Field(
        None,
        description="Total tokens consumed (cumulative across all agent loop iterations).",
    )
    error: Optional[str] = Field(
        None,
        description="Error message if status is 'error'.",
    )
