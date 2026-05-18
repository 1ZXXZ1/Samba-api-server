"""
Pydantic models for the AI Chat system (v1.8).

Provides structured request/response models for:
    - Chat CRUD (create, list, delete, connect)
    - Chat messages (send, history)
    - User isolation (each user sees only their own chats)
    - Admin access (admin can see/list all chats)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Chat Session ────────────────────────────────────────────────────────


class ChatCreateRequest(BaseModel):
    """Request to create a new AI chat session."""

    title: str = Field(
        default="New Chat",
        max_length=200,
        description="Chat session title.",
    )
    model_override: Optional[str] = Field(
        None,
        description="Override the default LLM model for this chat.",
    )
    system_prompt: Optional[str] = Field(
        None,
        max_length=4000,
        description="Custom system prompt for the AI in this chat session.",
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Initial context data for the chat (e.g. current AD state).",
    )


class ChatUpdateRequest(BaseModel):
    """Request to update a chat session."""

    title: Optional[str] = Field(None, max_length=200, description="New title.")
    system_prompt: Optional[str] = Field(None, max_length=4000, description="New system prompt.")


class ChatSessionResponse(BaseModel):
    """Response with chat session details."""

    id: str = Field(description="Unique chat session ID (UUID).")
    title: str = Field(description="Chat session title.")
    owner_id: str = Field(description="User ID of the chat owner.")
    owner_username: str = Field(default="", description="Username of the chat owner.")
    created_at: str = Field(description="ISO 8601 creation timestamp.")
    updated_at: str = Field(description="ISO 8601 last update timestamp.")
    message_count: int = Field(default=0, description="Number of messages in the chat.")
    model: str = Field(default="", description="LLM model used in this chat.")
    is_archived: bool = Field(default=False, description="Whether the chat is archived.")
    total_cost_rub: Optional[float] = Field(
        default=None,
        description="Total cost of all AI requests in this chat session in RUB (v1.8.4).",
    )
    total_tokens: Optional[int] = Field(
        default=None,
        description="Total tokens consumed across all AI requests in this chat (v1.8.4).",
    )


class ChatListResponse(BaseModel):
    """Response with a list of chat sessions."""

    chats: List[ChatSessionResponse] = Field(default_factory=list)
    total: int = Field(default=0, description="Total number of chats.")


# ── Chat Messages ───────────────────────────────────────────────────────


class ChatMessageSend(BaseModel):
    """Request to send a message in a chat session."""

    message: str = Field(
        ...,
        min_length=1,
        max_length=8000,
        description="User message to send to the AI.",
    )
    use_agent: bool = Field(
        default=True,
        description=(
            "When True, use the AI Agent mode (tool calling, direct execution). "
            "When False, use the Task Builder mode (returns suggestions only)."
        ),
    )
    max_steps: Optional[int] = Field(
        None,
        description="Override max agent steps for this message.",
    )


class ChatMessageUsageInfo(BaseModel):
    """Detailed usage info for a single chat message (v1.8.4).

    Shows token counts, reasoning tokens, cached tokens,
    and cost in RUB — all in one place so the user can
    see exactly what each request cost.
    """

    prompt_tokens: Optional[int] = Field(None, description="Tokens in the prompt.")
    completion_tokens: Optional[int] = Field(None, description="Tokens in the completion.")
    total_tokens: Optional[int] = Field(None, description="Total tokens (prompt + completion).")
    reasoning_tokens: Optional[int] = Field(None, description="Reasoning tokens (Polza.ai only).")
    cached_tokens: Optional[int] = Field(None, description="Cached prompt tokens (Polza.ai only).")
    cost_rub: Optional[float] = Field(None, description="Cost of this request in RUB (Polza.ai only).")
    provider: Optional[str] = Field(None, description="AI provider: 'polza'.")


class ChatMessageResponse(BaseModel):
    """A single chat message (user or assistant)."""

    id: str = Field(description="Message ID.")
    role: str = Field(description="Message role: 'user', 'assistant', 'system', 'tool'.")
    content: str = Field(default="", description="Message text content.")
    timestamp: str = Field(description="ISO 8601 timestamp.")
    model_used: Optional[str] = Field(None, description="LLM model used (for assistant messages).")
    tokens_used: Optional[int] = Field(None, description="Tokens consumed (for assistant messages).")
    cost_rub: Optional[float] = Field(None, description="Cost of this request in RUB (Polza.ai only, v1.8.4).")
    usage: Optional[ChatMessageUsageInfo] = Field(
        None,
        description=(
            "Detailed usage info: prompt_tokens, completion_tokens, "
            "reasoning_tokens, cached_tokens, cost_rub (v1.8.4)."
        ),
    )
    tool_steps: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Agent tool call steps (for assistant messages with use_agent=True).",
    )


class ChatHistoryResponse(BaseModel):
    """Response with chat message history."""

    chat_id: str = Field(description="Chat session ID.")
    messages: List[ChatMessageResponse] = Field(default_factory=list)
    total: int = Field(default=0, description="Total messages in the chat.")
    has_more: bool = Field(default=False, description="Whether older messages exist.")


# ── Chat Connect (WebSocket handshake info) ────────────────────────────


class ChatConnectInfo(BaseModel):
    """Info returned when connecting to a chat (for WebSocket or polling)."""

    chat_id: str = Field(description="Chat session ID.")
    title: str = Field(description="Chat title.")
    ws_url: Optional[str] = Field(
        None,
        description="WebSocket URL for real-time chat updates (if available).",
    )
    history: ChatHistoryResponse = Field(description="Recent message history.")


class ChatInfoResponse(BaseModel):
    """Detailed chat session info with cost/usage summary (v1.8.4).

    Provides a clear overview of the chat session including
    total cost, token usage, balance, and per-message cost
    breakdown so the user can see exactly what each request cost.
    """

    chat_id: str = Field(description="Chat session ID.")
    title: str = Field(description="Chat title.")
    owner_id: str = Field(description="User ID of the chat owner.")
    model: str = Field(default="", description="LLM model used.")
    message_count: int = Field(default=0, description="Number of messages in the chat.")
    assistant_message_count: int = Field(default=0, description="Number of AI responses.")
    total_cost_rub: float = Field(default=0.0, description="Total cost of all AI requests in RUB.")
    total_tokens: int = Field(default=0, description="Total tokens consumed.")
    total_prompt_tokens: int = Field(default=0, description="Total prompt tokens.")
    total_completion_tokens: int = Field(default=0, description="Total completion tokens.")
    total_reasoning_tokens: int = Field(default=0, description="Total reasoning tokens.")
    balance: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Current AI provider balance. "
            "Keys: amount, reserved_amount, spent_amount, updated_at."
        ),
    )
    provider: str = Field(default="polza", description="AI provider name.")
    messages: Optional[List[Dict[str, Any]]] = Field(
        None,
        description=(
            "Per-message cost breakdown. Each entry has: "
            "timestamp, model_used, tokens_used, cost_rub."
        ),
    )
