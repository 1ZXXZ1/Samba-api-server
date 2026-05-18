"""
AI Chat service — manages chat sessions with user isolation (v1.8).

Features:
    - Create/list/delete/connect chat sessions
    - Each user sees only their own chats
    - Admin can see/list/manage all chats
    - Chat messages are persisted in PostgreSQL via app.mgmt_db
    - Supports both polling and WebSocket modes
    - Integrates with the AI agent for tool-calling responses

v1.8.5-2: Migrated from JSON-backed storage to PostgreSQL via app.mgmt_db.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.mgmt_db import (
    chat_add_message,
    chat_count_messages,
    chat_count_sessions,
    chat_create_session,
    chat_delete_session,
    chat_get_all_cost_summary,
    chat_get_cost_summary,
    chat_get_messages,
    chat_get_messages_for_agent,
    chat_get_session,
    chat_list_sessions,
    chat_prune_old_messages,
    chat_update_session,
)
from app.config import get_settings

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════
#  Chat Session CRUD
# ═══════════════════════════════════════════════════════════════════════


def create_chat(
    owner_id: str,
    owner_username: str = "",
    title: str = "New Chat",
    model_override: Optional[str] = None,
    system_prompt: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a new AI chat session."""
    settings = get_settings()

    max_per_user = getattr(settings, "AI_CHAT_MAX_PER_USER", 20)
    existing = chat_count_sessions(owner_id)
    if existing >= max_per_user:
        raise ValueError(
            f"Maximum number of chat sessions reached ({max_per_user}). "
            f"Delete some chats before creating new ones."
        )

    chat_id = str(uuid.uuid4())
    now = _now_iso()
    model = model_override or ""

    chat_create_session(
        session_id=chat_id,
        title=title,
        owner_id=owner_id,
        owner_username=owner_username,
        model=model,
        system_prompt=system_prompt or "",
        context=json.dumps(context or {}, ensure_ascii=False),
        created_at=now,
        updated_at=now,
    )

    logger.info("[AI-CHAT] Created chat %s for user %s (%s)", chat_id, owner_id, title)

    return {
        "id": chat_id,
        "title": title,
        "owner_id": owner_id,
        "owner_username": owner_username,
        "created_at": now,
        "updated_at": now,
        "message_count": 0,
        "model": model,
        "is_archived": False,
    }


def list_chats(
    user_id: str,
    role: str = "operator",
    include_archived: bool = False,
) -> List[Dict[str, Any]]:
    """List chat sessions for a user."""
    if role == "admin":
        sessions = chat_list_sessions(include_archived=include_archived)
    else:
        sessions = chat_list_sessions(owner_id=user_id, include_archived=include_archived)

    chats = []
    for s in sessions:
        chat_id = s.get("id", "")
        msg_count = chat_count_messages(chat_id)
        chats.append({
            "id": chat_id,
            "title": s.get("title", "New Chat"),
            "owner_id": s.get("owner_id", ""),
            "owner_username": s.get("owner_username", ""),
            "model": s.get("model", ""),
            "is_archived": bool(s.get("is_archived", 0)),
            "created_at": s.get("created_at", ""),
            "updated_at": s.get("updated_at", ""),
            "message_count": msg_count,
        })

    return chats


def get_chat(chat_id: str, user_id: str, role: str = "operator") -> Optional[Dict[str, Any]]:
    """Get a single chat session. Returns None if not found or no access."""
    session = chat_get_session(chat_id)
    if not session:
        return None

    if session.get("owner_id") != user_id and role != "admin":
        return None

    context_str = session.get("context", "{}")
    try:
        context = json.loads(context_str) if isinstance(context_str, str) else (context_str or {})
    except json.JSONDecodeError:
        context = {}

    return {
        "id": session.get("id", ""),
        "title": session.get("title", "New Chat"),
        "owner_id": session.get("owner_id", ""),
        "owner_username": session.get("owner_username", ""),
        "model": session.get("model", ""),
        "system_prompt": session.get("system_prompt", ""),
        "context": context,
        "is_archived": bool(session.get("is_archived", 0)),
        "created_at": session.get("created_at", ""),
        "updated_at": session.get("updated_at", ""),
        "message_count": chat_count_messages(chat_id),
    }


def update_chat(
    chat_id: str,
    user_id: str,
    role: str = "operator",
    title: Optional[str] = None,
    system_prompt: Optional[str] = None,
    archive: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    """Update a chat session."""
    chat = get_chat(chat_id, user_id, role)
    if not chat:
        return None

    updates: Dict[str, Any] = {}
    if title is not None:
        updates["title"] = title
    if system_prompt is not None:
        updates["system_prompt"] = system_prompt
    if archive is not None:
        updates["is_archived"] = 1 if archive else 0

    if updates:
        updates["updated_at"] = _now_iso()
        chat_update_session(chat_id, **updates)

    return get_chat(chat_id, user_id, role)


def delete_chat(chat_id: str, user_id: str, role: str = "operator") -> bool:
    """Delete a chat session."""
    chat = get_chat(chat_id, user_id, role)
    if not chat:
        return False

    chat_delete_session(chat_id)
    logger.info("[AI-CHAT] Deleted chat %s by user %s", chat_id, user_id)
    return True


# ═══════════════════════════════════════════════════════════════════════
#  Chat Messages
# ═══════════════════════════════════════════════════════════════════════


def add_message(
    chat_id: str,
    role: str,
    content: str,
    model_used: Optional[str] = None,
    tokens_used: Optional[int] = None,
    cost_rub: Optional[float] = None,
    usage_info: Optional[Dict[str, Any]] = None,
    tool_steps: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Add a message to a chat session."""
    settings = get_settings()

    msg_id = str(uuid.uuid4())
    now = _now_iso()

    chat_add_message(
        msg_id=msg_id,
        chat_id=chat_id,
        role=role,
        content=content,
        model_used=model_used,
        tokens_used=tokens_used,
        cost_rub=cost_rub,
        usage_info=json.dumps(usage_info, ensure_ascii=False) if usage_info else None,
        tool_steps=json.dumps(tool_steps, ensure_ascii=False) if tool_steps else None,
        timestamp=now,
    )

    max_history = getattr(settings, "AI_CHAT_MAX_HISTORY", 100)
    chat_prune_old_messages(chat_id, max_history)

    return {
        "id": msg_id,
        "role": role,
        "content": content,
        "timestamp": now,
        "model_used": model_used,
        "tokens_used": tokens_used,
        "cost_rub": cost_rub,
        "usage": usage_info,
        "tool_steps": tool_steps,
    }


def get_chat_history(
    chat_id: str,
    user_id: str,
    role: str = "operator",
    limit: int = 50,
    before: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Get chat message history. Returns (messages, has_more)."""
    chat = get_chat(chat_id, user_id, role)
    if not chat:
        return [], False

    raw_msgs, has_more = chat_get_messages(chat_id, limit=limit, before=before)

    messages = []
    for m in raw_msgs:
        tool_steps = m.get("tool_steps")
        usage_info = m.get("usage_info")

        messages.append({
            "id": m.get("id", ""),
            "role": m.get("role", ""),
            "content": m.get("content", ""),
            "model_used": m.get("model_used"),
            "tokens_used": m.get("tokens_used"),
            "cost_rub": m.get("cost_rub"),
            "usage": usage_info,
            "tool_steps": tool_steps,
            "timestamp": m.get("timestamp", ""),
        })

    return messages, has_more


def get_chat_messages_for_agent(chat_id: str) -> List[Dict[str, Any]]:
    """Get all chat messages in OpenAI-compatible format for the agent loop."""
    return chat_get_messages_for_agent(chat_id)


# ═══════════════════════════════════════════════════════════════════════
#  Cost & Usage Summaries
# ═══════════════════════════════════════════════════════════════════════


def get_chat_cost_summary(chat_id: str) -> Dict[str, Any]:
    """Get cost and usage summary for a chat session."""
    return chat_get_cost_summary(chat_id)


def get_all_chats_cost_summary() -> Dict[str, Any]:
    """Get cost and usage summary across ALL chat sessions."""
    return chat_get_all_cost_summary()
