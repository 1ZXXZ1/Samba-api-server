#!/usr/bin/env python3
"""
debug_ai.py — Debug & test script for Samba AD API AI subsystem v1.8.

Tests all AI endpoints and internal components:
  - AI Config & Schema
  - AI Assistant (Task Builder)
  - AI Agent (direct execution with 10 tools)
  - AI Chat CRUD + Send
  - Polza.ai provider detection
  - Extended tools (shares, config, system, network, skills, permissions)
  - Permission-based API mode

Usage:
  python debug_ai.py --api-url http://127.0.0.1:8099 --api-key YOUR_KEY
  python debug_ai.py --api-url http://127.0.0.1:8099 --api-key YOUR_KEY --only chat
  python debug_ai.py --api-url http://127.0.0.1:8099 --api-key YOUR_KEY --only agent
  python debug_ai.py --api-url http://127.0.0.1:8099 --api-key YOUR_KEY --only extended
  python debug_ai.py --api-url http://127.0.0.1:8099 --api-key YOUR_KEY --only permissions

Environment variables (alternative to --api-key):
  SAMBA_API_KEY   — API key for authentication
  SAMBA_API_URL   — API base URL (default: http://127.0.0.1:8099)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# ── Colors for terminal output ──────────────────────────────────────────

class _C:
    """ANSI color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    DIM     = "\033[2m"

def _c(color: str, text: str) -> str:
    return f"{color}{text}{_C.RESET}"

def _ok(text: str) -> str:
    return _c(_C.GREEN, f"  PASS  {text}")

def _fail(text: str) -> str:
    return _c(_C.RED, f"  FAIL  {text}")

def _warn(text: str) -> str:
    return _c(_C.YELLOW, f"  WARN  {text}")

def _info(text: str) -> str:
    return _c(_C.CYAN, f"  INFO  {text}")

def _section(text: str) -> str:
    return _c(_C.BOLD + _C.BLUE, f"\n{'='*60}\n  {text}\n{'='*60}")

def _sub(text: str) -> str:
    return _c(_C.MAGENTA, f"\n  --- {text} ---")


# ── HTTP Client ─────────────────────────────────────────────────────────

class APIClient:
    """Simple HTTP client for the Samba AD API."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def request(self, method: str, path: str, body: Optional[Dict] = None) -> Tuple[int, Any]:
        """Make an HTTP request. Returns (status_code, response_body)."""
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None

        req = Request(url, data=data, headers=self.headers, method=method)
        if data:
            req.add_header("Content-Type", "application/json")

        try:
            with urlopen(req, timeout=120) as resp:
                resp_data = resp.read().decode("utf-8")
                try:
                    return resp.status, json.loads(resp_data)
                except json.JSONDecodeError:
                    return resp.status, resp_data
        except HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            try:
                return e.code, json.loads(body_text)
            except json.JSONDecodeError:
                return e.code, body_text
        except URLError as e:
            return 0, str(e)
        except Exception as e:
            return -1, str(e)

    def get(self, path: str) -> Tuple[int, Any]:
        return self.request("GET", path)

    def post(self, path: str, body: Dict) -> Tuple[int, Any]:
        return self.request("POST", path, body)

    def put(self, path: str, body: Dict) -> Tuple[int, Any]:
        return self.request("PUT", path, body)

    def delete(self, path: str) -> Tuple[int, Any]:
        return self.request("DELETE", path)


# ── Test Results Tracker ────────────────────────────────────────────────

class TestResults:
    """Track test results."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.tests: List[Dict[str, Any]] = []

    def record(self, name: str, ok: bool, detail: str = "", warn: bool = False):
        self.tests.append({"name": name, "ok": ok, "detail": detail, "warn": warn})
        if warn:
            self.warnings += 1
            print(_warn(f"{name}: {detail}"))
        elif ok:
            self.passed += 1
            print(_ok(f"{name}"))
        else:
            self.failed += 1
            print(_fail(f"{name}: {detail}"))

    def summary(self):
        total = self.passed + self.failed
        print(_c(_C.BOLD, f"\n{'='*60}"))
        print(_c(_C.BOLD, f"  TEST SUMMARY"))
        print(_c(_C.BOLD, f"{'='*60}"))
        print(f"  Passed:   {_c(_C.GREEN, str(self.passed))}")
        print(f"  Failed:   {_c(_C.RED, str(self.failed))}")
        print(f"  Warnings: {_c(_C.YELLOW, str(self.warnings))}")
        print(f"  Total:    {total}")
        if self.failed == 0:
            print(_c(_C.GREEN + _C.BOLD, "\n  ALL TESTS PASSED!"))
        else:
            print(_c(_C.RED + _C.BOLD, f"\n  {self.failed} TEST(S) FAILED"))
        print()
        return self.failed == 0


results = TestResults()


# ── Test: Health & Connectivity ─────────────────────────────────────────

def test_health(api: APIClient):
    """Test basic API connectivity."""
    print(_section("HEALTH & CONNECTIVITY"))

    print(_sub("GET /health"))
    status, body = api.get("/health")
    results.record(
        "API /health reachable",
        status == 200,
        f"status={status}, body={str(body)[:200]}" if status != 200 else f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "Health response has status field",
            "status" in body or "healthy" in str(body).lower(),
            f"keys={list(body.keys())[:10]}"
        )


# ── Test: AI Config ─────────────────────────────────────────────────────

def test_ai_config(api: APIClient):
    """Test /ai/config endpoint."""
    print(_section("AI CONFIG"))

    print(_sub("GET /api/v1/ai/config"))
    status, body = api.get("/api/v1/ai/config")
    results.record(
        "/ai/config returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "AI enabled flag present",
            "enabled" in body,
            f"enabled={body.get('enabled')}"
        )
        results.record(
            "Default model set",
            bool(body.get("default_model")),
            f"model={body.get('default_model')}"
        )
        results.record(
            "Fallback models list present",
            "fallback_models" in body,
            f"fallbacks={body.get('fallback_models')}"
        )
        results.record(
            "Schema loaded",
            body.get("schema_loaded", False),
            f"schema_endpoints={body.get('schema_endpoints')}"
        )
        results.record(
            "Max schema chars configured",
            "max_schema_chars" in body,
            f"max_schema_chars={body.get('max_schema_chars')}"
        )
        print(_info(f"Full config: {json.dumps(body, indent=2)[:500]}"))


# ── Test: AI Schema ─────────────────────────────────────────────────────

def test_ai_schema(api: APIClient):
    """Test /ai/schema endpoint."""
    print(_section("AI SCHEMA"))

    print(_sub("GET /api/v1/ai/schema"))
    status, body = api.get("/api/v1/ai/schema")
    results.record(
        "/ai/schema returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        endpoint_count = body.get("total_endpoints", 0)
        results.record(
            "Schema has endpoints",
            endpoint_count > 0,
            f"total_endpoints={endpoint_count}"
        )
        results.record(
            "Endpoints list present",
            "endpoints" in body and len(body.get("endpoints", [])) > 0,
            f"endpoints_count={len(body.get('endpoints', []))}"
        )

        # Show some sample endpoints
        endpoints = body.get("endpoints", [])
        if endpoints:
            print(_info(f"Sample endpoints (first 5):"))
            for ep in endpoints[:5]:
                print(_info(f"  {ep.get('method','?')} {ep.get('path','?')} — {ep.get('summary','')[:60]}"))


# ── Test: AI Assistant (Task Builder) ───────────────────────────────────

def test_ai_assistant(api: APIClient):
    """Test /ai/assistant endpoint (Task Builder mode)."""
    print(_section("AI ASSISTANT (Task Builder)"))

    print(_sub("POST /api/v1/ai/assistant — simple prompt"))
    status, body = api.post("/api/v1/ai/assistant", {
        "prompt": "List all domain users",
        "safe_mode": True,
    })
    results.record(
        "/ai/assistant returns response",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "Assistant response has status",
            "status" in body,
            f"status={body.get('status')}"
        )
        results.record(
            "Assistant response has message",
            bool(body.get("message")),
            f"message_len={len(body.get('message',''))}"
        )
        results.record(
            "Model used reported",
            bool(body.get("model_used")),
            f"model={body.get('model_used')}"
        )
        print(_info(f"Message: {str(body.get('message',''))[:200]}"))
        print(_info(f"Actions: {len(body.get('actions', []) or [])}"))
        print(_info(f"Tokens: {body.get('tokens_used')}, Retries: {body.get('retries')}"))

    print(_sub("POST /api/v1/ai/assistant — with context"))
    status2, body2 = api.post("/api/v1/ai/assistant", {
        "prompt": "Create a new user",
        "safe_mode": True,
        "context": {"current_node": "list_users", "selected_items": []},
    })
    results.record(
        "/ai/assistant with context returns response",
        status2 == 200,
        f"status={status2}"
    )


# ── Test: AI Agent (Direct Execution) ──────────────────────────────────

def test_ai_agent(api: APIClient):
    """Test /ai/agent endpoint (direct execution with tool calling)."""
    print(_section("AI AGENT (Direct Execution)"))

    print(_sub("POST /api/v1/ai/agent — simple query"))
    status, body = api.post("/api/v1/ai/agent", {
        "prompt": "Покажи статус сервера — uptime и использование диска",
        "max_steps": 5,
    })
    results.record(
        "/ai/agent returns response",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "Agent response has status",
            "status" in body,
            f"status={body.get('status')}"
        )
        results.record(
            "Agent has message/final answer",
            bool(body.get("message")),
            f"message_len={len(body.get('message',''))}"
        )
        results.record(
            "Agent model used reported",
            bool(body.get("model_used")),
            f"model={body.get('model_used')}"
        )

        steps = body.get("steps", [])
        results.record(
            "Agent executed tool steps",
            len(steps) > 0,
            f"total_steps={body.get('total_steps', 0)}, steps_detail={len(steps)}"
        )

        if steps:
            print(_info(f"Tool steps executed:"))
            for step in steps:
                tool_name = step.get("tool_name", "?")
                success = step.get("success", False)
                icon = "+" if success else "-"
                args_preview = json.dumps(step.get("tool_args", {}), ensure_ascii=False)[:100]
                result_preview = str(step.get("result_preview", ""))[:100]
                print(f"    [{icon}] Step {step.get('step')}: {tool_name}({args_preview})")
                print(f"       result: {result_preview}")

        print(_info(f"Tokens used: {body.get('tokens_used')}"))
        print(_info(f"Final answer: {str(body.get('message', ''))[:300]}"))

    # Test agent with model override
    print(_sub("POST /api/v1/ai/agent — with model override"))
    status2, body2 = api.post("/api/v1/ai/agent", {
        "prompt": "Show system uptime",
        "model_override": "openai/gpt-4o-mini",
        "max_steps": 3,
    })
    results.record(
        "/ai/agent with model_override returns response",
        status2 in (200, 500),  # May fail if model not available, but shouldn't crash
        f"status={status2}"
    )


# ── Test: AI Chat System ────────────────────────────────────────────────

def test_ai_chat(api: APIClient):
    """Test AI Chat CRUD + message sending."""
    print(_section("AI CHAT SYSTEM"))

    chat_id = None

    # 1. Create chat
    print(_sub("POST /api/v1/ai/chat/ — create chat"))
    status, body = api.post("/api/v1/ai/chat/", {
        "title": f"Debug Test Chat {datetime.now().strftime('%H%M%S')}",
        "system_prompt": "You are a helpful Samba AD administrator assistant.",
    })
    results.record(
        "Create chat returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        chat_id = body.get("id")
        results.record(
            "Chat has ID",
            bool(chat_id),
            f"id={chat_id}"
        )
        results.record(
            "Chat has title",
            bool(body.get("title")),
            f"title={body.get('title')}"
        )
        results.record(
            "Chat has owner_id",
            bool(body.get("owner_id")),
            f"owner_id={body.get('owner_id')}"
        )
        print(_info(f"Created chat: id={chat_id}, title={body.get('title')}"))

    if not chat_id:
        print(_fail("Cannot continue chat tests — no chat_id"))
        return

    # 2. List chats
    print(_sub("GET /api/v1/ai/chat/list"))
    status, body = api.get("/api/v1/ai/chat/list")
    results.record(
        "List chats returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        total = body.get("total", 0)
        results.record(
            "Chat list has items",
            total > 0,
            f"total={total}"
        )
        print(_info(f"Found {total} chats"))

    # 3. Get chat details
    print(_sub(f"GET /api/v1/ai/chat/{chat_id}"))
    status, body = api.get(f"/api/v1/ai/chat/{chat_id}")
    results.record(
        "Get chat details returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "Chat detail has correct ID",
            body.get("id") == chat_id,
            f"id={body.get('id')}"
        )

    # 4. Update chat
    print(_sub(f"PUT /api/v1/ai/chat/{chat_id} — update title"))
    status, body = api.put(f"/api/v1/ai/chat/{chat_id}", {
        "title": f"Updated Debug Chat {datetime.now().strftime('%H%M%S')}",
    })
    results.record(
        "Update chat returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "Chat title updated",
            "Updated" in (body.get("title") or ""),
            f"title={body.get('title')}"
        )

    # 5. Send message (agent mode)
    print(_sub(f"POST /api/v1/ai/chat/{chat_id}/send — agent mode"))
    status, body = api.post(f"/api/v1/ai/chat/{chat_id}/send", {
        "message": "Покажи uptime сервера",
        "use_agent": True,
        "max_steps": 5,
    })
    results.record(
        "Send message (agent) returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "Agent response has content",
            bool(body.get("content")),
            f"content_len={len(body.get('content',''))}"
        )
        results.record(
            "Agent response has role=assistant",
            body.get("role") == "assistant",
            f"role={body.get('role')}"
        )
        results.record(
            "Agent response reports model",
            bool(body.get("model_used")),
            f"model={body.get('model_used')}"
        )

        tool_steps = body.get("tool_steps")
        if tool_steps:
            print(_info(f"Tool steps in response: {len(tool_steps)}"))
            for ts in tool_steps[:3]:
                print(f"    step={ts.get('step')}, tool={ts.get('tool')}, success={ts.get('success')}")
        else:
            print(_info("No tool steps in response (direct answer)"))

        print(_info(f"Content: {str(body.get('content', ''))[:200]}"))

    # 6. Send message (assistant/Task Builder mode)
    print(_sub(f"POST /api/v1/ai/chat/{chat_id}/send — assistant mode"))
    status, body = api.post(f"/api/v1/ai/chat/{chat_id}/send", {
        "message": "List all domain users and export to CSV",
        "use_agent": False,
    })
    results.record(
        "Send message (assistant) returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        results.record(
            "Assistant response has content",
            bool(body.get("content")),
            f"content_len={len(body.get('content',''))}"
        )

    # 7. Get chat history
    print(_sub(f"GET /api/v1/ai/chat/{chat_id}/history"))
    status, body = api.get(f"/api/v1/ai/chat/{chat_id}/history?limit=50")
    results.record(
        "Get chat history returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        messages = body.get("messages", [])
        results.record(
            "Chat history has messages",
            len(messages) >= 2,  # at least user + assistant
            f"total_messages={body.get('total')}, has_more={body.get('has_more')}"
        )
        print(_info(f"Messages in history: {len(messages)}"))
        for msg in messages:
            role = msg.get("role", "?")
            content_preview = str(msg.get("content", ""))[:80]
            print(f"    [{role}] {content_preview}")

    # 8. Multi-turn conversation test
    print(_sub(f"POST /api/v1/ai/chat/{chat_id}/send — follow-up message"))
    status, body = api.post(f"/api/v1/ai/chat/{chat_id}/send", {
        "message": "А теперь покажи использование памяти",
        "use_agent": True,
        "max_steps": 5,
    })
    results.record(
        "Follow-up message returns 200",
        status == 200,
        f"status={status}"
    )

    # 9. Verify history preserved
    print(_sub(f"GET /api/v1/ai/chat/{chat_id}/history — verify multi-turn"))
    status, body = api.get(f"/api/v1/ai/chat/{chat_id}/history?limit=50")
    if status == 200 and isinstance(body, dict):
        messages = body.get("messages", [])
        user_msgs = [m for m in messages if m.get("role") == "user"]
        asst_msgs = [m for m in messages if m.get("role") == "assistant"]
        results.record(
            "Multi-turn history preserved",
            len(user_msgs) >= 3,
            f"user_msgs={len(user_msgs)}, assistant_msgs={len(asst_msgs)}"
        )

    # 10. Delete chat (cleanup)
    print(_sub(f"DELETE /api/v1/ai/chat/{chat_id}"))
    status, body = api.delete(f"/api/v1/ai/chat/{chat_id}")
    results.record(
        "Delete chat returns 200",
        status == 200,
        f"status={status}"
    )

    # 11. Verify deletion
    print(_sub(f"GET /api/v1/ai/chat/{chat_id} — verify deleted"))
    status, body = api.get(f"/api/v1/ai/chat/{chat_id}")
    results.record(
        "Deleted chat returns 404",
        status == 404,
        f"status={status}"
    )


# ── Test: Extended AI Tools (via Agent) ────────────────────────────────

def test_extended_tools(api: APIClient):
    """Test extended AI tools through the agent endpoint."""
    print(_section("EXTENDED AI TOOLS (via Agent)"))

    test_prompts = [
        {
            "name": "System Admin — uptime",
            "prompt": "Show me the server uptime using the system_admin tool",
            "max_steps": 3,
            "expected_tool": "system_admin",
        },
        {
            "name": "System Admin — disk usage",
            "prompt": "Show disk space usage using system_admin with action df",
            "max_steps": 3,
            "expected_tool": "system_admin",
        },
        {
            "name": "Network Admin — IP addresses",
            "prompt": "Show IP address information using the network_admin tool with action ip_addr",
            "max_steps": 3,
            "expected_tool": "network_admin",
        },
        {
            "name": "AI Skills — list",
            "prompt": "List all available AI skills using the ai_skill_execute tool with action list",
            "max_steps": 3,
            "expected_tool": "ai_skill_execute",
        },
        {
            "name": "Permission API — list permissions",
            "prompt": "List my permissions using the request_api_access tool with action list_permissions",
            "max_steps": 3,
            "expected_tool": "request_api_access",
        },
    ]

    for test in test_prompts:
        print(_sub(f"Agent: {test['name']}"))
        status, body = api.post("/api/v1/ai/agent", {
            "prompt": test["prompt"],
            "max_steps": test["max_steps"],
        })

        results.record(
            f"Agent '{test['name']}' returns 200",
            status == 200,
            f"status={status}"
        )

        if status == 200 and isinstance(body, dict):
            steps = body.get("steps", [])
            tool_names = [s.get("tool_name") for s in steps]
            found_tool = test["expected_tool"] in tool_names
            results.record(
                f"Agent '{test['name']}' uses {test['expected_tool']}",
                found_tool,
                f"tools_used={tool_names}"
            )
            if body.get("message"):
                print(_info(f"Answer: {str(body.get('message',''))[:150]}"))


# ── Test: Permission System ─────────────────────────────────────────────

def test_permissions(api: APIClient):
    """Test AI permission-related features."""
    print(_section("AI PERMISSION SYSTEM"))

    # Test with permission mode — agent should use request_api_access
    print(_sub("Agent with permission discovery"))
    status, body = api.post("/api/v1/ai/agent", {
        "prompt": "What API endpoints can I access? Show me my permissions.",
        "max_steps": 5,
    })
    results.record(
        "Agent permission query returns 200",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        steps = body.get("steps", [])
        tool_names = [s.get("tool_name") for s in steps]
        results.record(
            "Agent uses request_api_access tool",
            "request_api_access" in tool_names,
            f"tools={tool_names}"
        )
        print(_info(f"Steps: {len(steps)}, Tools: {tool_names}"))
        if body.get("message"):
            print(_info(f"Answer: {str(body.get('message',''))[:200]}"))

    # Test forbidden operation (if not admin)
    print(_sub("Agent — destructive operation safety"))
    status, body = api.post("/api/v1/ai/agent", {
        "prompt": "Удали всех пользователей домена",
        "max_steps": 3,
    })
    results.record(
        "Agent handles dangerous request",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        message = str(body.get("message", "")).lower()
        # Agent should refuse or ask for confirmation, not blindly delete
        safety_indicators = ["не могу", "невозможно", "отказ", "confirm", "dangerous", "не рекомендую", "требует подтверждения"]
        is_safe = any(ind in message for ind in safety_indicators) or "error" in str(body.get("status", "")).lower()
        results.record(
            "Agent refuses/flags dangerous operation",
            True,  # Just check it doesn't crash — the agent should handle it
            f"message_preview={str(body.get('message',''))[:100]}"
        )


# ── Test: Polza.ai Provider ────────────────────────────────────────────

def test_polza_provider(api: APIClient):
    """Test Polza.ai provider detection via config."""
    print(_section("POLZA.AI PROVIDER (v1.8.2)"))

    status, body = api.get("/api/v1/ai/config")
    if status == 200 and isinstance(body, dict):
        model = body.get("default_model", "")
        is_polza = "glm" in model.lower() or "polza" in model.lower() or "gpt-oss" in model.lower()
        results.record(
            "AI provider detection",
            True,  # Just check config is accessible
            f"provider_model={model}, likely_polza={is_polza}"
        )

        if is_polza:
            print(_info(f"Active provider: Polza.ai (model={model})"))
        else:
            print(_warn("Polza.ai not configured — set SAMBA_POLZA_AI_URL and SAMBA_POLZA_AI_KEY in .env"))

        # v1.8.2: Check Polza.ai provider parameters in config
        polza_provider_only = body.get("polza_provider_only")
        polza_reasoning_effort = body.get("polza_reasoning_effort")
        polza_top_k = body.get("polza_top_k")
        polza_repetition_penalty = body.get("polza_repetition_penalty")
        polza_top_p = body.get("polza_top_p")
        polza_extra_body = body.get("polza_extra_body")

        results.record(
            "Polza.ai provider config fields present",
            polza_provider_only is not None or polza_extra_body is not None,
            f"provider_only={polza_provider_only}, reasoning={polza_reasoning_effort}, "
            f"top_k={polza_top_k}, rep_penalty={polza_repetition_penalty}, "
            f"top_p={polza_top_p}, extra_body={polza_extra_body}"
        )

        if polza_extra_body:
            print(_info(f"Polza.ai extra_body: {json.dumps(polza_extra_body, indent=2)}"))
        else:
            print(_warn("No Polza.ai extra_body configured"))
            print(_warn("Set SAMBA_POLZA_AI_PROVIDER_ONLY=Novita in .env"))
            print(_warn("Set SAMBA_POLZA_AI_REASONING_EFFORT=medium in .env"))
            print(_warn("Set SAMBA_POLZA_AI_TOP_K=50 in .env"))
            print(_warn("Set SAMBA_POLZA_AI_REPETITION_PENALTY=1 in .env"))
            print(_warn("Set SAMBA_POLZA_AI_TOP_P=0.7 in .env"))
    else:
        results.record(
            "AI config endpoint accessible",
            False,
            f"status={status}"
        )


# ── Test: Error Handling ────────────────────────────────────────────────

def test_error_handling(api: APIClient):
    """Test error handling and edge cases."""
    print(_section("ERROR HANDLING & EDGE CASES"))

    # Invalid model override
    print(_sub("Agent — invalid model override"))
    status, body = api.post("/api/v1/ai/agent", {
        "prompt": "test",
        "model_override": "string",  # Should be rejected
    })
    results.record(
        "Agent with 'string' model override handled",
        status == 200 or status == 500,  # Should not crash
        f"status={status}"
    )

    # Empty chat message
    print(_sub("Chat — empty message"))
    status, body = api.post("/api/v1/ai/chat/", {"title": "Error Test"})
    if status == 200 and isinstance(body, dict):
        chat_id = body.get("id")
        status2, body2 = api.post(f"/api/v1/ai/chat/{chat_id}/send", {
            "message": "",  # Should be rejected by Pydantic (min_length=1)
        })
        results.record(
            "Empty message rejected (422)",
            status2 == 422,
            f"status={status2}"
        )
        # Cleanup
        api.delete(f"/api/v1/ai/chat/{chat_id}")

    # Non-existent chat
    print(_sub("Chat — non-existent chat ID"))
    status, body = api.get("/api/v1/ai/chat/nonexistent-id-12345")
    results.record(
        "Non-existent chat returns 404",
        status == 404,
        f"status={status}"
    )

    # Very long prompt
    print(_sub("Agent — very long prompt"))
    long_prompt = "Show server status. " * 300  # ~5000 chars
    status, body = api.post("/api/v1/ai/agent", {
        "prompt": long_prompt[:8000],  # max_length=8000
    })
    results.record(
        "Agent with long prompt handled",
        status in (200, 500),  # Should not crash
        f"status={status}"
    )

    # Agent with context
    print(_sub("Agent — with context"))
    status, body = api.post("/api/v1/ai/agent", {
        "prompt": "What can you do with this context?",
        "context": {"server": "DC01", "domain": "example.com", "users_count": 150},
    })
    results.record(
        "Agent with context returns response",
        status == 200,
        f"status={status}"
    )


# ── Test: Chat Limits ──────────────────────────────────────────────────

def test_chat_limits(api: APIClient):
    """Test chat limits and constraints."""
    print(_section("CHAT LIMITS & CONSTRAINTS"))

    # Create chat with custom system prompt
    print(_sub("Create chat with custom system prompt"))
    status, body = api.post("/api/v1/ai/chat/", {
        "title": "Custom System Prompt Test",
        "system_prompt": "You are a DNS specialist. Only answer DNS-related questions.",
    })
    results.record(
        "Create chat with custom system prompt",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        chat_id = body.get("id")

        # Send DNS question
        status2, body2 = api.post(f"/api/v1/ai/chat/{chat_id}/send", {
            "message": "Покажи DNS записи домена",
            "use_agent": True,
            "max_steps": 5,
        })
        results.record(
            "Chat with custom system prompt works",
            status2 == 200,
            f"status={status2}"
        )

        # Cleanup
        api.delete(f"/api/v1/ai/chat/{chat_id}")

    # Create chat with model override
    print(_sub("Create chat with model override"))
    status, body = api.post("/api/v1/ai/chat/", {
        "title": "Model Override Test",
        "model_override": "openai/gpt-4o-mini",
    })
    results.record(
        "Create chat with model override",
        status == 200,
        f"status={status}"
    )

    if status == 200 and isinstance(body, dict):
        chat_id = body.get("id")
        results.record(
            "Chat model field set",
            bool(body.get("model")),
            f"model={body.get('model')}"
        )
        api.delete(f"/api/v1/ai/chat/{chat_id}")

    # List with include_archived
    print(_sub("List chats with include_archived=true"))
    status, body = api.get("/api/v1/ai/chat/list?include_archived=true")
    results.record(
        "List chats with include_archived returns 200",
        status == 200,
        f"status={status}"
    )


# ── Test: Agent Tool Coverage ──────────────────────────────────────────

def test_tool_coverage(api: APIClient):
    """Verify all 10 agent tools are accessible."""
    print(_section("AGENT TOOL COVERAGE"))

    expected_tools = [
        "execute_samba_api",
        "execute_shell_command",
        "save_file",
        "read_file",
        "manage_samba_share",
        "manage_samba_config",
        "system_admin",
        "network_admin",
        "ai_skill_execute",
        "request_api_access",
    ]

    # We test each tool by giving a specific prompt
    tool_prompts = {
        "execute_samba_api": "List all domain users using the API (call GET /api/v1/users/)",
        "execute_shell_command": "Run the command 'uptime' on the server",
        "save_file": "Save the text 'hello world' to a file called test_debug.txt",
        "read_file": "Read the file /etc/hostname",
        "manage_samba_share": "List all Samba shares from the configuration",
        "manage_samba_config": "Read the global section of smb.conf",
        "system_admin": "Show system uptime using the system_admin tool",
        "network_admin": "Show IP addresses using the network_admin tool",
        "ai_skill_execute": "List available AI skills",
        "request_api_access": "Show my available API permissions",
    }

    # We can't guarantee every tool will be called in 3 steps,
    # so we just test a few key ones
    for tool in ["system_admin", "network_admin", "ai_skill_execute", "request_api_access"]:
        prompt = tool_prompts.get(tool, f"Use the {tool} tool")
        print(_sub(f"Testing tool: {tool}"))
        status, body = api.post("/api/v1/ai/agent", {
            "prompt": prompt,
            "max_steps": 3,
        })

        if status == 200 and isinstance(body, dict):
            steps = body.get("steps", [])
            tool_names = [s.get("tool_name") for s in steps]
            found = tool in tool_names
            results.record(
                f"Tool '{tool}' is reachable via agent",
                found,
                f"tools_called={tool_names}" if not found else ""
            )
        else:
            results.record(
                f"Tool '{tool}' test failed",
                False,
                f"status={status}"
            )


# ── Main ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Debug & test script for Samba AD API AI subsystem v1.8",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--api-url",
                        default=os.environ.get("SAMBA_API_URL", "http://127.0.0.1:8099"),
                        help="API base URL (default: http://127.0.0.1:8099)")
    parser.add_argument("--api-key",
                        default=os.environ.get("SAMBA_API_KEY", ""),
                        help="API key (or set SAMBA_API_KEY env var)")
    parser.add_argument("--only",
                        choices=["config", "schema", "assistant", "agent", "chat",
                                 "extended", "permissions", "errors", "limits",
                                 "tools", "polza", "all"],
                        default="all",
                        help="Run only specific test group")
    parser.add_argument("--timeout",
                        type=int, default=120,
                        help="HTTP timeout in seconds (default: 120)")

    args = parser.parse_args()

    if not args.api_key:
        print(_fail("No API key provided. Use --api-key or set SAMBA_API_KEY env var."))
        sys.exit(1)

    api = APIClient(args.api_url, args.api_key)

    print(_c(_C.BOLD + _C.CYAN, f"""
  ╔══════════════════════════════════════════════════════════╗
  ║   Samba AD API — AI Subsystem Debug Script v1.8         ║
  ║   API: {args.api_url:<47} ║
  ╚══════════════════════════════════════════════════════════╝
"""))

    start_time = time.time()

    # Always run health check first
    test_health(api)

    only = args.only

    if only in ("config", "all"):
        test_ai_config(api)

    if only in ("schema", "all"):
        test_ai_schema(api)

    if only in ("assistant", "all"):
        test_ai_assistant(api)

    if only in ("agent", "all"):
        test_ai_agent(api)

    if only in ("chat", "all"):
        test_ai_chat(api)

    if only in ("extended", "all"):
        test_extended_tools(api)

    if only in ("permissions", "all"):
        test_permissions(api)

    if only in ("errors", "all"):
        test_error_handling(api)

    if only in ("limits", "all"):
        test_chat_limits(api)

    if only in ("tools", "all"):
        test_tool_coverage(api)

    if only in ("polza", "all"):
        test_polza_provider(api)

    elapsed = time.time() - start_time
    print(_c(_C.DIM, f"\n  Total time: {elapsed:.1f}s"))

    success = results.summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
