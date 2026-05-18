#!/usr/bin/env python3
"""
ai_chat_cli.py — Interactive CLI chat client for Samba AD API AI system v1.8.6.

Supports two modes:
  - Agent mode (default): AI executes actions via tool calling (10 tools)
  - Assistant mode: AI returns structured suggestions (Task Builder)

v1.8.6 features:
  - SSE streaming: tool steps appear in real-time, no waiting for full response
  - Cost tracking per message and per session
  - Auto-reconnect on last chat
  - Better UX: spinner, timestamps, Markdown-friendly output
  - /balance, /cost, /redo commands
  - Tab-completion hints
  - FIX: SSE reader now reads by lines (fixes UTF-8 mojibake for Cyrillic)
  - FIX: KeyboardInterrupt during streaming no longer crashes
  - FIX: /exit, /q aliases work properly

Usage:
  python3 ai_chat_cli.py --api-key YOUR_KEY
  python3 ai_chat_cli.py --api-key YOUR_KEY --mode assistant
  python3 ai_chat_cli.py --api-key YOUR_KEY --model openai/gpt-4o-mini
  python3 ai_chat_cli.py --chat-id EXISTING_CHAT_ID

Environment variables:
  SAMBA_API_KEY   — API key for authentication
  SAMBA_API_URL   — API base URL (default: http://127.0.0.1:8099)
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ── Colors ──────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    BG_BLUE = "\033[44m"
    BG_GRAY = "\033[48;5;236m"


def c(color: str, text: str) -> str:
    return f"{color}{text}{C.RESET}"


# ── Spinner ─────────────────────────────────────────────────────────────

_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

class Spinner:
    """Threaded spinner that shows progress while waiting."""

    def __init__(self, message: str = "Thinking"):
        self.message = message
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
            sys.stdout.write(f"\r  {c(C.CYAN, frame)} {c(C.DIM, self.message + '...')}")
            sys.stdout.flush()
            self._stop.wait(0.12)
            i += 1
        # Clear the line
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()

    def update(self, message: str):
        self.message = message

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)


# ── HTTP Client ─────────────────────────────────────────────────────────

class APIClient:
    """HTTP client for the Samba AD API."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def request(self, method: str, path: str, body: Optional[Dict] = None, timeout: int = 120) -> Tuple[int, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None

        req = Request(url, data=data, headers=self.headers, method=method)
        if data:
            req.add_header("Content-Type", "application/json")

        try:
            with urlopen(req, timeout=timeout) as resp:
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

    def get(self, path: str, timeout: int = 60) -> Tuple[int, Any]:
        return self.request("GET", path, timeout=timeout)

    def post(self, path: str, body: Dict, timeout: int = 300) -> Tuple[int, Any]:
        return self.request("POST", path, body, timeout=timeout)

    def put(self, path: str, body: Dict) -> Tuple[int, Any]:
        return self.request("PUT", path, body)

    def delete(self, path: str) -> Tuple[int, Any]:
        return self.request("DELETE", path)

    def stream_sse(self, path: str, body: Dict, timeout: int = 300):
        """Send POST request and yield SSE events as dicts.

        v1.8.6 FIX: Read by lines instead of byte-by-byte.
        The old `resp.read(1).decode("utf-8", errors="replace")` approach
        corrupted multi-byte UTF-8 characters (Cyrillic, CJK, etc.) because
        reading 1 byte splits a 2-4 byte UTF-8 sequence and the partial
        bytes get replaced with '?'. Reading by lines preserves UTF-8.

        SSE protocol: each event is "data: <json>\\n\\n" so readline()
        naturally reads complete lines and preserves multi-byte characters.
        """
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8")

        req = Request(url, data=data, headers={
            **self.headers,
            "Accept": "text/event-stream",
        }, method="POST")

        try:
            with urlopen(req, timeout=timeout) as resp:
                # v1.8.6: Read by lines — SSE is line-based protocol.
                # Each event is: "data: ...\\n\\n" so readline() works
                # perfectly and preserves multi-byte UTF-8 characters.
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    line_str = line.decode("utf-8", errors="replace").rstrip("\n\r")
                    if line_str.startswith("data: "):
                        try:
                            yield json.loads(line_str[6:])
                        except json.JSONDecodeError:
                            pass
                    # Empty line = event boundary, just skip
        except HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            try:
                yield {"type": "error", "error": json.loads(body_text)}
            except json.JSONDecodeError:
                yield {"type": "error", "error": f"HTTP {e.code}: {body_text[:200]}"}
        except Exception as e:
            yield {"type": "error", "error": str(e)}


# ── Chat Session Manager ───────────────────────────────────────────────

class ChatSession:
    """Manages a chat session with the AI."""

    def __init__(self, api: APIClient, chat_id: str, title: str = "",
                 use_agent: bool = True, max_steps: int = 10):
        self.api = api
        self.chat_id = chat_id
        self.title = title
        self.use_agent = use_agent
        self.max_steps = max_steps
        self.model_override: Optional[str] = None
        self.session_cost: float = 0.0
        self.session_tokens: int = 0

    def send(self, message: str) -> Dict[str, Any]:
        """Send a message and return the response (non-streaming)."""
        body = {
            "message": message,
            "use_agent": self.use_agent,
        }
        if self.max_steps:
            body["max_steps"] = self.max_steps

        status, resp = self.api.post(f"/api/v1/ai/chat/{self.chat_id}/send", body)
        if status != 200:
            return {"error": True, "status": status, "detail": resp}

        # Track cost
        if isinstance(resp, dict):
            cost = resp.get("cost_rub") or 0
            tokens = resp.get("tokens_used") or 0
            self.session_cost += cost if isinstance(cost, (int, float)) else 0
            self.session_tokens += tokens if isinstance(tokens, int) else 0

        return resp

    def stream(self, message: str):
        """Send a message and yield SSE events in real-time."""
        body = {
            "message": message,
            "use_agent": self.use_agent,
        }
        if self.max_steps:
            body["max_steps"] = self.max_steps

        for event in self.api.stream_sse(f"/api/v1/ai/chat/{self.chat_id}/stream", body):
            if event.get("type") == "done":
                cost = event.get("cost_rub") or 0
                tokens = event.get("tokens") or 0
                self.session_cost += cost if isinstance(cost, (int, float)) else 0
                self.session_tokens += tokens if isinstance(tokens, int) else 0
            yield event

    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get chat message history."""
        status, resp = self.api.get(f"/api/v1/ai/chat/{self.chat_id}/history?limit={limit}")
        if status == 200 and isinstance(resp, dict):
            return resp.get("messages", [])
        return []

    def update(self, title: Optional[str] = None, system_prompt: Optional[str] = None) -> bool:
        """Update chat session."""
        body = {}
        if title:
            body["title"] = title
        if system_prompt:
            body["system_prompt"] = system_prompt
        if not body:
            return True
        status, _ = self.api.put(f"/api/v1/ai/chat/{self.chat_id}", body)
        return status == 200

    def delete(self) -> bool:
        """Delete this chat session."""
        status, _ = self.api.delete(f"/api/v1/ai/chat/{self.chat_id}")
        return status == 200


# ── CLI Chat Interface ─────────────────────────────────────────────────

class AIChatCLI:
    """Interactive CLI for AI chat with SSE streaming support."""

    def __init__(self, api: APIClient, default_mode: str = "agent",
                 default_model: Optional[str] = None, max_steps: int = 10,
                 no_stream: bool = False):
        self.api = api
        self.default_mode = default_mode
        self.default_model = default_model
        self.max_steps = max_steps
        self.no_stream = no_stream
        self.current_session: Optional[ChatSession] = None
        self.sessions: Dict[str, ChatSession] = {}
        self.running = True
        self.last_message: str = ""
        self._stream_interrupted = False

    def _print_banner(self):
        print(c(C.CYAN + C.BOLD, r"""
  ╔═════════════════════════════════════════════════════════════╗
  ║     Samba AD API — AI Chat CLI v1.8.8                        ║
  ║     Real-time streaming • Tool step visualization           ║
  ╚═════════════════════════════════════════════════════════════╝
"""))
        stream_status = c(C.GREEN, "ON") if not self.no_stream else c(C.YELLOW, "OFF")
        print(f"  Mode: {c(C.YELLOW, self.default_mode)}  |  "
              f"Stream: {stream_status}  |  "
              f"Steps: {c(C.YELLOW, str(self.max_steps))}")
        print(f"  {c(C.GREEN, '/help')} for commands  •  Just type to chat  •  {c(C.RED, '/quit')} to exit")
        print()

    def _print_help(self):
        print(c(C.CYAN, """
  Chat Commands:
    /new [title]            — Create a new chat session
    /list                   — List all chat sessions
    /switch <id|#N>         — Switch to chat (partial ID or #number)
    /delete [chat_id]       — Delete current or specified chat
    /history [limit]        — Show chat message history
    /mode <agent|assistant> — Switch between agent and assistant mode
    /model <name>           — Override LLM model (empty to reset)
    /steps <N>              — Set max agent steps
    /title <new_title>      — Rename current chat
    /info                   — Show current session info
    /cost                   — Show session cost summary
    /balance                — Show AI provider balance
    /config                 — Show AI configuration
    /stream                 — Toggle SSE streaming on/off
    /cancel                 — Cancel current streaming request
    /redo                   — Re-send last message
    /clear                  — Clear screen
    /help                   — Show this help
    /quit, /exit, /q        — Exit

  Input Tips:
    Just type your message and press Enter
    End with ;; for multi-line input (empty line to finish)
    Prefix with ! for direct agent call (no chat session)
    Press Ctrl+C to cancel a running stream

  Streaming:
    Tool steps appear in real-time as the agent works.
    Use /stream to toggle between streaming and waiting modes.
"""))

    def _create_session(self, title: str = "", system_prompt: str = "",
                        model_override: Optional[str] = None) -> Optional[ChatSession]:
        body = {"title": title or f"Chat {datetime.now().strftime('%H:%M:%S')}"}
        if system_prompt:
            body["system_prompt"] = system_prompt
        if model_override:
            body["model_override"] = model_override
        elif self.default_model:
            body["model_override"] = self.default_model

        status, resp = self.api.post("/api/v1/ai/chat/", body)
        if status != 200:
            print(c(C.RED, f"  Failed to create chat: {resp}"))
            return None

        chat_id = resp.get("id", "")
        session = ChatSession(
            api=self.api,
            chat_id=chat_id,
            title=resp.get("title", ""),
            use_agent=(self.default_mode == "agent"),
            max_steps=self.max_steps,
        )
        self.sessions[chat_id] = session
        return session

    def _load_existing_chats(self):
        status, resp = self.api.get("/api/v1/ai/chat/list")
        if status == 200 and isinstance(resp, dict):
            for chat_data in resp.get("chats", []):
                chat_id = chat_data.get("id", "")
                if chat_id and chat_id not in self.sessions:
                    session = ChatSession(
                        api=self.api,
                        chat_id=chat_id,
                        title=chat_data.get("title", ""),
                        use_agent=(self.default_mode == "agent"),
                        max_steps=self.max_steps,
                    )
                    self.sessions[chat_id] = session

    def _switch_session(self, chat_id: str) -> bool:
        # Check for #N syntax (switch by number)
        if chat_id.startswith("#") and chat_id[1:].isdigit():
            idx = int(chat_id[1:]) - 1
            session_list = list(self.sessions.values())
            if 0 <= idx < len(session_list):
                self.current_session = session_list[idx]
                return True
            print(c(C.RED, f"  No chat number {idx + 1}. Use /list to see chats."))
            return False

        # Exact match
        if chat_id in self.sessions:
            self.current_session = self.sessions[chat_id]
            return True

        # Partial match
        matches = [cid for cid in self.sessions if cid.startswith(chat_id)]
        if len(matches) == 1:
            self.current_session = self.sessions[matches[0]]
            return True
        elif len(matches) > 1:
            print(c(C.YELLOW, f"  Multiple chats match '{chat_id}':"))
            for m in matches:
                print(f"    {m} — {self.sessions[m].title}")
            return False
        return False

    def _print_session_info(self):
        if not self.current_session:
            print(c(C.YELLOW, "  No active chat session. Use /new to create one."))
            return

        s = self.current_session
        stream = c(C.GREEN, "ON") if not self.no_stream else c(C.YELLOW, "OFF")
        print(c(C.CYAN, f"""
  Current Session:
    ID:       {s.chat_id[:12]}...
    Title:    {s.title}
    Mode:     {'Agent (tool calling)' if s.use_agent else 'Assistant (Task Builder)'}
    Model:    {s.model_override or 'default'}
    Steps:    {s.max_steps}
    Stream:   {stream}
    Cost:     {s.session_cost:.4f} RUB
    Tokens:   {s.session_tokens}
"""))

    def _print_cost(self):
        if not self.current_session:
            print(c(C.YELLOW, "  No active session"))
            return

        s = self.current_session
        print(c(C.CYAN, f"""
  Session Cost Summary:
    Title:    {s.title}
    Cost:     {c(C.YELLOW, f'{s.session_cost:.4f} RUB')}
    Tokens:   {s.session_tokens:,}
"""))

    def _print_balance(self):
        status, resp = self.api.get("/api/v1/ai/balance")
        if status == 200 and isinstance(resp, dict):
            amount = resp.get("amount", "?")
            spent = resp.get("spent_amount", "?")
            print(c(C.CYAN, f"\n  AI Provider Balance:"))
            print(f"    Available:  {c(C.GREEN, str(amount))} RUB")
            print(f"    Spent:      {c(C.YELLOW, str(spent))} RUB")
            print()
        else:
            print(c(C.RED, f"  Failed to get balance: {resp}"))

    def _print_history(self, limit: int = 20):
        if not self.current_session:
            print(c(C.YELLOW, "  No active session"))
            return

        messages = self.current_session.get_history(limit)
        if not messages:
            print(c(C.DIM, "  (no messages)"))
            return

        print(c(C.CYAN, f"  Chat History ({len(messages)} messages):"))
        print(c(C.DIM, "  " + "─" * 60))

        for msg in messages:
            role = msg.get("role", "?")
            content = msg.get("content", "")
            timestamp = msg.get("timestamp", "")[:19].replace("T", " ")

            if role == "user":
                prefix = c(C.GREEN, f"  You [{timestamp}]")
            elif role == "assistant":
                prefix = c(C.BLUE, f"  AI  [{timestamp}]")
            else:
                prefix = c(C.DIM, f"  {role} [{timestamp}]")

            # Show content (truncated for history)
            max_len = 300
            display = content[:max_len] + ("..." if len(content) > max_len else "")
            print(prefix)
            for line in display.split("\n"):
                print(f"    {line}")

            # Tool steps
            tool_steps = msg.get("tool_steps")
            if tool_steps:
                print(c(C.DIM, f"    Steps: {len(tool_steps)}"))
                for ts in tool_steps[:3]:
                    tool = ts.get("tool", "?")
                    success = ts.get("success", False)
                    icon = c(C.GREEN, "✓") if success else c(C.RED, "✗")
                    print(f"      {icon} {tool}")

            # Cost
            cost = msg.get("cost_rub")
            if cost:
                print(c(C.DIM, f"    Cost: {cost} RUB"))
            print()

    def _print_streaming_response(self, events):
        """Print SSE events as they arrive in real-time.

        v1.8.6: Added KeyboardInterrupt handling so Ctrl+C during
        streaming gracefully cancels instead of crashing with traceback.
        """
        step_count = 0
        start_time = time.time()

        try:
            for event in events:
                evt_type = event.get("type", "")

                if evt_type == "start":
                    model = event.get("model", "")
                    print(c(C.DIM, f"  Model: {model}"))
                    print()

                elif evt_type == "step_start":
                    step = event.get("step", "?")
                    tool = event.get("tool", "?")
                    args = event.get("args", {})
                    args_str = json.dumps(args, ensure_ascii=False)[:80]
                    step_count += 1
                    print(c(C.YELLOW, f"  ⚡ Step {step}: ") +
                          c(C.BOLD, tool) +
                          c(C.DIM, f"({args_str})"))

                elif evt_type == "step_result":
                    step = event.get("step", "?")
                    tool = event.get("tool", "?")
                    success = event.get("success", False)
                    result_preview = event.get("result_preview", "")
                    icon = c(C.GREEN, "✓") if success else c(C.RED, "✗")
                    # Show brief result
                    preview = result_preview[:120].replace("\n", " ")
                    print(f"  {icon} {tool}: {c(C.DIM, preview)}")
                    print()

                elif evt_type == "fallback":
                    model = event.get("model", "")
                    reason = event.get("reason", "")
                    msg = f"  ↳ Fallback to {model}"
                    if reason:
                        msg += c(C.DIM, f" ({reason})")
                    print(c(C.YELLOW, msg))

                elif evt_type == "content":
                    content = event.get("content", "")
                    if content:
                        print(c(C.BLUE + C.BOLD, "  AI:"))
                        for line in content.split("\n"):
                            print(f"    {line}")
                        print()

                elif evt_type == "done":
                    elapsed = time.time() - start_time
                    tokens = event.get("tokens", 0)
                    cost = event.get("cost_rub", 0)
                    model = event.get("model", "")

                    meta = [f"{elapsed:.1f}s"]
                    if model:
                        meta.append(f"model={model}")
                    if tokens:
                        meta.append(f"tokens={tokens}")
                    if cost:
                        meta.append(f"cost={cost:.4f}₽")
                    if step_count:
                        meta.append(f"steps={step_count}")
                    print(c(C.DIM, f"  [{', '.join(meta)}]"))
                    print()

                elif evt_type == "error":
                    error = event.get("error", "Unknown error")
                    print(c(C.RED, f"\n  Error: {str(error)[:300]}"))
                    print()

        except KeyboardInterrupt:
            self._stream_interrupted = True
            print(c(C.YELLOW, "\n  [Cancelled] Stream interrupted by Ctrl+C"))
            print()

    def _print_agent_response(self, resp: Dict[str, Any]):
        """Pretty-print non-streaming agent response."""
        if resp.get("error"):
            status = resp.get("status", "?")
            detail = resp.get("detail", "")
            print(c(C.RED, f"\n  Error (HTTP {status}): {str(detail)[:300]}"))
            return

        content = resp.get("content", "")
        tool_steps = resp.get("tool_steps")

        if tool_steps:
            print(c(C.DIM, f"\n  Tool Steps ({len(tool_steps)}):"))
            for ts in tool_steps:
                step = ts.get("step", "?")
                tool = ts.get("tool", "?")
                success = ts.get("success", False)
                args = ts.get("args", {})
                icon = c(C.GREEN, "✓") if success else c(C.RED, "✗")
                args_str = json.dumps(args, ensure_ascii=False)[:80]
                print(f"  {icon} Step {step}: {c(C.YELLOW, tool)}({args_str})")
            print(c(C.DIM, "  " + "─" * 60))

        if content:
            print(c(C.BLUE + C.BOLD, f"\n  AI:"))
            for line in content.split("\n"):
                print(f"    {line}")

        # Meta
        model_used = resp.get("model_used", "")
        tokens_used = resp.get("tokens_used")
        cost_rub = resp.get("cost_rub")

        meta = []
        if model_used:
            meta.append(f"model={model_used}")
        if tokens_used:
            meta.append(f"tokens={tokens_used}")
        if cost_rub:
            meta.append(f"cost={cost_rub:.4f}₽")
        if meta:
            print(c(C.DIM, f"    [{', '.join(meta)}]"))
        print()

    def _send_chat_message(self, message: str):
        """Send a message — streaming or non-streaming based on setting."""
        if not self.current_session:
            print(c(C.YELLOW, "  No active chat session. Use /new to create one."))
            return

        self.last_message = message
        self._stream_interrupted = False
        start = time.time()

        if not self.no_stream:
            # Streaming mode
            spinner = Spinner("Connecting").start()
            try:
                events = self.current_session.stream(message)
                spinner.stop()
                self._print_streaming_response(events)
            except KeyboardInterrupt:
                spinner.stop()
                print(c(C.YELLOW, "\n  [Cancelled]"))
                print()
            except Exception as exc:
                spinner.stop()
                print(c(C.RED, f"\n  Stream error: {exc}"))
                print(c(C.YELLOW, "  Retrying without streaming..."))
                try:
                    resp = self.current_session.send(message)
                except Exception as exc2:
                    print(c(C.RED, f"\n  Error: {exc2}"))
                    return
                elapsed = time.time() - start
                if resp.get("error"):
                    print(c(C.RED, f"\n  Error: {str(resp.get('detail', ''))[:300]}"))
                else:
                    self._print_agent_response(resp)
                    print(c(C.DIM, f"  [{elapsed:.1f}s]"))
        else:
            # Non-streaming mode
            spinner = Spinner("Thinking").start()
            try:
                resp = self.current_session.send(message)
                spinner.stop()
            except KeyboardInterrupt:
                spinner.stop()
                print(c(C.YELLOW, "\n  [Cancelled]"))
                print()
                return
            except Exception as exc:
                spinner.stop()
                print(c(C.RED, f"\n  Error: {exc}"))
                return

            elapsed = time.time() - start
            if resp.get("error"):
                print(c(C.RED, f"\n  Error: {str(resp.get('detail', ''))[:300]}"))
            else:
                self._print_agent_response(resp)
                print(c(C.DIM, f"  [{elapsed:.1f}s]"))

    def _send_direct_agent(self, prompt: str):
        """Send directly to agent endpoint (no chat session)."""
        body = {
            "prompt": prompt,
            "max_steps": self.max_steps,
        }
        if self.default_model:
            body["model_override"] = self.default_model

        spinner = Spinner("Agent thinking").start()
        start = time.time()

        status, resp = self.api.post("/api/v1/ai/agent", body, timeout=300)
        spinner.stop()
        elapsed = time.time() - start

        if status != 200:
            print(c(C.RED, f"\n  Error (HTTP {status}): {str(resp)[:300]}"))
            return

        if isinstance(resp, dict):
            steps = resp.get("steps", [])
            if steps:
                print(c(C.DIM, f"\n  Tool Steps ({len(steps)}) [{elapsed:.1f}s]:"))
                for step in steps:
                    s_num = step.get("step", "?")
                    tool = step.get("tool_name", "?")
                    success = step.get("success", False)
                    icon = c(C.GREEN, "✓") if success else c(C.RED, "✗")
                    print(f"  {icon} Step {s_num}: {c(C.YELLOW, tool)}")
                print(c(C.DIM, "  " + "─" * 56))

            message = resp.get("message", "")
            if message:
                print(c(C.BLUE + C.BOLD, f"\n  AI:"))
                for line in message.split("\n"):
                    print(f"    {line}")

            model_used = resp.get("model_used", "")
            tokens_used = resp.get("tokens_used")
            meta = [f"{elapsed:.1f}s"]
            if model_used:
                meta.append(f"model={model_used}")
            if tokens_used:
                meta.append(f"tokens={tokens_used}")
            print(c(C.DIM, f"    [{', '.join(meta)}]"))
            print()

    def _handle_multiline(self) -> str:
        lines = []
        print(c(C.DIM, "  Multi-line mode. Empty line to send, Ctrl+C to cancel."))
        while True:
            try:
                line = input(c(C.DIM, "  ... "))
                if line == "":
                    break
                lines.append(line)
            except KeyboardInterrupt:
                print(c(C.YELLOW, "  Cancelled."))
                return ""
        return "\n".join(lines)

    def _prompt(self) -> str:
        if self.current_session:
            mode = "A" if self.current_session.use_agent else "T"
            title = self.current_session.title[:20]
            stream_icon = "⇶" if not self.no_stream else "·"
            cost_str = f" {self.current_session.session_cost:.2f}₽" if self.current_session.session_cost > 0 else ""
            return c(C.GREEN, f"  [{mode}{stream_icon}] {title}>{cost_str} ")
        else:
            return c(C.GREEN, f"  chat> ")

    def _list_chats(self):
        self._load_existing_chats()

        if not self.sessions:
            print(c(C.YELLOW, "  No chat sessions. Use /new to create one."))
            return

        print(c(C.CYAN, f"\n  Chat Sessions ({len(self.sessions)}):"))
        print(c(C.DIM, "  " + "─" * 72))

        for i, (chat_id, session) in enumerate(self.sessions.items(), 1):
            current = " → " if self.current_session and self.current_session.chat_id == chat_id else "   "
            mode = c(C.YELLOW, "Agent") if session.use_agent else c(C.MAGENTA, "Asst")
            cost_str = f" {session.session_cost:.2f}₽" if session.session_cost > 0 else ""
            print(f"{current}{c(C.BOLD, f'#{i}')} {session.title[:25]:<26} "
                  f"{mode}  "
                  f"{c(C.DIM, chat_id[:12])}...{cost_str}")

        print()

    def _show_config(self):
        status, resp = self.api.get("/api/v1/ai/config")
        if status == 200 and isinstance(resp, dict):
            print(c(C.CYAN, "\n  AI Configuration:"))
            print(f"    Enabled:        {resp.get('enabled')}")
            print(f"    Default model:  {resp.get('default_model')}")
            print(f"    Temperature:    {resp.get('temperature')}")
            print(f"    Max tokens:     {resp.get('max_tokens')}")
            print(f"    Endpoints:      {resp.get('schema_endpoints')}")
            print(f"    Fallback models:{resp.get('fallback_models')}")
            active = resp.get('active_provider', '?')
            print(f"    Provider:       {c(C.YELLOW, active)}")
            print(f"    Polza active:   {resp.get('polza_configured')}")
            extra = resp.get('polza_extra_body')
            if extra:
                print(f"    Extra body:     {json.dumps(extra, ensure_ascii=False)}")
            print()
        else:
            print(c(C.RED, f"  Failed to get config: {resp}"))

    def run(self, chat_id: Optional[str] = None):
        self._print_banner()
        self._load_existing_chats()

        # Resume or create session
        if chat_id:
            if self._switch_session(chat_id):
                print(c(C.GREEN, f"  Resumed chat: {self.current_session.title}"))
                self._print_history(limit=5)
            else:
                print(c(C.YELLOW, f"  Chat '{chat_id}' not found. Creating new session."))
                session = self._create_session()
                if session:
                    self.current_session = session
                    print(c(C.GREEN, f"  Created: {session.title}"))
        elif self.sessions:
            latest = list(self.sessions.values())[-1]
            self.current_session = latest
            print(c(C.GREEN, f"  Resumed latest: {latest.title}"))
            self._print_history(limit=3)
        else:
            session = self._create_session(
                title=f"Session {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            if session:
                self.current_session = session
                print(c(C.GREEN, f"  Created: {session.title}"))
            else:
                print(c(C.RED, "  Failed to create initial chat."))
                print(c(C.YELLOW, "  Use ! prefix to send messages directly to agent."))

        print()

        # Main loop
        while self.running:
            try:
                user_input = input(self._prompt()).strip()
            except (KeyboardInterrupt, EOFError):
                print(c(C.YELLOW, "\n  Bye!"))
                break

            if not user_input:
                continue

            # Multi-line
            if user_input.endswith(";;"):
                user_input = user_input[:-2].strip()
                multiline = self._handle_multiline()
                if multiline:
                    user_input += "\n" + multiline
                else:
                    continue

            # Commands
            if user_input.startswith("/"):
                cmd_parts = user_input[1:].split(maxsplit=1)
                cmd = cmd_parts[0].lower()
                arg = cmd_parts[1] if len(cmd_parts) > 1 else ""

                if cmd in ("quit", "exit", "q", "bye"):
                    print(c(C.YELLOW, "  Bye!"))
                    self.running = False

                elif cmd in ("help", "?"):
                    self._print_help()

                elif cmd == "new":
                    title = arg or f"Chat {datetime.now().strftime('%H:%M:%S')}"
                    session = self._create_session(title=title)
                    if session:
                        self.current_session = session
                        print(c(C.GREEN, f"  Created: {session.title} (#{len(self.sessions)})"))

                elif cmd in ("list", "ls"):
                    self._list_chats()

                elif cmd == "switch":
                    if not arg:
                        self._list_chats()
                        continue
                    if self._switch_session(arg):
                        print(c(C.GREEN, f"  Switched to: {self.current_session.title}"))

                elif cmd in ("delete", "del"):
                    target_id = arg
                    if target_id:
                        if target_id in self.sessions:
                            self.sessions[target_id].delete()
                            del self.sessions[target_id]
                            print(c(C.GREEN, f"  Deleted chat {target_id[:12]}..."))
                            if self.current_session and self.current_session.chat_id == target_id:
                                self.current_session = None
                        else:
                            print(c(C.RED, f"  Chat '{target_id}' not found"))
                    elif self.current_session:
                        chat_id_del = self.current_session.chat_id
                        title = self.current_session.title
                        if self.current_session.delete():
                            del self.sessions[chat_id_del]
                            self.current_session = None
                            print(c(C.GREEN, f"  Deleted: {title}"))
                    else:
                        print(c(C.YELLOW, "  No active chat"))

                elif cmd in ("history", "hist"):
                    limit = int(arg) if arg.isdigit() else 20
                    self._print_history(limit=limit)

                elif cmd == "mode":
                    if arg in ("agent", "a"):
                        if self.current_session:
                            self.current_session.use_agent = True
                        self.default_mode = "agent"
                        print(c(C.GREEN, "  Mode: Agent (tool calling)"))
                    elif arg in ("assistant", "taskbuilder", "t"):
                        if self.current_session:
                            self.current_session.use_agent = False
                        self.default_mode = "assistant"
                        print(c(C.GREEN, "  Mode: Assistant (suggestions)"))
                    else:
                        mode = "Agent" if (self.current_session and self.current_session.use_agent) else "Assistant"
                        print(c(C.YELLOW, f"  Mode: {mode}  (/mode agent | /mode assistant)"))

                elif cmd == "model":
                    if arg:
                        if self.current_session:
                            self.current_session.model_override = arg
                        self.default_model = arg
                        print(c(C.GREEN, f"  Model: {arg}"))
                    else:
                        current = self.current_session.model_override if self.current_session else self.default_model
                        print(c(C.YELLOW, f"  Model: {current or 'default'}  (/model <name>)"))

                elif cmd == "steps":
                    if arg.isdigit():
                        n = int(arg)
                        if 1 <= n <= 100:
                            self.max_steps = n
                            if self.current_session:
                                self.current_session.max_steps = n
                            print(c(C.GREEN, f"  Max steps: {n}"))
                        else:
                            print(c(C.RED, "  Steps must be 1-100"))
                    else:
                        print(c(C.YELLOW, f"  Max steps: {self.max_steps}"))

                elif cmd == "title":
                    if not arg:
                        print(c(C.DIM, "  Usage: /title New Title"))
                    elif self.current_session:
                        if self.current_session.update(title=arg):
                            self.current_session.title = arg
                            print(c(C.GREEN, f"  Title: {arg}"))

                elif cmd == "info":
                    self._print_session_info()

                elif cmd == "cost":
                    self._print_cost()

                elif cmd == "balance":
                    self._print_balance()

                elif cmd == "config":
                    self._show_config()

                elif cmd == "stream":
                    self.no_stream = not self.no_stream
                    status = "OFF" if self.no_stream else "ON"
                    print(c(C.GREEN, f"  Streaming: {status}"))

                elif cmd == "cancel":
                    if self._stream_interrupted:
                        print(c(C.YELLOW, "  Already cancelled"))
                    else:
                        print(c(C.YELLOW, "  No active stream to cancel (press Ctrl+C during streaming)"))

                elif cmd == "redo":
                    if self.last_message:
                        print(c(C.DIM, f"  Re-sending: {self.last_message[:60]}..."))
                        self._send_chat_message(self.last_message)
                    else:
                        print(c(C.YELLOW, "  No previous message to redo"))

                elif cmd == "clear":
                    os.system("clear" if os.name != "nt" else "cls")

                else:
                    print(c(C.RED, f"  Unknown: /{cmd}  (/help for commands)"))

                print()
                continue

            # Direct agent
            if user_input.startswith("!"):
                message = user_input[1:].strip()
                if message:
                    self._send_direct_agent(message)
                else:
                    print(c(C.DIM, "  Usage: !your message here"))
                continue

            # Chat message
            self.last_message = user_input
            if self.current_session:
                self._send_chat_message(user_input)
            else:
                print(c(C.DIM, "  No session, sending to agent directly..."))
                self._send_direct_agent(user_input)


# ── Main ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Interactive CLI chat client for Samba AD API AI v1.8.6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--api-url",
                        default=os.environ.get("SAMBA_API_URL", "http://127.0.0.1:8099"),
                        help="API base URL (default: http://127.0.0.1:8099)")
    parser.add_argument("--api-key",
                        default=os.environ.get("SAMBA_API_KEY", ""),
                        help="API key (or set SAMBA_API_KEY env var)")
    parser.add_argument("--mode",
                        choices=["agent", "assistant"],
                        default="agent",
                        help="Default chat mode (default: agent)")
    parser.add_argument("--model",
                        default=None,
                        help="Override LLM model (e.g. openai/gpt-4o-mini)")
    parser.add_argument("--chat-id",
                        default=None,
                        help="Resume existing chat by ID")
    parser.add_argument("--steps",
                        type=int, default=10,
                        help="Max agent steps per message (default: 10)")
    parser.add_argument("--title",
                        default="",
                        help="Title for new chat session")
    parser.add_argument("--no-stream",
                        action="store_true",
                        help="Disable SSE streaming (wait for full response)")

    args = parser.parse_args()

    if not args.api_key:
        print(c(C.RED, "No API key. Use --api-key or set SAMBA_API_KEY env var."))
        sys.exit(1)

    api = APIClient(args.api_url, args.api_key)
    cli = AIChatCLI(
        api=api,
        default_mode=args.mode,
        default_model=args.model,
        max_steps=args.steps,
        no_stream=args.no_stream,
    )

    if args.title and not args.chat_id:
        session = cli._create_session(title=args.title)
        if session:
            cli.current_session = session

    cli.run(chat_id=args.chat_id)


if __name__ == "__main__":
    main()
