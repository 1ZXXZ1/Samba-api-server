"""
WebSocket support for real-time task status updates.

Provides:

- :class:`TaskWebSocketManager` — manages per-task and global WebSocket
  connections and broadcasts state changes.
- :func:`install_task_hooks` — hooks into :class:`~app.tasks.TaskManager`
  to automatically broadcast task updates when state changes.
- FastAPI WebSocket endpoints for per-task and global (dashboard)
  subscriptions.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


# ── TaskWebSocketManager ────────────────────────────────────────────────

class TaskWebSocketManager:
    """Manage WebSocket connections for task status updates.

    Connections can be registered for:

    - A **specific task** (``/ws/tasks/{task_id}``) — receives updates
      only for that task.
    - **All tasks** (``/ws/tasks``) — receives updates for every task
      state change (useful for dashboards).

    Thread-safety is ensured via an ``asyncio.Lock`` because all
    operations run inside the async event loop.
    """

    def __init__(self) -> None:
        # task_id → set of connected WebSockets
        self._task_connections: dict[str, set[WebSocket]] = {}
        # Global connections that receive ALL task updates
        self._global_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    # ── Connection lifecycle ─────────────────────────────────────────

    async def connect(self, websocket: WebSocket, task_id: Optional[str] = None) -> None:
        """Accept and register a WebSocket connection.

        Parameters
        ----------
        websocket:
            The incoming WebSocket connection.
        task_id:
            If provided, register for updates about this specific task.
            If ``None``, register as a global listener for all tasks.
        """
        await websocket.accept()

        async with self._lock:
            if task_id is not None:
                if task_id not in self._task_connections:
                    self._task_connections[task_id] = set()
                self._task_connections[task_id].add(websocket)
                logger.debug("WS connected for task %s (total=%d)", task_id, len(self._task_connections[task_id]))
            else:
                self._global_connections.add(websocket)
                logger.debug("WS connected globally (total=%d)", len(self._global_connections))

    async def disconnect(self, websocket: WebSocket, task_id: Optional[str] = None) -> None:
        """Unregister a WebSocket connection.

        Parameters
        ----------
        websocket:
            The WebSocket to disconnect.
        task_id:
            The task the connection was watching, or ``None`` for a
            global connection.
        """
        async with self._lock:
            if task_id is not None:
                conns = self._task_connections.get(task_id)
                if conns is not None:
                    conns.discard(websocket)
                    if not conns:
                        del self._task_connections[task_id]
                    logger.debug("WS disconnected from task %s", task_id)
            else:
                self._global_connections.discard(websocket)
                logger.debug("WS disconnected globally (remaining=%d)", len(self._global_connections))

    # ── Broadcasting ─────────────────────────────────────────────────

    async def broadcast_task_update(self, task_id: str, status: str) -> None:
        """Send a status update to all connections watching *task_id*.

        Also broadcasts to all global connections.

        Parameters
        ----------
        task_id:
            The task whose status changed.
        status:
            New status string (e.g. ``"RUNNING"``, ``"COMPLETED"``).
        """
        message = json.dumps({
            "type": "task_status",
            "task_id": task_id,
            "status": status,
        })

        await self._send_to_task(task_id, message)
        await self._send_to_global(message)

    async def send_task_update(self, task_id: str, data: dict[str, Any]) -> None:
        """Send arbitrary data to all connections watching *task_id*.

        Also broadcasts to all global connections.

        Parameters
        ----------
        task_id:
            The task to update.
        data:
            Arbitrary JSON-serialisable payload.
        """
        message = json.dumps({
            "type": "task_update",
            "task_id": task_id,
            **data,
        })

        await self._send_to_task(task_id, message)
        await self._send_to_global(message)

    # ── Internal helpers ─────────────────────────────────────────────

    async def _send_to_task(self, task_id: str, message: str) -> None:
        """Send *message* to all sockets watching *task_id*."""
        async with self._lock:
            conns = list(self._task_connections.get(task_id, set()))

        for ws in conns:
            try:
                await ws.send_text(message)
            except Exception:
                logger.warning("Failed to send to WS for task %s, removing", task_id)
                await self.disconnect(ws, task_id)

    async def _send_to_global(self, message: str) -> None:
        """Send *message* to all global listeners."""
        async with self._lock:
            conns = list(self._global_connections)

        for ws in conns:
            try:
                await ws.send_text(message)
            except Exception:
                logger.warning("Failed to send to global WS, removing")
                await self.disconnect(ws, task_id=None)

    # ── Introspection ────────────────────────────────────────────────

    @property
    def connection_count(self) -> int:
        """Total number of active WebSocket connections."""
        task_total = sum(len(s) for s in self._task_connections.values())
        return task_total + len(self._global_connections)


# ── Singleton ───────────────────────────────────────────────────────────

_ws_manager: Optional[TaskWebSocketManager] = None


def get_ws_manager() -> TaskWebSocketManager:
    """Return (and lazily create) the global :class:`TaskWebSocketManager`."""
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = TaskWebSocketManager()
        logger.info("TaskWebSocketManager singleton created")
    return _ws_manager


# ── TaskManager integration ─────────────────────────────────────────────

def install_task_hooks(
    task_manager: Any,
    ws_manager: Optional[TaskWebSocketManager] = None,
) -> None:
    """Hook into a :class:`~app.tasks.TaskManager` to broadcast updates.

    This wraps :meth:`TaskManager._run_task` so that every state
    transition (PENDING → RUNNING → COMPLETED/FAILED) is pushed to
    connected WebSocket clients.

    Parameters
    ----------
    task_manager:
        The :class:`~app.tasks.TaskManager` instance to hook.
    ws_manager:
        The :class:`TaskWebSocketManager` to use.  If ``None`` the
        global singleton is used.
    """
    if ws_manager is None:
        ws_manager = get_ws_manager()

    original_run_task = task_manager._run_task

    async def _hooked_run_task(task: Any) -> None:
        """Wrapper around ``_run_task`` that broadcasts state changes."""
        # Broadcast: task has started (PENDING → RUNNING)
        await ws_manager.broadcast_task_update(task.task_id, "RUNNING")

        try:
            await original_run_task(task)
        finally:
            # After _run_task completes, the task state will be
            # either COMPLETED or FAILED.
            state_value = task.state.value if hasattr(task.state, "value") else str(task.state)
            await ws_manager.broadcast_task_update(task.task_id, state_value)

    # Also broadcast when a task is first submitted (PENDING)
    original_submit_task = task_manager.submit_task

    def _hooked_submit_task(cmd: list[str], timeout: int = 1200) -> str:
        """Wrapper around ``submit_task`` that broadcasts PENDING state."""
        task_id = original_submit_task(cmd, timeout=timeout)

        # Schedule the broadcast — submit_task is sync but _run_task
        # is async, so we schedule the broadcast in the running loop.
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(ws_manager.broadcast_task_update(task_id, "PENDING"))
        except RuntimeError:
            # No running event loop (shouldn't happen in FastAPI context)
            logger.warning("Cannot broadcast PENDING for task %s: no event loop", task_id)

        return task_id

    task_manager._run_task = _hooked_run_task
    task_manager.submit_task = _hooked_submit_task

    logger.info("TaskManager hooks installed for WebSocket broadcasts")


# ── FastAPI WebSocket router ────────────────────────────────────────────

router = APIRouter()


@router.websocket("/ws/tasks/{task_id}")
async def websocket_task_status(websocket: WebSocket, task_id: str) -> None:
    """WebSocket endpoint for per-task status updates.

    On connection the current task status is sent immediately, then
    the connection remains open to receive real-time updates as the
    task progresses through PENDING → RUNNING → COMPLETED/FAILED.

    If the task does not exist at connection time the socket is
    closed with a ``1008`` policy violation code.
    """
    ws_manager = get_ws_manager()

    # Verify the task exists before accepting
    from app.tasks import get_task_manager
    tm = get_task_manager()
    current_status = tm.get_task_status(task_id)

    await ws_manager.connect(websocket, task_id=task_id)

    try:
        # Send current status immediately on connect
        if current_status is not None:
            await websocket.send_text(json.dumps({
                "type": "task_status",
                "task_id": task_id,
                "status": current_status.get("state", "UNKNOWN"),
                "data": current_status,
            }))
        else:
            # Task not found — inform client and close
            await websocket.send_text(json.dumps({
                "type": "error",
                "task_id": task_id,
                "message": f"Task {task_id} not found",
            }))
            await websocket.close(code=1008, reason="Task not found")
            return

        # Keep the connection alive — the TaskWebSocketManager will
        # push updates via broadcast_task_update / send_task_update.
        # We just need to detect when the client disconnects.
        while True:
            # Wait for any incoming message (clients may send pings
            # or just keep the socket open).  We don't expect
            # application-level messages from the client, but
            # receiving lets us detect a clean disconnect.
            try:
                data = await websocket.receive_text()
                # Ignore incoming data; could extend with commands
                # like "subscribe", "unsubscribe" in the future.
                logger.debug("WS received from client for task %s: %s", task_id, data[:100])
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("WebSocket error for task %s: %s", task_id, exc)
    finally:
        await ws_manager.disconnect(websocket, task_id=task_id)


@router.websocket("/ws/tasks")
async def websocket_all_tasks(websocket: WebSocket) -> None:
    """WebSocket endpoint for updates on ALL tasks (dashboard).

    Receives every task state change across the system.  Useful for
    building real-time dashboards that show running tasks.

    On connection a snapshot of all current tasks is sent, then
    the connection stays open for live updates.
    """
    ws_manager = get_ws_manager()

    await ws_manager.connect(websocket, task_id=None)

    try:
        # Send snapshot of current tasks immediately
        from app.tasks import get_task_manager
        tm = get_task_manager()
        all_tasks = tm.list_tasks()

        await websocket.send_text(json.dumps({
            "type": "tasks_snapshot",
            "tasks": all_tasks,
            "count": len(all_tasks),
        }))

        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()
                logger.debug("WS received on global channel: %s", data[:100])
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("WebSocket error on global channel: %s", exc)
    finally:
        await ws_manager.disconnect(websocket, task_id=None)
