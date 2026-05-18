"""
WebSocket manager for Shell Project real-time output streaming.

Provides:
- :class:`ProjetWebSocketManager` — manages WebSocket connections for
  project execution output streaming in real-time.
- Per-project output broadcasting with stdout/stderr channels.
- Integration with the shell projet router for live execution feedback.

v1.6.5: New module for real-time project execution output.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ProjetWebSocketManager:
    """Manage WebSocket connections for shell project output streaming.

    Connections can be registered for:
    - A **specific project** (``/ws/projet/{projet_id}``) — receives
      real-time stdout/stderr output for that project's command execution.
    - **All projects** (``/ws/projet``) — receives events for every
      project state change (useful for dashboards).

    Thread-safety is ensured via an ``asyncio.Lock`` because all
    operations run inside the async event loop.
    """

    def __init__(self) -> None:
        # projet_id → set of connected WebSockets
        self._projet_connections: Dict[str, Set[WebSocket]] = {}
        # Global connections that receive ALL project events
        self._global_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    # ── Connection lifecycle ─────────────────────────────────────────

    async def connect(
        self,
        websocket: WebSocket,
        projet_id: Optional[str] = None,
    ) -> None:
        """Accept and register a WebSocket connection.

        Parameters
        ----------
        websocket:
            The incoming WebSocket connection.
        projet_id:
            If provided, register for updates about this specific project.
            If ``None``, register as a global listener for all projects.
        """
        await websocket.accept()

        async with self._lock:
            if projet_id is not None:
                if projet_id not in self._projet_connections:
                    self._projet_connections[projet_id] = set()
                self._projet_connections[projet_id].add(websocket)
                logger.debug(
                    "WS connected for projet %s (total=%d)",
                    projet_id,
                    len(self._projet_connections[projet_id]),
                )
            else:
                self._global_connections.add(websocket)
                logger.debug(
                    "WS connected globally for projets (total=%d)",
                    len(self._global_connections),
                )

    async def disconnect(
        self,
        websocket: WebSocket,
        projet_id: Optional[str] = None,
    ) -> None:
        """Unregister a WebSocket connection."""
        async with self._lock:
            if projet_id is not None:
                conns = self._projet_connections.get(projet_id)
                if conns is not None:
                    conns.discard(websocket)
                    if not conns:
                        del self._projet_connections[projet_id]
                    logger.debug("WS disconnected from projet %s", projet_id)
            else:
                self._global_connections.discard(websocket)
                logger.debug(
                    "WS disconnected globally (remaining=%d)",
                    len(self._global_connections),
                )

    # ── Broadcasting ─────────────────────────────────────────────────

    async def send_output(
        self,
        projet_id: str,
        stream: str,
        data: str,
    ) -> None:
        """Send stdout/stderr output to all connections watching a project.

        Parameters
        ----------
        projet_id:
            The project whose command produced output.
        stream:
            Either ``"stdout"`` or ``"stderr"``.
        data:
            The output text chunk.
        """
        message = json.dumps({
            "type": "output",
            "projet_id": projet_id,
            "stream": stream,
            "data": data,
            "ts": time.time(),
        })

        await self._send_to_projet(projet_id, message)
        await self._send_to_global(message)

    async def send_status(
        self,
        projet_id: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send a status update for a project.

        Parameters
        ----------
        projet_id:
            The project whose status changed.
        status:
            New status string (e.g. ``"creating"``, ``"running"``,
            ``"completed"``, ``"failed"``).
        details:
            Optional additional data about the status change.
        """
        payload: Dict[str, Any] = {
            "type": "status",
            "projet_id": projet_id,
            "status": status,
            "ts": time.time(),
        }
        if details:
            payload["details"] = details

        message = json.dumps(payload)
        await self._send_to_projet(projet_id, message)
        await self._send_to_global(message)

    async def send_command_result(
        self,
        projet_id: str,
        run_command: str,
        returncode: int,
        stdout: str,
        stderr: str,
        timed_out: bool,
        elapsed: float,
    ) -> None:
        """Send the final result of a command execution.

        Parameters
        ----------
        projet_id:
            The project that executed the command.
        run_command:
            The command that was run.
        returncode:
            Exit code of the process.
        stdout:
            Full standard output.
        stderr:
            Full standard error.
        timed_out:
            Whether the command was killed due to timeout.
        elapsed:
            Execution time in seconds.
        """
        message = json.dumps({
            "type": "command_result",
            "projet_id": projet_id,
            "run_command": run_command,
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "elapsed": elapsed,
            "ts": time.time(),
        })

        await self._send_to_projet(projet_id, message)
        await self._send_to_global(message)

    async def send_extract_result(
        self,
        projet_id: str,
        archive: str,
        extracted_files: List[str],
        success: bool,
        error: Optional[str] = None,
    ) -> None:
        """Send the result of archive extraction.

        Parameters
        ----------
        projet_id:
            The project where the archive was extracted.
        archive:
            The archive filename.
        extracted_files:
            List of extracted file paths.
        success:
            Whether extraction succeeded.
        error:
            Error message if extraction failed.
        """
        payload: Dict[str, Any] = {
            "type": "extract_result",
            "projet_id": projet_id,
            "archive": archive,
            "extracted_files": extracted_files,
            "success": success,
            "ts": time.time(),
        }
        if error:
            payload["error"] = error

        message = json.dumps(payload)
        await self._send_to_projet(projet_id, message)
        await self._send_to_global(message)

    # ── Internal helpers ─────────────────────────────────────────────

    async def _send_to_projet(self, projet_id: str, message: str) -> None:
        """Send *message* to all sockets watching *projet_id*."""
        async with self._lock:
            conns = list(self._projet_connections.get(projet_id, set()))

        for ws in conns:
            try:
                await ws.send_text(message)
            except Exception:
                logger.warning(
                    "Failed to send to WS for projet %s, removing",
                    projet_id,
                )
                await self.disconnect(ws, projet_id)

    async def _send_to_global(self, message: str) -> None:
        """Send *message* to all global listeners."""
        async with self._lock:
            conns = list(self._global_connections)

        for ws in conns:
            try:
                await ws.send_text(message)
            except Exception:
                logger.warning("Failed to send to global projet WS, removing")
                await self.disconnect(ws, projet_id=None)

    # ── Introspection ────────────────────────────────────────────────

    @property
    def connection_count(self) -> int:
        """Total number of active WebSocket connections."""
        projet_total = sum(len(s) for s in self._projet_connections.values())
        return projet_total + len(self._global_connections)


# ── Singleton ───────────────────────────────────────────────────────────

_projet_ws_manager: Optional[ProjetWebSocketManager] = None


def get_projet_ws_manager() -> ProjetWebSocketManager:
    """Return (and lazily create) the global :class:`ProjetWebSocketManager`."""
    global _projet_ws_manager
    if _projet_ws_manager is None:
        _projet_ws_manager = ProjetWebSocketManager()
        logger.info("ProjetWebSocketManager singleton created")
    return _projet_ws_manager
