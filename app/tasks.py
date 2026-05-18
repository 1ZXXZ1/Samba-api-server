"""
Background task tracking for long-running samba-tool operations.

Operations such as replication, backup, and bulk imports can take
minutes to complete.  This module provides an in-memory task manager
that tracks such operations and exposes their status via a simple API.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.worker import get_worker_pool

logger = logging.getLogger(__name__)


class TaskState(str, enum.Enum):
    """Possible states for a background task."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Task:
    """Represents a single background samba-tool execution."""

    __slots__ = (
        "task_id",
        "command",
        "state",
        "output",
        "error",
        "created_at",
        "started_at",
        "completed_at",
        "_timeout",
    )

    def __init__(
        self,
        task_id: str,
        command: list[str],
        timeout: int = 1200,
    ) -> None:
        self.task_id: str = task_id
        self.command: list[str] = command
        self.state: TaskState = TaskState.PENDING
        self.output: str = ""
        self.error: str = ""
        self.created_at: datetime = datetime.now(timezone.utc)
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self._timeout: int = timeout

    def to_dict(self) -> dict[str, Any]:
        """Serialise the task to a JSON-friendly dictionary."""
        return {
            "task_id": self.task_id,
            "command": self.command,
            "state": self.state.value,
            "output": self.output,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class TaskManager:
    """In-memory task store with async execution support.

    Tasks are submitted via :meth:`submit_task` which returns a unique
    task ID immediately.  The actual samba-tool invocation runs in the
    background; callers poll :meth:`get_task_status` for progress.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

    # ── Public API ─────────────────────────────────────────────────────

    def submit_task(
        self,
        cmd: list[str],
        timeout: int = 1200,
    ) -> str:
        """Register a new task and begin execution in the background.

        Parameters
        ----------
        cmd:
            Full samba-tool command line.
        timeout:
            Per-process timeout in seconds (default 600 = 10 min).

        Returns
        -------
        str
            Unique task identifier (UUID4).
        """
        task_id = uuid.uuid4().hex
        task = Task(task_id=task_id, command=cmd, timeout=timeout)
        self._tasks[task_id] = task

        # Fire-and-forget background coroutine.
        asyncio.get_running_loop().create_task(self._run_task(task))

        logger.info("Task %s submitted: %s", task_id, " ".join(cmd))
        return task_id

    def get_task_status(self, task_id: str) -> Optional[dict[str, Any]]:
        """Return the current status dict for *task_id*, or *None*."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        return task.to_dict()

    def list_tasks(self) -> list[dict[str, Any]]:
        """Return a lightweight list of all tracked tasks."""
        return [
            {
                "task_id": t.task_id,
                "state": t.state.value,
                "created_at": t.created_at.isoformat(),
            }
            for t in self._tasks.values()
        ]

    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """Remove completed/failed tasks older than *max_age_seconds*.

        Returns
        -------
        int
            Number of tasks removed.
        """
        now = datetime.now(timezone.utc)
        to_remove: list[str] = []
        for tid, task in self._tasks.items():
            if task.state in (TaskState.COMPLETED, TaskState.FAILED):
                if task.completed_at and (now - task.completed_at).total_seconds() > max_age_seconds:
                    to_remove.append(tid)
        for tid in to_remove:
            del self._tasks[tid]
        if to_remove:
            logger.info("Cleaned up %d expired tasks", len(to_remove))
        return len(to_remove)

    # ── Internal ───────────────────────────────────────────────────────

    async def _run_task(self, task: Task) -> None:
        """Execute the task's command via the worker pool."""
        task.state = TaskState.RUNNING
        task.started_at = datetime.now(timezone.utc)

        pool = get_worker_pool()
        try:
            returncode, stdout, stderr = await pool.run_command(
                task.command,
                timeout=task._timeout,
            )
            # Fix v12-8: Filter non-fatal warnings from stderr in
            # background tasks, same as worker.py's _run_subprocess.
            # This prevents "Unknown parameter encountered: \"tmp dir\""
            # from being reported as a task error when the command
            # actually succeeded.
            _NON_FATAL_PATTERNS = (
                "Unknown parameter encountered",
                "Ignoring unknown parameter",
                "Using passwords on command line",
            )
            stderr_lines = stderr.splitlines()
            filtered_stderr = "\n".join(
                line for line in stderr_lines
                if not any(pat in line for pat in _NON_FATAL_PATTERNS)
            )

            task.output = stdout
            if returncode != 0:
                task.error = filtered_stderr.strip() or f"Process exited with code {returncode}"
                task.state = TaskState.FAILED
                logger.warning(
                    "Task %s failed (rc=%d): %s",
                    task.task_id,
                    returncode,
                    task.error[:200],
                )
            else:
                task.state = TaskState.COMPLETED
                logger.info("Task %s completed successfully", task.task_id)

        except Exception as exc:  # pragma: no cover
            task.error = str(exc)
            task.state = TaskState.FAILED
            logger.exception("Task %s raised unexpected error", task.task_id)

        finally:
            task.completed_at = datetime.now(timezone.utc)


# ── Singleton ──────────────────────────────────────────────────────────

_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    """Return (and lazily create) the global :class:`TaskManager` singleton."""
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
