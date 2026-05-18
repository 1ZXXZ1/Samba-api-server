"""
Worker pool management for isolated samba-tool execution.

samba-tool is **not** thread-safe, so we offload every invocation to a
``ProcessPoolExecutor``.  This keeps the async event-loop free while
ensuring each call runs in its own process.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Optional

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

# Module-level reference so we can clean up on shutdown.
_pool: Optional[ProcessPoolExecutor] = None


def _run_subprocess(cmd: list[str], timeout: int = 600) -> tuple[int, str, str]:
    """Execute *cmd* in a subprocess and return (returncode, stdout, stderr).

    This function is designed to be submitted to a ``ProcessPoolExecutor``
    – it must be a top-level (picklable) function, **not** a method.

    Parameters
    ----------
    cmd:
        Complete command-line as a list of strings.
    timeout:
        Maximum wall-time in seconds for the subprocess.

    Returns
    -------
    tuple[int, str, str]
        ``(return_code, stdout, stderr)`` – stdout and stderr are decoded
        as UTF-8 with error replacement.
    """
    # Derive a short command label for timing logs
    _cmd_label = " ".join(cmd[1:3]) if len(cmd) >= 3 else " ".join(cmd[1:])
    t_start = time.monotonic()

    logger.debug("Executing: %s", " ".join(cmd))
    try:
        import os as _os

        # Fix v10-2/v14-2/v18: Always force TMPDIR for samba-tool.
        # Samba's DRSUAPI bind creates temp files for GSSAPI auth that
        # can exceed tmpfs quotas on /tmp.  Even if TMPDIR is already
        # set (e.g. to /tmp), override it to /var/tmp which is on a
        # real filesystem with more space.  This prevents
        # STATUS_QUOTA_EXCEEDED errors in DRS commands.
        # v14-2: Also ensure the directory exists and is writable.
        # v18: Read TMPDIR from Settings (SAMBA_TMPDIR env var) so it
        # can be configured via .env. Default remains /var/tmp.
        try:
            from app.config import get_settings as _get_settings
            _settings_tmpdir = _get_settings().TMPDIR
        except Exception:
            _settings_tmpdir = "/var/tmp"
        _tmpdir = _settings_tmpdir if _settings_tmpdir and _os.path.isdir(_settings_tmpdir) else "/var/tmp"
        # If /var/tmp doesn't exist, try other common paths on disk
        if not _tmpdir:
            for _candidate in ["/var/tmp", "/tmp", "/var/spool/tmp"]:
                if _os.path.isdir(_candidate):
                    _tmpdir = _candidate
                    break

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env={
                **_os.environ,
                # Suppress the "Using passwords on command line is insecure" warning (Fix #10).
                "PYTHONWARNINGS": "ignore",
                # Fix v4/v14-2: Use /var/tmp for temporary files to avoid quota
                # errors on tmpfs-based /tmp (Samba bug #15462).
                # Also set TMP and TEMP as some code paths use these instead.
                **({"TMPDIR": _tmpdir, "TMP": _tmpdir, "TEMP": _tmpdir} if _tmpdir else {}),
            },
        )

        t_elapsed = time.monotonic() - t_start
        logger.info(
            "[TIMING] _run_subprocess '%s' completed in %.2fs (rc=%d)",
            _cmd_label, t_elapsed, proc.returncode,
        )

        # Filter out non-fatal warnings from stderr that should not
        # be treated as errors.  These include:
        # 1. "Using passwords on command line is insecure" (Fix #10)
        # 2. "Unknown parameter encountered: \"tmp dir\"" — ALT Linux
        #    samba-tool builds emit this when smb.conf contains a
        #    parameter not supported by the build (e.g. "tmp dir").
        #    The warning is harmless: samba-tool prints it but then
        #    says "Ignoring unknown parameter" and continues normally.
        #    Without filtering, these warnings pollute stderr and cause
        #    execute_samba_command to classify the output as a 400 error
        #    even when the command succeeded (rc=0) or when the real
        #    error is something entirely different.
        # Fix v12-1: Filter "Unknown parameter encountered" and
        # "Ignoring unknown parameter" from stderr.
        _NON_FATAL_STDERR_PATTERNS = (
            "Using passwords on command line",
            "Unknown parameter encountered",
            "Ignoring unknown parameter",
        )
        stderr_lines = proc.stderr.splitlines()
        filtered_stderr = "\n".join(
            line for line in stderr_lines
            if not any(pat in line for pat in _NON_FATAL_STDERR_PATTERNS)
        )
        return proc.returncode, proc.stdout, filtered_stderr
    except subprocess.TimeoutExpired:
        t_elapsed = time.monotonic() - t_start
        logger.error(
            "[TIMING] _run_subprocess '%s' TIMED OUT after %.2fs (limit=%ds): %s",
            _cmd_label, t_elapsed, timeout, " ".join(cmd),
        )
        return -1, "", f"Command timed out after {timeout} seconds"
    except FileNotFoundError:
        t_elapsed = time.monotonic() - t_start
        logger.error(
            "[TIMING] _run_subprocess '%s' FILE NOT FOUND after %.2fs: %s",
            _cmd_label, t_elapsed, cmd[0],
        )
        return -2, "", f"Executable not found: {cmd[0]}"
    except Exception as exc:  # pragma: no cover – unexpected failures
        t_elapsed = time.monotonic() - t_start
        logger.exception(
            "[TIMING] _run_subprocess '%s' UNEXPECTED ERROR after %.2fs: %s",
            _cmd_label, t_elapsed, exc,
        )
        return -3, "", str(exc)


class WorkerPool:
    """Thin wrapper around :class:`concurrent.futures.ProcessPoolExecutor`.

    Provides an async interface (:meth:`run_command`) that submits
    commands to the process pool and awaits results without blocking the
    event loop.
    """

    def __init__(self, max_workers: int = 4) -> None:
        self._executor = ProcessPoolExecutor(max_workers=max_workers)
        logger.info("WorkerPool initialised with %d workers", max_workers)

    async def run_command(
        self,
        cmd: list[str],
        timeout: int = 600,
    ) -> tuple[int, str, str]:
        """Submit *cmd* to the process pool and await the result.

        Parameters
        ----------
        cmd:
            Full command-line to execute.
        timeout:
            Per-process timeout in seconds.

        Returns
        -------
        tuple[int, str, str]
            ``(return_code, stdout, stderr)``
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            _run_subprocess,
            cmd,
            timeout,
        )

    def shutdown(self, wait: bool = True) -> None:
        """Gracefully shut down the process pool.

        Parameters
        ----------
        wait:
            If *True*, block until all running futures complete.
        """
        logger.info("Shutting down WorkerPool (wait=%s)", wait)
        self._executor.shutdown(wait=wait)


# ── Singleton helpers ──────────────────────────────────────────────────

def get_worker_pool() -> WorkerPool:
    """Return (and lazily create) the global :class:`WorkerPool` singleton."""
    global _pool
    if _pool is None:
        settings = get_settings()
        _pool = WorkerPool(max_workers=settings.WORKER_POOL_SIZE)
    return _pool


def shutdown_worker_pool(wait: bool = True) -> None:
    """Shut down the global worker pool if it was created."""
    global _pool
    if _pool is not None:
        _pool.shutdown(wait=wait)
        _pool = None
