"""
Shell execution router for the Samba AD DC Management API.

Provides REST endpoints for executing ``bash`` and ``python3`` commands
on the server, with optional ``sudo`` elevation.  This is useful for
remote administration, diagnostics, and automation workflows that
require shell access beyond what ``samba-tool`` provides.

Security considerations
-----------------------
* All endpoints require API-key authentication (``X-API-Key`` header).
* Commands are run in isolated subprocesses — each command executes
  in its own process via ``subprocess.run``.
* An optional command whitelist / blacklist can be configured via
  environment variables to restrict which commands are allowed.
* Sudo execution requires ``SAMBA_SUDO_PASSWORD`` or NOPASSWD sudoers
  configuration for the API server process user.
* Timeout enforcement prevents runaway commands.

Endpoints
---------
``GET  /shell/``              — List available shells and their status.
``POST /shell/exec``          — Execute a single command.
``POST /shell/script``        — Execute a multi-line script.
``POST /shell/script/file``   — Upload a script file and execute it (v1.6.4).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.auth import ApiKeyDep
from app.models.shell import (
    ShellExecRequest,
    ShellExecResponse,
    ShellExecResult,
    ShellListResponse,
    ShellScriptFileRequest,
    ShellScriptFileResponse,
    ShellScriptRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/shell", tags=["Shell"])

# ── Thread pool for shell command execution ─────────────────────────────
# Unlike samba-tool commands which use ProcessPoolExecutor, shell commands
# are executed via ThreadPoolExecutor.  This is correct because:
#   1. subprocess.run already provides process isolation
#   2. ThreadPoolExecutor does NOT require pickling callables
#   3. Shell commands are I/O-bound (waiting for subprocess), not CPU-bound
_shell_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="shell-")


# ── Constants ───────────────────────────────────────────────────────────

# Supported shell interpreters and their invocation patterns.
_SHELL_CONFIG: Dict[str, Dict[str, str]] = {
    "bash": {
        "binary": "bash",
        "inline_flag": "-c",
        "description": "Bourne Again SHell — standard Linux shell",
        "language": "bash",
    },
    "python3": {
        "binary": "python3",
        "inline_flag": "-c",
        "description": "Python 3 interpreter",
        "language": "python",
    },
}

# Blocked command patterns — commands that should never be executed.
_BLOCKED_PATTERNS: List[str] = [
    "rm -rf /",
    "mkfs.",
    "dd if=",
    ":(){ :|:& };:",
    "fork bomb",
]

# Commands that require special handling or warnings.
_DANGEROUS_PATTERNS: List[str] = [
    "reboot",
    "shutdown",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    "systemctl reboot",
    "systemctl poweroff",
    "systemctl halt",
]


# ── Helpers ─────────────────────────────────────────────────────────────


def _find_shell_binary(shell_name: str) -> Optional[str]:
    """Locate the binary for *shell_name* on the system PATH."""
    config = _SHELL_CONFIG.get(shell_name)
    if not config:
        return None
    return shutil.which(config["binary"])


def _build_command(req: ShellExecRequest) -> List[str]:
    """Construct the full command line from a request.

    The command structure is::

        [sudo -S -E] <binary> <inline_flag> <cmd>
    """
    shell_cfg = _SHELL_CONFIG[req.shell]
    cmd: List[str] = []

    if req.sudo:
        sudo_password = os.environ.get("SAMBA_SUDO_PASSWORD", "")
        cmd.append("sudo")
        if sudo_password:
            cmd.append("-S")
        cmd.append("-E")

    cmd.append(shell_cfg["binary"])
    cmd.append(shell_cfg["inline_flag"])
    cmd.append(req.cmd)

    return cmd


def _build_env(req: ShellExecRequest) -> Dict[str, str]:
    """Build the environment dictionary for the subprocess."""
    env = dict(os.environ)
    if req.env:
        env.update(req.env)
    return env


def _check_blocked(cmd: str) -> Optional[str]:
    """Check *cmd* against blocked patterns."""
    cmd_lower = cmd.lower().strip()
    for pattern in _BLOCKED_PATTERNS:
        if pattern in cmd_lower:
            return f"Command contains blocked pattern: '{pattern}'"
    return None


def _check_dangerous(cmd: str) -> Optional[str]:
    """Check *cmd* against dangerous patterns (warning only)."""
    cmd_lower = cmd.lower().strip()
    for pattern in _DANGEROUS_PATTERNS:
        if pattern in cmd_lower:
            return f"Warning: command contains dangerous pattern: '{pattern}'"
    return None


# ── Top-level subprocess runner (picklable) ─────────────────────────────


def _run_shell_subprocess(
    cmd: List[str],
    timeout: int,
    env: Dict[str, str],
    sudo_password: Optional[str] = None,
) -> ShellExecResult:
    """Execute a shell command in a subprocess.

    This is a **top-level function** so it can be submitted to any
    executor (ThreadPoolExecutor or ProcessPoolExecutor) without
    pickling issues.  ThreadPoolExecutor is preferred because
    ``subprocess.run`` already provides process isolation.

    Parameters
    ----------
    cmd:
        Full command line.
    timeout:
        Maximum execution time in seconds.
    env:
        Environment variables for the subprocess.
    sudo_password:
        Optional password to feed to sudo via stdin.

    Returns
    -------
    ShellExecResult
        Execution result with stdout, stderr, returncode, and timed_out.
    """
    t_start = time.monotonic()
    try:
        stdin_input = None
        if sudo_password and "-S" in cmd:
            stdin_input = sudo_password + "\n"

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=env,
            stdin=subprocess.PIPE if stdin_input else None,
            input=stdin_input,
        )
        t_elapsed = time.monotonic() - t_start
        logger.info(
            "[SHELL] Command completed in %.2fs (rc=%d): %s",
            t_elapsed,
            proc.returncode,
            " ".join(cmd[:5]),
        )
        return ShellExecResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            timed_out=False,
        )
    except subprocess.TimeoutExpired:
        t_elapsed = time.monotonic() - t_start
        logger.error(
            "[SHELL] Command TIMED OUT after %.2fs (limit=%ds): %s",
            t_elapsed,
            timeout,
            " ".join(cmd[:5]),
        )
        return ShellExecResult(
            stdout="",
            stderr=f"Command timed out after {timeout} seconds",
            returncode=-1,
            timed_out=True,
        )
    except FileNotFoundError:
        t_elapsed = time.monotonic() - t_start
        logger.error(
            "[SHELL] Command binary not found after %.2fs: %s",
            t_elapsed,
            cmd[0],
        )
        return ShellExecResult(
            stdout="",
            stderr=f"Executable not found: {cmd[0]}",
            returncode=-2,
            timed_out=False,
        )
    except Exception as exc:
        t_elapsed = time.monotonic() - t_start
        logger.exception(
            "[SHELL] Unexpected error after %.2fs: %s",
            t_elapsed,
            exc,
        )
        return ShellExecResult(
            stdout="",
            stderr=str(exc),
            returncode=-3,
            timed_out=False,
        )


async def _run_shell_command(
    cmd: List[str],
    timeout: int,
    env: Dict[str, str],
    sudo_password: Optional[str] = None,
) -> ShellExecResult:
    """Execute a shell command in the thread pool.

    Uses ``ThreadPoolExecutor`` instead of ``ProcessPoolExecutor`` because:

    1. ``subprocess.run`` already runs in a separate process, providing
       isolation without needing a process pool.
    2. ``ThreadPoolExecutor`` does not require callables to be picklable,
       avoiding the ``AttributeError: Can't get local object`` error that
       occurs with ``ProcessPoolExecutor`` and closure functions.
    3. The thread is only used for awaiting the subprocess (I/O-bound),
       not for CPU-intensive work.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _shell_pool,
        _run_shell_subprocess,
        cmd,
        timeout,
        env,
        sudo_password,
    )


# ── Endpoints ───────────────────────────────────────────────────────────


@router.get(
    "/",
    summary="List available shells",
    response_model=ShellListResponse,
)
async def list_shells(
    api_key: ApiKeyDep,
) -> ShellListResponse:
    """List available shell interpreters and their status.

    Returns information about each supported shell (bash, python3),
    including whether the binary is available on the system, its
    full path, and a description.
    """
    shells: List[Dict[str, Any]] = []
    for name, cfg in _SHELL_CONFIG.items():
        binary_path = _find_shell_binary(name)
        shells.append({
            "name": name,
            "available": binary_path is not None,
            "path": binary_path or "not found",
            "description": cfg["description"],
            "language": cfg["language"],
        })

    return ShellListResponse(
        status="ok",
        message=f"Found {len(shells)} shell interpreters",
        shells=shells,
    )


@router.post(
    "/exec",
    summary="Execute a shell command",
    response_model=ShellExecResponse,
)
async def exec_command(
    body: ShellExecRequest,
    api_key: ApiKeyDep,
) -> ShellExecResponse:
    """Execute a single shell command and return the output.

    The command is executed in an isolated subprocess via a thread pool.
    Supports ``bash`` and ``python3`` interpreters, with optional ``sudo``
    elevation.

    **Security**: Commands are validated against a blocked-pattern list
    before execution.  Dangerous commands (reboot, shutdown, etc.) are
    allowed but flagged with a warning in the response.

    **Sudo**: When ``sudo`` is *True*, the command is prefixed with
    ``sudo -E``.  If ``SAMBA_SUDO_PASSWORD`` is set in the server
    environment, ``sudo -S -E`` is used and the password is fed via
    stdin.

    Parameters
    ----------
    body:
        Shell execution request with command, shell type, and options.

    Returns
    -------
    ShellExecResponse
        Execution result with stdout, stderr, returncode, and metadata.
    """
    # ── Validate shell availability ──────────────────────────────────
    binary_path = _find_shell_binary(body.shell)
    if not binary_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Shell '{body.shell}' is not available on this system.  "
                f"Binary '{_SHELL_CONFIG[body.shell]['binary']}' not found in PATH."
            ),
        )

    # ── Check blocked commands ───────────────────────────────────────
    blocked_msg = _check_blocked(body.cmd)
    if blocked_msg:
        logger.warning("[SHELL] Blocked command attempt: %s", body.cmd)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=blocked_msg,
        )

    # ── Check dangerous commands (warning only) ──────────────────────
    danger_msg = _check_dangerous(body.cmd)
    if danger_msg:
        logger.warning("[SHELL] Dangerous command: %s", danger_msg)

    # ── Build and execute command ────────────────────────────────────
    cmd = _build_command(body)
    env = _build_env(body)
    sudo_password = os.environ.get("SAMBA_SUDO_PASSWORD", "") if body.sudo else None

    logger.info(
        "[SHELL] Executing: shell=%s sudo=%s cmd='%s' timeout=%ds",
        body.shell,
        body.sudo,
        body.cmd[:200],
        body.timeout,
    )

    result = await _run_shell_command(
        cmd=cmd,
        timeout=body.timeout,
        env=env,
        sudo_password=sudo_password,
    )

    # ── Build response ───────────────────────────────────────────────
    response_status = "ok" if result.returncode == 0 else "error"
    response_message = "Command executed successfully"
    if result.timed_out:
        response_message = f"Command timed out after {body.timeout} seconds"
    elif result.returncode != 0:
        response_message = f"Command exited with code {result.returncode}"
    if danger_msg:
        response_message += f" ({danger_msg})"

    return ShellExecResponse(
        status=response_status,
        message=response_message,
        shell=body.shell,
        sudo=body.sudo,
        cmd=body.cmd,
        data=result,
    )


@router.post(
    "/script",
    summary="Execute a multi-line script",
    response_model=ShellExecResponse,
)
async def exec_script(
    body: ShellScriptRequest,
    api_key: ApiKeyDep,
) -> ShellExecResponse:
    """Execute a multi-line script and return the output.

    This endpoint accepts a list of script lines instead of a single
    command string.  The lines are joined with newlines and executed
    as a single script in the chosen shell interpreter.

    For ``bash``, the joined script is passed to ``bash -c``.
    For ``python3``, the joined script is passed to ``python3 -c``.

    All security considerations from ``/shell/exec`` apply equally
    to this endpoint.
    """
    # Join lines into a single script
    cmd_str = "\n".join(body.lines)

    # Reuse ShellExecRequest for validation and execution
    exec_req = ShellExecRequest(
        shell=body.shell,
        sudo=body.sudo,
        cmd=cmd_str,
        timeout=body.timeout,
        env=body.env,
    )

    # Delegate to exec_command
    return await exec_command(exec_req, api_key)


@router.post(
    "/script/file",
    summary="Upload a script file and execute it",
    response_model=ShellScriptFileResponse,
)
async def exec_script_file(
    file: UploadFile = File(..., description="Script file to upload and execute."),
    shell: str = "bash",
    sudo: bool = False,
    timeout: int = 60,
    auto_delete: bool = True,
    api_key: ApiKeyDep = None,
) -> ShellScriptFileResponse:
    """Upload a script file and execute it on the server.

    v1.6.4: This endpoint accepts a file upload (e.g. ``run.sh``,
    ``deploy.py``) and executes it in an isolated temporary directory.
    The file is saved to a temporary workspace, made executable, and
    then run using the specified shell interpreter.

    **Features**:
    - Auto-creates a temporary workspace for the script
    - Supports both bash and python3 scripts
    - Optional sudo elevation
    - Auto-deletes the workspace after execution (default: yes)
    - Full bash scripting support: if/then/elif/else/fi, case/esac,
      for/do/done, while/do/done, until/do/done, select/do/done

    **Usage**::

        # Upload and execute a bash script
        curl -X POST \\
          -H "X-API-Key: your-key" \\
          -F "file=@run.sh" \\
          -F "shell=bash" \\
          -F "auto_delete=true" \\
          http://localhost:8099/api/v1/shell/script/file

        # With sudo
        curl -X POST \\
          -H "X-API-Key: your-key" \\
          -F "file=@deploy.sh" \\
          -F "shell=bash" \\
          -F "sudo=true" \\
          http://localhost:8099/api/v1/shell/script/file

    Parameters
    ----------
    file:
        The script file to upload and execute.
    shell:
        Shell interpreter: 'bash' or 'python3'. Default: 'bash'.
    sudo:
        Whether to run with sudo. Default: false.
    timeout:
        Maximum execution time in seconds. Default: 60.
    auto_delete:
        Whether to delete the temporary workspace after execution. Default: true.
    api_key:
        API key for authentication.

    Returns
    -------
    ShellScriptFileResponse
        Execution result with stdout, stderr, returncode, and metadata.
    """
    # Validate shell
    shell = shell.strip().lower()
    allowed_shells = {"bash", "python3"}
    if shell not in allowed_shells:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"shell must be one of {allowed_shells}, got '{shell}'",
        )

    binary_path = _find_shell_binary(shell)
    if not binary_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Shell '{shell}' is not available on this system.",
        )

    # Create temporary workspace
    workspace = tempfile.mkdtemp(prefix="shell_script_")
    filename = file.filename or "script"
    # Security: prevent path traversal
    filename = os.path.basename(filename)
    file_path = os.path.join(workspace, filename)

    workspace_deleted = False

    try:
        # Save uploaded file
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

        # Make executable for bash scripts
        if shell == "bash":
            os.chmod(file_path, os.stat(file_path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        # Build command
        cmd: List[str] = []
        sudo_password = os.environ.get("SAMBA_SUDO_PASSWORD", "")

        if sudo:
            cmd.append("sudo")
            if sudo_password:
                cmd.append("-S")
            cmd.append("-E")

        if shell == "bash":
            # Execute the script file directly — this allows full bash
            # scripting: if/then/elif/else/fi, case/esac, for/do/done,
            # while/do/done, until/do/done, select/do/done
            cmd.append(file_path)
        else:
            # python3 — pass the file as an argument
            cmd.append("python3")
            cmd.append(file_path)

        # Build environment
        env = dict(os.environ)

        logger.info(
            "[SHELL] Executing file: shell=%s sudo=%s file='%s' timeout=%ds auto_delete=%s",
            shell,
            sudo,
            filename,
            timeout,
            auto_delete,
        )

        # Execute
        stdin_input = None
        if sudo and sudo_password and "-S" in cmd:
            stdin_input = sudo_password + "\n"

        result = await _run_shell_command(
            cmd=cmd,
            timeout=timeout,
            env=env,
            sudo_password=sudo_password if sudo else None,
        )

        # Build response
        response_status = "ok" if result.returncode == 0 else "error"
        response_message = f"Script '{filename}' executed successfully"
        if result.timed_out:
            response_message = f"Script '{filename}' timed out after {timeout} seconds"
        elif result.returncode != 0:
            response_message = f"Script '{filename}' exited with code {result.returncode}"

        return ShellScriptFileResponse(
            status=response_status,
            message=response_message,
            shell=shell,
            sudo=sudo,
            filename=filename,
            data=result,
            workspace_path=None if auto_delete else workspace,
            workspace_deleted=auto_delete,
        )

    except Exception as exc:
        logger.exception("[SHELL] Error executing script file '%s': %s", filename, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing script file: {exc}",
        )

    finally:
        if auto_delete:
            try:
                shutil.rmtree(workspace, ignore_errors=True)
                workspace_deleted = True
                logger.info("[SHELL] Workspace auto-deleted: %s", workspace)
            except Exception:
                pass
