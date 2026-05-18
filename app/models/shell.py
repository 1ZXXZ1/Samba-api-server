"""
Pydantic models for the Shell execution API.

Provides request/response schemas for executing bash and python3
commands with optional sudo privileges through the REST API.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── Request models ──────────────────────────────────────────────────────


class ShellExecRequest(BaseModel):
    """Request body for executing a shell command.

    Supports both ``bash`` and ``python3`` shells, with optional
    sudo elevation.  The ``cmd`` field contains the raw command
    string to be executed.

    Examples
    --------
    Bash command without sudo::

        {
            "shell": "bash",
            "sudo": false,
            "cmd": "ip a"
        }

    Python3 script with sudo::

        {
            "shell": "python3",
            "sudo": true,
            "cmd": "import os; print(os.listdir('/root'))"
        }
    """

    shell: str = Field(
        default="bash",
        description=(
            "Shell interpreter to use.  Must be one of: 'bash', 'python3'.  "
            "For 'bash', the command is passed as ``bash -c '<cmd>'``.  "
            "For 'python3', the command is passed as ``python3 -c '<cmd>'``."
        ),
    )
    sudo: bool = Field(
        default=False,
        description=(
            "Whether to run the command with ``sudo``.  When True, the "
            "command is prefixed with ``sudo``.  The API server process "
            "must have sudo privileges (NOPASSWD or the SAMBA_SUDO_PASSWORD "
            "environment variable must be set for password-based sudo)."
        ),
    )
    cmd: str = Field(
        ...,
        description=(
            "The raw command string to execute.  For bash, this is the "
            "script passed to ``bash -c``.  For python3, this is the "
            "Python code passed to ``python3 -c``."
        ),
    )
    timeout: int = Field(
        default=30,
        ge=1,
        le=600,
        description=(
            "Maximum execution time in seconds.  Commands exceeding this "
            "limit are killed and a timeout error is returned.  Default: 30s, "
            "maximum: 600s (10 minutes)."
        ),
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description=(
            "Optional environment variables to set before executing the "
            "command.  Keys are variable names, values are their string "
            "values.  These are merged with the inherited process environment."
        ),
    )

    @field_validator("shell", mode="before")
    @classmethod
    def _validate_shell(cls, v: str) -> str:
        """Normalise and validate the shell name."""
        v = v.strip().lower()
        allowed = {"bash", "python3"}
        if v not in allowed:
            raise ValueError(
                f"shell must be one of {allowed}, got '{v}'"
            )
        return v


class ShellScriptRequest(BaseModel):
    """Request body for executing a multi-line script.

    Unlike :class:`ShellExecRequest` which takes a single ``cmd`` string,
    this model accepts a ``lines`` list that is joined with newlines before
    execution.  This is more convenient for multi-line scripts.
    """

    shell: str = Field(
        default="bash",
        description="Shell interpreter: 'bash' or 'python3'.",
    )
    sudo: bool = Field(
        default=False,
        description="Whether to run with sudo.",
    )
    lines: List[str] = Field(
        ...,
        min_length=1,
        description=(
            "Script lines to execute.  Lines are joined with ``\\n`` "
            "and passed to the shell interpreter."
        ),
    )
    timeout: int = Field(
        default=60,
        ge=1,
        le=600,
        description="Maximum execution time in seconds.  Default: 60s.",
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional environment variables.",
    )

    @field_validator("shell", mode="before")
    @classmethod
    def _validate_shell(cls, v: str) -> str:
        """Normalise and validate the shell name."""
        v = v.strip().lower()
        allowed = {"bash", "python3"}
        if v not in allowed:
            raise ValueError(
                f"shell must be one of {allowed}, got '{v}'"
            )
        return v


# ── Response models ─────────────────────────────────────────────────────


class ShellExecResult(BaseModel):
    """Result of a shell command execution."""

    stdout: str = Field(
        default="",
        description="Standard output from the command.",
    )
    stderr: str = Field(
        default="",
        description="Standard error from the command.",
    )
    returncode: int = Field(
        default=0,
        description="Exit code of the process.  0 means success.",
    )
    timed_out: bool = Field(
        default=False,
        description="Whether the command exceeded the timeout limit.",
    )


class ShellExecResponse(BaseModel):
    """Full API response wrapping a shell execution result.

    Includes metadata about how the command was executed (shell type,
    sudo mode, the original command) and the execution result.
    """

    status: str = Field(
        default="ok",
        description="One of 'ok' or 'error'.",
    )
    message: str = Field(
        default="",
        description="Human-readable summary of the result.",
    )
    shell: str = Field(
        description="Shell interpreter that was used ('bash' or 'python3').",
    )
    sudo: bool = Field(
        description="Whether sudo was applied.",
    )
    cmd: str = Field(
        description="The original command string that was executed.",
    )
    data: ShellExecResult = Field(
        description="Execution result including stdout, stderr, and return code.",
    )


class ShellListResponse(BaseModel):
    """Response listing available shells and their status."""

    status: str = "ok"
    message: str = ""
    shells: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of available shell interpreters with metadata.",
    )


# v1.6.4: File-based script execution


class ShellScriptFileRequest(BaseModel):
    """Request body for executing a script from an uploaded file.

    v1.6.4: New model — supports uploading a script file and executing it,
    with optional auto-cleanup of the temporary workspace.
    """

    shell: str = Field(
        default="bash",
        description="Shell interpreter: 'bash' or 'python3'.",
    )
    sudo: bool = Field(
        default=False,
        description="Whether to run with sudo.",
    )
    timeout: int = Field(
        default=60,
        ge=1,
        le=600,
        description="Maximum execution time in seconds.  Default: 60s.",
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional environment variables.",
    )
    auto_delete: bool = Field(
        default=True,
        description=(
            "Automatically delete the temporary directory after execution. "
            "Default: True. Set to False to keep the file for inspection."
        ),
    )
    run_args: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional arguments to pass to the script. "
            "Example: ['--force', '--verbose']"
        ),
    )

    @field_validator("shell", mode="before")
    @classmethod
    def _validate_shell(cls, v: str) -> str:
        """Normalise and validate the shell name."""
        v = v.strip().lower()
        allowed = {"bash", "python3"}
        if v not in allowed:
            raise ValueError(
                f"shell must be one of {allowed}, got '{v}'"
            )
        return v


class ShellScriptFileResponse(BaseModel):
    """Response for file-based script execution.

    v1.6.4: Includes info about the uploaded file and workspace.
    """

    status: str = Field(
        default="ok",
        description="One of 'ok' or 'error'.",
    )
    message: str = Field(
        default="",
        description="Human-readable summary of the result.",
    )
    shell: str = Field(
        description="Shell interpreter that was used.",
    )
    sudo: bool = Field(
        description="Whether sudo was applied.",
    )
    filename: str = Field(
        description="The uploaded script filename.",
    )
    data: ShellExecResult = Field(
        description="Execution result including stdout, stderr, and return code.",
    )
    workspace_path: Optional[str] = Field(
        default=None,
        description="Path to the temporary workspace (only if auto_delete=false).",
    )
    workspace_deleted: bool = Field(
        default=True,
        description="Whether the workspace was auto-deleted.",
    )
