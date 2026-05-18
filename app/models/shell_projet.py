"""
Pydantic models for the Shell Project API.

Provides request/response schemas for project-based shell execution
with workspace management, file upload, archive extraction, and
real-time WebSocket output streaming.

v1.6.7-5: PostgreSQL migration (replaces SQLite):
    Migrated projet_db from SQLite to PostgreSQL for ALT Linux.
    New config: PG_HOST, PG_PORT, PG_DBNAME, PG_USER, PG_PASSWORD,
    PG_DSN, PG_POOL_MIN, PG_POOL_MAX.
    Health response now shows pg_* fields instead of db_path/db_size.

v1.6.7-4: Major overhaul (20+ improvements):
  P0 Bug Fixes: _running_processes, state machine, per-project locks,
    path traversal hardening.
  PostgreSQL Persistence: projet_db module replaces in-memory dict.
  Callback & Retry: urllib fallback, configurable TTL interval,
    exponential backoff.
  New Features: Scheduler/Cron, Templates, Shared Volumes,
    Resource Limits, Audit Log, Batch Ops, Snapshot/Rollback,
    Encrypted Env, Dry-Run, Dependency Chain.

v1.6.7-3: Tags/labels, TTL, disk logging, output limit, download .zip,
  health check, owner transfer, state machine, multi-upload,
  wait_for_completion, webhook, max projects, disk quota.

v1.6.5: New module — Shell Project execution with isolated workspaces.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── Request models ──────────────────────────────────────────────────────


class ShellProjetCreateRequest(BaseModel):
    """Request body for creating a new shell project workspace.

    A project workspace is an isolated directory at
    ``/home/AD-API-USER/{name}/{id}`` where scripts and files can be
    uploaded, extracted, and executed.

    The workspace can optionally be auto-deleted after execution completes.

    Examples
    --------
    Minimal — create workspace, upload zip later::

        {
            "name": "deploy-app",
            "auto_delete": true
        }

    Full — with archive, run command, tags, TTL, and callback::

        {
            "name": "deploy-app",
            "archive": "deploy.zip",
            "run_command": "./run.sh",
            "auto_delete": false,
            "timeout": 300,
            "env": {"APP_ENV": "production"},
            "tags": ["production", "v2.1"],
            "labels": {"team": "backend"},
            "ttl_seconds": 3600,
            "callback_url": "https://ci.example.com/hook",
            "wait_for_completion": false
        }
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description=(
            "Project name. Used as part of the workspace directory path: "
            "/home/AD-API-USER/{name}/{id}. Must be a valid directory name "
            "(alphanumeric, hyphens, underscores, dots)."
        ),
    )
    archive: Optional[str] = Field(
        default=None,
        description=(
            "Filename of the archive to extract in the workspace. "
            "Supported formats: .zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar, .gz, .7z. "
            "The file must be uploaded first via /shell/projet/upload or "
            "sent as multipart in the same request."
        ),
    )
    run_command: Optional[str] = Field(
        default=None,
        description=(
            "Command to execute inside the workspace after extraction. "
            "Examples: './run.sh', 'bash deploy.sh', 'python3 main.py'. "
            "The command runs with the workspace as CWD. "
            "If not provided, only workspace creation and archive extraction "
            "are performed."
        ),
    )
    run_args: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional arguments to pass to run_command. "
            "Example: ['--force', '--verbose']"
        ),
    )
    auto_delete: bool = Field(
        default=True,
        description=(
            "Automatically delete the workspace directory after execution "
            "completes (regardless of success or failure). "
            "Default: True — workspace is removed after the command finishes. "
            "Set to False to keep the workspace for later inspection via "
            "/shell/projet/show or /shell/projet/list."
        ),
    )
    sudo: bool = Field(
        default=False,
        description=(
            "Whether to run the command with sudo. When True, the command "
            "is prefixed with sudo -E (or sudo -S -E if SAMBA_SUDO_PASSWORD is set)."
        ),
    )
    timeout: int = Field(
        default=300,
        ge=1,
        le=3600,
        description=(
            "Maximum execution time in seconds. Commands exceeding this "
            "limit are killed and a timeout error is returned. "
            "Default: 300s (5 minutes), maximum: 3600s (1 hour)."
        ),
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description=(
            "Optional environment variables to set before executing "
            "the command. Merged with the inherited process environment."
        ),
    )
    owner: Optional[str] = Field(
        default=None,
        description=(
            "Optional owner label for the project. Used for access control "
            "and filtering in /shell/projet/list. If not set, defaults to "
            "the authenticated user."
        ),
    )
    permissions: Optional[str] = Field(
        default=None,
        description=(
            "Optional permissions for the workspace directory. "
            "Examples: '755', '700'. Default: '700' (owner-only)."
        ),
    )
    pre_commands: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of commands to execute BEFORE run_command. "
            "These run sequentially in the workspace directory. "
            "Example: ['chmod +x run.sh', 'pip install -r requirements.txt']"
        ),
    )
    post_commands: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of commands to execute AFTER run_command. "
            "These run sequentially in the workspace directory. "
            "Example: ['rm -f secrets.env', 'echo done > .completed']"
        ),
    )
    # ── v1.6.7-3: New fields ──────────────────────────────────────────
    tags: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional tags/labels for categorizing the project. "
            "Used for filtering in /shell/projet/list?tag=production. "
            "Example: ['production', 'v2.1']"
        ),
    )
    labels: Optional[Dict[str, str]] = Field(
        default=None,
        description=(
            "Optional key-value labels for the project. "
            "Example: {'team': 'backend', 'env': 'prod'}"
        ),
    )
    ttl_seconds: Optional[int] = Field(
        default=None,
        ge=1,
        description=(
            "Time-to-live in seconds. The project will be automatically "
            "deleted after this many seconds, even if auto_delete is false. "
            "Useful for preventing forgotten projects from consuming disk. "
            "Example: 3600 = delete after 1 hour."
        ),
    )
    callback_url: Optional[str] = Field(
        default=None,
        description=(
            "URL to receive a POST callback when execution completes. "
            "The callback body contains the full execution result: "
            "projet_id, returncode, stdout, stderr, elapsed, timed_out. "
            "Example: 'https://ci.example.com/hook'"
        ),
    )
    wait_for_completion: bool = Field(
        default=False,
        description=(
            "If True and run_command is specified, the create endpoint "
            "will wait for the command to finish and return the full "
            "execution result (like /run). If False (default), the "
            "command runs asynchronously and the response returns immediately."
        ),
    )
    # ── v1.6.7-4: New fields ──────────────────────────────────────────
    dry_run: bool = Field(
        default=False,
        description=(
            "If True, return what WOULD be executed without actually "
            "running the command. Useful for preview/validation."
        ),
    )
    volumes: Optional[List[str]] = Field(
        default=None,
        description=(
            "List of shared volume paths to symlink into the workspace. "
            "Example: ['/shared/data', '/opt/tools']. "
            "Paths are symlinked as /workspace/_volumes/<basename>."
        ),
    )
    resource_limits: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Resource limits for command execution. "
            "Keys: cpu_quota (seconds), max_memory_mb (MB), "
            "max_processes (count). Applied via ulimit. "
            "Example: {'cpu_quota': 60, 'max_memory_mb': 512, 'max_processes': 10}"
        ),
    )
    encrypted_env: Optional[Dict[str, str]] = Field(
        default=None,
        description=(
            "Environment variables stored encrypted in the database. "
            "Decrypted only at runtime. Never shown in API responses. "
            "Example: {'DB_PASSWORD': 's3cret', 'API_KEY': 'abc123'}"
        ),
    )
    depends_on: Optional[List[str]] = Field(
        default=None,
        description=(
            "List of projet_ids this project depends on. "
            "When running, waits for all dependencies to complete "
            "successfully before executing. "
            "Example: ['abc123', 'def456']"
        ),
    )
    template_id: Optional[str] = Field(
        default=None,
        description=(
            "If specified, create the project from this template ID. "
            "Template provides: archive, run_command, env, tags, labels, "
            "pre_commands, post_commands, resource_limits, volumes."
        ),
    )

    @field_validator("name", mode="before")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        """Validate project name is a safe directory name."""
        v = v.strip()
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', v):
            raise ValueError(
                f"Project name must contain only alphanumeric characters, "
                f"hyphens, underscores, and dots. Got: '{v}'"
            )
        # Prevent path traversal
        if '..' in v or v.startswith('.') or v.startswith('-'):
            raise ValueError(
                f"Project name cannot start with '.', '-', or contain '..'. Got: '{v}'"
            )
        return v

    @field_validator("permissions", mode="before")
    @classmethod
    def _validate_permissions(cls, v: Optional[str]) -> Optional[str]:
        """Validate Unix permissions format."""
        if v is None:
            return v
        import re
        if not re.match(r'^[0-7]{3,4}$', v):
            raise ValueError(
                f"Permissions must be a valid Unix octal mode (e.g. '755', '0700'). Got: '{v}'"
            )
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tags(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate tags: no empty strings, max length 64."""
        if v is None:
            return v
        import re
        result = []
        for tag in v:
            tag = tag.strip()
            if not tag:
                continue
            if len(tag) > 64:
                raise ValueError(f"Tag too long (max 64 chars): '{tag[:20]}...'")
            if not re.match(r'^[a-zA-Z0-9._-]+$', tag):
                raise ValueError(
                    f"Tag must contain only alphanumeric, hyphens, underscores, dots. Got: '{tag}'"
                )
            result.append(tag)
        return result

    @field_validator("callback_url", mode="before")
    @classmethod
    def _validate_callback_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate callback URL starts with http:// or https://."""
        if v is None:
            return v
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                f"callback_url must start with http:// or https://. Got: '{v}'"
            )
        return v


class ShellProjetRunRequest(BaseModel):
    """Request body for running a command in an existing project workspace.

    Used to execute additional commands in a project that was previously
    created with ``auto_delete=false``.
    """

    run_command: str = Field(
        ...,
        description=(
            "Command to execute inside the workspace. "
            "The command runs with the workspace as CWD."
        ),
    )
    run_args: Optional[List[str]] = Field(
        default=None,
        description="Optional arguments to pass to run_command.",
    )
    sudo: bool = Field(
        default=False,
        description="Whether to run with sudo.",
    )
    timeout: int = Field(
        default=300,
        ge=1,
        le=3600,
        description="Maximum execution time in seconds.",
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional environment variables.",
    )
    auto_delete: bool = Field(
        default=False,
        description=(
            "Delete the workspace after this command completes. "
            "Useful for cleanup after the final command in a sequence."
        ),
    )
    pre_commands: Optional[List[str]] = Field(
        default=None,
        description="Commands to execute BEFORE run_command.",
    )
    post_commands: Optional[List[str]] = Field(
        default=None,
        description="Commands to execute AFTER run_command.",
    )
    # ── v1.6.7-3: New fields ──────────────────────────────────────────
    callback_url: Optional[str] = Field(
        default=None,
        description=(
            "URL to receive a POST callback when this execution completes. "
            "Overrides the project-level callback_url if set."
        ),
    )
    # ── v1.6.7-4: New fields ──────────────────────────────────────────
    dry_run: bool = Field(
        default=False,
        description="If True, return what WOULD be executed without actually running.",
    )
    resource_limits: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Resource limits for this execution (overrides project-level).",
    )


class ShellProjetDeleteRequest(BaseModel):
    """Request body for deleting a project workspace."""

    force: bool = Field(
        default=False,
        description=(
            "Force deletion even if a command is currently running. "
            "Default: False — refuses to delete if a command is active."
        ),
    )


class ShellProjetOwnerChangeRequest(BaseModel):
    """Request body for changing project owner (v1.6.7-3 #14)."""

    new_owner: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="New owner for the project.",
    )


class ShellProjetTagsUpdateRequest(BaseModel):
    """Request body for updating project tags/labels (v1.6.7-3 #11)."""

    tags: Optional[List[str]] = Field(
        default=None,
        description="Replace project tags. Set to [] to clear all tags.",
    )
    labels: Optional[Dict[str, str]] = Field(
        default=None,
        description="Replace project labels. Set to {} to clear all labels.",
    )


# ── Response models ─────────────────────────────────────────────────────


class ShellProjetExecutionHistoryEntry(BaseModel):
    """Single execution history entry (v1.6.7-3 #6)."""

    command: str = Field(description="Command that was executed.")
    rc: int = Field(description="Return code of the command.")
    elapsed: float = Field(description="Execution time in seconds.")
    at: str = Field(description="ISO 8601 timestamp of execution.")
    timed_out: bool = Field(default=False, description="Whether the command timed out.")


class ShellProjetWorkspaceInfo(BaseModel):
    """Information about a project workspace."""

    projet_id: str = Field(description="Unique project identifier (UUID4).")
    name: str = Field(description="Project name.")
    workspace_path: str = Field(description="Absolute path to the workspace directory.")
    owner: str = Field(default="", description="Owner of the project.")
    status: str = Field(
        description="Current status: 'creating', 'ready', 'running', 'completed', 'failed', 'aborted', 'deleting'."
    )
    created_at: str = Field(default="", description="ISO 8601 creation timestamp.")
    completed_at: Optional[str] = Field(default=None, description="ISO 8601 completion timestamp.")
    auto_delete: bool = Field(default=True, description="Whether workspace will be auto-deleted.")
    archive: Optional[str] = Field(default=None, description="Archive filename that was extracted.")
    last_command: Optional[str] = Field(default=None, description="Last executed command.")
    last_returncode: Optional[int] = Field(default=None, description="Last command exit code.")
    directory_size: Optional[int] = Field(default=None, description="Workspace directory size in bytes.")
    file_count: Optional[int] = Field(default=None, description="Number of files in workspace.")
    # ── v1.6.7-3: New fields ──────────────────────────────────────────
    tags: Optional[List[str]] = Field(default=None, description="Project tags for filtering.")
    labels: Optional[Dict[str, str]] = Field(default=None, description="Project labels (key-value).")
    ttl_seconds: Optional[int] = Field(default=None, description="TTL in seconds (auto-delete timer).")
    ttl_expires_at: Optional[str] = Field(default=None, description="ISO 8601 when TTL expires.")
    execution_history: Optional[List[ShellProjetExecutionHistoryEntry]] = Field(
        default=None,
        description="List of executed commands with results.",
    )
    callback_url: Optional[str] = Field(default=None, description="Webhook URL for execution callbacks.")
    # ── v1.6.7-4: New fields ──────────────────────────────────────────
    volumes: Optional[List[str]] = Field(default=None, description="Shared volume paths symlinked into workspace.")
    resource_limits: Optional[Dict[str, Any]] = Field(default=None, description="Resource limits for command execution.")
    depends_on: Optional[List[str]] = Field(default=None, description="Project IDs this project depends on.")
    template_id: Optional[str] = Field(default=None, description="Template ID used to create this project.")


class ShellProjetCreateResponse(BaseModel):
    """Response for project creation."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Unique project identifier.")
    name: str = Field(description="Project name.")
    workspace_path: str = Field(description="Absolute path to the workspace.")
    auto_delete: bool = Field(default=True)
    ws_url: Optional[str] = Field(
        default=None,
        description=(
            "WebSocket URL for real-time output streaming. "
            "Connect to this URL to receive stdout/stderr output "
            "as the command executes. "
            "Format: ws://<host>/ws/projet/{projet_id}"
        ),
    )
    # ── v1.6.7-3: wait_for_completion result ──────────────────────────
    run_result: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "When wait_for_completion=True, contains the full execution "
            "result: returncode, stdout, stderr, timed_out, elapsed, "
            "workspace_deleted."
        ),
    )
    # ── v1.6.7-4: dry_run result ─────────────────────────────────────
    dry_run_result: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "When dry_run=True, contains what WOULD be executed: "
            "command, workspace, env, resource_limits, etc."
        ),
    )


class ShellProjetRunResponse(BaseModel):
    """Response for project command execution (REST — final result)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    run_command: str = Field(description="Command that was executed.")
    returncode: int = Field(default=0, description="Exit code of the command.")
    stdout: str = Field(default="", description="Standard output.")
    stderr: str = Field(default="", description="Standard error.")
    timed_out: bool = Field(default=False, description="Whether the command timed out.")
    elapsed: float = Field(default=0.0, description="Execution time in seconds.")
    workspace_deleted: bool = Field(
        default=False,
        description="Whether the workspace was auto-deleted after execution.",
    )
    # ── v1.6.7-3: output truncation info ──────────────────────────────
    output_truncated: bool = Field(
        default=False,
        description="Whether stdout/stderr were truncated due to size limit.",
    )
    output_total_bytes: Optional[int] = Field(
        default=None,
        description="Total output bytes before truncation (if truncated).",
    )
    # ── v1.6.7-4: dry_run result ─────────────────────────────────────
    dry_run_result: Optional[Dict[str, Any]] = Field(
        default=None,
        description="When dry_run=True, preview of what would execute.",
    )


class ShellProjetShowResponse(BaseModel):
    """Response for project details."""

    status: str = Field(default="ok")
    projet_id: str = Field(description="Project identifier.")
    workspace: ShellProjetWorkspaceInfo = Field(description="Workspace information.")
    files: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of files in the workspace with metadata.",
    )
    # ── v1.6.7-3: disk log availability ───────────────────────────────
    logs_available: bool = Field(
        default=False,
        description="Whether disk logs (.projet_logs/) exist for this project.",
    )


class ShellProjetListResponse(BaseModel):
    """Response for listing projects."""

    status: str = Field(default="ok")
    count: int = Field(default=0, description="Total number of projects.")
    projects: List[ShellProjetWorkspaceInfo] = Field(
        default_factory=list,
        description="List of project workspaces.",
    )


class ShellProjetDeleteResponse(BaseModel):
    """Response for project deletion."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier that was deleted.")
    workspace_path: str = Field(description="Path that was removed.")


class ShellProjetUploadResponse(BaseModel):
    """Response for file upload to a project workspace."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    filename: str = Field(description="Uploaded filename.")
    size: int = Field(default=0, description="File size in bytes.")
    extracted: bool = Field(
        default=False,
        description="Whether the file was auto-extracted (for archives).",
    )
    extracted_files: Optional[List[str]] = Field(
        default=None,
        description="List of extracted files (if archive was auto-extracted).",
    )


class ShellProjetMultiUploadResponse(BaseModel):
    """Response for multi-file upload (v1.6.7-3 #7)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    uploaded_files: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of uploaded file results: {filename, size, extracted, extracted_files}.",
    )
    total_size: int = Field(default=0, description="Total bytes uploaded.")


# v1.6.5: Abort response model


class ShellProjetAbortResponse(BaseModel):
    """Response for aborting a running project command.

    v1.6.5: New model — abort a running command in a project workspace.
    """

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    aborted: bool = Field(
        default=False,
        description="Whether the command was successfully aborted.",
    )


# ── v1.6.7-3: New response models ──────────────────────────────────────


class ShellProjetHealthResponse(BaseModel):
    """Response for projet system health check (v1.6.7-3 #13)."""

    status: str = Field(default="ok")
    total_projects: int = Field(description="Total number of registered projects.")
    running: int = Field(description="Number of projects currently running.")
    ready: int = Field(description="Number of projects in ready state.")
    completed: int = Field(description="Number of completed projects.")
    failed: int = Field(description="Number of failed projects.")
    disk_usage_mb: float = Field(default=0.0, description="Total disk usage in MB.")
    pool_active: int = Field(description="Active threads in execution pool.")
    pool_max: int = Field(description="Maximum threads in execution pool.")
    max_projects: int = Field(description="Configured max projects limit.")
    max_workspace_size_mb: int = Field(description="Configured max workspace size in MB.")
    max_output_size_mb: float = Field(description="Configured max output size in MB.")
    # v1.6.7-5: PostgreSQL health fields (replaces SQLite)
    pg_host: Optional[str] = Field(default=None, description="PostgreSQL server host.")
    pg_port: Optional[int] = Field(default=None, description="PostgreSQL server port.")
    pg_dbname: Optional[str] = Field(default=None, description="PostgreSQL database name.")
    pg_pool_min: Optional[int] = Field(default=None, description="Min pool connections.")
    pg_pool_max: Optional[int] = Field(default=None, description="Max pool connections.")
    pg_connected: Optional[bool] = Field(default=None, description="Whether PostgreSQL connection is alive.")
    orphan_workspaces: Optional[int] = Field(default=None, description="Number of orphan workspaces on disk.")


class ShellProjetOwnerChangeResponse(BaseModel):
    """Response for owner change (v1.6.7-3 #14)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    old_owner: str = Field(description="Previous owner.")
    new_owner: str = Field(description="New owner.")


class ShellProjetTagsUpdateResponse(BaseModel):
    """Response for tags/labels update (v1.6.7-3 #11)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    tags: Optional[List[str]] = Field(default=None, description="Updated tags.")
    labels: Optional[Dict[str, str]] = Field(default=None, description="Updated labels.")


# ── v1.6.7-4: New request/response models ──────────────────────────────


class ShellProjetScheduleRequest(BaseModel):
    """Request body for creating a cron schedule (v1.6.7-4)."""

    cron_expr: str = Field(
        ...,
        description=(
            "Cron expression for scheduling. "
            "Format: 'minute hour day month weekday'. "
            "Examples: '*/5 * * * *' (every 5 min), "
            "'0 2 * * *' (daily at 2am), "
            "'30 */6 * * *' (every 6 hours at :30)."
        ),
    )
    run_command: str = Field(
        ...,
        description="Command to execute on schedule.",
    )
    enabled: bool = Field(
        default=True,
        description="Whether the schedule is active.",
    )


class ShellProjetScheduleResponse(BaseModel):
    """Response for schedule operations (v1.6.7-4)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    schedule_id: Optional[int] = Field(default=None, description="Schedule entry ID.")
    cron_expr: Optional[str] = Field(default=None, description="Cron expression.")
    run_command: Optional[str] = Field(default=None, description="Scheduled command.")
    enabled: Optional[bool] = Field(default=None, description="Whether schedule is active.")
    schedules: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of schedules (for GET response).",
    )


class ShellProjetTemplateCreateRequest(BaseModel):
    """Request body for creating a project template (v1.6.7-4)."""

    template_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique template identifier.",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Human-readable template name.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Template description.",
    )
    archive_path: Optional[str] = Field(
        default=None,
        description="Path to archive file to use as template workspace.",
    )
    run_command: Optional[str] = Field(
        default=None,
        description="Default command to execute.",
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Default environment variables.",
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description="Default tags.",
    )
    labels: Optional[Dict[str, str]] = Field(
        default=None,
        description="Default labels.",
    )
    pre_commands: Optional[List[str]] = Field(
        default=None,
        description="Default pre-commands.",
    )
    post_commands: Optional[List[str]] = Field(
        default=None,
        description="Default post-commands.",
    )
    resource_limits: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Default resource limits.",
    )
    volumes: Optional[List[str]] = Field(
        default=None,
        description="Default shared volumes.",
    )


class ShellProjetTemplateResponse(BaseModel):
    """Response for template operations (v1.6.7-4)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    template_id: Optional[str] = Field(default=None)
    template: Optional[Dict[str, Any]] = Field(default=None)
    templates: Optional[List[Dict[str, Any]]] = Field(default=None)


class ShellProjetSnapshotResponse(BaseModel):
    """Response for snapshot operations (v1.6.7-4)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    projet_id: str = Field(description="Project identifier.")
    snapshot_id: Optional[str] = Field(default=None, description="Snapshot identifier.")
    snapshots: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of snapshots (for list response).",
    )


class ShellProjetBatchRequest(BaseModel):
    """Request body for batch project operations (v1.6.7-4)."""

    action: str = Field(
        ...,
        description=(
            "Batch action to perform. "
            "Options: 'create_multiple', 'run_all', 'delete_completed', "
            "'delete_failed', 'delete_all'."
        ),
    )
    params: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Parameters for the batch action. "
            "create_multiple: {count: N, name_prefix: 'batch', ...}. "
            "run_all: {run_command: '...', status_filter: 'ready'}. "
            "delete_completed/delete_failed/delete_all: no params needed."
        ),
    )


class ShellProjetBatchResponse(BaseModel):
    """Response for batch project operations (v1.6.7-4)."""

    status: str = Field(default="ok")
    message: str = Field(default="")
    action: str = Field(description="Batch action performed.")
    total: int = Field(default=0, description="Total items processed.")
    succeeded: int = Field(default=0, description="Items that succeeded.")
    failed: int = Field(default=0, description="Items that failed.")
    details: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Per-item results.",
    )


class ShellProjetAuditResponse(BaseModel):
    """Response for audit log (v1.6.7-4)."""

    status: str = Field(default="ok")
    count: int = Field(default=0, description="Number of audit entries.")
    entries: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Audit log entries.",
    )
