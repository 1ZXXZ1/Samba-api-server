"""
Shell Project execution router for the Samba AD DC Management API.

Provides REST + WebSocket endpoints for project-based shell execution
with isolated workspaces, file upload, archive extraction, and
real-time output streaming.

v1.6.7-7: ForeignKeyViolation fix:
    #1  audit_log() is now called BEFORE delete_project() in all 4 places
        (auto_delete, ttl_expired, delete_projet, batch_delete). Previously
        the FK constraint on audit_log.projet_id → projects.projet_id caused
        psycopg2.errors.ForeignKeyViolation because the parent row was already
        gone when the audit INSERT was attempted.
    #2  projet_db.init_db() now migrates existing audit_log FK constraints
        to ON DELETE SET NULL, so older databases are also fixed.

v1.6.8-2: Ctrl+C / shutdown fix:
    #1  Removed atexit.register + signal.signal(SIGTERM/SIGINT) — these
        caused shutdown to fire 7+ times because atexit, SIGTERM, and SIGINT
        all triggered _graceful_shutdown independently. Now the shutdown
        is called ONLY from the FastAPI lifespan context in main.py, so it
        runs exactly ONCE on Ctrl+C.
    #2  Replaced bare bool _shutdown_done guard with threading.Lock for
        thread-safe one-shot protection.
    #3  Renamed _graceful_shutdown → graceful_shutdown_projet (public)
        so main.py can import and call it from lifespan shutdown.
    #4  run.sh fixes: DB init checks if DB already exists (skips CREATE
        USER/DB if present), password prompt only once via sudo cache.

v1.6.7-6: Critical PostgreSQL fixes:
    #1  DSN construction bug — replaced string-based DSN with keyword
        arguments to psycopg2, fixing "invalid dsn: missing = after #"
        error caused by special characters in passwords.
    #2  (Replaced by v1.6.8-2 #1-#3 — shutdown now uses lifespan)
    #3  PostgreSQL pool not closed on shutdown — added projet_db.close_db()
        call in graceful_shutdown_projet().
    #4  run.sh DB_* env vars ignored — _init_projet_db() now falls back
        to DB_PASSWORD, DB_USER, DB_NAME, DB_HOST, DB_PORT from run.sh.
    #5  run.sh now exports SAMBA_SHELL_PROJET_PG_* env vars AND uses
        sudo -E to preserve environment variables.
    #6  psycopg2-binary and cryptography added to requirements.txt.
    #7  .env SAMBA_SHELL_PROJET_PG_PASSWORD now defaults to "12345"
        (matching run.sh DB_PASSWORD).

v1.6.7-5: PostgreSQL migration (replaces SQLite):
    Migrated from SQLite to PostgreSQL for ALT Linux compatibility.
    Uses psycopg2 with ThreadedConnectionPool.
    New config: SHELL_PROJET_PG_HOST, PG_PORT, PG_DBNAME, PG_USER,
    PG_PASSWORD, PG_DSN, PG_POOL_MIN, PG_POOL_MAX.
    Removed: SHELL_PROJET_DB_PATH (was SQLite-only).
    All other v1.6.7-4 features preserved unchanged.

v1.6.7-4: Major overhaul (20+ improvements):
  P0 Bug Fixes:
    #1  _running_processes declared at module level — track Popen objects,
        clean up in _graceful_shutdown and on command completion.
    #2  State machine bypass removed — ALL status changes go through
        set_status(); force-assignments eliminated.
    #3  Per-project asyncio.Lock — _project_locks dict ensures serial
        mutations per project.
    #4  Path traversal hardening — _extract_archive REJECTS entire archive
        if any dangerous member is found.

  PostgreSQL Persistence (via app.services.projet_db):
    #5  Replace _projects in-memory dict with PostgreSQL-backed storage.
    #6  On every project mutation, call projet_db.save_project().
    #7  On startup (module load), call projet_db.load_all_projects().
    #8  Orphan recovery — scan base dir for workspaces not in DB, re-link.

  Callback & Retry:
    #9  Replace aiohttp with urllib.request stdlib fallback.
    #10 Configurable TTL cleanup interval.
    #11 Retry with exponential backoff for callback_url.

  New Features:
    #12 Scheduler/Cron — POST/GET/DELETE /{id}/schedule endpoints.
    #13 Project Templates — POST /template, POST /from-template/{id}.
    #14 Shared Workspaces/Volumes — volumes field, symlink shared dirs.
    #15 Resource Limits — cpu_quota, max_memory_mb, max_processes via ulimit.
    #16 Audit Log — all actions logged; GET /{id}/audit and GET /audit.
    #17 Batch Project Operations — POST /batch.
    #18 Snapshot/Rollback — POST /{id}/snapshot, POST /{id}/rollback/{snap_id}.
    #19 Environment Variables Encryption — Fernet-encrypted in DB.
    #20 Dry-Run Mode — dry_run flag in create/run.
    #21 Dependency Chain — depends_on field; waits for deps to complete.

  Config additions (v1.6.7-5 PostgreSQL):
    SHELL_PROJET_PG_HOST (default localhost)
    SHELL_PROJET_PG_PORT (default 5432)
    SHELL_PROJET_PG_DBNAME (default samba_api)
    SHELL_PROJET_PG_USER (default samba_api)
    SHELL_PROJET_PG_PASSWORD (default "")
    SHELL_PROJET_PG_DSN (default "" — overrides individual params)
    SHELL_PROJET_PG_POOL_MIN (default 2)
    SHELL_PROJET_PG_POOL_MAX (default 10)

  Other Fixes:
    Fix Prometheus _start_time — set it in middleware / store before dispatch.
    Fix cache key — include role info in cache key.

v1.6.7-3: Major feature additions (15 improvements):
  Critical (reliability):
    #1  Disk logging — stdout.log, stderr.log, meta.json in .projet_logs/
    #2  Graceful shutdown — atexit/signal handler for cleanup
    #3  Output limit — OOM protection (MAX_OUTPUT_SIZE, default 5MB)
  Important (functionality):
    #4  Download workspace as .zip — GET /{id}/download
    #5  TTL project — auto-delete by timer with background task
    #6  Execution history — per-project command history
    #7  Multi-file upload — multiple files in one request
    #8  Synchronous mode — wait_for_completion in create
  UX/Security:
    #9  Max projects limit enforcement
    #10 Disk quota per project — MAX_WORKSPACE_SIZE
    #11 Tags/labels — categorize and filter projects
    #12 Webhook/callback — POST on execution completion
    #13 Health check — GET /shell/projet/health
    #14 Owner transfer — PATCH /{id}/owner
    #15 State machine — transition validation

Endpoints
---------
``POST   /shell/projet``              — Create project + optional archive + command.
``POST   /shell/projet/{id}/upload``   — Upload file(s)/archive to workspace.
``POST   /shell/projet/{id}/run``      — Run command in existing workspace.
``GET    /shell/projet/{id}``          — Show project details (alias: /show/{id}).
``GET    /shell/projet/show/{id}``     — Show project details.
``GET    /shell/projet/list``          — List all projects (filter by tag/owner/status).
``GET    /shell/projet/{id}/download`` — Download workspace as .zip.
``GET    /shell/projet/health``        — Health check for projet system.
``PATCH  /shell/projet/{id}/owner``    — Transfer project ownership.
``PATCH  /shell/projet/{id}/tags``     — Update project tags/labels.
``DELETE /shell/projet/{id}``          — Delete project workspace.
``POST   /shell/projet/{id}/abort``    — Abort running command (v1.6.5).
``POST   /shell/projet/{id}/schedule`` — Create cron schedule (v1.6.7-4).
``GET    /shell/projet/{id}/schedule`` — List schedules (v1.6.7-4).
``DELETE /shell/projet/{id}/schedule/{schedule_id}`` — Delete schedule (v1.6.7-4).
``POST   /shell/projet/template``      — Create template (v1.6.7-4).
``POST   /shell/projet/from-template/{template_id}`` — Create from template (v1.6.7-4).
``GET    /shell/projet/templates``     — List templates (v1.6.7-4).
``DELETE /shell/projet/template/{template_id}`` — Delete template (v1.6.7-4).
``POST   /shell/projet/{id}/snapshot`` — Create workspace snapshot (v1.6.7-4).
``POST   /shell/projet/{id}/rollback/{snapshot_id}`` — Rollback to snapshot (v1.6.7-4).
``GET    /shell/projet/{id}/audit``    — Get project audit log (v1.6.7-4).
``GET    /shell/projet/audit``         — Get global audit log (v1.6.7-4).
``POST   /shell/projet/batch``         — Batch project operations (v1.6.7-4).
``WS     /ws/projet/{id}``             — Real-time output stream for project.
``WS     /ws/projet``                  — Global project events stream.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse

from app.auth import ApiKeyDep
from app.config import get_settings
from app.models.shell_projet import (
    ShellProjetCreateRequest,
    ShellProjetCreateResponse,
    ShellProjetDeleteResponse,
    ShellProjetHealthResponse,
    ShellProjetListResponse,
    ShellProjetMultiUploadResponse,
    ShellProjetOwnerChangeRequest,
    ShellProjetOwnerChangeResponse,
    ShellProjetRunRequest,
    ShellProjetRunResponse,
    ShellProjetShowResponse,
    ShellProjetTagsUpdateRequest,
    ShellProjetTagsUpdateResponse,
    ShellProjetUploadResponse,
    ShellProjetWorkspaceInfo,
    ShellProjetAbortResponse,
    # v1.6.7-4: New models
    ShellProjetScheduleRequest,
    ShellProjetScheduleResponse,
    ShellProjetTemplateCreateRequest,
    ShellProjetTemplateResponse,
    ShellProjetSnapshotResponse,
    ShellProjetBatchRequest,
    ShellProjetBatchResponse,
    ShellProjetAuditResponse,
)
from app.services import projet_db
from app.shell_projet_ws import get_projet_ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/shell/projet", tags=["Shell Project"])

# ── Thread pool for project command execution ─────────────────────────
_settings = get_settings()
_projet_pool = ThreadPoolExecutor(
    max_workers=getattr(_settings, 'SHELL_PROJET_POOL_SIZE', 8),
    thread_name_prefix="projet-",
)

# ── Base directory for project workspaces ──────────────────────────────
_BASE_DIR = Path(_settings.SHELL_PROJET_BASE_DIR)

# ── Supported archive extensions ──────────────────────────────────────
_ARCHIVE_EXTENSIONS = {
    ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
    ".tar", ".gz", ".7z",
}

# ── v1.6.7-3 #3: Output size limit (OOM protection) ──────────────────
_MAX_OUTPUT_SIZE = getattr(_settings, 'SHELL_PROJET_MAX_OUTPUT_SIZE', 5 * 1024 * 1024)

# ── v1.6.7-3 #9: Max projects limit ──────────────────────────────────
_MAX_PROJECTS = getattr(_settings, 'SHELL_PROJET_MAX_PROJECTS', 100)

# ── v1.6.7-3 #10: Max workspace size ─────────────────────────────────
_MAX_WORKSPACE_SIZE = getattr(_settings, 'SHELL_PROJET_MAX_WORKSPACE_SIZE', 500) * 1024 * 1024

# ── v1.6.7-4: New config values ───────────────────────────────────────
_TTL_CLEANUP_INTERVAL = getattr(_settings, 'SHELL_PROJET_TTL_CLEANUP_INTERVAL', 30)
_PG_HOST = getattr(_settings, 'SHELL_PROJET_PG_HOST', 'localhost')
_PG_PORT = getattr(_settings, 'SHELL_PROJET_PG_PORT', 5432)
_PG_DBNAME = getattr(_settings, 'SHELL_PROJET_PG_DBNAME', 'samba_api')
_PG_USER = getattr(_settings, 'SHELL_PROJET_PG_USER', 'samba_api')
_PG_PASSWORD = getattr(_settings, 'SHELL_PROJET_PG_PASSWORD', '')
_PG_DSN = getattr(_settings, 'SHELL_PROJET_PG_DSN', '')
_PG_POOL_MIN = getattr(_settings, 'SHELL_PROJET_PG_POOL_MIN', 2)
_PG_POOL_MAX = getattr(_settings, 'SHELL_PROJET_PG_POOL_MAX', 10)
_CALLBACK_MAX_RETRIES = getattr(_settings, 'SHELL_PROJET_CALLBACK_MAX_RETRIES', 3)
_SHARED_VOLUMES_DIR = Path(getattr(_settings, 'SHELL_PROJET_SHARED_VOLUMES_DIR', '/home/AD-API-USER/_shared'))

# ── v1.6.7-4 #1: Running processes tracker (module-level) ────────────
_running_processes: Dict[str, subprocess.Popen] = {}

# ── v1.6.7-4 #3: Per-project asyncio locks ───────────────────────────
_project_locks: Dict[str, asyncio.Lock] = {}

# ── v1.6.7-3 #15: Valid state transitions ─────────────────────────────
_VALID_TRANSITIONS: Dict[str, set] = {
    "creating":  {"ready"},
    "ready":     {"running", "deleting", "deleted"},
    "running":   {"completed", "failed", "aborted", "deleting"},
    "completed": {"running", "deleting", "deleted"},
    "failed":    {"running", "deleting", "deleted"},
    "aborted":   {"running", "deleting", "deleted"},
    "deleting":  {"deleted"},
    "deleted":   set(),
}

# ── v1.6.7-5: In-memory project registry (backed by PostgreSQL) ──────
_projects: Dict[str, "ProjetRecord"] = {}

# ── v1.6.7-4 #19: Encryption (Fernet) ────────────────────────────────
_encryption_key: Optional[bytes] = None
_fernet_cipher = None


def _init_encryption() -> None:
    """Initialize Fernet cipher for encrypted_env storage."""
    global _encryption_key, _fernet_cipher
    try:
        from cryptography.fernet import Fernet
        raw_key = getattr(_settings, 'SHELL_PROJET_ENCRYPTION_KEY', '')
        if raw_key:
            # Ensure it's a valid 32-byte base64 key
            _encryption_key = raw_key.encode("utf-8")
        else:
            # Auto-generate a key and store it
            _encryption_key = Fernet.generate_key()
        _fernet_cipher = Fernet(_encryption_key)
        logger.info("[PROJET] Encryption initialized (key %s)",
                    "provided" if raw_key else "auto-generated")
    except ImportError:
        logger.warning("[PROJET] cryptography package not available, "
                       "encrypted_env will be stored as plaintext")
        _fernet_cipher = None
    except Exception as exc:
        logger.error("[PROJET] Failed to initialize encryption: %s", exc)
        _fernet_cipher = None


def _encrypt_value(plaintext: str) -> str:
    """Encrypt a string value using Fernet. Returns base64-encoded ciphertext."""
    if _fernet_cipher is None:
        return base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
    return _fernet_cipher.encrypt(plaintext.encode("utf-8")).decode("ascii")


def _decrypt_value(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string. Returns plaintext."""
    if _fernet_cipher is None:
        try:
            return base64.b64decode(ciphertext.encode("ascii")).decode("utf-8")
        except Exception:
            return ciphertext
    return _fernet_cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


def _encrypt_env(env: Dict[str, str]) -> Dict[str, str]:
    """Encrypt all values in an env dict."""
    return {k: _encrypt_value(v) for k, v in env.items()}


def _decrypt_env(encrypted_env: Dict[str, str]) -> Dict[str, str]:
    """Decrypt all values in an encrypted env dict."""
    return {k: _decrypt_value(v) for k, v in encrypted_env.items()}


# ── v1.6.7-4 #3: Per-project lock helper ─────────────────────────────


def _get_project_lock(projet_id: str) -> asyncio.Lock:
    """Get or create an asyncio.Lock for a specific project."""
    if projet_id not in _project_locks:
        _project_locks[projet_id] = asyncio.Lock()
    return _project_locks[projet_id]


# ── v1.6.7-4: Prometheus _start_time fix ─────────────────────────────
_prometheus_start_time: float = time.monotonic()


def _get_prometheus_start_time() -> float:
    """Return the module-level start time for Prometheus metrics."""
    return _prometheus_start_time


# ── v1.6.7-4: Cache key fix — include role info ──────────────────────


def _cache_key(prefix: str, projet_id: str, role: str = "") -> str:
    """Generate a cache key that includes role information."""
    if role:
        return f"{prefix}:{projet_id}:role={role}"
    return f"{prefix}:{projet_id}"


# ══════════════════════════════════════════════════════════════════════
#  ProjetRecord class
# ══════════════════════════════════════════════════════════════════════


class ProjetRecord:
    """In-memory record for a project workspace.

    v1.6.7-5: Adapted to load from / save to PostgreSQL via projet_db.
    Extended with volumes, resource_limits, encrypted_env, depends_on,
    template_id, and dry_run support.
    """

    __slots__ = (
        "projet_id",
        "name",
        "workspace_path",
        "owner",
        "status",
        "created_at",
        "completed_at",
        "auto_delete",
        "archive",
        "last_command",
        "last_returncode",
        "sudo",
        "env",
        "permissions",
        # v1.6.7-3 fields
        "tags",
        "labels",
        "ttl_seconds",
        "ttl_expires_at",
        "execution_history",
        "callback_url",
        # v1.6.7-4 fields
        "volumes",
        "resource_limits",
        "encrypted_env",
        "depends_on",
        "template_id",
    )

    def __init__(
        self,
        projet_id: str,
        name: str,
        workspace_path: str,
        owner: str = "",
        auto_delete: bool = True,
        sudo: bool = False,
        env: Optional[Dict[str, str]] = None,
        permissions: Optional[str] = None,
        tags: Optional[List[str]] = None,
        labels: Optional[Dict[str, str]] = None,
        ttl_seconds: Optional[int] = None,
        callback_url: Optional[str] = None,
        volumes: Optional[List[str]] = None,
        resource_limits: Optional[Dict[str, Any]] = None,
        encrypted_env: Optional[Dict[str, str]] = None,
        depends_on: Optional[List[str]] = None,
        template_id: Optional[str] = None,
    ) -> None:
        self.projet_id = projet_id
        self.name = name
        self.workspace_path = workspace_path
        self.owner = owner
        self.status = "creating"
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None
        self.auto_delete = auto_delete
        self.archive: Optional[str] = None
        self.last_command: Optional[str] = None
        self.last_returncode: Optional[int] = None
        self.sudo = sudo
        self.env = env
        self.permissions = permissions
        # v1.6.7-3 fields
        self.tags = tags or []
        self.labels = labels or {}
        self.ttl_seconds = ttl_seconds
        self.ttl_expires_at: Optional[str] = None
        self.execution_history: List[Dict[str, Any]] = []
        self.callback_url = callback_url
        # v1.6.7-4 fields
        self.volumes = volumes or []
        self.resource_limits = resource_limits or {}
        self.encrypted_env = encrypted_env or {}
        self.depends_on = depends_on or []
        self.template_id = template_id

        # Calculate TTL expiry
        if ttl_seconds:
            expires = datetime.now(timezone.utc).timestamp() + ttl_seconds
            self.ttl_expires_at = datetime.fromtimestamp(
                expires, tz=timezone.utc
            ).isoformat()

    def set_status(self, new_status: str) -> bool:
        """v1.6.7-3 #15 + v1.6.7-4 #2: Transition status with validation.

        Returns True if transition is valid, False otherwise.
        v1.6.7-4: No force-assignment bypass. Callers must handle False.
        """
        allowed = _VALID_TRANSITIONS.get(self.status, set())
        if new_status in allowed or new_status == self.status:
            self.status = new_status
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the record to a dict suitable for projet_db.save_project()."""
        return {
            "projet_id": self.projet_id,
            "name": self.name,
            "workspace_path": self.workspace_path,
            "owner": self.owner,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "auto_delete": self.auto_delete,
            "archive": self.archive,
            "last_command": self.last_command,
            "last_returncode": self.last_returncode,
            "sudo": self.sudo,
            "env": self.env or {},
            "permissions": self.permissions,
            "tags": self.tags,
            "labels": self.labels,
            "ttl_seconds": self.ttl_seconds,
            "ttl_expires_at": self.ttl_expires_at,
            "callback_url": self.callback_url,
            "volumes": self.volumes,
            "resource_limits": self.resource_limits,
            "encrypted_env": self.encrypted_env,
            "depends_on": self.depends_on,
            "template_id": self.template_id,
        }

    def save_to_db(self) -> None:
        """Persist this record to PostgreSQL."""
        try:
            projet_db.save_project(self.to_dict())
        except Exception as exc:
            logger.warning("[PROJET %s] Failed to save to DB: %s", self.projet_id, exc)

    @classmethod
    def from_db_dict(cls, data: Dict[str, Any]) -> "ProjetRecord":
        """Create a ProjetRecord from a dict loaded from the database."""
        record = cls(
            projet_id=data["projet_id"],
            name=data["name"],
            workspace_path=data["workspace_path"],
            owner=data.get("owner", ""),
            auto_delete=data.get("auto_delete", True),
            sudo=data.get("sudo", False),
            env=data.get("env"),
            permissions=data.get("permissions"),
            tags=data.get("tags"),
            labels=data.get("labels"),
            ttl_seconds=data.get("ttl_seconds"),
            callback_url=data.get("callback_url"),
            volumes=data.get("volumes"),
            resource_limits=data.get("resource_limits"),
            encrypted_env=data.get("encrypted_env"),
            depends_on=data.get("depends_on"),
            template_id=data.get("template_id"),
        )
        record.status = data.get("status", "creating")
        record.created_at = data.get("created_at", record.created_at)
        record.completed_at = data.get("completed_at")
        record.archive = data.get("archive")
        record.last_command = data.get("last_command")
        record.last_returncode = data.get("last_returncode")
        record.ttl_expires_at = data.get("ttl_expires_at")
        # Load execution history from DB
        try:
            record.execution_history = projet_db.load_history(record.projet_id, limit=50)
        except Exception:
            record.execution_history = []
        return record

    def to_workspace_info(self) -> ShellProjetWorkspaceInfo:
        """Convert to API response model."""
        dir_size = None
        file_count = None
        ws_path = Path(self.workspace_path)
        if ws_path.exists():
            try:
                dir_size = sum(
                    f.stat().st_size for f in ws_path.rglob("*") if f.is_file()
                )
                file_count = sum(1 for f in ws_path.rglob("*") if f.is_file())
            except Exception:
                pass

        from app.models.shell_projet import ShellProjetExecutionHistoryEntry
        history = [
            ShellProjetExecutionHistoryEntry(**h)
            for h in self.execution_history[-50:]
        ]

        return ShellProjetWorkspaceInfo(
            projet_id=self.projet_id,
            name=self.name,
            workspace_path=self.workspace_path,
            owner=self.owner,
            status=self.status,
            created_at=self.created_at,
            completed_at=self.completed_at,
            auto_delete=self.auto_delete,
            archive=self.archive,
            last_command=self.last_command,
            last_returncode=self.last_returncode,
            directory_size=dir_size,
            file_count=file_count,
            tags=self.tags,
            labels=self.labels,
            ttl_seconds=self.ttl_seconds,
            ttl_expires_at=self.ttl_expires_at,
            execution_history=history,
            callback_url=self.callback_url,
        )


# ══════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════


def _ensure_base_dir() -> Path:
    """Ensure the base directory for project workspaces exists."""
    base = _BASE_DIR
    base.mkdir(parents=True, exist_ok=True)
    return base


def _create_workspace(
    name: str,
    projet_id: str,
    permissions: Optional[str] = None,
    volumes: Optional[List[str]] = None,
) -> str:
    """Create the workspace directory /home/AD-API-USER/{name}/{id}.

    v1.6.7-4 #14: If volumes are specified, create symlinks to shared dirs.

    Returns the absolute path to the workspace directory.
    """
    _ensure_base_dir()
    workspace = _BASE_DIR / name / projet_id
    workspace.mkdir(parents=True, exist_ok=True)

    # Set permissions if specified
    if permissions:
        try:
            os.chmod(str(workspace), int(permissions, 8))
        except (ValueError, OSError) as exc:
            logger.warning("Failed to set permissions %s on %s: %s", permissions, workspace, exc)

    # v1.6.7-4 #14: Create shared volume symlinks
    if volumes:
        _SHARED_VOLUMES_DIR.mkdir(parents=True, exist_ok=True)
        for vol in volumes:
            vol_name = os.path.basename(vol.rstrip("/"))
            shared_path = _SHARED_VOLUMES_DIR / vol_name
            link_path = os.path.join(str(workspace), vol_name)
            try:
                shared_path.mkdir(parents=True, exist_ok=True)
                if not os.path.exists(link_path):
                    os.symlink(str(shared_path), link_path)
                    logger.info("[PROJET %s] Linked shared volume: %s -> %s",
                                projet_id, link_path, shared_path)
            except Exception as exc:
                logger.warning("[PROJET %s] Failed to create volume symlink for %s: %s",
                               projet_id, vol, exc)

    return str(workspace)


def _is_archive(filename: str) -> bool:
    """Check if a filename has a supported archive extension."""
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in _ARCHIVE_EXTENSIONS)


def _extract_archive(archive_path: str, workspace: str) -> List[str]:
    """Extract an archive into the workspace directory.

    v1.6.7-4 #4: If ANY dangerous member is found (path traversal),
    the ENTIRE archive is REJECTED (ValueError raised).

    Supports: .zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar, .gz, .7z

    Returns a list of extracted file/directory names.
    """
    lower = archive_path.lower()
    extracted: List[str] = []

    try:
        if lower.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                # v1.6.7-4 #4: Reject entire archive if any dangerous member
                for member in zf.namelist():
                    if member.startswith("/") or ".." in member:
                        raise ValueError(
                            f"Archive rejected: dangerous path '{member}' found. "
                            f"Entire archive is rejected for security."
                        )
                zf.extractall(workspace)
                extracted = zf.namelist()

        elif lower.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive_path, "r:gz") as tf:
                members = tf.getmembers()
                for member in members:
                    if member.name.startswith("/") or ".." in member.name:
                        raise ValueError(
                            f"Archive rejected: dangerous path '{member.name}' found. "
                            f"Entire archive is rejected for security."
                        )
                tf.extractall(workspace, members=members)
                extracted = [m.name for m in members]

        elif lower.endswith(".tar.bz2"):
            with tarfile.open(archive_path, "r:bz2") as tf:
                members = tf.getmembers()
                for member in members:
                    if member.name.startswith("/") or ".." in member.name:
                        raise ValueError(
                            f"Archive rejected: dangerous path '{member.name}' found. "
                            f"Entire archive is rejected for security."
                        )
                tf.extractall(workspace, members=members)
                extracted = [m.name for m in members]

        elif lower.endswith(".tar.xz"):
            with tarfile.open(archive_path, "r:xz") as tf:
                members = tf.getmembers()
                for member in members:
                    if member.name.startswith("/") or ".." in member.name:
                        raise ValueError(
                            f"Archive rejected: dangerous path '{member.name}' found. "
                            f"Entire archive is rejected for security."
                        )
                tf.extractall(workspace, members=members)
                extracted = [m.name for m in members]

        elif lower.endswith(".tar"):
            with tarfile.open(archive_path, "r:") as tf:
                members = tf.getmembers()
                for member in members:
                    if member.name.startswith("/") or ".." in member.name:
                        raise ValueError(
                            f"Archive rejected: dangerous path '{member.name}' found. "
                            f"Entire archive is rejected for security."
                        )
                tf.extractall(workspace, members=members)
                extracted = [m.name for m in members]

        elif lower.endswith(".gz") and not lower.endswith(".tar.gz"):
            import gzip
            basename = os.path.basename(archive_path)
            if basename.endswith(".gz"):
                basename = basename[:-3]
            out_path = os.path.join(workspace, basename)
            with gzip.open(archive_path, "rb") as gz_in:
                with open(out_path, "wb") as f_out:
                    shutil.copyfileobj(gz_in, f_out)
            extracted = [basename]

        elif lower.endswith(".7z"):
            result = subprocess.run(
                ["7z", "x", archive_path, f"-o{workspace}", "-y"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                raise RuntimeError(f"7z extraction failed: {result.stderr}")
            for line in result.stdout.splitlines():
                if line.startswith("Extracting "):
                    fname = line.replace("Extracting ", "").strip()
                    if fname:
                        # v1.6.7-4 #4: Check for path traversal in 7z output
                        if fname.startswith("/") or ".." in fname:
                            raise ValueError(
                                f"Archive rejected: dangerous path '{fname}' found. "
                                f"Entire archive is rejected for security."
                            )
                        extracted.append(fname)

        else:
            raise ValueError(f"Unsupported archive format: {archive_path}")

    except ValueError:
        raise
    except Exception as exc:
        logger.error("Archive extraction failed for %s: %s", archive_path, exc)
        raise

    return extracted


# ── v1.6.7-3 #10: Disk quota check ────────────────────────────────────


def _check_workspace_size(workspace: str) -> int:
    """Return total size of workspace in bytes."""
    ws_path = Path(workspace)
    if not ws_path.exists():
        return 0
    try:
        return sum(f.stat().st_size for f in ws_path.rglob("*") if f.is_file())
    except Exception:
        return 0


def _enforce_workspace_quota(workspace: str, extra_bytes: int = 0) -> None:
    """Raise HTTPException if workspace exceeds MAX_WORKSPACE_SIZE."""
    if _MAX_WORKSPACE_SIZE <= 0:
        return
    current = _check_workspace_size(workspace)
    if current + extra_bytes > _MAX_WORKSPACE_SIZE:
        limit_mb = _MAX_WORKSPACE_SIZE / (1024 * 1024)
        current_mb = current / (1024 * 1024)
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=(
                f"Workspace quota exceeded: {current_mb:.1f}MB used + "
                f"{extra_bytes / (1024*1024):.1f}MB new > "
                f"{limit_mb:.0f}MB limit. "
                f"Set SHELL_PROJET_MAX_WORKSPACE_SIZE to increase."
            ),
        )


# ── v1.6.7-3 #1: Disk logging ─────────────────────────────────────────


def _write_disk_logs(
    workspace: str,
    run_command: str,
    stdout: str,
    stderr: str,
    returncode: int,
    elapsed: float,
    timed_out: bool,
    projet_id: str,
) -> None:
    """Write execution logs to disk in .projet_logs/ directory."""
    try:
        logs_dir = os.path.join(workspace, ".projet_logs")
        os.makedirs(logs_dir, exist_ok=True)

        with open(os.path.join(logs_dir, "stdout.log"), "a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"# Command: {run_command}\n")
            f.write(f"# Time: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Projet ID: {projet_id}\n")
            f.write(f"{'='*60}\n")
            f.write(stdout)
            if not stdout.endswith("\n"):
                f.write("\n")

        with open(os.path.join(logs_dir, "stderr.log"), "a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"# Command: {run_command}\n")
            f.write(f"# Time: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Projet ID: {projet_id}\n")
            f.write(f"{'='*60}\n")
            f.write(stderr)
            if not stderr.endswith("\n"):
                f.write("\n")

        meta = {
            "projet_id": projet_id,
            "last_command": run_command,
            "rc": returncode,
            "elapsed": round(elapsed, 3),
            "timed_out": timed_out,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        meta_path = os.path.join(logs_dir, "meta.json")
        existing_meta = {}
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    existing_meta = json.load(f)
            except Exception:
                pass

        history = existing_meta.get("execution_history", [])
        history.append({
            "command": run_command,
            "rc": returncode,
            "elapsed": round(elapsed, 3),
            "timed_out": timed_out,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        meta["execution_history"] = history

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)

    except Exception as exc:
        logger.warning("[PROJET %s] Failed to write disk logs: %s", projet_id, exc)


# ── v1.6.7-3 #3: Output truncation ────────────────────────────────────


def _truncate_output(text: str, max_size: int, label: str = "output") -> tuple:
    """Truncate text if it exceeds max_size.

    Returns (truncated_text, was_truncated, total_bytes).
    """
    total_bytes = len(text.encode("utf-8", errors="replace"))
    if total_bytes <= max_size:
        return text, False, total_bytes

    raw = text.encode("utf-8", errors="replace")[:max_size]
    truncated = raw.decode("utf-8", errors="ignore")
    truncation_msg = (
        f"\n\n[truncated: {total_bytes} bytes total, "
        f"showing first {max_size} bytes]"
    )
    return truncated + truncation_msg, True, total_bytes


# ── v1.6.7-4 #9+#11: Webhook callback (urllib + retry) ────────────────


async def _send_callback(
    callback_url: str,
    projet_id: str,
    run_command: str,
    returncode: int,
    stdout: str,
    stderr: str,
    elapsed: float,
    timed_out: bool,
) -> None:
    """Send POST callback with execution results using urllib.

    v1.6.7-4: Replaced aiohttp with urllib.request.
    Retry with exponential backoff: max _CALLBACK_MAX_RETRIES with
    1s / 2s / 4s delays.
    """
    payload = json.dumps({
        "projet_id": projet_id,
        "run_command": run_command,
        "returncode": returncode,
        "stdout": stdout[:10000],
        "stderr": stderr[:5000],
        "elapsed": round(elapsed, 3),
        "timed_out": timed_out,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }).encode("utf-8")

    delays = [1, 2, 4]
    max_retries = _CALLBACK_MAX_RETRIES

    for attempt in range(max_retries + 1):
        try:
            req = urllib.request.Request(
                callback_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10),
            )
            status_code = resp.getcode() if hasattr(resp, 'getcode') else 0
            logger.info(
                "[PROJET %s] Callback %s returned status %d (attempt %d)",
                projet_id, callback_url, status_code, attempt + 1,
            )
            return
        except urllib.error.URLError as exc:
            logger.warning(
                "[PROJET %s] Callback %s failed (attempt %d/%d): %s",
                projet_id, callback_url, attempt + 1, max_retries + 1, exc,
            )
            if attempt < max_retries:
                delay = delays[attempt] if attempt < len(delays) else delays[-1]
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "[PROJET %s] Callback %s failed after %d retries",
                    projet_id, callback_url, max_retries + 1,
                )
        except Exception as exc:
            logger.warning(
                "[PROJET %s] Callback %s unexpected error: %s",
                projet_id, callback_url, exc,
            )
            if attempt < max_retries:
                delay = delays[attempt] if attempt < len(delays) else delays[-1]
                await asyncio.sleep(delay)
            else:
                break


# ── v1.6.7-4 #15: Resource limits ────────────────────────────────────


def _build_ulimit_prefix(resource_limits: Dict[str, Any]) -> str:
    """Build a bash prefix string that applies ulimit-based resource limits.

    Supported keys:
        cpu_quota: int — CPU time limit in seconds (ulimit -t)
        max_memory_mb: int — Memory limit in MB (ulimit -v)
        max_processes: int — Max processes (ulimit -u)
    """
    parts: List[str] = []
    cpu_quota = resource_limits.get("cpu_quota")
    if cpu_quota is not None:
        parts.append(f"ulimit -t {int(cpu_quota)} 2>/dev/null")
    max_memory_mb = resource_limits.get("max_memory_mb")
    if max_memory_mb is not None:
        # ulimit -v is in KB
        parts.append(f"ulimit -v {int(max_memory_mb) * 1024} 2>/dev/null")
    max_processes = resource_limits.get("max_processes")
    if max_processes is not None:
        parts.append(f"ulimit -u {int(max_processes)} 2>/dev/null")
    if parts:
        return " && ".join(parts) + " && "
    return ""


# ── v1.6.7-4 #21: Dependency chain ───────────────────────────────────


async def _wait_for_dependencies(depends_on: List[str], timeout_per_dep: int = 600) -> None:
    """Wait for all dependency projects to complete successfully.

    Raises HTTPException if any dependency fails or times out.
    """
    for dep_id in depends_on:
        dep_record = _projects.get(dep_id)
        if dep_record is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Dependency project '{dep_id}' not found",
            )
        start = time.monotonic()
        while dep_record.status not in ("completed", "failed", "aborted", "deleted"):
            if time.monotonic() - start > timeout_per_dep:
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail=f"Dependency '{dep_id}' did not complete within {timeout_per_dep}s",
                )
            await asyncio.sleep(1)
        if dep_record.status != "completed":
            raise HTTPException(
                status_code=status.HTTP_424_FAILED_DEPENDENCY,
                detail=f"Dependency '{dep_id}' ended with status '{dep_record.status}'",
            )


# ── Command execution ──────────────────────────────────────────────────


async def _run_command_in_workspace(
    workspace: str,
    command: str,
    args: Optional[List[str]] = None,
    sudo: bool = False,
    timeout: int = 300,
    env: Optional[Dict[str, str]] = None,
    projet_id: Optional[str] = None,
    resource_limits: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute a command in the workspace directory.

    v1.6.7-4 #1: Track Popen in _running_processes for abort/shutdown.
    v1.6.7-4 #15: Apply resource_limits via ulimit prefix.

    Returns a dict with stdout, stderr, returncode, timed_out, elapsed,
    output_truncated, output_total_bytes.
    """
    # Build the full command
    full_cmd = command
    if args:
        full_cmd = f"{command} {' '.join(args)}"

    # v1.6.7-4 #15: Prepend ulimit-based resource limits
    if resource_limits:
        ulimit_prefix = _build_ulimit_prefix(resource_limits)
        if ulimit_prefix:
            full_cmd = ulimit_prefix + full_cmd

    # Build subprocess command
    cmd_parts: List[str] = []
    sudo_password = os.environ.get("SAMBA_SUDO_PASSWORD", "")

    if sudo:
        cmd_parts.append("sudo")
        if sudo_password:
            cmd_parts.append("-S")
        cmd_parts.append("-E")

    cmd_parts.extend(["bash", "-c", full_cmd])

    # Build environment
    run_env = dict(os.environ)
    if env:
        run_env.update(env)

    t_start = time.monotonic()
    stdin_input = None
    if sudo and sudo_password and "-S" in cmd_parts:
        stdin_input = sudo_password + "\n"

    loop = asyncio.get_running_loop()

    def _run():
        proc = None
        try:
            proc = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=run_env,
                cwd=workspace,
                stdin=subprocess.PIPE if stdin_input else None,
            )
            # v1.6.7-4 #1: Track Popen for abort/shutdown
            if projet_id:
                _running_processes[projet_id] = proc

            try:
                stdout_bytes, stderr_bytes = proc.communicate(
                    input=(stdin_input or "").encode("utf-8") if stdin_input else None,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate(timeout=5)
                t_elapsed = time.monotonic() - t_start

                stdout_text = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
                stderr_text = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
                if not stderr_text:
                    stderr_text = f"Command timed out after {timeout} seconds"

                return {
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "returncode": proc.returncode if proc.returncode is not None else -1,
                    "timed_out": True,
                    "elapsed": t_elapsed,
                    "output_truncated": False,
                    "output_total_bytes": 0,
                }
            finally:
                # v1.6.7-4 #1: Clean up Popen tracking
                if projet_id:
                    _running_processes.pop(projet_id, None)

            t_elapsed = time.monotonic() - t_start

            stdout_text = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr_text = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

            # v1.6.7-3 #3: Truncate output if too large
            stdout_trunc, stdout_was_trunc, stdout_total = _truncate_output(
                stdout_text, _MAX_OUTPUT_SIZE, "stdout"
            )
            stderr_trunc, stderr_was_trunc, stderr_total = _truncate_output(
                stderr_text, _MAX_OUTPUT_SIZE, "stderr"
            )

            return {
                "stdout": stdout_trunc,
                "stderr": stderr_trunc,
                "returncode": proc.returncode,
                "timed_out": False,
                "elapsed": t_elapsed,
                "output_truncated": stdout_was_trunc or stderr_was_trunc,
                "output_total_bytes": stdout_total + stderr_total,
            }
        except Exception as exc:
            t_elapsed = time.monotonic() - t_start
            # v1.6.7-4 #1: Clean up Popen tracking on error
            if projet_id:
                _running_processes.pop(projet_id, None)
            return {
                "stdout": "",
                "stderr": str(exc),
                "returncode": -3,
                "timed_out": False,
                "elapsed": t_elapsed,
                "output_truncated": False,
                "output_total_bytes": 0,
            }

    return await loop.run_in_executor(_projet_pool, _run)


async def _execute_project(
    projet_id: str,
    workspace: str,
    run_command: str,
    run_args: Optional[List[str]] = None,
    sudo: bool = False,
    timeout: int = 300,
    env: Optional[Dict[str, str]] = None,
    auto_delete: bool = True,
    pre_commands: Optional[List[str]] = None,
    post_commands: Optional[List[str]] = None,
    callback_url: Optional[str] = None,
    resource_limits: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute a command in a project workspace with full lifecycle.

    v1.6.7-4 #2: No state machine bypass. If set_status() fails, raise.
    v1.6.7-4 #15: Apply resource_limits.
    v1.6.7-4 #16: Audit log all actions.
    v1.6.7-4 #6: Save to DB on every mutation.
    """
    ws_mgr = get_projet_ws_manager()
    record = _projects.get(projet_id)
    if not record:
        return {"status": "error", "message": "Project not found"}

    # v1.6.7-4 #2: State machine — no bypass
    if not record.set_status("running"):
        raise RuntimeError(
            f"Invalid state transition: {record.status} -> running "
            f"for project {projet_id}"
        )
    record.save_to_db()

    # v1.6.7-4 #16: Audit log
    projet_db.audit_log(projet_id, "execute", detail=f"command: {run_command}")

    await ws_mgr.send_status(projet_id, "running", {"command": run_command})

    all_stdout = ""
    all_stderr = ""
    final_rc = 0
    timed_out = False
    output_truncated = False
    output_total_bytes = 0
    t_total_start = time.monotonic()

    # ── Pre-commands ────────────────────────────────────────────────
    if pre_commands:
        for cmd in pre_commands:
            logger.info("[PROJET %s] Pre-command: %s", projet_id, cmd)
            result = await _run_command_in_workspace(
                workspace, cmd, sudo=sudo, timeout=timeout, env=env,
                projet_id=projet_id, resource_limits=resource_limits,
            )
            all_stdout += result["stdout"]
            all_stderr += result["stderr"]
            await ws_mgr.send_output(projet_id, "stdout", result["stdout"])
            if result["stderr"]:
                await ws_mgr.send_output(projet_id, "stderr", result["stderr"])
            if result["returncode"] != 0:
                final_rc = result["returncode"]
                timed_out = result["timed_out"]
                logger.warning(
                    "[PROJET %s] Pre-command failed (rc=%d): %s",
                    projet_id, final_rc, cmd,
                )
                break

    # ── Main command ────────────────────────────────────────────────
    if final_rc == 0 and run_command:
        logger.info("[PROJET %s] Running: %s", projet_id, run_command)
        record.last_command = run_command
        result = await _run_command_in_workspace(
            workspace, run_command, args=run_args,
            sudo=sudo, timeout=timeout, env=env,
            projet_id=projet_id, resource_limits=resource_limits,
        )
        all_stdout += result["stdout"]
        all_stderr += result["stderr"]
        final_rc = result["returncode"]
        timed_out = result["timed_out"]
        output_truncated = result.get("output_truncated", False)
        output_total_bytes = result.get("output_total_bytes", 0)
        record.last_returncode = final_rc
        record.save_to_db()

        await ws_mgr.send_output(projet_id, "stdout", result["stdout"])
        if result["stderr"]:
            await ws_mgr.send_output(projet_id, "stderr", result["stderr"])

    # ── Post-commands ───────────────────────────────────────────────
    if final_rc == 0 and post_commands:
        for cmd in post_commands:
            logger.info("[PROJET %s] Post-command: %s", projet_id, cmd)
            result = await _run_command_in_workspace(
                workspace, cmd, sudo=sudo, timeout=timeout, env=env,
                projet_id=projet_id, resource_limits=resource_limits,
            )
            all_stdout += result["stdout"]
            all_stderr += result["stderr"]
            await ws_mgr.send_output(projet_id, "stdout", result["stdout"])
            if result["stderr"]:
                await ws_mgr.send_output(projet_id, "stderr", result["stderr"])
            if result["returncode"] != 0 and final_rc == 0:
                final_rc = result["returncode"]

    t_total_elapsed = time.monotonic() - t_total_start

    # ── Update record ───────────────────────────────────────────────
    proj_status = "completed" if final_rc == 0 else "failed"

    # v1.6.7-4 #2: State machine — no bypass, proper error handling
    if not record.set_status(proj_status):
        logger.error(
            "[PROJET %s] Invalid state transition: %s -> %s",
            projet_id, record.status, proj_status,
        )
        # We must still record the result — force via DB if set_status fails
        projet_db.update_project_status(projet_id, proj_status)
        record.status = proj_status
    record.completed_at = datetime.now(timezone.utc).isoformat()

    # v1.6.7-3 #6 + v1.6.7-4 #6: Append history + save
    projet_db.append_history(
        projet_id, run_command, final_rc, t_total_elapsed, timed_out
    )
    record.execution_history = projet_db.load_history(projet_id, limit=50)
    record.save_to_db()

    # v1.6.7-3 #1: Write disk logs
    _write_disk_logs(
        workspace=workspace,
        run_command=run_command,
        stdout=all_stdout,
        stderr=all_stderr,
        returncode=final_rc,
        elapsed=t_total_elapsed,
        timed_out=timed_out,
        projet_id=projet_id,
    )

    # ── Send final result via WebSocket ─────────────────────────────
    await ws_mgr.send_command_result(
        projet_id=projet_id,
        run_command=run_command,
        returncode=final_rc,
        stdout=all_stdout,
        stderr=all_stderr,
        timed_out=timed_out,
        elapsed=t_total_elapsed,
    )
    await ws_mgr.send_status(
        projet_id,
        proj_status,
        {"returncode": final_rc, "elapsed": t_total_elapsed},
    )

    # v1.6.7-3 #12 + v1.6.7-4 #9+#11: Webhook callback with retry
    effective_callback = callback_url or record.callback_url
    if effective_callback:
        asyncio.get_running_loop().create_task(
            _send_callback(
                callback_url=effective_callback,
                projet_id=projet_id,
                run_command=run_command,
                returncode=final_rc,
                stdout=all_stdout,
                stderr=all_stderr,
                elapsed=t_total_elapsed,
                timed_out=timed_out,
            )
        )

    # ── Auto-delete if configured ───────────────────────────────────
    workspace_deleted = False
    if auto_delete:
        try:
            shutil.rmtree(workspace, ignore_errors=True)
            workspace_deleted = True
            # v1.6.7-4 #2: Use set_status for deletion
            if not record.set_status("deleted"):
                projet_db.update_project_status(projet_id, "deleted")
                record.status = "deleted"
            logger.info("[PROJET %s] Workspace auto-deleted: %s", projet_id, workspace)
            # v1.6.7-2: Remove empty parent directory
            parent = os.path.dirname(workspace)
            try:
                if os.path.isdir(parent) and not os.listdir(parent):
                    os.rmdir(parent)
                    logger.info("[PROJET %s] Empty parent directory removed: %s", projet_id, parent)
            except Exception:
                pass
            # v1.6.7-4 #16: Audit — log BEFORE delete (FK constraint)
            projet_db.audit_log(projet_id, "auto_delete", detail="auto_delete after execution")
            # Remove from registries
            _projects.pop(projet_id, None)
            projet_db.delete_project(projet_id)
        except Exception as exc:
            logger.error("[PROJET %s] Failed to delete workspace: %s", projet_id, exc)

    return {
        "status": proj_status,
        "run_command": run_command,
        "returncode": final_rc,
        "stdout": all_stdout,
        "stderr": all_stderr,
        "timed_out": timed_out,
        "elapsed": t_total_elapsed,
        "workspace_deleted": workspace_deleted,
        "output_truncated": output_truncated,
        "output_total_bytes": output_total_bytes if output_truncated else None,
    }


# ── v1.6.7-3 #5 + v1.6.7-4 #10: TTL background task ──────────────────

_ttl_task: Optional[asyncio.Task] = None


async def _ttl_cleanup_loop() -> None:
    """Background task that periodically checks and deletes expired TTL projects.

    v1.6.7-4 #10: Uses SHELL_PROJET_TTL_CLEANUP_INTERVAL (default 30s).
    v1.6.7-4 #2: Uses set_status properly (no bypass).
    """
    while True:
        try:
            await asyncio.sleep(_TTL_CLEANUP_INTERVAL)
            now = datetime.now(timezone.utc).timestamp()
            expired_ids = []

            for pid, record in list(_projects.items()):
                if record.ttl_seconds and record.ttl_expires_at:
                    try:
                        expires_ts = datetime.fromisoformat(
                            record.ttl_expires_at
                        ).timestamp()
                        if now >= expires_ts and record.status not in ("running", "deleting"):
                            expired_ids.append(pid)
                    except Exception:
                        pass

            for pid in expired_ids:
                record = _projects.get(pid)
                if not record:
                    continue
                logger.info("[PROJET %s] TTL expired, auto-deleting", pid)
                workspace = record.workspace_path
                try:
                    if os.path.isdir(workspace):
                        shutil.rmtree(workspace, ignore_errors=True)
                        parent = os.path.dirname(workspace)
                        try:
                            if os.path.isdir(parent) and not os.listdir(parent):
                                os.rmdir(parent)
                        except Exception:
                            pass
                except Exception as exc:
                    logger.error("[PROJET %s] TTL cleanup failed: %s", pid, exc)

                # v1.6.7-4 #2: Use set_status
                if not record.set_status("deleted"):
                    projet_db.update_project_status(pid, "deleted")
                    record.status = "deleted"

                # v1.6.7-4 #16: Audit — log BEFORE delete (FK constraint)
                projet_db.audit_log(pid, "ttl_expired", detail="auto-deleted by TTL")

                _projects.pop(pid, None)
                projet_db.delete_project(pid)

                ws_mgr = get_projet_ws_manager()
                await ws_mgr.send_status(pid, "deleted", {"reason": "ttl_expired"})

            if expired_ids:
                logger.info("[TTL] Cleaned up %d expired projects", len(expired_ids))

        except asyncio.CancelledError:
            logger.info("[TTL] Cleanup task cancelled")
            break
        except Exception as exc:
            logger.error("[TTL] Cleanup loop error: %s", exc)


def _start_ttl_task() -> None:
    """Start the TTL cleanup background task if not already running."""
    global _ttl_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    if _ttl_task is None or _ttl_task.done():
        _ttl_task = loop.create_task(_ttl_cleanup_loop())
        logger.info("[TTL] Background cleanup task started (interval=%ds)", _TTL_CLEANUP_INTERVAL)


# ── v1.6.7-4 #12: Scheduler background task ───────────────────────────

_scheduler_task: Optional[asyncio.Task] = None


def _evaluate_cron(cron_expr: str, now: Optional[datetime] = None) -> bool:
    """Simple cron expression evaluator.

    Supports: * or specific values for minute, hour, day-of-month, month, day-of-week.
    Format: minute hour dom month dow
    Example: "*/5 * * * *" (every 5 minutes), "0 2 * * *" (2 AM daily)
    """
    if now is None:
        now = datetime.now(timezone.utc)
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False

    def _match(field: str, value: int) -> bool:
        if field == "*":
            return True
        if field.startswith("*/"):
            step = int(field[2:])
            return value % step == 0
        if "," in field:
            return str(value) in field.split(",")
        if "-" in field:
            lo, hi = field.split("-", 1)
            return int(lo) <= value <= int(hi)
        try:
            return int(field) == value
        except ValueError:
            return False

    return (
        _match(parts[0], now.minute) and
        _match(parts[1], now.hour) and
        _match(parts[2], now.day) and
        _match(parts[3], now.month) and
        _match(parts[4], now.isoweekday() % 7)
    )


async def _scheduler_loop() -> None:
    """Background task that evaluates cron schedules and runs commands."""
    while True:
        try:
            await asyncio.sleep(30)
            schedules = projet_db.load_schedules(enabled_only=True)
            now = datetime.now(timezone.utc)

            for sched in schedules:
                try:
                    if _evaluate_cron(sched["cron_expr"], now):
                        pid = sched["projet_id"]
                        record = _projects.get(pid)
                        if record and record.status in ("ready", "completed", "failed", "aborted"):
                            logger.info("[SCHEDULER] Running scheduled command for %s: %s",
                                        pid, sched["run_command"])
                            asyncio.get_running_loop().create_task(
                                _execute_project(
                                    projet_id=pid,
                                    workspace=record.workspace_path,
                                    run_command=sched["run_command"],
                                    sudo=record.sudo,
                                    env=record.env,
                                    auto_delete=False,
                                    resource_limits=record.resource_limits,
                                )
                            )
                            projet_db.update_schedule_run(
                                sched["id"],
                                now.isoformat(),
                                now.isoformat(),
                            )
                except Exception as exc:
                    logger.error("[SCHEDULER] Error evaluating schedule %s: %s",
                                 sched.get("id"), exc)

        except asyncio.CancelledError:
            logger.info("[SCHEDULER] Task cancelled")
            break
        except Exception as exc:
            logger.error("[SCHEDULER] Loop error: %s", exc)


def _start_scheduler_task() -> None:
    """Start the scheduler background task if not already running."""
    global _scheduler_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _scheduler_task is None or _scheduler_task.done():
        _scheduler_task = loop.create_task(_scheduler_loop())
        logger.info("[SCHEDULER] Background task started")


# ── v1.6.7-3 #2 + v1.6.7-4 #1: Graceful shutdown ────────────────────


# v1.6.8-2 fix: Thread-safe shutdown guard (replaces bool flag)
# Prevents shutdown handler running multiple times.
_shutdown_lock = threading.Lock()
_shutdown_done: bool = False


def graceful_shutdown_projet() -> None:
    """Clean up on API shutdown: kill running processes, auto-delete, etc.

    v1.6.8-2: Removed atexit + signal handlers. Now called ONLY from the
    FastAPI lifespan shutdown in main.py, so it runs exactly ONCE.
    Uses threading.Lock for thread-safety instead of a bare bool.
    """
    global _shutdown_done, _ttl_task, _scheduler_task

    with _shutdown_lock:
        if _shutdown_done:
            return
        _shutdown_done = True

    logger.info("[SHUTDOWN] Graceful shutdown initiated")

    # v1.6.7-4 #1: Kill running processes from _running_processes
    for pid, proc in list(_running_processes.items()):
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    # Auto-delete projects with auto_delete=True
    for pid, record in list(_projects.items()):
        if record.auto_delete:
            workspace = record.workspace_path
            try:
                if os.path.isdir(workspace):
                    shutil.rmtree(workspace, ignore_errors=True)
                    parent = os.path.dirname(workspace)
                    try:
                        if os.path.isdir(parent) and not os.listdir(parent):
                            os.rmdir(parent)
                    except Exception:
                        pass
                    logger.info("[SHUTDOWN] Auto-deleted project %s: %s", pid, workspace)
            except Exception as exc:
                logger.error("[SHUTDOWN] Failed to delete %s: %s", pid, exc)

    # Shutdown thread pool
    _projet_pool.shutdown(wait=False)

    # Cancel TTL task
    if _ttl_task and not _ttl_task.done():
        _ttl_task.cancel()

    # Cancel scheduler task
    if _scheduler_task and not _scheduler_task.done():
        _scheduler_task.cancel()

    # v1.6.7-6 fix: Close PostgreSQL connection pool on shutdown
    try:
        projet_db.close_db()
    except Exception as exc:
        logger.warning("[SHUTDOWN] Failed to close PostgreSQL pool: %s", exc)

    logger.info("[SHUTDOWN] Cleanup complete")


# ── v1.6.7-4 #7+#8: DB initialization and startup recovery ───────────


def _init_projet_db() -> None:
    """Initialize the projet PostgreSQL database and restore state.

    v1.6.7-5: Migrated from SQLite to PostgreSQL.
    v1.6.7-6: Also reads DB_* env vars from run.sh as fallback.
    Reads PG_* settings from environment / config.
    """
    # v1.6.7-6 fix: Also support DB_* env vars from run.sh
    # (run.sh exports DB_PASSWORD, DB_USER, etc. without SAMBA_ prefix)
    _effective_host = _PG_HOST or os.environ.get('DB_HOST', 'localhost')
    _effective_port = _PG_PORT or int(os.environ.get('DB_PORT', '5432'))
    _effective_dbname = _PG_DBNAME or os.environ.get('DB_NAME', 'samba_api')
    _effective_user = _PG_USER or os.environ.get('DB_USER', 'samba_api')
    _effective_password = _PG_PASSWORD or os.environ.get('DB_PASSWORD', '')

    # v1.6.7-6 fix: Log which password source is being used
    if not _PG_PASSWORD and os.environ.get('DB_PASSWORD'):
        logger.info("[PROJET DB] Using DB_PASSWORD from environment (run.sh)")
    elif _PG_PASSWORD:
        logger.info("[PROJET DB] Using SAMBA_SHELL_PROJET_PG_PASSWORD from config")
    else:
        logger.info("[PROJET DB] No PostgreSQL password configured (using peer/trust auth)")

    try:
        projet_db.init_db(
            host=_effective_host,
            port=_effective_port,
            dbname=_effective_dbname,
            user=_effective_user,
            password=_effective_password,
            dsn=_PG_DSN if _PG_DSN else None,
            min_conn=_PG_POOL_MIN,
            max_conn=_PG_POOL_MAX,
        )
    except Exception as exc:
        logger.error("[PROJET DB] Failed to initialize PostgreSQL: %s", exc)
        return

    # v1.6.7-4 #7: Load all projects from DB
    try:
        all_records = projet_db.load_all_projects()
        for pid, data in all_records.items():
            record = ProjetRecord.from_db_dict(data)
            _projects[pid] = record
        logger.info("[PROJET DB] Loaded %d projects from database", len(all_records))
    except Exception as exc:
        logger.error("[PROJET DB] Failed to load projects: %s", exc)

    # v1.6.7-4 #8: Orphan recovery
    try:
        orphans = projet_db.find_orphan_workspaces(str(_BASE_DIR))
        for orphan in orphans:
            try:
                projet_db.recover_orphan(
                    orphan["projet_id"],
                    orphan["name"],
                    orphan["workspace_path"],
                )
                record = ProjetRecord(
                    projet_id=orphan["projet_id"],
                    name=orphan["name"],
                    workspace_path=orphan["workspace_path"],
                    owner="recovered",
                    auto_delete=False,
                )
                record.status = "ready"
                _projects[orphan["projet_id"]] = record
                logger.info("[PROJET DB] Recovered orphan workspace: %s", orphan["projet_id"])
            except Exception as exc:
                logger.warning("[PROJET DB] Failed to recover orphan %s: %s",
                               orphan["projet_id"], exc)
    except Exception as exc:
        logger.warning("[PROJET DB] Orphan scan failed: %s", exc)


# Initialize encryption and DB on module load
_init_encryption()
_init_projet_db()


# ══════════════════════════════════════════════════════════════════════
#  Endpoints
# ══════════════════════════════════════════════════════════════════════


@router.post(
    "/",
    summary="Create a shell project workspace",
    response_model=ShellProjetCreateResponse,
)
async def create_projet(
    body: ShellProjetCreateRequest,
    api_key: ApiKeyDep,
) -> ShellProjetCreateResponse:
    """Create a new project workspace with optional archive and command execution.

    v1.6.7-4: Added dry_run, volumes, resource_limits, encrypted_env,
    depends_on, template support. Per-project lock enforced.
    """
    ws_mgr = get_projet_ws_manager()

    # v1.6.7-3 #9: Enforce max projects limit
    if len(_projects) >= _MAX_PROJECTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Maximum number of projects reached ({_MAX_PROJECTS}). "
                f"Delete existing projects or increase SHELL_PROJET_MAX_PROJECTS."
            ),
        )

    # Generate unique project ID
    projet_id = uuid.uuid4().hex[:12]

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        # Determine owner
        owner = body.owner or getattr(_settings, 'SHELL_PROJET_OWNER_DEFAULT', 'api-user')

        # v1.6.7-4: Extract new fields from body (with defaults for backward compat)
        volumes = getattr(body, 'volumes', None)
        resource_limits = getattr(body, 'resource_limits', None)
        encrypted_env_raw = getattr(body, 'encrypted_env', None)
        depends_on = getattr(body, 'depends_on', None)
        dry_run = getattr(body, 'dry_run', False)

        # v1.6.7-4 #19: Encrypt env vars
        encrypted_env: Dict[str, str] = {}
        if encrypted_env_raw:
            encrypted_env = _encrypt_env(encrypted_env_raw)

        # v1.6.7-4 #21: Validate dependencies
        if depends_on:
            for dep_id in depends_on:
                if dep_id not in _projects:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Dependency project '{dep_id}' not found",
                    )

        # v1.6.7-4 #20: Dry-run mode
        if dry_run:
            return ShellProjetCreateResponse(
                status="ok",
                message="[DRY RUN] Would create project",
                projet_id=projet_id,
                name=body.name,
                workspace_path=str(_BASE_DIR / body.name / projet_id),
                auto_delete=body.auto_delete,
                ws_url=f"/ws/projet/{projet_id}",
                run_result={
                    "dry_run": True,
                    "would_execute": body.run_command or "nothing",
                    "would_extract": body.archive or "nothing",
                    "volumes": volumes or [],
                    "resource_limits": resource_limits or {},
                    "depends_on": depends_on or [],
                } if body.run_command or body.archive else None,
            )

        # Create workspace
        try:
            workspace = _create_workspace(
                name=body.name,
                projet_id=projet_id,
                permissions=body.permissions,
                volumes=volumes,
            )
        except Exception as exc:
            logger.error("Failed to create workspace: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create workspace: {exc}",
            )

        # Create project record
        record = ProjetRecord(
            projet_id=projet_id,
            name=body.name,
            workspace_path=workspace,
            owner=owner,
            auto_delete=body.auto_delete,
            sudo=body.sudo,
            env=body.env,
            permissions=body.permissions,
            tags=body.tags,
            labels=body.labels,
            ttl_seconds=body.ttl_seconds,
            callback_url=body.callback_url,
            volumes=volumes,
            resource_limits=resource_limits,
            encrypted_env=encrypted_env,
            depends_on=depends_on,
        )
        _projects[projet_id] = record
        if not record.set_status("ready"):
            raise RuntimeError(f"Cannot transition from {record.status} to ready")
        # v1.6.7-4 #6: Save to DB
        record.save_to_db()
        # v1.6.7-4 #16: Audit
        projet_db.audit_log(projet_id, "create", detail=f"name={body.name}")

        # v1.6.7-3 #5: Start TTL cleanup task
        if body.ttl_seconds:
            _start_ttl_task()

        # Broadcast creation
        await ws_mgr.send_status(projet_id, "created", {
            "name": body.name,
            "workspace": workspace,
        })

        # ── Extract archive if specified ────────────────────────────
        if body.archive:
            archive_path = os.path.join(workspace, body.archive)
            if os.path.exists(archive_path):
                try:
                    _enforce_workspace_quota(workspace)
                    extracted = _extract_archive(archive_path, workspace)
                    record.archive = body.archive
                    record.save_to_db()
                    await ws_mgr.send_extract_result(
                        projet_id, body.archive, extracted, success=True,
                    )
                    logger.info(
                        "[PROJET %s] Extracted %s (%d files)",
                        projet_id, body.archive, len(extracted),
                    )
                except ValueError:
                    # v1.6.7-4 #4: Archive rejected for path traversal
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=str(Exception),
                    )
                except Exception as exc:
                    await ws_mgr.send_extract_result(
                        projet_id, body.archive, [], success=False, error=str(exc),
                    )
                    logger.warning(
                        "[PROJET %s] Archive extraction failed: %s",
                        projet_id, exc,
                    )
            else:
                logger.warning(
                    "[PROJET %s] Archive '%s' not found in workspace",
                    projet_id, body.archive,
                )

        # ── Run command if specified ────────────────────────────────
        ws_url = f"/ws/projet/{projet_id}"

        # Build merged env (decrypted encrypted_env + regular env)
        merged_env = dict(body.env or {})
        if encrypted_env_raw:
            merged_env.update(encrypted_env_raw)

        if body.run_command:
            # v1.6.7-4 #21: Wait for dependencies
            if depends_on:
                await _wait_for_dependencies(depends_on)

            # v1.6.7-3 #8: Synchronous mode
            if body.wait_for_completion:
                result = await _execute_project(
                    projet_id=projet_id,
                    workspace=workspace,
                    run_command=body.run_command,
                    run_args=body.run_args,
                    sudo=body.sudo,
                    timeout=body.timeout,
                    env=merged_env,
                    auto_delete=body.auto_delete,
                    pre_commands=body.pre_commands,
                    post_commands=body.post_commands,
                    callback_url=body.callback_url,
                    resource_limits=resource_limits,
                )
                return ShellProjetCreateResponse(
                    status="ok" if result["returncode"] == 0 else "error",
                    message=(
                        f"Project '{body.name}' created, command "
                        f"{'completed' if result['returncode'] == 0 else 'failed'}"
                    ),
                    projet_id=projet_id,
                    name=body.name,
                    workspace_path=workspace,
                    auto_delete=body.auto_delete,
                    ws_url=ws_url,
                    run_result={
                        "returncode": result["returncode"],
                        "stdout": result["stdout"],
                        "stderr": result["stderr"],
                        "timed_out": result["timed_out"],
                        "elapsed": result["elapsed"],
                        "workspace_deleted": result["workspace_deleted"],
                        "output_truncated": result.get("output_truncated", False),
                        "output_total_bytes": result.get("output_total_bytes"),
                    },
                )

            # Async mode
            asyncio.get_running_loop().create_task(
                _execute_project(
                    projet_id=projet_id,
                    workspace=workspace,
                    run_command=body.run_command,
                    run_args=body.run_args,
                    sudo=body.sudo,
                    timeout=body.timeout,
                    env=merged_env,
                    auto_delete=body.auto_delete,
                    pre_commands=body.pre_commands,
                    post_commands=body.post_commands,
                    callback_url=body.callback_url,
                    resource_limits=resource_limits,
                )
            )

            return ShellProjetCreateResponse(
                status="ok",
                message=f"Project '{body.name}' created, command executing",
                projet_id=projet_id,
                name=body.name,
                workspace_path=workspace,
                auto_delete=body.auto_delete,
                ws_url=ws_url,
            )

        return ShellProjetCreateResponse(
            status="ok",
            message=f"Project '{body.name}' created, workspace ready",
            projet_id=projet_id,
            name=body.name,
            workspace_path=workspace,
            auto_delete=body.auto_delete,
            ws_url=ws_url,
        )


@router.post(
    "/{projet_id}/upload",
    summary="Upload file(s)/archive to project workspace",
    response_model=ShellProjetUploadResponse,
)
async def upload_to_projet(
    projet_id: str,
    file: UploadFile = File(...),
    api_key: ApiKeyDep = None,
) -> ShellProjetUploadResponse:
    """Upload a file or archive to a project workspace.

    If the uploaded file is an archive (.zip, .tar.gz, etc.), it is
    automatically extracted into the workspace directory.
    """
    ws_mgr = get_projet_ws_manager()
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        if record.status == "running":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot upload to project '{projet_id}' while a command is running",
            )

        workspace = record.workspace_path
        if not os.path.isdir(workspace):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"Workspace directory no longer exists: {workspace}",
            )

        filename = file.filename or "upload"
        filename = os.path.basename(filename)
        file_path = os.path.join(workspace, filename)

        try:
            contents = await file.read()
            _enforce_workspace_quota(workspace, len(contents))
            with open(file_path, "wb") as f:
                f.write(contents)
            file_size = len(contents)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to save file: {exc}",
            )

        # Auto-extract if archive
        extracted = False
        extracted_files: Optional[List[str]] = None

        if _is_archive(filename):
            try:
                extracted_files = _extract_archive(file_path, workspace)
                extracted = True
                record.archive = filename
                record.save_to_db()

                try:
                    os.remove(file_path)
                except Exception:
                    pass

                await ws_mgr.send_extract_result(
                    projet_id, filename, extracted_files, success=True,
                )
                logger.info(
                    "[PROJET %s] Extracted %s (%d files)",
                    projet_id, filename, len(extracted_files),
                )
            except ValueError as exc:
                # v1.6.7-4 #4: Archive rejected for path traversal
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(exc),
                )
            except Exception as exc:
                await ws_mgr.send_extract_result(
                    projet_id, filename, [], success=False, error=str(exc),
                )
                logger.error(
                    "[PROJET %s] Archive extraction failed for %s: %s",
                    projet_id, filename, exc,
                )

        # v1.6.7-4 #16: Audit
        projet_db.audit_log(projet_id, "upload", detail=f"file={filename} size={file_size}")

        return ShellProjetUploadResponse(
            status="ok",
            message=f"File '{filename}' uploaded successfully",
            projet_id=projet_id,
            filename=filename,
            size=file_size,
            extracted=extracted,
            extracted_files=extracted_files,
        )


@router.post(
    "/{projet_id}/upload-multi",
    summary="Upload multiple files/archives to project workspace (v1.6.7-3)",
    response_model=ShellProjetMultiUploadResponse,
)
async def upload_multi_to_projet(
    projet_id: str,
    files: List[UploadFile] = File(...),
    api_key: ApiKeyDep = None,
) -> ShellProjetMultiUploadResponse:
    """Upload multiple files or archives to a project workspace."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        if record.status == "running":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot upload to project '{projet_id}' while a command is running",
            )

        workspace = record.workspace_path
        if not os.path.isdir(workspace):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"Workspace directory no longer exists: {workspace}",
            )

        uploaded_files: List[Dict[str, Any]] = []
        total_size = 0
        errors: List[str] = []

        for upload_file in files:
            filename = upload_file.filename or "upload"
            filename = os.path.basename(filename)
            file_path = os.path.join(workspace, filename)

            try:
                contents = await upload_file.read()
                _enforce_workspace_quota(workspace, total_size + len(contents))

                with open(file_path, "wb") as f:
                    f.write(contents)
                file_size = len(contents)
                total_size += file_size

                extracted = False
                extracted_files_item: Optional[List[str]] = None

                if _is_archive(filename):
                    try:
                        extracted_files_item = _extract_archive(file_path, workspace)
                        extracted = True
                        if not record.archive:
                            record.archive = filename
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass
                    except ValueError as exc:
                        errors.append(f"{filename}: rejected for security: {exc}")
                        extracted_files_item = []
                    except Exception as exc:
                        errors.append(f"{filename}: extraction failed: {exc}")
                        extracted_files_item = []

                uploaded_files.append({
                    "filename": filename,
                    "size": file_size,
                    "extracted": extracted,
                    "extracted_files": extracted_files_item,
                })

            except HTTPException:
                raise
            except Exception as exc:
                errors.append(f"{filename}: {exc}")

        record.save_to_db()
        projet_db.audit_log(projet_id, "upload_multi",
                            detail=f"{len(uploaded_files)} files, {total_size} bytes")

        msg = f"Uploaded {len(uploaded_files)} files"
        if errors:
            msg += f" ({len(errors)} errors)"

        return ShellProjetMultiUploadResponse(
            status="ok" if not errors else "partial",
            message=msg,
            projet_id=projet_id,
            uploaded_files=uploaded_files,
            total_size=total_size,
        )


@router.post(
    "/{projet_id}/run",
    summary="Execute command in project workspace",
    response_model=ShellProjetRunResponse,
)
async def run_in_projet(
    projet_id: str,
    body: ShellProjetRunRequest,
    api_key: ApiKeyDep,
) -> ShellProjetRunResponse:
    """Execute a command in an existing project workspace.

    v1.6.7-4: Added dry_run, resource_limits from project.
    """
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        if record.status == "running":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Project '{projet_id}' already has a running command",
            )

        allowed = _VALID_TRANSITIONS.get(record.status, set())
        if "running" not in allowed and record.status != "running":
            if record.status not in ("completed", "failed", "aborted", "ready"):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Project '{projet_id}' is in '{record.status}' state. "
                        f"Cannot run command from this state."
                    ),
                )

        workspace = record.workspace_path
        if not os.path.isdir(workspace):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"Workspace directory no longer exists: {workspace}",
            )

        # v1.6.7-4 #20: Dry-run mode
        dry_run = getattr(body, 'dry_run', False)
        if dry_run:
            return ShellProjetRunResponse(
                status="ok",
                message="[DRY RUN] Would execute command",
                projet_id=projet_id,
                run_command=body.run_command,
                returncode=0,
                stdout=f"[DRY RUN] Would run: {body.run_command}",
                stderr="",
                timed_out=False,
                elapsed=0.0,
                workspace_deleted=False,
            )

        # v1.6.7-4 #21: Wait for dependencies
        if record.depends_on:
            await _wait_for_dependencies(record.depends_on)

        # Build merged env (decrypted encrypted_env + body env)
        merged_env = dict(body.env or {})
        if record.encrypted_env:
            try:
                decrypted = _decrypt_env(record.encrypted_env)
                merged_env.update(decrypted)
            except Exception as exc:
                logger.warning("[PROJET %s] Failed to decrypt env: %s", projet_id, exc)

        # Merge project-level env
        if record.env:
            for k, v in record.env.items():
                if k not in merged_env:
                    merged_env[k] = v

        # Execute synchronously
        result = await _execute_project(
            projet_id=projet_id,
            workspace=workspace,
            run_command=body.run_command,
            run_args=body.run_args,
            sudo=body.sudo,
            timeout=body.timeout,
            env=merged_env,
            auto_delete=body.auto_delete,
            pre_commands=body.pre_commands,
            post_commands=body.post_commands,
            callback_url=body.callback_url,
            resource_limits=record.resource_limits,
        )

        response_status = "ok" if result["returncode"] == 0 else "error"
        response_message = "Command executed successfully"
        if result["timed_out"]:
            response_message = f"Command timed out after {body.timeout} seconds"
        elif result["returncode"] != 0:
            response_message = f"Command exited with code {result['returncode']}"

        return ShellProjetRunResponse(
            status=response_status,
            message=response_message,
            projet_id=projet_id,
            run_command=body.run_command,
            returncode=result["returncode"],
            stdout=result["stdout"],
            stderr=result["stderr"],
            timed_out=result["timed_out"],
            elapsed=result["elapsed"],
            workspace_deleted=result["workspace_deleted"],
            output_truncated=result.get("output_truncated", False),
            output_total_bytes=result.get("output_total_bytes"),
        )


# v1.6.6: /list MUST be defined BEFORE /show/{projet_id} and /{projet_id}

@router.get(
    "/list",
    summary="List all projects",
    response_model=ShellProjetListResponse,
)
async def list_projets(
    api_key: ApiKeyDep,
    owner: Optional[str] = None,
    status_filter: Optional[str] = None,
    name: Optional[str] = None,
    tag: Optional[str] = None,
    label: Optional[str] = None,
) -> ShellProjetListResponse:
    """List all project workspaces.

    v1.6.7-3 #11: Added tag and label filtering.
    """
    projects = list(_projects.values())

    if owner:
        projects = [p for p in projects if p.owner == owner]
    if status_filter:
        projects = [p for p in projects if p.status == status_filter]
    if name:
        projects = [p for p in projects if name in p.name]
    if tag:
        projects = [p for p in projects if tag in (p.tags or [])]
    if label:
        if "=" in label:
            lk, lv = label.split("=", 1)
            projects = [p for p in projects if (p.labels or {}).get(lk) == lv]
        else:
            projects = [p for p in projects if label in (p.labels or {})]

    return ShellProjetListResponse(
        status="ok",
        count=len(projects),
        projects=[p.to_workspace_info() for p in projects],
    )


# ── v1.6.7-3 #13: Health check (MUST be before /{projet_id}) ───────────


@router.get(
    "/health",
    summary="Shell projet system health check (v1.6.7-3)",
    response_model=ShellProjetHealthResponse,
)
async def health_projet(
    api_key: ApiKeyDep,
) -> ShellProjetHealthResponse:
    """Health check for the projet subsystem."""
    total = len(_projects)
    running = sum(1 for p in _projects.values() if p.status == "running")
    ready = sum(1 for p in _projects.values() if p.status == "ready")
    completed = sum(1 for p in _projects.values() if p.status == "completed")
    failed = sum(1 for p in _projects.values() if p.status == "failed")

    disk_usage = 0.0
    try:
        if _BASE_DIR.exists():
            disk_usage = sum(
                f.stat().st_size for f in _BASE_DIR.rglob("*") if f.is_file()
            ) / (1024 * 1024)
    except Exception:
        pass

    pool_active = len(_projet_pool._threads) if hasattr(_projet_pool, '_threads') else 0
    pool_max = _projet_pool._max_workers

    # v1.6.7-5: PostgreSQL health check
    pg_connected = False
    try:
        conn = projet_db._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        pg_connected = True
        projet_db._return_conn(conn)
    except Exception:
        pg_connected = False

    # Count orphan workspaces
    orphan_count = 0
    try:
        orphans = projet_db.find_orphan_workspaces(str(_BASE_DIR))
        orphan_count = len(orphans)
    except Exception:
        pass

    return ShellProjetHealthResponse(
        status="ok",
        total_projects=total,
        running=running,
        ready=ready,
        completed=completed,
        failed=failed,
        disk_usage_mb=round(disk_usage, 2),
        pool_active=pool_active,
        pool_max=pool_max,
        max_projects=_MAX_PROJECTS,
        max_workspace_size_mb=int(_MAX_WORKSPACE_SIZE / (1024 * 1024)),
        max_output_size_mb=round(_MAX_OUTPUT_SIZE / (1024 * 1024), 1),
        pg_host=_PG_HOST,
        pg_port=_PG_PORT,
        pg_dbname=_PG_DBNAME,
        pg_pool_min=_PG_POOL_MIN,
        pg_pool_max=_PG_POOL_MAX,
        pg_connected=pg_connected,
        orphan_workspaces=orphan_count,
    )


@router.get(
    "/show/{projet_id}",
    summary="Show project details",
    response_model=ShellProjetShowResponse,
)
async def show_projet(
    projet_id: str,
    api_key: ApiKeyDep,
) -> ShellProjetShowResponse:
    """Show detailed information about a project workspace."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    files: List[Dict[str, Any]] = []
    ws_path = Path(record.workspace_path)
    logs_available = False
    if ws_path.exists():
        try:
            for item in ws_path.rglob("*"):
                try:
                    stat = item.stat()
                    rel = item.relative_to(ws_path).as_posix()
                    files.append({
                        "name": rel,
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size if item.is_file() else None,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:],
                    })
                except Exception:
                    pass
            logs_available = (ws_path / ".projet_logs" / "meta.json").exists()
        except Exception:
            pass

    return ShellProjetShowResponse(
        status="ok",
        projet_id=projet_id,
        workspace=record.to_workspace_info(),
        files=files,
        logs_available=logs_available,
    )


# Alias: /{projet_id} redirects to /show/{projet_id}
@router.get(
    "/{projet_id}",
    summary="Show project details (alias)",
    response_model=ShellProjetShowResponse,
    include_in_schema=False,
)
async def show_projet_alias(
    projet_id: str,
    api_key: ApiKeyDep,
) -> ShellProjetShowResponse:
    """Alias for /shell/projet/show/{projet_id}."""
    return await show_projet(projet_id, api_key)


# ── v1.6.7-3 #4: Download workspace as .zip ───────────────────────────


@router.get(
    "/{projet_id}/download",
    summary="Download workspace as .zip archive",
)
async def download_projet(
    projet_id: str,
    api_key: ApiKeyDep,
) -> StreamingResponse:
    """Download the entire workspace as a .zip file."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    workspace = record.workspace_path
    if not os.path.isdir(workspace):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=f"Workspace directory no longer exists: {workspace}",
        )

    def _generate_zip():
        buf = tempfile.SpooledTemporaryFile(max_size=10 * 1024 * 1024)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, flist in os.walk(workspace):
                for fname in flist:
                    file_path = os.path.join(root, fname)
                    arcname = os.path.relpath(file_path, workspace)
                    try:
                        zf.write(file_path, arcname)
                    except Exception:
                        pass
        buf.seek(0)
        while True:
            chunk = buf.read(65536)
            if not chunk:
                break
            yield chunk
        buf.close()

    zip_filename = f"{record.name}_{projet_id}.zip"
    projet_db.audit_log(projet_id, "download", detail="workspace zip")
    return StreamingResponse(
        _generate_zip(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{zip_filename}"',
        },
    )


# ── v1.6.7-3 #14: Change owner ────────────────────────────────────────


@router.patch(
    "/{projet_id}/owner",
    summary="Transfer project ownership (v1.6.7-3)",
    response_model=ShellProjetOwnerChangeResponse,
)
async def change_owner(
    projet_id: str,
    body: ShellProjetOwnerChangeRequest,
    api_key: ApiKeyDep,
) -> ShellProjetOwnerChangeResponse:
    """Transfer project ownership to a new owner."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        old_owner = record.owner
        record.owner = body.new_owner
        record.save_to_db()

        projet_db.audit_log(projet_id, "change_owner",
                            detail=f"{old_owner} -> {body.new_owner}")

        logger.info(
            "[PROJET %s] Owner changed: %s -> %s",
            projet_id, old_owner, body.new_owner,
        )

        return ShellProjetOwnerChangeResponse(
            status="ok",
            message=f"Owner changed from '{old_owner}' to '{body.new_owner}'",
            projet_id=projet_id,
            old_owner=old_owner,
            new_owner=body.new_owner,
        )


# ── v1.6.7-3 #11: Update tags/labels ──────────────────────────────────


@router.patch(
    "/{projet_id}/tags",
    summary="Update project tags/labels (v1.6.7-3)",
    response_model=ShellProjetTagsUpdateResponse,
)
async def update_tags(
    projet_id: str,
    body: ShellProjetTagsUpdateRequest,
    api_key: ApiKeyDep,
) -> ShellProjetTagsUpdateResponse:
    """Update tags and/or labels for a project."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        if body.tags is not None:
            record.tags = body.tags
        if body.labels is not None:
            record.labels = body.labels
        record.save_to_db()

        projet_db.audit_log(projet_id, "update_tags", detail=f"tags={record.tags}")

        return ShellProjetTagsUpdateResponse(
            status="ok",
            message="Tags/labels updated",
            projet_id=projet_id,
            tags=record.tags,
            labels=record.labels,
        )


# ── Delete ──────────────────────────────────────────────────────────────


@router.delete(
    "/{projet_id}",
    summary="Delete project workspace",
    response_model=ShellProjetDeleteResponse,
)
async def delete_projet(
    projet_id: str,
    api_key: ApiKeyDep,
    force: bool = False,
) -> ShellProjetDeleteResponse:
    """Delete a project workspace and all its files.

    v1.6.7-4 #2: Uses set_status properly, no bypass.
    """
    ws_mgr = get_projet_ws_manager()
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        if record.status == "running" and not force:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Project '{projet_id}' has a running command. "
                    f"Use force=true to delete anyway."
                ),
            )

        # v1.6.7-4 #2: State machine transition
        if not record.set_status("deleting"):
            logger.warning(
                "[PROJET %s] Cannot transition from %s to deleting",
                projet_id, record.status,
            )
            if not force:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Cannot delete project in '{record.status}' state",
                )
        record.save_to_db()

        workspace = record.workspace_path

        # Delete workspace directory
        deleted_path = workspace
        try:
            if os.path.isdir(workspace):
                shutil.rmtree(workspace, ignore_errors=True)
                logger.info("[PROJET %s] Workspace deleted: %s", projet_id, workspace)

                parent = os.path.dirname(workspace)
                try:
                    if os.path.isdir(parent) and not os.listdir(parent):
                        os.rmdir(parent)
                except Exception:
                    pass
        except Exception as exc:
            logger.error("[PROJET %s] Failed to delete workspace: %s", projet_id, exc)

        # v1.6.7-4 #2: Set deleted status properly
        if not record.set_status("deleted"):
            projet_db.update_project_status(projet_id, "deleted")
            record.status = "deleted"

        # Audit BEFORE delete — FK constraint requires parent row to exist
        projet_db.audit_log(projet_id, "delete", detail=f"workspace={deleted_path}")

        _projects.pop(projet_id, None)
        projet_db.delete_project(projet_id)

        await ws_mgr.send_status(projet_id, "deleted", {"workspace": workspace})

        return ShellProjetDeleteResponse(
            status="ok",
            message=f"Project '{projet_id}' deleted",
            projet_id=projet_id,
            workspace_path=deleted_path,
        )


# ── v1.6.5: Abort running command ──────────────────────────────────────


@router.post(
    "/{projet_id}/abort",
    summary="Abort running command in project",
    response_model=ShellProjetAbortResponse,
)
async def abort_projet(
    projet_id: str,
    api_key: ApiKeyDep,
) -> ShellProjetAbortResponse:
    """Abort a running command in a project workspace.

    v1.6.7-4 #2: Uses set_status properly.
    """
    ws_mgr = get_projet_ws_manager()
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    if record.status != "running":
        return ShellProjetAbortResponse(
            status="ok",
            message=f"Project '{projet_id}' is not running any command",
            projet_id=projet_id,
            aborted=False,
        )

    # Try to terminate the running process
    proc = _running_processes.get(projet_id)
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        except Exception as exc:
            logger.warning("[PROJET %s] Error terminating process: %s", projet_id, exc)

    # v1.6.7-4 #2: State machine transition
    if not record.set_status("aborted"):
        projet_db.update_project_status(projet_id, "aborted")
        record.status = "aborted"
    record.completed_at = datetime.now(timezone.utc).isoformat()
    record.save_to_db()

    # Clean up
    _running_processes.pop(projet_id, None)

    projet_db.audit_log(projet_id, "abort", detail="user abort")

    await ws_mgr.send_status(projet_id, "aborted", {"reason": "user_abort"})

    logger.info("[PROJET %s] Command aborted by user", projet_id)

    return ShellProjetAbortResponse(
        status="ok",
        message=f"Command in project '{projet_id}' aborted",
        projet_id=projet_id,
        aborted=True,
    )


# ══════════════════════════════════════════════════════════════════════
#  v1.6.7-4 #12: Scheduler/Cron endpoints
# ══════════════════════════════════════════════════════════════════════


@router.post(
    "/{projet_id}/schedule",
    summary="Create a cron schedule for project (v1.6.7-4)",
)
async def create_schedule(
    projet_id: str,
    cron_expr: str = "",
    run_command: str = "",
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Create a cron schedule for a project."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    if not cron_expr or not run_command:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cron_expr and run_command are required",
        )

    # Validate cron expression format
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cron_expr must have 5 fields: minute hour dom month dow",
        )

    schedule_id = projet_db.save_schedule(projet_id, cron_expr, run_command)
    _start_scheduler_task()

    projet_db.audit_log(projet_id, "create_schedule",
                        detail=f"cron={cron_expr} cmd={run_command}")

    return {
        "status": "ok",
        "message": "Schedule created",
        "projet_id": projet_id,
        "schedule_id": schedule_id,
        "cron_expr": cron_expr,
        "run_command": run_command,
    }


@router.get(
    "/{projet_id}/schedule",
    summary="List schedules for project (v1.6.7-4)",
)
async def list_schedules(
    projet_id: str,
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """List all schedules for a project."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    schedules = projet_db.load_schedules(projet_id=projet_id)
    return {
        "status": "ok",
        "projet_id": projet_id,
        "schedules": schedules,
    }


@router.delete(
    "/{projet_id}/schedule/{schedule_id}",
    summary="Delete a schedule (v1.6.7-4)",
)
async def delete_schedule(
    projet_id: str,
    schedule_id: int,
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Delete a schedule entry."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    deleted = projet_db.delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found",
        )

    projet_db.audit_log(projet_id, "delete_schedule", detail=f"schedule_id={schedule_id}")

    return {
        "status": "ok",
        "message": f"Schedule {schedule_id} deleted",
        "projet_id": projet_id,
    }


# ══════════════════════════════════════════════════════════════════════
#  v1.6.7-4 #13: Project Templates endpoints
# ══════════════════════════════════════════════════════════════════════


@router.post(
    "/template",
    summary="Create a project template (v1.6.7-4)",
)
async def create_template(
    name: str = "",
    description: str = "",
    run_command: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    tags: Optional[List[str]] = None,
    labels: Optional[Dict[str, str]] = None,
    pre_commands: Optional[List[str]] = None,
    post_commands: Optional[List[str]] = None,
    resource_limits: Optional[Dict[str, Any]] = None,
    volumes: Optional[List[str]] = None,
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Create a new project template."""
    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Template name is required",
        )

    template_id = uuid.uuid4().hex[:12]
    template = {
        "template_id": template_id,
        "name": name,
        "description": description,
        "run_command": run_command,
        "env": env or {},
        "tags": tags or [],
        "labels": labels or {},
        "pre_commands": pre_commands or [],
        "post_commands": post_commands or [],
        "resource_limits": resource_limits or {},
        "volumes": volumes or [],
    }
    projet_db.save_template(template)

    projet_db.audit_log(None, "create_template", detail=f"template_id={template_id} name={name}")

    return {
        "status": "ok",
        "message": "Template created",
        "template_id": template_id,
        "name": name,
    }


@router.post(
    "/from-template/{template_id}",
    summary="Create project from template (v1.6.7-4)",
    response_model=ShellProjetCreateResponse,
)
async def create_from_template(
    template_id: str,
    name: Optional[str] = None,
    owner: Optional[str] = None,
    auto_delete: bool = True,
    api_key: ApiKeyDep = None,
) -> ShellProjetCreateResponse:
    """Create a new project from an existing template."""
    template = projet_db.load_template(template_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{template_id}' not found",
        )

    project_name = name or template["name"]
    projet_id = uuid.uuid4().hex[:12]
    proj_owner = owner or getattr(_settings, 'SHELL_PROJET_OWNER_DEFAULT', 'api-user')

    workspace = _create_workspace(
        name=project_name,
        projet_id=projet_id,
        volumes=template.get("volumes"),
    )

    record = ProjetRecord(
        projet_id=projet_id,
        name=project_name,
        workspace_path=workspace,
        owner=proj_owner,
        auto_delete=auto_delete,
        env=template.get("env"),
        tags=template.get("tags"),
        labels=template.get("labels"),
        volumes=template.get("volumes"),
        resource_limits=template.get("resource_limits"),
        template_id=template_id,
    )
    record.set_status("ready")
    _projects[projet_id] = record
    record.save_to_db()

    # If template has a run_command, execute it
    if template.get("run_command"):
        merged_env = dict(template.get("env") or {})
        asyncio.get_running_loop().create_task(
            _execute_project(
                projet_id=projet_id,
                workspace=workspace,
                run_command=template["run_command"],
                pre_commands=template.get("pre_commands"),
                post_commands=template.get("post_commands"),
                env=merged_env,
                auto_delete=auto_delete,
                resource_limits=template.get("resource_limits"),
            )
        )

    projet_db.audit_log(projet_id, "create_from_template",
                        detail=f"template_id={template_id}")

    return ShellProjetCreateResponse(
        status="ok",
        message=f"Project '{project_name}' created from template '{template_id}'",
        projet_id=projet_id,
        name=project_name,
        workspace_path=workspace,
        auto_delete=auto_delete,
        ws_url=f"/ws/projet/{projet_id}",
    )


@router.get(
    "/templates",
    summary="List all templates (v1.6.7-4)",
)
async def list_templates(
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """List all project templates."""
    templates = projet_db.load_all_templates()
    return {
        "status": "ok",
        "count": len(templates),
        "templates": templates,
    }


@router.delete(
    "/template/{template_id}",
    summary="Delete a template (v1.6.7-4)",
)
async def delete_template(
    template_id: str,
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Delete a project template."""
    deleted = projet_db.delete_template(template_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{template_id}' not found",
        )

    projet_db.audit_log(None, "delete_template", detail=f"template_id={template_id}")

    return {
        "status": "ok",
        "message": f"Template '{template_id}' deleted",
    }


# ══════════════════════════════════════════════════════════════════════
#  v1.6.7-4 #18: Snapshot/Rollback endpoints
# ══════════════════════════════════════════════════════════════════════


@router.post(
    "/{projet_id}/snapshot",
    summary="Create workspace snapshot (v1.6.7-4)",
)
async def create_snapshot(
    projet_id: str,
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Create a snapshot (zip) of the current workspace."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    workspace = record.workspace_path
    if not os.path.isdir(workspace):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=f"Workspace directory no longer exists",
        )

    snapshot_id = uuid.uuid4().hex[:12]
    snapshot_dir = os.path.join(workspace, ".projet_snapshots")
    os.makedirs(snapshot_dir, exist_ok=True)
    archive_path = os.path.join(snapshot_dir, f"{snapshot_id}.zip")

    try:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, flist in os.walk(workspace):
                # Skip the snapshots directory itself
                if ".projet_snapshots" in root:
                    continue
                for fname in flist:
                    file_path = os.path.join(root, fname)
                    arcname = os.path.relpath(file_path, workspace)
                    try:
                        zf.write(file_path, arcname)
                    except Exception:
                        pass
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create snapshot: {exc}",
        )

    projet_db.save_snapshot(projet_id, snapshot_id, archive_path)
    projet_db.audit_log(projet_id, "create_snapshot", detail=f"snapshot_id={snapshot_id}")

    return {
        "status": "ok",
        "message": "Snapshot created",
        "projet_id": projet_id,
        "snapshot_id": snapshot_id,
        "archive_path": archive_path,
    }


@router.post(
    "/{projet_id}/rollback/{snapshot_id}",
    summary="Rollback workspace to snapshot (v1.6.7-4)",
)
async def rollback_snapshot(
    projet_id: str,
    snapshot_id: str,
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Rollback the workspace to a previous snapshot."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    if record.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot rollback while a command is running",
        )

    # Find the snapshot
    snapshots = projet_db.load_snapshots(projet_id)
    snapshot = None
    for snap in snapshots:
        if snap["snapshot_id"] == snapshot_id:
            snapshot = snap
            break

    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Snapshot '{snapshot_id}' not found",
        )

    archive_path = snapshot["archive_path"]
    if not os.path.exists(archive_path):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=f"Snapshot archive no longer exists: {archive_path}",
        )

    workspace = record.workspace_path

    # v1.6.7-4 #3: Acquire per-project lock
    lock = _get_project_lock(projet_id)
    async with lock:
        # Clear workspace (except .projet_snapshots)
        snapshots_dir = os.path.join(workspace, ".projet_snapshots")
        for item in os.listdir(workspace):
            item_path = os.path.join(workspace, item)
            if item == ".projet_snapshots":
                continue
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
            except Exception:
                pass

        # Extract snapshot
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                # v1.6.7-4 #4: Validate before extraction
                for member in zf.namelist():
                    if member.startswith("/") or ".." in member:
                        raise ValueError("Snapshot contains dangerous paths")
                zf.extractall(workspace)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Snapshot rejected: {exc}",
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to extract snapshot: {exc}",
            )

    projet_db.audit_log(projet_id, "rollback_snapshot",
                        detail=f"snapshot_id={snapshot_id}")

    return {
        "status": "ok",
        "message": f"Rolled back to snapshot '{snapshot_id}'",
        "projet_id": projet_id,
        "snapshot_id": snapshot_id,
    }


# ══════════════════════════════════════════════════════════════════════
#  v1.6.7-4 #16: Audit Log endpoints
# ══════════════════════════════════════════════════════════════════════


@router.get(
    "/audit",
    summary="Get global audit log (v1.6.7-4)",
)
async def global_audit_log(
    api_key: ApiKeyDep = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Get the global audit log for all project actions."""
    entries = projet_db.load_audit_log(limit=limit)
    return {
        "status": "ok",
        "count": len(entries),
        "entries": entries,
    }


@router.get(
    "/{projet_id}/audit",
    summary="Get project audit log (v1.6.7-4)",
)
async def project_audit_log(
    projet_id: str,
    api_key: ApiKeyDep = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Get the audit log for a specific project."""
    record = _projects.get(projet_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{projet_id}' not found",
        )

    entries = projet_db.load_audit_log(projet_id=projet_id, limit=limit)
    return {
        "status": "ok",
        "projet_id": projet_id,
        "count": len(entries),
        "entries": entries,
    }


# ══════════════════════════════════════════════════════════════════════
#  v1.6.7-4 #17: Batch Project Operations
# ══════════════════════════════════════════════════════════════════════


@router.post(
    "/batch",
    summary="Batch project operations (v1.6.7-4)",
)
async def batch_operations(
    action: str = "",
    projects: Optional[List[Dict[str, Any]]] = None,
    api_key: ApiKeyDep = None,
) -> Dict[str, Any]:
    """Perform batch operations on projects.

    Supported actions:
        - create_multiple: Create multiple projects at once
        - run_all: Run a command on all non-running projects
        - delete_completed: Delete all completed projects
    """
    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    if action == "create_multiple" and projects:
        for proj_data in projects:
            try:
                pid = uuid.uuid4().hex[:12]
                name = proj_data.get("name", f"batch-{pid[:6]}")
                owner = proj_data.get("owner", "batch-user")
                workspace = _create_workspace(name=name, projet_id=pid)

                record = ProjetRecord(
                    projet_id=pid,
                    name=name,
                    workspace_path=workspace,
                    owner=owner,
                    auto_delete=proj_data.get("auto_delete", True),
                    env=proj_data.get("env"),
                    tags=proj_data.get("tags"),
                    volumes=proj_data.get("volumes"),
                    resource_limits=proj_data.get("resource_limits"),
                )
                record.set_status("ready")
                _projects[pid] = record
                record.save_to_db()
                projet_db.audit_log(pid, "batch_create", detail=f"name={name}")

                results.append({
                    "projet_id": pid,
                    "name": name,
                    "status": "created",
                })
            except Exception as exc:
                errors.append(f"Failed to create {proj_data.get('name', '?')}: {exc}")

    elif action == "run_all":
        run_command = (projects or [{}])[0].get("run_command", "echo 'batch run'")
        for pid, record in list(_projects.items()):
            if record.status in ("ready", "completed", "failed", "aborted"):
                try:
                    asyncio.get_running_loop().create_task(
                        _execute_project(
                            projet_id=pid,
                            workspace=record.workspace_path,
                            run_command=run_command,
                            sudo=record.sudo,
                            env=record.env,
                            auto_delete=False,
                            resource_limits=record.resource_limits,
                        )
                    )
                    results.append({"projet_id": pid, "status": "started"})
                except Exception as exc:
                    errors.append(f"Failed to run {pid}: {exc}")

    elif action == "delete_completed":
        to_delete = [
            pid for pid, rec in list(_projects.items())
            if rec.status in ("completed", "failed", "aborted")
        ]
        for pid in to_delete:
            record = _projects.get(pid)
            if not record:
                continue
            try:
                workspace = record.workspace_path
                if os.path.isdir(workspace):
                    shutil.rmtree(workspace, ignore_errors=True)
                    parent = os.path.dirname(workspace)
                    try:
                        if os.path.isdir(parent) and not os.listdir(parent):
                            os.rmdir(parent)
                    except Exception:
                        pass
                # Audit BEFORE delete — FK constraint requires parent row to exist
                projet_db.audit_log(pid, "batch_delete", detail="delete_completed")
                _projects.pop(pid, None)
                projet_db.delete_project(pid)
                results.append({"projet_id": pid, "status": "deleted"})
            except Exception as exc:
                errors.append(f"Failed to delete {pid}: {exc}")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown batch action: '{action}'. "
                   f"Supported: create_multiple, run_all, delete_completed",
        )

    projet_db.audit_log(None, "batch_operation",
                        detail=f"action={action} results={len(results)} errors={len(errors)}")

    return {
        "status": "ok" if not errors else "partial",
        "action": action,
        "results": results,
        "errors": errors,
    }
