"""
Configuration management for the Samba AD DC Management API server.

All settings are loaded from environment variables with sensible defaults.
Uses pydantic-settings for validation and type coercion.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Environment variable names are derived from field names with the
    ``SAMBA_`` prefix (e.g. ``SAMBA_API_HOST``, ``SAMBA_API_PORT``).
    """

    # ── Server ──────────────────────────────────────────────────────────
    API_HOST: str = Field(
        default="127.0.0.1",
        description="Host address the API server binds to.",
    )
    API_PORT: int = Field(
        default=8099,
        description="Port the API server listens on.",
    )
    API_KEY: str = Field(
        ...,
        description="Required API key for authenticating requests.",
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    # ── samba-tool paths ────────────────────────────────────────────────
    TOOL_PATH: str = Field(
        default="samba-tool",
        description="Path to the samba-tool binary.",
    )
    LDBSEARCH_PATH: str = Field(
        default="ldbsearch",
        description="Path to the ldbsearch binary for direct LDB queries.",
    )
    SMB_CONF: str = Field(
        default="/etc/samba/smb.conf",
        description="Path to the smb.conf configuration file.",
    )
    SERVER: str = Field(
        default="localhost",
        description=(
            "Default Samba server hostname (FQDN preferred). "
            "IMPORTANT: For DNS and DRS RPC commands, 'localhost' or "
            "'127.0.0.1' will NOT work because Kerberos cannot issue "
            "service tickets for 'localhost'. Use SAMBA_DC_HOSTNAME "
            "to set the real DC hostname for RPC operations."
        ),
    )
    DC_HOSTNAME: str = Field(
        default="",
        description=(
            "Real DC hostname for DNS and DRS RPC commands. "
            "DNS and DRS use DCE/RPC over SMB, not LDAP, so they need "
            "the DC's real network name (FQDN or short NetBIOS name). "
            "Using 'localhost' causes NT_STATUS_INVALID_PARAMETER because "
            "Kerberos cannot issue a service ticket for 'localhost'. "
            "If empty, auto-detected from hostname + realm. "
            "Examples: 'dc1.kcrb.local', 'dc1'."
        ),
    )
    REALM: str = Field(
        default="",
        description=(
            "Kerberos realm / DNS domain name (e.g. kcrb.local). "
            "Used by DRS, GPO, and time commands to locate the correct DC. "
            "If empty, derived from the SERVER FQDN when possible."
        ),
    )

    # ── LDAP / Kerberos ────────────────────────────────────────────────
    LDAP_URL: str = Field(
        default="",
        description=(
            "LDAP URL for Samba AD (e.g. ldaps://dc1.example.com). "
            "IMPORTANT: For DRS commands (showrepl, bind, options) to work, "
            "this should NOT be 'ldap://localhost' — use 'ldapi://' instead "
            "or the real DC IP address. ldap://localhost fails on many systems "
            "because there is no LDAP listener on the loopback interface. "
            "The ldapi:// protocol connects via the Unix domain socket and is "
            "always available on a local DC.  If both SAMBA_LDAPI_URL and "
            "SAMBA_LDAP_URL are set, SAMBA_LDAPI_URL is preferred for "
            "password/keytab operations."
        ),
    )
    LDAPI_URL: str = Field(
        default="",
        description=(
            "LDAPI URL for local Samba AD access (e.g. "
            "ldapi://%2Fvar%2Flib%2Fsamba%2Fprivate%2Fldap_priv%2Fldapi). "
            "Required for WRITE operations that need local sam.ldb access "
            "via the Samba server (create, delete, setpassword, etc.). "
            "READ operations use TDB_URL instead (see below). "
            "If empty, commands requiring local access will fall back "
            "to LDAP_URL, which may not support password/keytab retrieval."
        ),
    )
    TDB_URL: str = Field(
        default="",
        description=(
            "TDB URL for direct read-only sam.ldb access (e.g. "
            "tdb:///var/lib/samba/private/sam.ldb).  TDB opens the "
            "database file directly without going through the Samba LDAP "
            "server, so no authentication is required.  This is safe for "
            "READ operations (getpassword, user list, gpo listall, etc.) "
            "and supports parallel reads.  NEVER use tdb:// for WRITE "
            "operations — concurrent writes via tdb:// will corrupt the "
            "database.  If empty, auto-detected from the private dir."
        ),
    )
    TDB_SAM_LDB_PATH: str = Field(
        default="",
        description=(
            "Path to the sam.ldb file for constructing the TDB URL. "
            "If empty, auto-detected from smb.conf's 'private dir' "
            "parameter (default: /var/lib/samba/private/sam.ldb). "
            "Only used when TDB_URL is not explicitly set."
        ),
    )
    DOMAIN_DN: str = Field(
        default="",
        description=(
            "Base distinguished name for the AD domain "
            "(e.g. DC=kcrb,DC=local).  Used by routers that need to "
            "auto-construct full DNs from simple names (e.g. OU creation).  "
            "If empty, derived from the realm/WORKGROUP when possible."
        ),
    )
    CREDENTIALS_USER: str = Field(
        default="",
        description="Username for samba-tool -U flag.",
    )
    CREDENTIALS_PASSWORD: str = Field(
        default="",
        description="Password for samba-tool -U flag.",
    )
    USE_KERBEROS: bool = Field(
        default=False,
        description="Whether to use Kerberos (--use-kerberos=required).",
    )

    # ── JSON output mode ─────────────────────────────────────────────
    JSON_MODE: str = Field(
        default="auto",
        description=(
            "How to handle --json / --output-format=json flags. "
            "Options: 'auto' (try --json, fall back to --output-format=json, "
            "then text), 'force_json' (always --json), "
            "'force_output_format' (always --output-format=json), "
            "'text' (never add JSON flags)."
        ),
    )

    # ── Worker pool ────────────────────────────────────────────────────
    WORKER_POOL_SIZE: int = Field(
        default=4,
        description="Maximum number of concurrent samba-tool processes.",
    )

    # ── TMPDIR for samba-tool subprocesses ────────────────────────────
    TMPDIR: str = Field(
        default="/var/tmp",
        description=(
            "TMPDIR for samba-tool subprocesses. DRS commands create temp "
            "files during GSSAPI/Kerberos authentication that can exceed "
            "tmpfs quotas on /tmp. Setting this to /var/tmp (a real "
            "filesystem) avoids STATUS_QUOTA_EXCEEDED errors. This value "
            "is also set in os.environ at startup and inherited by all "
            "subprocesses."
        ),
    )

    # ── JWT Authentication (v2.7) ────────────────────────────────────
    JWT_SECRET_KEY: str = Field(
        default="",
        description=(
            "Secret key for JWT token signing. If empty, auto-generated "
            "and stored in ~/.samba-api-jwt-secret. "
"Environment: SAMBA_JWT_SECRET_KEY"
        ),
    )
    JWT_ALGORITHM: str = Field(
        default="HS256",
        description="JWT signing algorithm (default: HS256).",
    )
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        description="Access token expiry in minutes (default: 30).",
    )
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7,
        description="Refresh token expiry in days (default: 7).",
    )

    # ── CORS (v2.7) ────────────────────────────────────────────────────
    CORS_ORIGINS: str = Field(
        default="",
        description=(
            "Comma-separated list of allowed CORS origins. "
"If empty, all origins are allowed (*). "
"Example: 'https://admin.example.com,https://dc.example.com'. "
"Environment: SAMBA_CORS_ORIGINS"
        ),
    )

    # ── Rate Limiting (v2.7) ───────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        description="Enable or disable rate limiting middleware.",
    )
    RATE_LIMIT_AUTH_PER_MIN: int = Field(
        default=10,
        description="Max auth requests per minute per IP.",
    )
    RATE_LIMIT_READ_PER_MIN: int = Field(
        default=100,
        description="Max read requests per minute per user.",
    )
    RATE_LIMIT_WRITE_PER_MIN: int = Field(
        default=30,
        description="Max write requests per minute per user.",
    )
    RATE_LIMIT_SHELL_PROJET_PER_MIN: int = Field(
        default=120,
        description=(
            "Max shell projet requests per minute per user. "
            "Shell projet has higher limits because project workflows "
            "involve multiple sequential API calls "
            "(create -> upload -> run -> show). Default: 120."
        ),
    )
    RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        description="Sliding window size in seconds for rate limiting.",
    )

    # ── Cache (v2.7) ───────────────────────────────────────────────────
    CACHE_ENABLED: bool = Field(
        default=True,
        description="Enable or disable response caching.",
    )
    CACHE_TTL: int = Field(
        default=3,
        description="Default cache TTL in seconds for list endpoints (3s for production AD).",
    )
    CACHE_MAX_SIZE: int = Field(
        default=512,
        description="Maximum number of cached responses.",
    )

    # ── Logging (v2.7) ─────────────────────────────────────────────────
    LOG_FORMAT: str = Field(
        default="standard",
        description=(
            "Log format: 'standard' (human-readable) or 'json' "
"(structured JSON for ELK/Grafana). "
"Environment: SAMBA_LOG_FORMAT"
        ),
    )

    # ── Management DB (v2.7) ───────────────────────────────────────────
    MGMT_DB_PATH: str = Field(
        default="/var/lib/samba/api_mgmt.db",
        description="Path to the management SQLite database.",
    )

    # ── Shell execution settings (v1.4.3) ─────────────────────────────
    SHELL_ENABLED: bool = Field(
        default=True,
        description=(
            "Enable or disable the shell execution API. When False, "
"all /api/v1/shell/* endpoints return HTTP 503."
        ),
    )
    SHELL_SUDO_PASSWORD: str = Field(
        default="",
        description=(
            "Password for sudo -S when executing shell commands with "
"sudo=True. If empty, NOPASSWD must be configured in sudoers "
"for the API server process user."
        ),
    )
    SHELL_MAX_TIMEOUT: int = Field(
        default=600,
        description="Maximum allowed timeout for shell commands (10-3600).",
    )
    SHELL_BLOCKED_COMMANDS: str = Field(
        default="rm -rf /,mkfs.,dd if=,:(){ :|:& };:,fork bomb",
        description="Comma-separated list of blocked command patterns.",
    )

    # ── Shell Project settings (v1.6.4) ─────────────────────────────────
    SHELL_PROJET_BASE_DIR: str = Field(
        default="/home/AD-API-USER",
        description=(
            "Base directory for project workspaces. Projects are created at "
            "{SHELL_PROJET_BASE_DIR}/{name}/{id}. Default: /home/AD-API-USER"
        ),
    )
    SHELL_PROJET_MAX_PROJECTS: int = Field(
        default=100,
        description="Maximum number of concurrent project workspaces.",
    )
    SHELL_PROJET_MAX_ARCHIVE_SIZE: int = Field(
        default=500,  # MB
        description="Maximum archive upload size in megabytes.",
    )
    SHELL_PROJET_ALLOWED_ARCHIVE_TYPES: str = Field(
        default=".zip,.tar.gz,.tgz,.tar.bz2,.tar.xz,.tar,.gz,.7z",
        description="Comma-separated list of allowed archive file extensions.",
    )
    SHELL_PROJET_POOL_SIZE: int = Field(
        default=8,
        description=(
            "Thread pool size for project command execution. "
            "Controls how many project commands can run concurrently. "
            "Default: 8."
        ),
    )
    SHELL_PROJET_DEFAULT_TIMEOUT: int = Field(
        default=300,
        description=(
            "Default timeout for project command execution in seconds. "
            "Used when client does not specify a timeout. Default: 300."
        ),
    )
    SHELL_PROJET_OWNER_DEFAULT: str = Field(
        default="api-user",
        description=(
            "Default owner for projects when not explicitly specified. "
            "Default: 'api-user'."
        ),
    )

    # ── Shell Project settings v1.6.7-3 (new) ───────────────────────────
    SHELL_PROJET_MAX_OUTPUT_SIZE: int = Field(
        default=5242880,  # 5MB
        description=(
            "Maximum output size in bytes for stdout/stderr. "
            "When exceeded, output is truncated with a marker. "
            "Prevents OOM from commands that produce huge output. "
            "Default: 5242880 (5MB)."
        ),
    )
    SHELL_PROJET_MAX_WORKSPACE_SIZE: int = Field(
        default=500,  # MB
        description=(
            "Maximum workspace size in megabytes. Upload and extraction "
            "are rejected if workspace would exceed this limit. "
            "0 = unlimited. Default: 500."
        ),
    )

    # ── Shell Project settings v1.6.7-4 (new) ───────────────────────────
    SHELL_PROJET_TTL_CLEANUP_INTERVAL: int = Field(
        default=30,
        description=(
            "Interval in seconds for TTL cleanup background task. "
            "Lower values provide faster cleanup but more CPU usage. "
            "Default: 30."
        ),
    )
    # ── Shell Project PostgreSQL settings v1.6.7-5 (replaces SQLite) ──
    SHELL_PROJET_PG_HOST: str = Field(
        default="localhost",
        description=(
            "PostgreSQL server hostname for project persistence. "
            "Default: localhost."
        ),
    )
    SHELL_PROJET_PG_PORT: int = Field(
        default=5432,
        description="PostgreSQL server port. Default: 5432.",
    )
    SHELL_PROJET_PG_DBNAME: str = Field(
        default="samba_api",
        description=(
            "PostgreSQL database name for project persistence. "
            "The database must exist before starting the API. "
            "Create with: createdb samba_api. "
            "Default: samba_api."
        ),
    )
    SHELL_PROJET_PG_USER: str = Field(
        default="samba_api",
        description=(
            "PostgreSQL user for project persistence. "
            "The user must have CREATE TABLE permission on the database. "
            "Default: samba_api."
        ),
    )
    SHELL_PROJET_PG_PASSWORD: str = Field(
        default="",
        description=(
            "PostgreSQL password for project persistence. "
            "Default: empty (use peer/trust auth)."
        ),
    )
    SHELL_PROJET_PG_DSN: str = Field(
        default="",
        description=(
            "PostgreSQL connection string (DSN). If set, overrides "
            "individual PG_HOST/PG_PORT/PG_DBNAME/PG_USER/PG_PASSWORD. "
            "Example: postgresql://samba_api:secret@localhost:5432/samba_api"
        ),
    )
    SHELL_PROJET_PG_POOL_MIN: int = Field(
        default=2,
        description="Minimum PostgreSQL connection pool size. Default: 2.",
    )
    SHELL_PROJET_PG_POOL_MAX: int = Field(
        default=10,
        description="Maximum PostgreSQL connection pool size. Default: 10.",
    )
    SHELL_PROJET_CALLBACK_MAX_RETRIES: int = Field(
        default=3,
        description=(
            "Maximum number of retry attempts for webhook callbacks. "
            "Uses exponential backoff: 1s, 2s, 4s. Default: 3."
        ),
    )
    SHELL_PROJET_ENCRYPTION_KEY: str = Field(
        default="",
        description=(
            "Fernet encryption key for encrypted_env storage. "
            "If empty, auto-generated on first run. "
            "To generate: python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        ),
    )
    SHELL_PROJET_SHARED_VOLUMES_DIR: str = Field(
        default="/home/AD-API-USER/_shared",
        description=(
            "Base directory for shared volumes. "
            "Volume paths like /shared/data are resolved as "
            "{SHELL_PROJET_SHARED_VOLUMES_DIR}/data. "
            "Default: /home/AD-API-USER/_shared"
        ),
    )

    # ── AI Assistant (v1.6.8-1) ──────────────────────────────────────────
    AI_OPENROUTER_API_KEY: str = Field(
        default="",
        description=(
            "OpenRouter API key for the AI assistant. "
            "If empty, the AI endpoints return an error. "
            "Get a key at https://openrouter.ai/keys. "
            "Environment: SAMBA_AI_OPENROUTER_API_KEY"
        ),
    )
    AI_DEFAULT_MODEL: str = Field(
        default="openrouter/free",
        description=(
            "Default LLM model for AI requests. Can be overridden per-request. "
            "Examples: 'openrouter/free', 'openai/gpt-4o-mini', "
            "'anthropic/claude-3-haiku'. "
            "See https://openrouter.ai/models for available models. "
            "Environment: SAMBA_AI_DEFAULT_MODEL"
        ),
    )

    @field_validator("AI_DEFAULT_MODEL", mode="before")
    @classmethod
    def _validate_ai_model(cls, v: Any) -> Any:
        """Reject type-name strings like 'string' that are not valid model IDs."""
        if isinstance(v, str):
            invalid = {"string", "str", "int", "float", "bool", "none", "null", ""}
            if v.lower().strip() in invalid:
                return "openrouter/free"
        return v

    AI_TEMPERATURE: float = Field(
        default=0.7,
        description=(
            "LLM temperature (0.0 - 2.0). Lower = more deterministic, "
            "higher = more creative. Default: 0.7. "
            "Environment: SAMBA_AI_TEMPERATURE"
        ),
    )
    AI_MAX_TOKENS: int = Field(
        default=2046,
        description=(
            "Maximum completion tokens for LLM responses. "
            "Default: 2046. "
            "Environment: SAMBA_AI_MAX_TOKENS"
        ),
    )
    AI_API_BASE: str = Field(
        default="http://127.0.0.1:8099",
        description=(
            "Base URL of this API server, used by the AI service to "
            "fetch its own /openapi.json schema. Must be accessible "
            "from the server process. Default: http://127.0.0.1:8099. "
            "Environment: SAMBA_AI_API_BASE"
        ),
    )

    # ── AI Assistant — Rate Limit & Fallback (v1.6.8-4) ────────────────
    AI_RATE_LIMIT_RETRIES: int = Field(
        default=3,
        description=(
            "Maximum number of retry attempts when the LLM provider "
            "returns a 429 Rate Limit error. Each retry waits for the "
            "duration specified by the provider's Retry-After header "
            "(capped by AI_RATE_LIMIT_MAX_WAIT). Default: 3. "
            "Environment: SAMBA_AI_RATE_LIMIT_RETRIES"
        ),
    )
    AI_RATE_LIMIT_MAX_WAIT: int = Field(
        default=30,
        description=(
            "Maximum wait time in seconds for a single 429 retry. "
            "If the provider's Retry-After value exceeds this, it is "
            "capped. Prevents excessively long waits. Default: 30. "
            "Environment: SAMBA_AI_RATE_LIMIT_MAX_WAIT"
        ),
    )
    AI_FALLBACK_MODELS: str = Field(
        default="",
        description=(
            "Comma-separated list of fallback LLM models to try if the "
            "primary model is rate-limited (429) and all retries are "
            "exhausted. Each fallback model gets its own retry budget. "
            "Example: 'meta-llama/llama-4-scout:free,google/gemma-3-27b-it:free'. "
            "If empty, no fallback is attempted. "
            "Environment: SAMBA_AI_FALLBACK_MODELS"
        ),
    )
    AI_MAX_SCHEMA_CHARS: int = Field(
        default=12000,
        description=(
            "Maximum size in characters for the compressed OpenAPI schema "
            "sent to the LLM. If the schema exceeds this limit, it is "
            "progressively stripped: first params/body_fields, then "
            "summaries, then operationIds, keeping only paths + methods. "
            "Lower values save tokens but give the LLM less context. "
            "Default: 12000 (~3000 tokens). "
            "Environment: SAMBA_AI_MAX_SCHEMA_CHARS"
        ),
    )

    # ── AI Agent — Direct Execution (v1.6.8-6) ────────────────────────
    AI_AGENT_MAX_STEPS: int = Field(
        default=10,
        description=(
            "Maximum number of agent loop iterations (tool call → execute → "
            "feed result back). Each iteration is one LLM API call + tool "
            "execution. Higher values allow more complex multi-step tasks. "
            "Default: 10. "
            "Environment: SAMBA_AI_AGENT_MAX_STEPS"
        ),
    )
    AI_AGENT_EXPORT_DIR: str = Field(
        default="/home/AD-API-USER/ai-exports",
        description=(
            "Directory where the AI agent saves exported files. Created "
            "automatically if it does not exist. Files saved via the "
            "save_file tool are sandboxed to this directory. "
            "Default: /home/AD-API-USER/ai-exports. "
            "Environment: SAMBA_AI_AGENT_EXPORT_DIR"
        ),
    )
    AI_AGENT_SHELL_ENABLED: bool = Field(
        default=True,
        description=(
            "Enable or disable shell command execution via the AI agent. "
            "When False, the execute_shell_command tool returns an error "
            "instead of executing the command. This is a safety switch for "
            "environments where shell access should be restricted. "
            "Default: True. "
            "Environment: SAMBA_AI_AGENT_SHELL_ENABLED"
        ),
    )
    AI_AGENT_SHELL_TIMEOUT: int = Field(
        default=30,
        description=(
            "Maximum execution time in seconds for shell commands run by "
            "the AI agent. Commands exceeding this timeout are killed. "
            "Hard cap at 300 seconds. Default: 30. "
            "Environment: SAMBA_AI_AGENT_SHELL_TIMEOUT"
        ),
    )
    AI_AGENT_SHELL_BLOCKED_CMDS: str = Field(
        default="rm -rf /,mkfs.,dd if=,:(){ :|:& };:,fork bomb,format ",
        description=(
            "Comma-separated list of blocked command patterns. Shell "
            "commands matching any of these patterns are rejected by the "
            "execute_shell_command tool. Use to prevent destructive "
            "operations. Default: 'rm -rf /,mkfs.,dd if=,:(){ :|:& };:,"
            "fork bomb,format '. "
            "Environment: SAMBA_AI_AGENT_SHELL_BLOCKED_CMDS"
        ),
    )
    AI_AGENT_API_TIMEOUT: int = Field(
        default=60,
        description=(
            "HTTP timeout in seconds for internal API calls made by the "
            "AI agent (execute_samba_api tool). The agent calls the API "
            "server on http://127.0.0.1:8099, so a longer timeout is safe "
            "for operations that may take time (e.g., DRS replication, "
            "large user lists). Default: 60. "
            "Environment: SAMBA_AI_AGENT_API_TIMEOUT"
        ),
    )
    AI_AGENT_MAX_MENU_CHARS: int = Field(
        default=8000,
        description=(
            "Maximum size in characters for the API endpoint menu included "
            "in the agent's system prompt. The menu is generated from the "
            "compressed OpenAPI schema and progressively stripped to fit: "
            "Level 1 — full detail (paths + summaries + params + body), "
            "Level 2 — paths + summaries only, "
            "Level 3 — paths only. "
            "Lower values save tokens but give the AI less context about "
            "available endpoints. Default: 8000 (~2000 tokens). "
            "Environment: SAMBA_AI_AGENT_MAX_MENU_CHARS"
        ),
    )

    # ── Auto-detected server role (cached at startup) ──────────────────
    SERVER_ROLE: str = Field(
        default="",
        description=(
            "Auto-detected Samba server role from smb.conf via testparm. "
            "Populated on first access if empty. Examples: "
            "'active directory domain controller', 'domain member', "
            "'standalone server'. Used by domain router for fast role "
            "checks without repeated testparm calls."
        ),
    )

    # ── Validators ─────────────────────────────────────────────────────
    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def _normalise_log_level(cls, v: str) -> str:
        """Coerce log level to uppercase and validate against known levels."""
        v = v.upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}, got '{v}'")
        return v

    @field_validator("API_PORT", mode="before")
    @classmethod
    def _validate_port(cls, v: int) -> int:
        """Ensure the port is in the valid range."""
        v = int(v)
        if not (1 <= v <= 65535):
            raise ValueError(f"API_PORT must be between 1 and 65535, got {v}")
        return v

    @field_validator("JSON_MODE", mode="before")
    @classmethod
    def _validate_json_mode(cls, v: str) -> str:
        """Validate JSON_MODE is one of the allowed values."""
        v = v.lower().strip()
        allowed = {"auto", "force_json", "force_output_format", "text"}
        if v not in allowed:
            raise ValueError(f"JSON_MODE must be one of {allowed}, got '{v}'")
        return v

    @field_validator("LOG_FORMAT", mode="before")
    @classmethod
    def _validate_log_format(cls, v: str) -> str:
        """Validate LOG_FORMAT is one of the allowed values."""
        v = v.lower().strip()
        allowed = {"standard", "json"}
        if v not in allowed:
            raise ValueError(f"LOG_FORMAT must be one of {allowed}, got '{v}'")
        return v

    @field_validator("JWT_ALGORITHM", mode="before")
    @classmethod
    def _validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm."""
        v = v.upper().strip()
        allowed = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
        if v not in allowed:
            raise ValueError(f"JWT_ALGORITHM must be one of {allowed}, got '{v}'")
        return v

    @field_validator("WORKER_POOL_SIZE", mode="before")
    @classmethod
    def _validate_pool_size(cls, v: int) -> int:
        """Ensure the pool size is at least 1."""
        v = int(v)
        if v < 1:
            raise ValueError(f"WORKER_POOL_SIZE must be >= 1, got {v}")
        return v

    model_config = {
        "env_prefix": "SAMBA_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }

    def ensure_server_role(self) -> str:
        """Return the server role, auto-detecting if not yet cached.

        Uses ``testparm --parameter-name=server role`` with a 5-second
        timeout.  The result is stored in ``self.SERVER_ROLE`` so that
        subsequent calls skip the testparm invocation.

        Returns the role string in lowercase, e.g.
        ``'active directory domain controller'``,
        ``'domain member'``, ``'standalone server'``,
        or ``'unknown'`` if detection fails.
        """
        # Fix v15: Map non-standard role names returned by some Samba
        # builds (e.g. ALT Linux) to their canonical equivalents.
        # testparm or LoadParm.server_role() can return
        # 'role_active_directory_dc' instead of
        # 'active directory domain controller', which breaks
        # string-based role checks in domain.py.
        _ROLE_MAP = {
            'role_active_directory_dc': 'active directory domain controller',
            'role_domain_member': 'domain member',
            'role_standalone': 'standalone server',
            'role_classic_primary_domain_controller': 'classic primary domain controller',
            'role_classic_backup_domain_controller': 'classic backup domain controller',
            # Fix v18: Additional non-standard role string variants
            # returned by some Samba builds (ALT Linux, custom patches).
            'active directory domain controller': 'active directory domain controller',
            'domain member': 'domain member',
            'standalone server': 'standalone server',
            'active directory dc': 'active directory domain controller',
            'ad dc': 'active directory domain controller',
            'dc': 'active directory domain controller',
            'member': 'domain member',
            'role_active_directory_domain_controller': 'active directory domain controller',
        }
        if self.SERVER_ROLE:
            return self.SERVER_ROLE

        try:
            import subprocess
            # Fix v3-11: Use --suppress-prompt instead of -s.
            # The -s flag requires an argument in some Samba builds
            # (ALT Linux), causing "testparm: error: -s option requires
            # 1 argument".  --suppress-prompt is the correct way to
            # suppress the interactive prompt in Samba 4.7+.
            cmd = [
                self.TOOL_PATH, "testparm",
                "--parameter-name=server role",
                f"--configfile={self.SMB_CONF}",
                "--suppress-prompt",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                role = result.stdout.strip().lower()
                if role:
                    # Fix v3-17: Use info level so role detection is visible
                    # in default (INFO) log output.
                    logger.info("testparm returned raw server role: '%s'", role)
                    # Fix v15: Normalise non-standard role names
                    role = _ROLE_MAP.get(role, role)
                    self.SERVER_ROLE = role
                    logger.info("Auto-detected server role: %s", role)
                    return role
        except FileNotFoundError:
            logger.warning("testparm binary not found at '%s'", self.TOOL_PATH)
        except subprocess.TimeoutExpired:
            logger.error("testparm timed out while detecting server role (5s timeout)")
        except Exception as exc:
            logger.error("Failed to detect server role via testparm: %s", exc, exc_info=True)

        # Fix v12/v13: Fallback — read server role directly from smb.conf
        # using samba.param.LoadParm.  This works even when testparm
        # is not installed or times out, because LoadParm reads the
        # configuration file directly without spawning a subprocess.
        #
        # Fix v15: _ROLE_MAP (defined above) normalises non-standard
        # role names from LoadParm.server_role().
        try:
            from samba.param import LoadParm
            lp = LoadParm()
            lp.load(self.SMB_CONF)
            role = lp.server_role()
            if role:
                role = role.lower()
                # Fix v3-17: Use info level so role detection is visible
                # in default (INFO) log output.
                logger.info("LoadParm.server_role() returned raw: '%s'", role)
                # Apply the mapping to normalise non-standard names
                role = _ROLE_MAP.get(role, role)
                self.SERVER_ROLE = role
                logger.info("Auto-detected server role via LoadParm: %s", role)
                return role
        except ImportError:
            logger.debug("samba.param.LoadParm not available, skipping LoadParm fallback")
        except Exception as exc:
            logger.warning("Failed to detect server role via LoadParm: %s", exc)

        # Fix v13: Third fallback — parse smb.conf directly.
        # On minimal installations neither testparm nor the samba Python
        # module may be available, but the plain-text smb.conf file
        # always exists.  Read it and look for the "server role" line.
        try:
            import re as _re
            with open(self.SMB_CONF, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    stripped = line.strip().lower()
                    # Match "server role = ..." (with any amount of whitespace)
                    m = _re.match(r"^server\s+role\s*=\s*(.+)$", stripped)
                    if m:
                        role = m.group(1).strip()
                        if role:
                            # Fix v15: Normalise non-standard role names
                            role = _ROLE_MAP.get(role, role)
                            self.SERVER_ROLE = role
                            logger.info(
                                "Auto-detected server role from smb.conf (direct read): %s",
                                role,
                            )
                            return role
        except FileNotFoundError:
            logger.warning("smb.conf not found at '%s'", self.SMB_CONF)
        except Exception as exc:
            logger.warning("Failed to read server role from smb.conf: %s", exc)

        # Fix v18: Fourth fallback — probe for local DC indicators.
        # If we got here, testparm, LoadParm, and smb.conf parsing all
        # failed or returned nothing useful.  Check for the presence of
        # a local sam.ldb LDAPI socket and the sam.ldb file itself.
        # On a Domain Controller, both /var/lib/samba/private/sam.ldb
        # and the LDAPI socket exist, and the processes list contains
        # dreplsrv/kdc_server.  On a domain member, sam.ldb does NOT
        # exist (only idmap.ldb or secrets.ldb).  This heuristic is
        # reliable for distinguishing DC from member/standalone.
        try:
            import os as _os
            _DC_INDICATORS = [
                "/var/lib/samba/private/sam.ldb",
                "/var/lib/samba/private/ldapi",
                "/var/lib/samba/private/ldap_priv/ldapi",
            ]
            found_indicators = sum(1 for p in _DC_INDICATORS if _os.path.exists(p))
            if found_indicators >= 2:
                # At least sam.ldb + LDAPI socket → very likely a DC
                self.SERVER_ROLE = "active directory domain controller"
                logger.info(
                    "Auto-detected server role via LDAPI/sam.ldb probe: %s "
                    "(found %d/%d DC indicators)",
                    self.SERVER_ROLE, found_indicators, len(_DC_INDICATORS),
                )
                return self.SERVER_ROLE
            elif found_indicators == 1:
                # Only one indicator — could be a DC with socket not yet
                # created, or a member with a stale file.  Try to run
                # 'samba-tool processes' as a more authoritative check.
                try:
                    import subprocess as _sp
                    proc_result = _sp.run(
                        [self.TOOL_PATH, "processes", f"--configfile={self.SMB_CONF}", "--suppress-prompt"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if proc_result.returncode == 0:
                        proc_output = proc_result.stdout.lower()
                        if "dreplsrv" in proc_output or "kdc_server" in proc_output:
                            self.SERVER_ROLE = "active directory domain controller"
                            logger.info(
                                "Auto-detected server role via samba-tool processes: %s",
                                self.SERVER_ROLE,
                            )
                            return self.SERVER_ROLE
                except Exception:
                    pass  # processes check failed, fall through
        except Exception as exc:
            logger.warning("Failed to probe for DC indicators: %s", exc)

        self.SERVER_ROLE = "unknown"
        return self.SERVER_ROLE


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton ``Settings`` instance.

    The first call creates the instance from environment variables;
    subsequent calls return the same object.  Call
    ``get_settings.cache_clear()`` to force re-creation (useful in tests).
    """
    settings = Settings()
    # Fix v3-14: Do NOT auto-detect server role eagerly at startup.
    # Previously, ensure_server_role() was called here, but this
    # caused race conditions: the API server might start before
    # Samba is fully initialized, leading to incorrect role detection
    # ("domain member" instead of "active directory domain controller")
    # and a permanently cached LDAPI-not-found result.
    #
    # Now, role detection is deferred until the first endpoint that
    # needs it calls settings.ensure_server_role().  This gives Samba
    # time to start up and create the LDAPI socket.

    # Fix v13-2: Warn if SAMBA_LDAP_URL is set to ldap://localhost.
    # This is a common misconfiguration that causes DRS commands
    # (showrepl, bind, options) to fail with NT_STATUS_BAD_NETWORK_NAME
    # because there is no LDAP listener on the loopback interface.
    # The recommended fix is to set SAMBA_LDAP_URL=ldapi:// or to
    # the real IP address of the DC.
    if settings.LDAP_URL and settings.LDAP_URL.lower().startswith("ldap://localhost"):
        logger.warning(
            "SAMBA_LDAP_URL is set to '%s' which likely will NOT work. "
            "DRS commands (showrepl, bind, options) and other operations "
            "that use this URL will fail with NT_STATUS_BAD_NETWORK_NAME "
            "because there is no LDAP listener on the loopback interface. "
            "Recommended fix: set SAMBA_LDAP_URL=ldapi:// (for local DC) "
            "or SAMBA_LDAP_URL=ldap://<real_DC_IP> (for remote DC). "
            "Alternatively, set SAMBA_LDAPI_URL=ldapi:// for local access.",
            settings.LDAP_URL,
        )

    return settings
