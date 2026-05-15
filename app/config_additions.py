"""
Configuration additions for Shell API (v1.4.3) and Shell Project (v1.6.7).

Add these fields to the Settings class in app/config.py:

    # ── Shell execution settings (v1.4.3) ─────────────────────────────
    SHELL_ENABLED: bool = Field(
        default=True,
        description=(
            "Enable or disable the shell execution API.  When False, "
            "all /api/v1/shell/* endpoints return HTTP 503."
        ),
    )
    SHELL_SUDO_PASSWORD: str = Field(
        default="",
        description=(
            "Password for sudo -S when executing shell commands with "
            "sudo=True.  If empty, NOPASSWD must be configured in sudoers "
            "for the API server process user."
        ),
    )
    SHELL_MAX_TIMEOUT: int = Field(
        default=600,
        ge=10,
        le=3600,
        description=(
            "Maximum allowed timeout for shell commands.  Clients requesting "
            "a timeout above this value will receive an error.  Default: 600s "
            "(10 minutes).  Maximum: 3600s (1 hour)."
        ),
    )
    SHELL_BLOCKED_COMMANDS: str = Field(
        default="rm -rf /,mkfs.,dd if=,:(){ :|:& };:,fork bomb",
        description=(
            "Comma-separated list of blocked command patterns.  Commands "
            "matching any of these patterns will be rejected with HTTP 403."
        ),
    )

    # ── Shell Project settings (v1.6.7) ─────────────────────────────────
    SHELL_PROJET_BASE_DIR: str = Field(
        default="/home/AD-API-USER",
        description="Base directory for project workspaces.",
    )
    SHELL_PROJET_MAX_PROJECTS: int = Field(
        default=100,
        description="Maximum number of concurrent project workspaces.",
    )
    SHELL_PROJET_MAX_ARCHIVE_SIZE: int = Field(
        default=500,
        description="Maximum archive upload size in megabytes.",
    )
    SHELL_PROJET_ALLOWED_ARCHIVE_TYPES: str = Field(
        default=".zip,.tar.gz,.tgz,.tar.bz2,.tar.xz,.tar,.gz,.7z",
        description="Comma-separated list of allowed archive file extensions.",
    )
    SHELL_PROJET_POOL_SIZE: int = Field(
        default=8,
        description="Thread pool size for project command execution.",
    )
    SHELL_PROJET_DEFAULT_TIMEOUT: int = Field(
        default=300,
        description="Default timeout for project command execution in seconds.",
    )
    SHELL_PROJET_OWNER_DEFAULT: str = Field(
        default="api-user",
        description="Default owner for projects when not explicitly specified.",
    )

And add SAMBA_ prefix via model_config (already configured).
These will be read as SAMBA_SHELL_ENABLED, SAMBA_SHELL_SUDO_PASSWORD,
SAMBA_SHELL_MAX_TIMEOUT, SAMBA_SHELL_BLOCKED_COMMANDS,
SAMBA_SHELL_PROJET_BASE_DIR, SAMBA_SHELL_PROJET_MAX_PROJECTS,
SAMBA_SHELL_PROJET_MAX_ARCHIVE_SIZE, SAMBA_SHELL_PROJET_ALLOWED_ARCHIVE_TYPES,
SAMBA_SHELL_PROJET_POOL_SIZE, SAMBA_SHELL_PROJET_DEFAULT_TIMEOUT,
SAMBA_SHELL_PROJET_OWNER_DEFAULT.
"""

# This file documents the config additions; it is not imported directly.
# Add the fields above to app/config.py Settings class manually.
