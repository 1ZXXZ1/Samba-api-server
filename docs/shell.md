# Shell Execution API — v1.4.3 Add-on

## Overview

This add-on module extends the Samba AD DC Management API (v1.4) with a new
**Shell** router that provides REST endpoints for executing `bash` and `python3`
commands on the server, with optional `sudo` elevation.

## New Endpoints

All endpoints are under the `/api/v1/shell` prefix and require the `X-API-Key`
header for authentication.

### `GET /api/v1/shell/`

List available shell interpreters and their status on the server.

**Response:**
```json
{
  "status": "ok",
  "message": "Found 2 shell interpreters",
  "shells": [
    {
      "name": "bash",
      "available": true,
      "path": "/usr/bin/bash",
      "description": "Bourne Again SHell — standard Linux shell",
      "language": "bash"
    },
    {
      "name": "python3",
      "available": true,
      "path": "/usr/bin/python3",
      "description": "Python 3 interpreter",
      "language": "python"
    }
  ]
}
```

### `POST /api/v1/shell/exec`

Execute a single shell command.

**Request body:**
```json
{
  "shell": "bash",
  "sudo": false,
  "cmd": "ip a",
  "timeout": 30,
  "env": null
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "Command executed successfully",
  "shell": "bash",
  "sudo": false,
  "cmd": "ip a",
  "data": {
    "stdout": "1: lo: <LOOPBACK,UP,LOWER_UP> ...",
    "stderr": "",
    "returncode": 0,
    "timed_out": false
  }
}
```

**Python3 example:**
```json
{
  "shell": "python3",
  "sudo": false,
  "cmd": "import platform; print(platform.node())",
  "timeout": 10
}
```

**Sudo example:**
```json
{
  "shell": "bash",
  "sudo": true,
  "cmd": "cat /etc/samba/smb.conf",
  "timeout": 10
}
```

### `POST /api/v1/shell/script`

Execute a multi-line script. Lines are joined with `\n` and passed to
the shell interpreter.

**Request body:**
```json
{
  "shell": "bash",
  "sudo": false,
  "lines": [
    "#!/bin/bash",
    "echo 'System info:'",
    "uname -a",
    "echo 'Uptime:'",
    "uptime"
  ],
  "timeout": 30
}
```

## Files Added / Modified

| File | Action | Description |
|------|--------|-------------|
| `app/routers/shell.py` | **NEW** | Shell execution router with 3 endpoints |
| `app/models/shell.py` | **NEW** | Pydantic request/response models |
| `app/routers/__init__.py` | **MODIFIED** | Added shell_router export |
| `app/models/__init__.py` | **MODIFIED** | Added shell model exports |
| `app/main.py` | **MODIFIED** | Added shell router registration, version bump to 1.4.3 |

## Installation

1. Extract `api_v1.4.3_add.zip` into your existing API directory
2. Overwrite the modified files (`__init__.py`, `main.py`)
3. The new files (`shell.py`, `models/shell.py`) will be placed automatically
4. Restart the API server

```bash
# Backup existing files
cp app/routers/__init__.py app/routers/__init__.py.bak
cp app/models/__init__.py app/models/__init__.py.bak
cp app/main.py app/main.py.bak

# Extract add-on
unzip api_v1.4.3_add.zip -d /path/to/api/

# Restart server
sudo systemctl restart samba-api
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_SUDO_PASSWORD` | *(empty)* | Password for sudo -S (if NOPASSWD not configured) |

### Sudo Setup

For sudo execution, the API server process user needs sudo privileges.
Recommended approach — add a sudoers entry:

```bash
# /etc/sudoers.d/samba-api
samba-api ALL=(ALL) NOPASSWD: ALL
```

Or if password-based sudo is required, set `SAMBA_SUDO_PASSWORD`:

```bash
# In .env
SAMBA_SUDO_PASSWORD=your_password
```

## Security

- All endpoints require API-key authentication
- Blocked command patterns (e.g., `rm -rf /`) are rejected with HTTP 403
- Dangerous commands (reboot, shutdown) are allowed but flagged with warnings
- Timeout enforcement prevents runaway commands
- Commands run in isolated subprocesses via the worker pool
- Shell command execution is logged with timestamps and duration

## Example Usage

### curl — List shells
```bash
curl -H "X-API-Key: your-key" http://localhost:8099/api/v1/shell/
```

### curl — Execute bash command
```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"shell":"bash","sudo":false,"cmd":"ip a"}' \
  http://localhost:8099/api/v1/shell/exec
```

### curl — Execute with sudo
```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"shell":"bash","sudo":true,"cmd":"samba-tool domain level show"}' \
  http://localhost:8099/api/v1/shell/exec
```

### curl — Python3 script
```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"shell":"python3","sudo":false,"cmd":"import socket; print(socket.getfqdn())"}' \
  http://localhost:8099/api/v1/shell/exec
```
