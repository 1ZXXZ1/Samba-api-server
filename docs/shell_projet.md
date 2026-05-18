# Shell Project API — v1.6.5

## Overview

This module extends the Samba AD DC Management API with a **Shell Project** system
that provides isolated workspace environments for script execution with file upload,
archive extraction, and real-time WebSocket output streaming.

## Key Features

- **Isolated Workspaces**: Each project creates an isolated directory at `/home/AD-API-USER/{name}/{id}`
- **File Upload**: Upload scripts, archives, and any files to project workspaces
- **Archive Extraction**: Auto-extract .zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar, .gz, .7z
- **Full Bash Scripting**: Execute standard bash scripts with if/then/elif/else/fi, case/esac,
  for/do/done, while/do/done, until/do/done, select/do/done
- **WebSocket Real-Time Output**: Stream stdout/stderr in real-time via WebSocket
- **Auto-Delete**: Workspaces are automatically cleaned up after execution (default: on)
- **Pre/Post Commands**: Run setup commands before and cleanup commands after the main script

## New Endpoints

### `POST /api/v1/shell/projet/`

Create a new project workspace. Optionally specify an archive to extract and a command to run.

**Request body:**
```json
{
    "name": "deploy-app",
    "archive": "deploy.zip",
    "run_command": "./run.sh",
    "run_args": ["--force"],
    "auto_delete": true,
    "sudo": false,
    "timeout": 300,
    "env": {"APP_ENV": "production"},
    "owner": "admin",
    "permissions": "755",
    "pre_commands": ["chmod +x run.sh", "pip install -r requirements.txt"],
    "post_commands": ["rm -f secrets.env"]
}
```

**Response:**
```json
{
    "status": "ok",
    "message": "Project 'deploy-app' created, command executing",
    "projet_id": "a1b2c3d4e5f6",
    "name": "deploy-app",
    "workspace_path": "/home/AD-API-USER/deploy-app/a1b2c3d4e5f6",
    "auto_delete": true,
    "ws_url": "/ws/projet/a1b2c3d4e5f6"
}
```

### `POST /api/v1/shell/projet/{id}/upload`

Upload a file or archive to an existing project workspace.

**Multipart form:**
```
curl -X POST \
  -H "X-API-Key: your-key" \
  -F "file=@deploy.zip" \
  http://localhost:8099/api/v1/shell/projet/a1b2c3d4e5f6/upload
```

Archives are automatically extracted after upload.

### `POST /api/v1/shell/projet/{id}/run`

Execute a command in an existing project workspace.

**Request body:**
```json
{
    "run_command": "echo -e 'ER: no ip\\nOK' | ./run.sh && echo 'OK - код 200' || echo 'ОШИБКА'",
    "timeout": 60,
    "auto_delete": false
}
```

**With bash conditions:**
```json
{
    "run_command": "if [ -f config.sh ]; then source config.sh; else echo 'no config'; fi",
    "pre_commands": ["chmod +x *.sh"],
    "post_commands": ["rm -f *.tmp"]
}
```

### `GET /api/v1/shell/projet/show/{id}`

Show project details including file listing.

### `GET /api/v1/shell/projet/list`

List all projects. Supports query parameters: `owner`, `status_filter`, `name`.

```
GET /api/v1/shell/projet/list?owner=admin&status_filter=completed
```

### `DELETE /api/v1/shell/projet/{id}`

Delete a project workspace. Use `force=true` to delete while a command is running.

### `POST /api/v1/shell/projet/{id}/abort` (v1.6.5)

Abort a running command in a project workspace. Sends SIGTERM to the process,
then SIGKILL if it doesn't stop within 5 seconds.

**Response:**
```json
{
    "status": "ok",
    "message": "Command in project 'a1b2c3d4e5f6' aborted",
    "projet_id": "a1b2c3d4e5f6",
    "aborted": true
}
```

### `POST /api/v1/shell/script/file` (v1.6.4 fix)

Upload a script file and execute it directly. This is the fix for `/shell/script` —
now you can send a file instead of just inline script text.

**Multipart form:**
```
curl -X POST \
  -H "X-API-Key: your-key" \
  -F "file=@run.sh" \
  -F "shell=bash" \
  -F "auto_delete=true" \
  http://localhost:8099/api/v1/shell/script/file
```

## WebSocket Endpoints

### `WS /ws/projet/{projet_id}`

Real-time output stream for a specific project. Receives:
- `output` — stdout/stderr data chunks
- `status` — project status changes (creating → ready → running → completed/failed)
- `command_result` — final execution result
- `extract_result` — archive extraction result

**Example (JavaScript):**
```javascript
const ws = new WebSocket('ws://localhost:8099/ws/projet/a1b2c3d4e5f6');
ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'output') {
        console.log(`[${msg.stream}] ${msg.data}`);
    } else if (msg.type === 'status') {
        console.log(`Status: ${msg.status}`);
    } else if (msg.type === 'command_result') {
        console.log(`Exit code: ${msg.returncode}`);
        console.log(`Output: ${msg.stdout}`);
    }
};
// Send ping to keep connection alive
setInterval(() => ws.send('ping'), 30000);
```

### `WS /ws/projet`

Global project events stream (dashboard). Receives all events from all projects.

## Permissions

| Permission | Description |
|-----------|-------------|
| `shell.projet.create` | Create project workspaces |
| `shell.projet.run` | Execute commands in projects |
| `shell.projet.show` | View project details |
| `shell.projet.list` | List all projects |
| `shell.projet.delete` | Delete project workspaces |
| `shell.projet.upload` | Upload files to projects |

All permissions are included in the `admin` role by default.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_SHELL_PROJET_BASE_DIR` | `/home/AD-API-USER` | Base directory for project workspaces |
| `SAMBA_SHELL_PROJET_MAX_PROJECTS` | `100` | Maximum concurrent project workspaces |
| `SAMBA_SHELL_PROJET_MAX_ARCHIVE_SIZE` | `500` | Maximum archive upload size in MB |

## Bash Scripting Examples

### Conditional execution
```json
{
    "run_command": "if [ -f /etc/config.ini ]; then cat /etc/config.ini; else echo 'Config not found'; fi"
}
```

### Case statement
```json
{
    "run_command": "case $ENV in prod) echo 'Production';; dev) echo 'Development';; *) echo 'Unknown';; esac"
}
```

### Loop
```json
{
    "run_command": "for f in *.sh; do chmod +x $f; done"
}
```

### Pipeline with exit code check
```json
{
    "run_command": "echo -e 'ER: no ip\\nOK' | ./run.sh && echo 'OK - код 200' || echo 'ОШИБКА'; echo -e 'ER: -1' | ./run.sh && echo 'OK' || echo 'ER: -1 - код 407 (ожидаемо)'"
}
```

## Files Added / Modified

| File | Action | Description |
|------|--------|-------------|
| `app/routers/shell_projet.py` | **MODIFIED** | Shell Project router with 7 REST endpoints (+abort v1.6.5) |
| `app/models/shell_projet.py` | **MODIFIED** | Pydantic models + ShellProjetAbortResponse (v1.6.5) |
| `app/shell_projet_ws.py` | **MODIFIED** | WebSocket manager for real-time project output |
| `debug/debug_shell_projet.py` | **NEW** | Debug/test script for Shell Project API (45 tests) |
| `app/routers/shell.py` | **MODIFIED** | Added `/shell/script/file` endpoint for file upload |
| `app/models/shell.py` | **MODIFIED** | Added ShellScriptFileRequest/Response models |
| `app/main.py` | **MODIFIED** | Added shell_projet router, WebSocket endpoints, version bump |
| `app/permissions.py` | **MODIFIED** | Added 7 new shell.projet.* permissions (+abort v1.6.5) |
| `app/config.py` | **MODIFIED** | Added SHELL_PROJET_* settings |
| `.env` | **MODIFIED** | Added Shell Project configuration |
