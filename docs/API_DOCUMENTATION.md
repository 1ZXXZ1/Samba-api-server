# Samba AD DC Management API — Complete Documentation

> **Version:** api_v1.9.6-7  

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Authorization & Permissions](#authorization--permissions)
4. [Rate Limiting](#rate-limiting)
5. [Caching](#caching)
6. [Pagination](#pagination)
7. [Error Handling](#error-handling)
8. [WebSocket Real-Time Notifications](#websocket-real-time-notifications)
9. [Configuration (Environment Variables)](#configuration)
10. [System Endpoints](#system-endpoints)
11. [Authentication Endpoints](#authentication-endpoints)
12. [User Management](#user-management)
13. [User Extended Management](#user-extended-management)
14. [Group Management](#group-management)
15. [Computer Management](#computer-management)
16. [Contact Management](#contact-management)
17. [Organizational Unit Management](#organizational-unit-management)
18. [OU Extended Management](#ou-extended-management)
19. [Domain Management](#domain-management)
20. [DNS Management](#dns-management)
21. [Group Policy (GPO) Management](#group-policy-gpo-management)
22. [FSMO Roles](#fsmo-roles)
23. [DRS Replication](#drs-replication)
24. [Sites & Subnets](#sites--subnets)
25. [Schema](#schema)
26. [Delegation](#delegation)
27. [Service Accounts](#service-accounts)
28. [Authentication Policies](#authentication-policies)
29. [Miscellaneous Operations](#miscellaneous-operations)
30. [Shell Execution](#shell-execution)
31. [Shell Project](#shell-project)
32. [Batch Operations](#batch-operations)
33. [AI Assistant](#ai-assistant)
34. [Management API (Admin Panel)](#management-api-admin-panel)
35. [Dashboard](#dashboard)
36. [Task Management](#task-management)
37. [Data Models Reference](#data-models-reference)
38. [Permissions Reference](#permissions-reference)

---

## Overview

The Samba AD DC Management API is a RESTful web service that provides comprehensive administration capabilities for Samba Active Directory Domain Controllers via `samba-tool` and direct `ldbsearch`/SamDB API calls. It exposes 230+ endpoints covering every aspect of AD management: users, groups, computers, contacts, OUs, DNS, GPO, DRS replication, FSMO roles, schema, delegation, service accounts, authentication policies, AI assistant with agent tool calls, shell project workspace, batch operations, and more.

### Key Features

- **Dual Authentication**: Supports both static API keys (`X-API-Key` header) and JWT Bearer tokens (`Authorization: Bearer <token>`)
- **Fast Read Path**: Read endpoints use `ldbsearch` (direct LDB/TDB access) instead of `samba-tool` for 10-100x faster queries
- **Direct SamDB Writes**: Write operations attempt direct SamDB API calls first (fast path ~1-2s), falling back to `samba-tool` subprocess
- **Granular RBAC**: 150+ individual permissions organized by resource category, with 3 built-in roles (admin, operator, auditor) and custom role support
- **Rate Limiting**: Per-IP and per-user sliding window rate limits for auth, read, write, and shell project endpoints
- **Response Caching**: Configurable TTL-based response cache with automatic invalidation on write operations
- **Background Tasks**: Long-running operations (backup, GPO restore, dbcheck, etc.) run as background tasks with polling and WebSocket notifications
- **Batch Operations**: Execute multi-step sequential operations with template resolution and rollback support
- **Shell Project**: Workspace-based command execution environment with archive upload, scheduling, snapshots, and webhook callbacks
- **AI Assistant**: Polza.ai-powered AI for natural language task building and direct API execution via agent tool calls, with persistent chat sessions
- **Prometheus Metrics**: Built-in lightweight HTTP metrics (request counts, duration histograms) without external dependencies
- **Structured Logging**: JSON or standard log format with request ID tracking
- **Audit Trail**: Full action audit logging via management database

### Changelog (v1.9.6-5 to v1.9.6-7)

#### v1.9.6-5 — Bug Fixes
- **DNS**: `_is_transient_dns_error()` now excludes STATUS_OBJECT_NAME_NOT_FOUND patterns — prevents 4+ minute retry loops on non-existent RPC server hostnames
- **GPO**: Device Timeout errors (STATUS_DEVICE_TIMEOUT) now return HTTP 504 immediately instead of HTTP 507, preventing unnecessary retry cascading
- **Domain Level**: Pydantic validator added to `DomainLevelSetRequest` — rejects invalid values like `"NEXT_LEVEL"`, restricting to: 2000, 2003, 2008, 2008_R2, 2012, 2012_R2, 2016
- **Rate Limiting**: Write limit increased from 30 to 60 req/min; 429 responses no longer count toward the rate counter
- **DRS**: Device Timeout errors now return HTTP 504 instead of HTTP 502

#### v1.9.6-6 — Test Suite Improvements
- **api_debug.py**: Added batch endpoint test (`POST /api/v1/batch`) with full lifecycle validation (create user+group+member, list, cleanup)
- **api_debug.py**: 429 rate-limit auto-retry with exponential backoff (max 2 retries) prevents cascading test failures
- **api_debug.py**: 1.5s delay between write operations to avoid rate limiting
- **debug_batch.py**: Timeout increased from 180s to 300s; 1.0s pre-request delay; retry-enabled HTTP requests

#### v1.9.6-7 — Documentation & AI Skills
- **API_DOCUMENTATION.md**: Updated to v1.9.6-7 with full changelog
- **AI Skills API Documentation**: Created per-module skill documents for the AI Assistant agent, covering all 19 API modules with endpoint summaries, parameter references, and usage examples
- **Rate Limiting**: Documented that write rate limit is now 60 req/min (was 30)

---

## Authentication

All endpoints (except public paths) require authentication. Two methods are supported:

### API Key Authentication

Include the `X-API-Key` header with every request:

```http
GET /api/v1/users/ HTTP/1.1
X-API-Key: your-api-key-here
```

API keys are validated against:
1. **Management Database** (api_ma) — keys created via `POST /api/v1/mgmt/keys`, with associated roles and permissions
2. **Static API Key** — the `SAMBA_API_KEY` environment variable (always has `admin` role)

### JWT Bearer Authentication

First obtain tokens via login, then include the access token:

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

Then use the access token:

```http
GET /api/v1/users/ HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Public Endpoints (No Authentication Required)

| Path | Description |
|------|-------------|
| `GET /health` | Basic health check |
| `GET /health/detailed` | Detailed health check |
| `GET /metrics` | Prometheus metrics |
| `GET /docs` | Swagger UI |
| `GET /openapi.json` | OpenAPI schema |
| `GET /redoc` | ReDoc documentation |
| `POST /api/v1/auth/login` | JWT login |
| `POST /api/v1/auth/refresh` | JWT token refresh |
| `POST /api/v1/auth/check` | Credential verification |
| `/ws/*` | WebSocket endpoints |

---

## Authorization & Permissions

The API implements granular role-based access control (RBAC) with 150+ individual permissions.

### Built-in Roles

| Role | Description | Access Level |
|------|-------------|-------------|
| `admin` | Full system access | All 150+ permissions |
| `operator` | Read-only operations | All read permissions (list, show, get, full endpoints) |
| `auditor` | Read + audit log access | Read permissions + `mgmt.audit.view` |

### Permission Format

Permissions follow the `resource.action` format, for example:
- `user.create` — Create user accounts
- `group.list` — List groups
- `dns.recordcreate` — Create DNS records
- `mgmt.users.create` — Create management users
- `shell.execute` — Execute shell commands

Custom roles can be created and assigned any combination of permissions via the Management API.

### Permission Enforcement

1. The combined auth middleware validates authentication (API key or JWT)
2. The role is extracted from the JWT payload or API key metadata
3. `has_permission(role, method, path)` checks the role's permissions against the required permission
4. If the role lacks the required permission, HTTP 403 is returned with the missing permission name

---

## Rate Limiting

Rate limits are enforced via in-memory sliding window counters:

| Endpoint Group | Default Limit | Scope | Environment Variable |
|---------------|--------------|-------|---------------------|
| Auth (`/api/v1/auth/*`) | 10 req/min | Per IP | `SAMBA_RATE_LIMIT_AUTH_PER_MIN` |
| Shell Project (`/api/v1/shell/projet/*`) | 120 req/min | Per user | `SAMBA_RATE_LIMIT_SHELL_PROJET_PER_MIN` |
| Read (GET) | 100 req/min | Per user | `SAMBA_RATE_LIMIT_READ_PER_MIN` |
| Write (POST/PUT/DELETE/PATCH) | 60 req/min | Per user | `SAMBA_RATE_LIMIT_WRITE_PER_MIN` |

When rate limited, the API returns HTTP 429 with a `Retry-After` header.

Exempt paths: `/health`, `/docs`, `/openapi.json`, `/redoc`, and `OPTIONS` requests.

---

## Caching

The API uses an in-memory TTL-based response cache:

| Setting | Default | Environment Variable |
|---------|---------|---------------------|
| Cache enabled | `true` | `SAMBA_CACHE_ENABLED` |
| Default TTL | 3 seconds | `SAMBA_CACHE_TTL` |
| Max cache size | 512 entries | `SAMBA_CACHE_MAX_SIZE` |

**Cache invalidation** is automatic on all write operations (POST, PUT, DELETE, PATCH). The cache middleware invalidates both the response cache and the `ldb_reader` internal cache so subsequent reads return fresh data.

**ldbsearch `/full` endpoints** cache results for 30 seconds. DNS server info caches for 300 seconds.

---

## Pagination

Paginated endpoints accept the following query parameters:

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `offset` | int | 0 | — | Zero-based index of the first item |
| `limit` | int | 100 | 1000 | Maximum number of items per page |

**Response format:**

```json
{
  "status": "ok",
  "message": "Found 150 users",
  "items": [...],
  "total": 150,
  "offset": 0,
  "limit": 100
}
```

### Search Parameters

Search endpoints accept additional parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Simple substring search (auto-wrapped as LDAP filter) |
| `filter` | string | Raw LDAP filter expression, e.g. `(sAMAccountName=john*)` |
| `attributes` | string | Comma-separated list of LDAP attributes to return |

---

## Error Handling

All errors follow a consistent JSON format:

```json
{
  "status": "error",
  "message": "Human-readable error description",
  "details": "Optional additional context (only in DEBUG mode)"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 400 | Bad Request — invalid input parameters |
| 401 | Unauthorized — missing or invalid authentication |
| 403 | Forbidden — insufficient permissions |
| 404 | Not Found — resource does not exist |
| 409 | Conflict — resource already exists |
| 412 | Precondition Failed — operation not applicable for server role |
| 422 | Unprocessable Entity — semantic validation error |
| 429 | Too Many Requests — rate limit exceeded |
| 500 | Internal Server Error |
| 504 | Gateway Timeout — operation timed out |
| 507 | Insufficient Storage — STATUS_QUOTA_EXCEEDED (DRS/GPO) |

---

## WebSocket Real-Time Notifications

### Task Status Updates

Connect to receive real-time updates on background task status:

```
ws://<host>:8099/ws/tasks/{task_id}
```

Messages are JSON objects with task status changes. Send `"ping"` to keep the connection alive (receives `{"type": "pong"}`).

### All Tasks Dashboard

Monitor all task updates:

```
ws://<host>:8099/ws/tasks
```

Receives an initial `tasks_snapshot` message with all current tasks, then incremental updates.

### Shell Project Output

Receive real-time stdout/stderr during project command execution:

```
ws://<host>:8099/ws/projet/{projet_id}
```

Message types: `output` (stdout/stderr chunk), `status` (project status change), `command_result` (final result), `extract_result` (archive extraction).

---

## Configuration

All settings are loaded from environment variables with the `SAMBA_` prefix (e.g. `SAMBA_API_HOST`, `SAMBA_API_PORT`). A `.env` file is also supported.

### Server Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_API_HOST` | `127.0.0.1` | Host address to bind |
| `SAMBA_API_PORT` | `8099` | Port to listen on |
| `SAMBA_API_KEY` | **Required** | Static API key for authentication |
| `SAMBA_LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL) |

### Samba Tool Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_TOOL_PATH` | `samba-tool` | Path to samba-tool binary |
| `SAMBA_LDBSEARCH_PATH` | `ldbsearch` | Path to ldbsearch binary |
| `SAMBA_SMB_CONF` | `/etc/samba/smb.conf` | Path to smb.conf |
| `SAMBA_SERVER` | `localhost` | Default Samba server hostname |
| `SAMBA_DC_HOSTNAME` | Auto-detected | Real DC hostname for RPC operations |
| `SAMBA_REALM` | Auto-detected | Kerberos realm / DNS domain |

### LDAP / Kerberos

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_LDAP_URL` | — | LDAP URL (e.g. `ldaps://dc1.example.com`) |
| `SAMBA_LDAPI_URL` | — | LDAPI URL for local access (write operations) |
| `SAMBA_TDB_URL` | Auto-detected | TDB URL for direct read-only sam.ldb access |
| `SAMBA_DOMAIN_DN` | Auto-detected | Base DN (e.g. `DC=kcrb,DC=local`) |
| `SAMBA_CREDENTIALS_USER` | — | Username for samba-tool `-U` flag |
| `SAMBA_CREDENTIALS_PASSWORD` | — | Password for samba-tool `-U` flag |
| `SAMBA_USE_KERBEROS` | `false` | Use Kerberos authentication |

### JWT Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_JWT_SECRET_KEY` | Auto-generated | Secret for JWT signing |
| `SAMBA_JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `SAMBA_JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token TTL |
| `SAMBA_JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token TTL |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_CORS_ORIGINS` | `*` (all origins) | Comma-separated allowed origins |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `SAMBA_RATE_LIMIT_AUTH_PER_MIN` | `10` | Auth endpoint limit |
| `SAMBA_RATE_LIMIT_READ_PER_MIN` | `100` | Read endpoint limit |
| `SAMBA_RATE_LIMIT_WRITE_PER_MIN` | `60` | Write endpoint limit |
| `SAMBA_RATE_LIMIT_SHELL_PROJET_PER_MIN` | `120` | Shell project limit |
| `SAMBA_RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding window size |

### Cache

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_CACHE_ENABLED` | `true` | Enable response caching |
| `SAMBA_CACHE_TTL` | `3` | Default TTL in seconds |
| `SAMBA_CACHE_MAX_SIZE` | `512` | Maximum cached entries |

### Worker Pool

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_WORKER_POOL_SIZE` | `4` | Max concurrent samba-tool processes |

### Shell Execution

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_SHELL_ENABLED` | `true` | Enable shell API |
| `SAMBA_SHELL_SUDO_PASSWORD` | — | Password for sudo -S |
| `SAMBA_SHELL_MAX_TIMEOUT` | `600` | Max command timeout (10-3600s) |
| `SAMBA_SHELL_BLOCKED_COMMANDS` | `rm -rf /,...` | Blocked command patterns |

### Shell Project

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_SHELL_PROJET_BASE_DIR` | `/home/AD-API-USER` | Base directory for workspaces |
| `SAMBA_SHELL_PROJET_MAX_PROJECTS` | `100` | Max concurrent projects |
| `SAMBA_SHELL_PROJET_MAX_ARCHIVE_SIZE` | `500` | Max archive size (MB) |
| `SAMBA_SHELL_PROJET_POOL_SIZE` | `8` | Thread pool size for commands |
| `SAMBA_SHELL_PROJET_DEFAULT_TIMEOUT` | `300` | Default command timeout (s) |
| `SAMBA_SHELL_PROJET_PG_DSN` | — | PostgreSQL connection string |
| `SAMBA_SHELL_PROJET_ENCRYPTION_KEY` | Auto-generated | Fernet key for encrypted env vars |

### AI Assistant

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_POLZA_AI_URL` | — | Polza.ai API base URL (required) |
| `SAMBA_POLZA_AI_KEY` | — | Polza.ai API key (required) |
| `SAMBA_POLZA_AI_MODEL` | — | Polza.ai model name (optional) |
| `SAMBA_AI_DEFAULT_MODEL` | `openai/gpt-oss-120b` | Default LLM model |
| `SAMBA_AI_TEMPERATURE` | `0.7` | LLM temperature |
| `SAMBA_AI_MAX_TOKENS` | `2046` | Max completion tokens |
| `SAMBA_AI_AGENT_MAX_STEPS` | `10` | Max agent loop iterations |
| `SAMBA_AI_AGENT_SHELL_ENABLED` | `true` | Allow agent shell execution |
| `SAMBA_AI_AGENT_SHELL_TIMEOUT` | `30` | Agent shell command timeout |
| `SAMBA_AI_FALLBACK_MODELS` | — | Comma-separated fallback models |
| `SAMBA_AI_MAX_SCHEMA_CHARS` | `12000` | Max compressed schema size |
| `SAMBA_AI_AGENT_MAX_MENU_CHARS` | `8000` | Max API menu chars in prompt |
| `SAMBA_AI_CHAT_ENABLED` | `true` | Enable AI chat system |
| `SAMBA_AI_PERMISSION_MODE` | `true` | Permission-based AI mode |

### Polza.ai Provider Routing

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_POLZA_AI_PROVIDER_ONLY` | — | Only use these providers (comma-sep) |
| `SAMBA_POLZA_AI_PROVIDER_ORDER` | — | Provider priority order (comma-sep) |
| `SAMBA_POLZA_AI_PROVIDER_IGNORE` | — | Ignore these providers (comma-sep) |
| `SAMBA_POLZA_AI_PROVIDER_ALLOW_FALLBACKS` | `true` | Allow provider fallbacks |
| `SAMBA_POLZA_AI_PROVIDER_SORT` | — | Sort strategy (price) |
| `SAMBA_POLZA_AI_PROVIDER_MAX_PRICE_PROMPT` | `0` | Max prompt price (RUB/million) |
| `SAMBA_POLZA_AI_PROVIDER_MAX_PRICE_COMPLETION` | `0` | Max completion price (RUB/million) |

### Polza.ai Reasoning

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_POLZA_AI_REASONING_EFFORT` | — | Reasoning effort (xhigh/high/medium/low/minimal/none) |
| `SAMBA_POLZA_AI_REASONING_SUMMARY` | — | Reasoning summary (auto/concise/detailed) |
| `SAMBA_POLZA_AI_REASONING_ENABLED` | `true` | Enable reasoning |
| `SAMBA_POLZA_AI_REASONING_MAX_TOKENS` | `0` | Max reasoning tokens |
| `SAMBA_POLZA_AI_REASONING_EXCLUDE` | `false` | Hide reasoning from response |

### Polza.ai Sampling / Generation

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_POLZA_AI_TOP_K` | `0` | Top-K sampling |
| `SAMBA_POLZA_AI_REPETITION_PENALTY` | `0.0` | Repetition penalty |
| `SAMBA_POLZA_AI_TOP_P` | `0.0` | Top-P nucleus sampling override |
| `SAMBA_POLZA_AI_FREQUENCY_PENALTY` | `0.0` | Frequency penalty |
| `SAMBA_POLZA_AI_PRESENCE_PENALTY` | `0.0` | Presence penalty |
| `SAMBA_POLZA_AI_SEED` | `0` | Seed for deterministic generation |

### Polza.ai Web Search

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_POLZA_AI_WEB_SEARCH_ENABLED` | `false` | Enable web search |
| `SAMBA_POLZA_AI_WEB_SEARCH_CONTEXT_SIZE` | `medium` | Context size (low/medium/high) |

### Management Database

| Variable | Default | Description |
|----------|---------|-------------|
| `SAMBA_SHELL_PROJET_PG_HOST` | `localhost` | PostgreSQL host |
| `SAMBA_SHELL_PROJET_PG_PORT` | `5432` | PostgreSQL port |
| `SAMBA_SHELL_PROJET_PG_DBNAME` | `samba_api` | PostgreSQL database name |
| `SAMBA_SHELL_PROJET_PG_USER` | `samba_api` | PostgreSQL user |
| `SAMBA_SHELL_PROJET_PG_PASSWORD` | — | PostgreSQL password |
| `SAMBA_SHELL_PROJET_PG_DSN` | — | Full PostgreSQL DSN (overrides individual settings) |
| `SAMBA_SHELL_PROJET_PG_POOL_MIN` | `2` | Minimum connection pool size |
| `SAMBA_SHELL_PROJET_PG_POOL_MAX` | `25` | Maximum connection pool size |

**Note:** The management database was migrated from SQLite to PostgreSQL in v1.8.5. The `SAMBA_MGMT_DB_PATH` environment variable is no longer used. All management data (users, keys, roles, audit log, AI chat sessions) is now stored in PostgreSQL.

---

## System Endpoints

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "service": "samba-api-server",
  "server_role": "active directory domain controller",
  "version": "api_v1.9.6"
}
```

### Detailed Health Check

```http
GET /health/detailed
```

Returns comprehensive health information including Samba service status, database connectivity, and worker pool state.

**Required Permission:** `system.health`

### Prometheus Metrics

```http
GET /metrics
```

Returns HTTP request metrics: total requests, counters by method/endpoint/status, duration histograms.

**Required Permission:** `system.metrics`

### System Statistics

```http
GET /api/v1/system/stats
```

Returns system stats (CPU, memory, disk, uptime) and Samba stats.

**Required Permission:** `system.stats`

---

## Authentication Endpoints

### Login

```http
POST /api/v1/auth/login
```

**Request Body:**
```json
{
  "username": "admin",
  "password": "admin"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 1800,
  "role": "admin",
  "permissions": ["user.create", "user.list", ...]
}
```

### Refresh Token

```http
POST /api/v1/auth/refresh
```

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

Returns a new access/refresh token pair. Re-fetches permissions from the current role definition.

### Get Current User Info

```http
GET /api/v1/auth/me
```

Works with both API key and JWT Bearer authentication.

**Response:**
```json
{
  "status": "ok",
  "auth_method": "jwt",
  "username": "admin",
  "role": "admin",
  "permissions": ["user.create", ...],
  "expires_at": "2026-05-16T12:30:00+00:00"
}
```

**Required Permission:** `auth.me`

### Check Credentials

```http
POST /api/v1/auth/check
```

Accepts three authentication methods (at least one required):
1. `X-API-Key` header
2. `Authorization: Bearer <token>` header
3. Username/password in body

**Request Body (optional):**
```json
{
  "username": "admin",
  "password": "your-password"
}
```

Priority: API key → JWT → username/password.

---

## User Management

### List Users

```http
GET /api/v1/users/
```

Lists all user accounts via ldbsearch (fast path). Results cached for 30 seconds.

**Required Permission:** `user.list`

**Response:**
```json
{
  "status": "ok",
  "users": [
    {
      "dn": "CN=administrator,CN=Users,DC=kcrb,DC=local",
      "sAMAccountName": "Administrator",
      "objectClass": ["user", ...],
      ...
    }
  ]
}
```

### Get All Users (Full, Fast)

```http
GET /api/v1/users/full
```

Same as list users but explicitly marks the fast ldbsearch path. Cached for 30 seconds.

**Required Permission:** `user.full`

### Create User

```http
POST /api/v1/users/
```

Creates a new user account. Attempts direct SamDB API call first, falls back to samba-tool.

**Required Permission:** `user.create`

**Request Body:**
```json
{
  "username": "jdoe",
  "password": "P@ssw0rd123",
  "userou": "OU=Staff",
  "surname": "Doe",
  "given_name": "John",
  "initials": "J",
  "profile_path": "\\\\server\\profiles\\jdoe",
  "script_path": "login.bat",
  "home_drive": "H:",
  "home_directory": "\\\\server\\homes\\jdoe",
  "job_title": "Engineer",
  "department": "IT",
  "company": "Acme Corp",
  "description": "John Doe account",
  "mail_address": "jdoe@example.com",
  "internet_address": "https://example.com",
  "telephone_number": "+1234567890",
  "physical_delivery_office": "Room 101",
  "must_change_at_next_login": true,
  "use_username_as_cn": false,
  "random_password": false,
  "smartcard_required": false,
  "uid_number": 10001,
  "gid_number": 10000,
  "gecos": "John Doe",
  "login_shell": "/bin/bash",
  "uid": "jdoe",
  "nis_domain": "example.com",
  "unix_home": "/home/jdoe"
}
```

Only `username` is required. Returns HTTP 201 on success, HTTP 409 if user already exists.

### Show User Details

```http
GET /api/v1/users/{username}
```

Returns all LDAP attributes for the specified user via ldbsearch.

**Required Permission:** `user.show`

### Delete User

```http
DELETE /api/v1/users/{username}
```

Deletes a user account. Attempts direct SamDB API call first.

**Required Permission:** `user.delete`

### Enable User

```http
POST /api/v1/users/{username}/enable
```

**Required Permission:** `user.enable`

### Disable User

```http
POST /api/v1/users/{username}/disable
```

**Required Permission:** `user.disable`

### Unlock User

```http
POST /api/v1/users/{username}/unlock
```

**Required Permission:** `user.unlock`

### Set Password

```http
PUT /api/v1/users/{username}/password
```

**Required Permission:** `user.setpassword`

**Request Body:**
```json
{
  "new_password": "NewP@ssw0rd",
  "must_change_at_next_login": false
}
```

### Get Password

```http
GET /api/v1/users/{username}/getpassword
```

Retrieves password attributes (requires elevated privileges). Uses `tdb://` for direct sam.ldb access.

**Required Permission:** `user.getpassword`

**Query Parameters:**
| Parameter | Default | Description |
|-----------|---------|-------------|
| `attributes` | `virtualClearTextUTF16` | Comma-separated password attributes |

### Get User Groups

```http
GET /api/v1/users/{username}/groups
```

Lists groups the user belongs to via ldbsearch (returns `memberOf` attribute).

**Required Permission:** `user.getgroups`

### Set Account Expiry

```http
PUT /api/v1/users/{username}/setexpiry
```

**Required Permission:** `user.setexpiry`

**Request Body:**
```json
{
  "days": 90
}
```

### Set Primary Group

```http
PUT /api/v1/users/{username}/setprimarygroup
```

**Required Permission:** `user.setprimarygroup`

**Request Body:**
```json
{
  "groupname": "Domain Admins"
}
```

### Add Unix Attributes

```http
POST /api/v1/users/{username}/addunixattrs
```

Adds RFC 2307 Unix attributes to a user.

**Required Permission:** `user.addunixattrs`

**Request Body:**
```json
{
  "uid_number": 10001,
  "gid_number": 10000,
  "unix_home": "/home/jdoe",
  "login_shell": "/bin/bash",
  "gecos": "John Doe",
  "nis_domain": "example.com",
  "uid": "jdoe"
}
```

### Set Sensitive Flag

```http
PUT /api/v1/users/{username}/sensitive
```

**Required Permission:** `user.sensitive`

**Request Body:**
```json
{
  "on": true
}
```

### Move User

```http
POST /api/v1/users/{username}/move
```

**Required Permission:** `user.move`

**Request Body:**
```json
{
  "new_parent_dn": "OU=Staff,DC=kcrb,DC=local"
}
```

### Rename User

```http
POST /api/v1/users/{username}/rename
```

**Required Permission:** `user.rename`

**Request Body:**
```json
{
  "new_name": "jdoe2"
}
```

### Get Kerberos Ticket

```http
GET /api/v1/users/{username}/get-kerberos-ticket
```

Requires `CREDENTIALS_USER` and `CREDENTIALS_PASSWORD` to be configured. Returns the ticket as base64-encoded krb5 ccache.

**Required Permission:** `user.getkerberosticket`

---

## User Extended Management

### Search Users

```http
GET /api/v1/users/search
```

Searches users by LDAP filter or simple substring. Uses SamDB fast path.

**Required Permission:** `user.search`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Substring search on sAMAccountName |
| `filter` | string | Raw LDAP filter |
| `attributes` | string | Comma-separated attributes to return |
| `offset` | int | Pagination offset (default: 0) |
| `limit` | int | Page size (1-1000, default: 100) |

### Import Users from CSV

```http
POST /api/v1/users/import
```

Bulk import users from CSV. Runs as a background task.

**Required Permission:** `user.import`

**Request:** Multipart form with CSV file (max 10MB). CSV headers: `username` (required), `password` (required), `first_name`, `last_name`, `email`, `department`, `ou` (optional).

### Export Users

```http
GET /api/v1/users/export
```

Export users as CSV or JSON stream.

**Required Permission:** `user.export`

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | string | `csv` | Output format: `csv` or `json` |
| `attributes` | string | — | Comma-separated attributes to include |

### Edit User Attributes

```http
PUT /api/v1/users/{username}/edit
```

Edit 22+ LDAP attributes via direct SamDB modify or ldbmodify fallback.

**Required Permission:** `user.create` (write operation)

**Request Body:** JSON with any of the 22 mappable attributes (e.g. `givenName`, `sn`, `mail`, `department`, `telephoneNumber`, `title`, `company`, `physicalDeliveryOfficeName`, `description`, `displayName`, `wWWHomePage`, `streetAddress`, `l`, `st`, `postalCode`, `co`, `postOfficeBox`, `mobile`, `homePhone`, `facsimileTelephoneNumber`, `pager`, `info`).

### Batch Get Users

```http
GET /api/v1/users/batch
```

Retrieve multiple users in one request (max 100).

**Required Permission:** `user.show`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `usernames` | string | Comma-separated usernames (required) |
| `attributes` | string | Comma-separated attributes |

---

## Group Management

### List Groups

```http
GET /api/v1/groups/
```

Lists all groups via ldbsearch. Cached for 30 seconds.

**Required Permission:** `group.list`

### Get All Groups (Full, Fast)

```http
GET /api/v1/groups/full
```

**Required Permission:** `group.full`

### Create Group

```http
POST /api/v1/groups/
```

**Required Permission:** `group.create`

**Request Body:**
```json
{
  "groupname": "Developers",
  "groupou": "OU=Groups",
  "group_scope": "Global",
  "group_type": "Security",
  "description": "Development team",
  "mail_address": "dev@example.com",
  "notes": "All developers",
  "gid_number": 10010,
  "nis_domain": "example.com"
}
```

### Group Statistics

```http
GET /api/v1/groups/stats
```

Returns group statistics computed via ldbsearch.

**Required Permission:** `group.stats`

### Show Group Details

```http
GET /api/v1/groups/{groupname}
```

**Required Permission:** `group.show`

### Delete Group

```http
DELETE /api/v1/groups/{groupname}
```

**Required Permission:** `group.delete`

### Add Members to Group

```http
POST /api/v1/groups/{groupname}/members
```

**Required Permission:** `group.addmembers`

**Request Body:**
```json
{
  "members": ["jdoe", "asmith"],
  "member_dn": ["CN=Bob,CN=Users,DC=kcrb,DC=local"],
  "object_types": "user,group,computer",
  "member_base_dn": "CN=Users,DC=kcrb,DC=local"
}
```

Base64-encoded member DNs are automatically decoded.

### Remove Members from Group

```http
DELETE /api/v1/groups/{groupname}/members
```

**Required Permission:** `group.removemembers`

Same request body as add members.

### List Group Members

```http
GET /api/v1/groups/{groupname}/members
```

Returns the group's `member` attribute as a list of DNs via ldbsearch.

**Required Permission:** `group.listmembers`

### Move Group

```http
POST /api/v1/groups/{groupname}/move
```

**Required Permission:** `group.move`

**Request Body:**
```json
{
  "new_parent_dn": "OU=NewGroups,DC=kcrb,DC=local"
}
```

---

## Computer Management

### List Computers

```http
GET /api/v1/computers/
```

Lists all computer accounts via ldbsearch. Cached for 30 seconds.

**Required Permission:** `computer.list`

### Get All Computers (Full, Fast)

```http
GET /api/v1/computers/full
```

**Required Permission:** `computer.full`

### Create Computer

```http
POST /api/v1/computers/
```

**Required Permission:** `computer.create`

**Request Body:**
```json
{
  "computername": "WORKSTATION01",
  "computerou": "OU=Computers",
  "description": "Employee workstation",
  "prepare_oldjoin": false,
  "ip_address_list": ["192.168.1.100"],
  "service_principal_name_list": ["HOST/workstation01.example.com"]
}
```

### Show Computer Details

```http
GET /api/v1/computers/{computername}
```

**Required Permission:** `computer.show`

### Delete Computer

```http
DELETE /api/v1/computers/{computername}
```

**Required Permission:** `computer.delete`

### Move Computer

```http
POST /api/v1/computers/{computername}/move
```

**Required Permission:** `computer.move`

**Request Body:**
```json
{
  "new_ou_dn": "OU=NewComputers,DC=kcrb,DC=local"
}
```

---

## Contact Management

### List Contacts

```http
GET /api/v1/contacts/
```

Lists all contacts via ldbsearch. Cached for 30 seconds.

**Required Permission:** `contact.list`

### Get All Contacts (Full, Fast)

```http
GET /api/v1/contacts/full
```

**Required Permission:** `contact.full`

### Create Contact

```http
POST /api/v1/contacts/
```

**Required Permission:** `contact.create`

**Request Body:**
```json
{
  "contactname": "John External",
  "ou": "OU=Contacts",
  "surname": "External",
  "given_name": "John",
  "initials": "J",
  "display_name": "John External",
  "description": "External contact",
  "mail_address": "john@external.com",
  "telephone_number": "+1234567890",
  "job_title": "Consultant",
  "department": "Advisory",
  "company": "External Corp",
  "mobile_number": "+1234567891",
  "internet_address": "https://external.com",
  "physical_delivery_office": "Remote"
}
```

### Show Contact Details

```http
GET /api/v1/contacts/{contactname}
```

**Required Permission:** `contact.show`

### Delete Contact

```http
DELETE /api/v1/contacts/{contactname}
```

**Required Permission:** `contact.delete`

### Move Contact

```http
POST /api/v1/contacts/{contactname}/move
```

**Required Permission:** `contact.move`

**Request Body:**
```json
{
  "new_parent_dn": "OU=NewContacts,DC=kcrb,DC=local"
}
```

### Rename Contact

```http
POST /api/v1/contacts/{contactname}/rename
```

**Required Permission:** `contact.rename`

**Request Body:**
```json
{
  "new_name": "Jane External"
}
```

---

## Organizational Unit Management

### List OUs

```http
GET /api/v1/ous/
```

Lists all Organizational Units via ldbsearch. Cached for 30 seconds.

**Required Permission:** `ou.list`

### Get All OUs (Full, Fast)

```http
GET /api/v1/ous/full
```

**Required Permission:** `ou.full`

### Create OU

```http
POST /api/v1/ous/
```

**Required Permission:** `ou.create`

**Request Body:**
```json
{
  "ouname": "Engineering",
  "description": "Engineering department"
}
```

Simple names (without `=`) are automatically converted to full DNs (e.g. `Engineering` → `OU=Engineering,DC=kcrb,DC=local`).

### Delete OU

```http
DELETE /api/v1/ous/{ouname}
```

**Required Permission:** `ou.delete`

### Move OU

```http
POST /api/v1/ous/{ouname}/move
```

**Required Permission:** `ou.move`

**Request Body:**
```json
{
  "new_parent_dn": "OU=Departments,DC=kcrb,DC=local"
}
```

### Rename OU

```http
POST /api/v1/ous/{ouname}/rename
```

**Required Permission:** `ou.rename`

**Request Body:**
```json
{
  "new_name": "EngineeringDept"
}
```

### List Objects in OU

```http
GET /api/v1/ous/{ouname}/objects
```

Lists direct children of the specified OU via ldbsearch (one-level scope).

**Required Permission:** `ou.listobjects`

---

## OU Extended Management

### Get OU Tree

```http
GET /api/v1/ous/tree
```

Returns hierarchical OU tree structure with `OUTreeNode` objects containing `name`, `dn`, `children`, and `object_count`.

**Required Permission:** `ou.tree`

### Search OUs

```http
GET /api/v1/ous/search
```

Search OUs by LDAP filter or substring.

**Required Permission:** `ou.search`

### Get OU Statistics

```http
GET /api/v1/ous/{ou_dn}/stats
```

Counts users, groups, computers, contacts, and sub-OUs within the specified OU.

**Required Permission:** `ou.stats`

### Get OU Sub-tree

```http
GET /api/v1/ous/{ou_dn}/tree
```

Returns the sub-tree under a specific OU.

**Required Permission:** `ou.tree`

---

## Domain Management

### Domain Info (Fast)

```http
GET /api/v1/domain/full
```

Returns domain DN, SID, functional level, and FSMO role owner via ldbsearch. Cached for 30 seconds.

**Required Permission:** `domain.full`

### Domain Info

```http
GET /api/v1/domain/info
```

General domain information via ldbsearch (no IP address required).

**Required Permission:** `domain.info`

### Get Domain Functional Level

```http
GET /api/v1/domain/level
```

Returns domain, forest, and lowest DC functional levels.

**Required Permission:** `domain.level`

**Response:**
```json
{
  "status": "ok",
  "domain_function_level": "Windows 2016",
  "forest_function_level": "Windows 2016",
  "lowest_dc_function_level": "Windows 2016",
  "msDS-Behavior-Version": "7",
  "msDS-forestBehaviorVersion": "7",
  "lowest_dc_msDS-Behavior-Version": "7"
}
```

Level mapping: 0=2000, 1=2003 Interim, 2=2003, 3=2008, 4=2008 R2, 5=2012, 6=2012 R2, 7=2016.

### Set Domain Functional Level

```http
PUT /api/v1/domain/level
```

**Required Permission:** `domain.level`

**Warning:** Raising the functional level is irreversible.

**Request Body:**
```json
{
  "level": "2016"
}
```

Returns HTTP 409 if the level is equal to or lower than the current level.

### Get Password Settings

```http
GET /api/v1/domain/passwordsettings
```

**Required Permission:** `domain.passwordsettings`

### Set Password Settings

```http
PUT /api/v1/domain/passwordsettings
```

**Required Permission:** `domain.passwordsettings`

**Request Body:**
```json
{
  "min_password_length": 8,
  "password_history_length": 24,
  "min_password_age": 1,
  "max_password_age": 90,
  "complexity": true,
  "store_plaintext": false,
  "account_lockout_duration": 30,
  "account_lockout_threshold": 5,
  "reset_account_lockout_after": 30
}
```

At least one setting must be provided.

### Create Trust

```http
POST /api/v1/domain/trust/create
```

**Required Permission:** `domain.trustcreate`

**Requires DC role.** Includes DNS SRV pre-check to avoid long timeouts for non-existent domains.

**Request Body:**
```json
{
  "trusted_domain_name": "other.example.com",
  "trusted_username": "admin",
  "trusted_password": "password",
  "trust_type": "forest",
  "trust_direction": "both"
}
```

### Delete Trust

```http
DELETE /api/v1/domain/trust/delete?trusted_domain_name=other.example.com
```

**Required Permission:** `domain.trustdelete`

### List Trusts

```http
GET /api/v1/domain/trust/list
```

Lists trustedDomain objects via ldbsearch.

**Required Permission:** `domain.trustlist`

### Trust Namespaces

```http
GET /api/v1/domain/trust/namespaces?trusted_domain_name=other.example.com
```

### Validate Trust

```http
POST /api/v1/domain/trust/validate?trusted_domain_name=other.example.com
```

### Online Backup

```http
POST /api/v1/domain/backup/online
```

Starts an online backup. Runs as a background task.

**Request Body:**
```json
{
  "target_dir": "/var/backups/samba",
  "server": "dc1.example.com"
}
```

### Offline Backup

```http
POST /api/v1/domain/backup/offline
```

Starts an offline backup. Runs as a background task.

### Create KDS Root Key

```http
POST /api/v1/domain/kds/root-key/create
```

### List KDS Root Keys

```http
GET /api/v1/domain/kds/root-key/list
```

Lists msKds-ProvRootKey objects via ldbsearch.

### Export Keytab

```http
POST /api/v1/domain/exportkeytab?principal=HTTP/web.example.com&keytab_path=/tmp/exported.keytab
```

Exports a keytab file. Computer account principals are rejected (HTTP 422). Runs as a background task.

### Join Domain

```http
POST /api/v1/domain/join
```

**Dangerous operation** — requires `force: true`. Fast-fails if server is already a DC or domain member.

### Leave Domain

```http
POST /api/v1/domain/leave
```

**Dangerous operation** — requires `force: true`. Fast-fails if server is a DC or standalone.

---

## DNS Management

All DNS commands require a server parameter (defaults to auto-detected DC hostname). DNS operations use DCE/RPC over SMB with Kerberos authentication.

### DNS Server Info

```http
GET /api/v1/dns/serverinfo
```

**Required Permission:** `dns.serverinfo`

Cached for 300 seconds (5 minutes). Not JSON-output compatible.

**Query Parameters:**
| Parameter | Description |
|-----------|-------------|
| `server` | DNS server hostname |
| `client_version` | Client version string |

### List DNS Zones

```http
GET /api/v1/dns/zones
```

**Required Permission:** `dns.zonelist`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `server` | string | DNS server hostname |
| `primary` | bool | List primary zones |
| `secondary` | bool | List secondary zones |
| `cache` | bool | List cache zones |
| `auto` | bool | List auto-created zones |
| `forward` | bool | List forward zones |
| `reverse` | bool | List reverse zones |
| `ds` | bool | List AD-integrated zones |
| `non_ds` | bool | List non-AD-integrated zones |

### Zone Info

```http
GET /api/v1/dns/zones/{zone}
```

**Required Permission:** `dns.zoneinfo`

### Create DNS Zone

```http
POST /api/v1/dns/zones
```

**Required Permission:** `dns.zonecreate`

**Request Body:**
```json
{
  "zone": "example.com",
  "dns_directory_partition": "domain"
}
```

**Query Parameters:**
| Parameter | Description |
|-----------|-------------|
| `server` | DNS server hostname |
| `overwrite` | Delete existing zone before creating (default: false) |

### Delete DNS Zone

```http
DELETE /api/v1/dns/zones/{zone}
```

**Required Permission:** `dns.zonedelete`

### List DNS Records

```http
GET /api/v1/dns/zones/{zone}/records
```

**Required Permission:** `dns.recordlist`

**Query Parameters:**
| Parameter | Description |
|-----------|-------------|
| `server` | DNS server hostname |
| `name` | Record name (default: `@` for zone root) |
| `record_type` | Record type (e.g. A, CNAME, MX; default: ALL) |

### Create DNS Record

```http
POST /api/v1/dns/zones/{zone}/records
```

**Required Permission:** `dns.recordcreate`

**Request Body:**
```json
{
  "name": "www",
  "record_type": "A",
  "data": "192.168.1.10"
}
```

### Delete DNS Record

```http
DELETE /api/v1/dns/zones/{zone}/records
```

**Required Permission:** `dns.recorddelete`

**Request Body:**
```json
{
  "name": "www",
  "record_type": "A",
  "data": "192.168.1.10"
}
```

### Update DNS Record

```http
PUT /api/v1/dns/zones/{zone}/records
```

**Required Permission:** `dns.recordupdate`

**Request Body:**
```json
{
  "name": "www",
  "old_record_type": "A",
  "old_data": "192.168.1.10",
  "new_data": "192.168.1.20"
}
```

### Read-Only Records Query

```http
GET /api/v1/dns/zones/{zone}/rorecords
```

**Required Permission:** `dns.rorecords`

Semantically distinct read-only access point (same backend as records list).

### Set Zone Options

```http
PUT /api/v1/dns/zones/{zone}/options
```

**Required Permission:** `dns.zoneoptions`

**Request Body:**
```json
{
  "aging": true,
  "no_scavenge": false
}
```

---

## Group Policy (GPO) Management

GPO identifiers (GUIDs) are automatically wrapped in braces if not already present.

### List GPOs

```http
GET /api/v1/gpo/
```

**Required Permission:** `gpo.list`

### Get All GPOs (Full, Fast)

```http
GET /api/v1/gpo/full
```

**Required Permission:** `gpo.full`

Cached for 30 seconds via ldbsearch.

### Create GPO

```http
POST /api/v1/gpo/
```

**Required Permission:** `gpo.create`

**Request Body:**
```json
{
  "displayname": "New Policy"
}
```

**Query Parameters:**
| Parameter | Description |
|-----------|-------------|
| `overwrite` | Delete+recreate on conflict (default: false) |

### Show GPO Details

```http
GET /api/v1/gpo/{gpo_id}
```

**Required Permission:** `gpo.show`

`gpo_id` can be a GUID (with or without braces) or display name.

### Delete GPO

```http
DELETE /api/v1/gpo/{gpo_id}
```

**Required Permission:** `gpo.delete`

Runs as a background task.

### Delete GPO by Name

```http
DELETE /api/v1/gpo/by-name/{displayname}
```

**Required Permission:** `gpo.deletebyname`

Deletes all GPOs matching the display name (synchronous).

### Link GPO

```http
POST /api/v1/gpo/{gpo_id}/link
```

**Required Permission:** `gpo.link`

**Request Body:**
```json
{
  "container_dn": "OU=Computers,DC=kcrb,DC=local"
}
```

### Unlink GPO

```http
DELETE /api/v1/gpo/{gpo_id}/link
```

**Required Permission:** `gpo.unlink`

**Request Body:**
```json
{
  "container_dn": "OU=Computers,DC=kcrb,DC=local"
}
```

### Get GPO Inheritance

```http
GET /api/v1/gpo/{gpo_id}/inherit
```

**Required Permission:** `gpo.getinherit`

### Set GPO Inheritance

```http
PUT /api/v1/gpo/{gpo_id}/inherit
```

**Required Permission:** `gpo.setinherit`

**Request Body:**
```json
{
  "container_dn": "OU=Computers,DC=kcrb,DC=local",
  "block_inheritance": true
}
```

### Backup GPO

```http
POST /api/v1/gpo/{gpo_id}/backup
```

**Required Permission:** `gpo.backup`

Runs as a background task.

### Restore GPO

```http
POST /api/v1/gpo/{gpo_id}/restore
```

**Required Permission:** `gpo.restore`

Runs as a background task.

### Fetch GPO Data

```http
GET /api/v1/gpo/{gpo_id}/fetch
```

**Required Permission:** `gpo.fetch`

---

## FSMO Roles

### Show FSMO Roles

```http
GET /api/v1/fsmo/
```

**Required Permission:** `fsmo.show`

### Get FSMO Roles (Full, Fast)

```http
GET /api/v1/fsmo/full
```

**Required Permission:** `fsmo.full`

Cached for 30 seconds via ldbsearch.

### Transfer FSMO Role

```http
PUT /api/v1/fsmo/transfer
```

**Required Permission:** `fsmo.transfer`

**Request Body:**
```json
{
  "role": "ridalloc"
}
```

Role options: `ridalloc`, `pdc`, `infrastructure`, `naming`, `schema`

### Seize FSMO Role

```http
PUT /api/v1/fsmo/seize
```

**Required Permission:** `fsmo.seize`

**Request Body:**
```json
{
  "role": "pdc"
}
```

---

## DRS Replication

### Show Replication Status

```http
GET /api/v1/drs/showrepl
```

**Required Permission:** `drs.showrepl`

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `server` | string | Auto-detected | DC hostname |
| `timeout` | int | 120 | Command timeout (5-1200s) |

### Replicate Naming Context

```http
POST /api/v1/drs/replicate
```

**Required Permission:** `drs.kcc`

Runs as a background task (HTTP 202).

### Check Up-to-dateness

```http
GET /api/v1/drs/uptodateness
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `object_dn` | string | — | Object DN to check |
| `timeout` | int | 900 | Timeout (60-1800s) |

### DRS Bind Info

```http
GET /api/v1/drs/bind
```

**Required Permission:** `drs.bind`

### Get DRS Options

```http
GET /api/v1/drs/options
```

**Required Permission:** `drs.options`

---

## Sites & Subnets

### List Sites

```http
GET /api/v1/sites/
```

**Required Permission:** `sites.list`

### View Site

```http
GET /api/v1/sites/{sitename}
```

**Required Permission:** `sites.show`

### Create Site

```http
POST /api/v1/sites/
```

**Required Permission:** `sites.create`

**Request Body:**
```json
{
  "sitename": "NewSite"
}
```

### Delete Site

```http
DELETE /api/v1/sites/{sitename}
```

**Required Permission:** `sites.delete`

### List Subnets in Site

```http
GET /api/v1/sites/{sitename}/subnets
```

**Required Permission:** `sites.subnetlist`

### View Subnet

```http
GET /api/v1/sites/subnets/?subnetname=192.168.1.0/24
```

### Create Subnet

```http
POST /api/v1/sites/{sitename}/subnets
```

**Request Body:**
```json
{
  "subnetname": "192.168.1.0/24"
}
```

### Delete Subnet

```http
DELETE /api/v1/sites/subnets/?subnetname=192.168.1.0/24
```

### Set Subnet Site

```http
PUT /api/v1/sites/subnets/site?subnetname=192.168.1.0/24
```

**Request Body:**
```json
{
  "sitename": "NewSite"
}
```

---

## Schema

### Show Schema Attribute

```http
GET /api/v1/schema/attributes/{attribute}
```

**Required Permission:** `schema.show`

### Show Schema Class

```http
GET /api/v1/schema/classes/{classname}
```

**Required Permission:** `schema.show`

---

## Delegation

### Add Delegation

```http
POST /api/v1/delegation/add
```

**Required Permission:** `delegation.set`

**Request Body:**
```json
{
  "accountname": "jdoe",
  "service": "cifs/server"
}
```

### Remove Delegation

```http
DELETE /api/v1/delegation/remove
```

**Required Permission:** `delegation.delete`

**Request Body:** Same as add.

### Show Delegations for Account

```http
GET /api/v1/delegation/for-account?accountname=jdoe
```

**Required Permission:** `delegation.list`

---

## Service Accounts

### List Service Accounts

```http
GET /api/v1/service-accounts/
```

**Required Permission:** `serviceaccount.list`

### Create Service Account

```http
POST /api/v1/service-accounts/
```

**Required Permission:** `serviceaccount.create`

**Request Body:**
```json
{
  "accountname": "svc_webapp",
  "dns_host_name": "webapp.example.com",
  "description": "Web application service account"
}
```

### Show Service Account

```http
GET /api/v1/service-accounts/{accountname}
```

**Required Permission:** `serviceaccount.show`

### Delete Service Account

```http
DELETE /api/v1/service-accounts/{accountname}
```

**Required Permission:** `serviceaccount.delete`

### Add gMSA Member

```http
POST /api/v1/service-accounts/{accountname}/gmsa-members/add
```

**Request Body:**
```json
{
  "members": ["DOMAIN\\jdoe", "DOMAIN\\webserver$"]
}
```

### Remove gMSA Member

```http
DELETE /api/v1/service-accounts/{accountname}/gmsa-members/remove
```

### List gMSA Members

```http
GET /api/v1/service-accounts/{accountname}/gmsa-members
```

---

## Authentication Policies

### List Authentication Silos

```http
GET /api/v1/auth/silos
```

**Required Permission:** `authpolicy.list`

### Create Authentication Silo

```http
POST /api/v1/auth/silos
```

**Required Permission:** `authpolicy.create`

**Request Body:**
```json
{
  "siloname": "HighSecuritySilo",
  "description": "High security authentication silo"
}
```

### Show Authentication Silo

```http
GET /api/v1/auth/silos/{siloname}
```

### Delete Authentication Silo

```http
DELETE /api/v1/auth/silos/{siloname}
```

### Add Silo Member

```http
POST /api/v1/auth/silos/{siloname}/members
```

**Request Body:**
```json
{
  "accountname": "jdoe"
}
```

### Remove Silo Member

```http
DELETE /api/v1/auth/silos/{siloname}/members
```

### List Authentication Policies

```http
GET /api/v1/auth/policies
```

### Create Authentication Policy

```http
POST /api/v1/auth/policies
```

**Request Body:**
```json
{
  "policyname": "StrictPolicy",
  "description": "Strict authentication policy"
}
```

### Show Authentication Policy

```http
GET /api/v1/auth/policies/{policyname}
```

### Delete Authentication Policy

```http
DELETE /api/v1/auth/policies/{policyname}
```

---

## Miscellaneous Operations

### Database Check

```http
GET /api/v1/misc/dbcheck
```

Runs as a background task.

### Database Check Fix

```http
POST /api/v1/misc/dbcheck/fix
```

**Request Body:**
```json
{
  "yes": true
}
```

Runs as a background task.

### Get NT ACL

```http
GET /api/v1/misc/ntacl?file_path=/var/lib/samba/sysvol
```

### Set NT ACL

```http
POST /api/v1/misc/ntacl/set
```

**Request Body:**
```json
{
  "file_path": "/var/lib/samba/sysvol/policy",
  "sddl": "D:PAI(A;OICI;0x001200a9;;;AU)"
}
```

### Reset Sysvol ACLs

```http
POST /api/v1/misc/ntacl/sysvolreset
```

Runs as a background task.

### Test Configuration (testparm)

```http
GET /api/v1/misc/testparm
```

Runs as a background task.

### List Samba Processes

```http
GET /api/v1/misc/processes
```

### Get Server Time

```http
GET /api/v1/misc/time
```

Uses 4 fallback methods: ldbsearch tdb:// → samba-tool time → CLDAP domain info → system clock.

### List SPNs

```http
GET /api/v1/misc/spn/list?accountname=jdoe
```

### Add SPN

```http
POST /api/v1/misc/spn/add
```

**Request Body:**
```json
{
  "accountname": "jdoe",
  "spn": "HTTP/web.example.com"
}
```

### Delete SPN

```http
DELETE /api/v1/misc/spn/delete
```

**Request Body:** Same as add.

---

## Shell Execution

### List Available Shells

```http
GET /api/v1/shell/
```

Returns available shell interpreters (`bash`, `python3`).

### Execute Command

```http
POST /api/v1/shell/exec
```

**Required Permission:** `shell.execute`

**Request Body:**
```json
{
  "command": "ls -la /var/log/samba/",
  "shell": "bash",
  "sudo": false,
  "timeout": 60
}
```

**Response:**
```json
{
  "status": "ok",
  "exit_code": 0,
  "stdout": "total 128\ndrwxr-xr-x...",
  "stderr": "",
  "command": "ls -la /var/log/samba/",
  "shell": "bash",
  "timeout": 60
}
```

Blocked patterns: `rm -rf /`, `mkfs.`, `dd if=`, fork bombs. Dangerous commands (reboot, shutdown) trigger warnings but are allowed.

### Execute Multi-line Script

```http
POST /api/v1/shell/script
```

**Request Body:**
```json
{
  "script": "#!/bin/bash\necho 'Hello'\ndate",
  "shell": "bash",
  "sudo": false,
  "timeout": 60
}
```

### Execute Script File

```http
POST /api/v1/shell/script/file
```

Upload a script file and execute it. Supports multipart form upload with `shell`, `sudo`, `timeout`, and `auto_delete` parameters.

---

## Shell Project

Shell Project provides a workspace-based environment for running commands with persistent state, archive extraction, scheduling, and webhook callbacks. Backed by PostgreSQL.

### Create Project

```http
POST /api/v1/shell/projet/
```

**Required Permission:** `shell.projet.create`

**Request Body:**
```json
{
  "name": "my-project",
  "description": "Test project",
  "command": "python3 main.py",
  "shell": "bash",
  "env": {"PYTHONPATH": "/app"},
  "encrypted_env": {"SECRET_KEY": "super-secret"},
  "tags": ["test", "automation"],
  "owner": "api-user",
  "ttl_seconds": 3600,
  "timeout": 300,
  "callback_url": "https://example.com/webhook",
  "working_dir": "src"
}
```

The project workspace is created at `{SHELL_PROJET_BASE_DIR}/{name}/{id}`.

### Upload Archive to Project

```http
POST /api/v1/shell/projet/{id}/upload
```

**Required Permission:** `shell.projet.upload`

Upload a file or archive (.zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar, .gz, .7z) to the project workspace. Archives are automatically extracted with path traversal rejection.

### Run Command in Project

```http
POST /api/v1/shell/projet/{id}/run
```

**Required Permission:** `shell.projet.run`

**Request Body:**
```json
{
  "command": "python3 main.py --verbose",
  "shell": "bash",
  "env": {"DEBUG": "1"},
  "timeout": 120
}
```

Only one command can run per project at a time (concurrent run protection).

### Show Project Details

```http
GET /api/v1/shell/projet/{id}
```

**Required Permission:** `shell.projet.show`

Also available as `GET /api/v1/shell/projet/show/{id}`.

### List Projects

```http
GET /api/v1/shell/projet/list
```

**Required Permission:** `shell.projet.list`

**Query Parameters:** `tag`, `owner`, `status` filters.

### Download Project Workspace

```http
GET /api/v1/shell/projet/{id}/download
```

Downloads the workspace as a .zip file.

### Delete Project

```http
DELETE /api/v1/shell/projet/{id}
```

**Required Permission:** `shell.projet.delete`

### Abort Running Command

```http
POST /api/v1/shell/projet/{id}/abort
```

**Required Permission:** `shell.projet.abort`

### Change Project Owner

```http
PATCH /api/v1/shell/projet/{id}/owner
```

**Request Body:**
```json
{
  "new_owner": "user2"
}
```

### Update Project Tags

```http
PATCH /api/v1/shell/projet/{id}/tags
```

**Request Body:**
```json
{
  "tags": ["production", "critical"]
}
```

### Create Schedule

```http
POST /api/v1/shell/projet/{id}/schedule
```

**Request Body:**
```json
{
  "cron_expression": "0 */6 * * *",
  "command_override": "python3 sync.py",
  "enabled": true
}
```

### List Schedules

```http
GET /api/v1/shell/projet/{id}/schedule
```

### Delete Schedule

```http
DELETE /api/v1/shell/projet/{id}/schedule/{schedule_id}
```

### Create Template

```http
POST /api/v1/shell/projet/template
```

**Request Body:**
```json
{
  "name": "web-deploy",
  "description": "Web deployment template",
  "command": "bash deploy.sh",
  "env": {"NODE_ENV": "production"},
  "tags": ["deploy"]
}
```

### Create Project from Template

```http
POST /api/v1/shell/projet/from-template/{template_id}
```

### List Templates

```http
GET /api/v1/shell/projet/templates
```

### Delete Template

```http
DELETE /api/v1/shell/projet/template/{template_id}
```

### Create Snapshot

```http
POST /api/v1/shell/projet/{id}/snapshot
```

### Rollback to Snapshot

```http
POST /api/v1/shell/projet/{id}/rollback/{snapshot_id}
```

### Get Project Audit Log

```http
GET /api/v1/shell/projet/{id}/audit
```

### Get Global Audit Log

```http
GET /api/v1/shell/projet/audit
```

### Batch Project Operations

```http
POST /api/v1/shell/projet/batch
```

### Project Health Check

```http
GET /api/v1/shell/projet/health
```

---

## Batch Operations

### Execute Batch

```http
POST /api/v1/batch/
```

**Required Permission:** `batch.execute`

Execute a sequence of operations with template resolution (`{{ step_id.field }}`).

**Request Body:**
```json
{
  "steps": [
    {
      "id": "create_user",
      "method": "user.create",
      "params": {
        "username": "jdoe",
        "password": "P@ssw0rd"
      }
    },
    {
      "id": "add_to_group",
      "method": "group.addmembers",
      "params": {
        "groupname": "Developers",
        "members": ["jdoe"]
      }
    }
  ],
  "stop_on_error": true,
  "rollback_on_error": false
}
```

**Supported Methods (60+):** `user.*`, `group.*`, `computer.*`, `contact.*`, `ou.*`, `dns.zone.*`, `dns.record.*`, `shell.exec`, `shell.script`, `misc.spn.*`, `misc.ntacl.*`, `domain.*`, `fsmo.show`, `drs.*`, `gpo.*`, `sites.*`, `delegation.*`, `service_account.*`, `auth.*`.

**Blocked Methods (too dangerous):** `domain.backup.*`, `domain.join`, `domain.leave`, `domain.demote`, `domain.provision`, `gpo.backup`, `gpo.restore`, `misc.dbcheck*`, `misc.ntacl.sysvolreset`, `misc.testparm`.

### Batch Request

```http
POST /api/v1/batch
```

**Required Permission:** `batch.execute`

**Request Body:**
```json
{
  "actions": [
    {
      "id": "step1",
      "method": "user.create",
      "params": {
        "username": "jdoe",
        "password": "P@ssw0rd123",
        "surname": "Doe",
        "given_name": "John"
      }
    },
    {
      "id": "step2",
      "method": "group.addmembers",
      "params": {
        "groupname": "Developers",
        "members": ["{{ step1.username }}"]
      }
    }
  ],
  "batch_id": "onboard-jdoe",
  "rollback_on_failure": false,
  "stop_on_failure": true,
  "default_timeout": 30
}
```

### Batch Action Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | No | Step identifier for template references (`{{ step_id.field }}`) |
| `method` | string | Yes | Dot-notation method name (e.g. `user.create`, `dns.zone.create`) |
| `params` | object | No | Parameters for the method; supports `{{ step_id.field }}` placeholders |
| `timeout` | int | No | Per-action timeout (1-600s); overrides `default_timeout` |

### Batch Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `actions` | array | — | Ordered list of actions (1-100 max) |
| `batch_id` | string | Auto UUID | Custom prefix, available as `{{ batch_id }}` |
| `rollback_on_failure` | bool | false | Attempt to undo successful steps on failure (best-effort) |
| `stop_on_failure` | bool | true | Stop on first failure; if false, continue and mark `partial_failure` |
| `default_timeout` | int | 30 | Default timeout for shell operations (1-600s) |

### Supported Batch Methods (60+)

**Users:** user.create, user.delete, user.enable, user.disable, user.unlock, user.setpassword, user.getpassword, user.list, user.show, user.getgroups, user.setexpiry, user.move, user.rename, user.addunixattrs, user.sensitive

**Groups:** group.create, group.delete, group.addmembers, group.removemembers, group.listmembers, group.list, group.show, group.move, group.stats

**Computers:** computer.create, computer.delete, computer.list, computer.show, computer.move

**Contacts:** contact.create, contact.delete, contact.list, contact.show, contact.move, contact.rename

**OUs:** ou.create, ou.delete, ou.list, ou.move, ou.rename

**DNS:** dns.zone.create, dns.zone.delete, dns.zone.list, dns.zone.info, dns.record.create, dns.record.delete, dns.record.update, dns.record.list, dns.serverinfo, dns.zone.options

**Shell:** shell.exec, shell.script

**Misc:** misc.spn.add, misc.spn.delete, misc.spn.list, misc.ntacl.get, misc.ntacl.set

**Domain:** domain.info, domain.level, domain.passwordsettings

**FSMO:** fsmo.show

**DRS:** drs.showrepl, drs.bind, drs.options, drs.replicate, drs.uptodateness

**GPO:** gpo.list, gpo.create, gpo.delete, gpo.show, gpo.setlink, gpo.dellink, gpo.getinheritance, gpo.setinheritance

**Sites:** sites.list, sites.create, sites.remove, sites.subnet.create, sites.subnet.remove

**Delegation:** delegation.add, delegation.remove, delegation.for_account

**Service Accounts:** service_account.create, service_account.delete, service_account.list, service_account.show, service_account.gmsa_members.add, service_account.gmsa_members.remove, service_account.gmsa_members.list

**Auth Policies:** auth.silo.create, auth.silo.delete, auth.silo.list, auth.silo.show, auth.silo.members.add, auth.silo.members.remove, auth.policy.create, auth.policy.delete, auth.policy.list, auth.policy.show

### Blocked Batch Methods

These methods are NOT allowed in batch because they are too slow (background tasks) or too dangerous:
- domain.backup.online, domain.backup.offline
- domain.join, domain.leave, domain.demote, domain.provision
- gpo.backup, gpo.restore
- misc.dbcheck, misc.dbcheck.fix
- misc.ntacl.sysvolreset, misc.testparm

---

## AI Assistant

### AI Assistant (Task Builder)

```http
POST /api/v1/ai/assistant
```

**Request Body:**
```json
{
  "prompt": "Create 5 users for the marketing department and add them to the Marketing group",
  "model": "openai/gpt-oss-120b",
  "safe_mode": true
}
```

**Response:**
```json
{
  "status": "ok",
  "actions": [
    {
      "method": "user.create",
      "params": {"username": "{{USER_INPUT}}", "password": "{{USER_INPUT}}"}
    }
  ],
  "explanation": "I'll create 5 users and add them to the Marketing group...",
  "model_used": "openai/gpt-oss-120b"
}
```

In **Safe Mode**, real values are replaced with `{{USER_INPUT}}` placeholders.

### AI Agent (Direct Execution)

```http
POST /api/v1/ai/agent
```

**Request Body:**
```json
{
  "prompt": "List all disabled users and enable them",
  "model": "openai/gpt-oss-120b",
  "max_steps": 5
}
```

The agent autonomously:
1. Reads the OpenAPI schema to discover available endpoints
2. Plans and executes tool calls (`execute_samba_api`, `execute_samba_api_as`, `execute_shell_command`, `save_file`, `read_file`)
3. Feeds results back to the LLM for next-step planning
4. Returns the final result with full audit trail

### AI Agent Tools

The AI agent has access to the following tools:

| Tool | Description |
|------|-------------|
| `execute_samba_api` | Call any API endpoint using the admin API key (full access) |
| `execute_samba_api_as` | Call API on behalf of a specific user (RBAC testing). Looks up user by username/ID, creates JWT token, makes request. Returns 403 if user lacks permission. |
| `execute_shell_command` | Execute shell commands on the server |
| `save_file` | Save/export data to files (CSV, JSON, XLSX, TXT) |
| `read_file` | Read files from the server |
| `manage_samba_share` | Create, edit, delete Samba file shares |
| `manage_samba_config` | Read/modify smb.conf |
| `system_admin` | System administration (services, logs, backups) |
| `network_admin` | Network diagnostics |
| `ai_skill_execute` | Execute AI skills |
| `request_api_access` | Discover available endpoints by permission |
| `manage_postgresql` | PostgreSQL database management |
| `ldbsearch_ad` | Direct AD database queries via ldbsearch |
| `data_import` | Import data from API, files, JSON |
| `data_export` | Export to XLSX/CSV/JSON |
| `data_transform` | Filter, sort, aggregate data |
| `data_diagram` | Create charts/diagrams |

**`execute_samba_api_as` — RBAC Testing (v1.9.6-4):**

This tool allows the AI agent to make API calls on behalf of a specific management user, which is essential for testing role-based access control. The tool:
1. Looks up the user by username or numeric user ID in the management database
2. Gets their role and permissions
3. Creates a temporary JWT access token for that user
4. Makes the API call using that JWT token
5. Returns the response (including 403 Forbidden if the user lacks the required permission)

**Example:** Test that a `junior_admin` user cannot delete AD users:
```
execute_samba_api_as(
  method="DELETE",
  path="/api/v1/users/testuser",
  as_user="junior_admin"
)
→ Response: http_status=403, "Role 'Junior Admin' does not have permission for DELETE /api/v1/users/testuser"
```

**Example:** Test that a `junior_admin` user can list users:
```
execute_samba_api_as(
  method="GET",
  path="/api/v1/users",
  as_user="junior_admin"
)
→ Response: http_status=200, data=[...]
```

The `as_user` parameter accepts either a username string (e.g. `"junior_admin"`) or a numeric user ID (e.g. `"4"`).

### Get AI Schema

```http
GET /api/v1/ai/schema
```

Returns the compressed OpenAPI schema used by the AI service.

### Get AI Configuration

```http
GET /api/v1/ai/config
```

### AI Chat (Persistent Sessions)

The AI Chat endpoints provide persistent, multi-turn conversation sessions with the AI assistant. Chat sessions, messages, and usage/cost tracking are stored in PostgreSQL.

**Create Chat:**
```http
POST /api/v1/ai/chat/
```

**Request Body:**
```json
{
  "title": "User Management Session",
  "model": "deepseek/deepseek-v4-flash"
}
```

**Send Message:**
```http
POST /api/v1/ai/chat/{chat_id}/send
```

**Request Body:**
```json
{
  "content": "Create a Junior Admin role with user management permissions"
}
```

**Stream Response:**
```http
POST /api/v1/ai/chat/{chat_id}/stream
```

Returns Server-Sent Events (SSE) stream for real-time token output.

**Chat Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ai/chat/` | Create new chat session |
| GET | `/ai/chat/list` | List user's chat sessions |
| GET | `/ai/chat/{chat_id}` | Get chat session details |
| PUT | `/ai/chat/{chat_id}` | Update chat (title, archive) |
| DELETE | `/ai/chat/{chat_id}` | Delete chat session |
| POST | `/ai/chat/{chat_id}/send` | Send message (returns full response) |
| POST | `/ai/chat/{chat_id}/stream` | Send message (SSE stream) |
| GET | `/ai/chat/{chat_id}/history` | Get chat message history |
| GET | `/ai/chat/{chat_id}/info` | Get chat info and cost summary |

### AI Info & Balance

```http
GET /api/v1/ai/info
GET /api/v1/ai/balance
GET /api/v1/ai/exports
GET /api/v1/ai/exports/{filename}
```

---

## Management API (Admin Panel)

The Management API provides user, API key, role, and permission management. All endpoints are under `/api/v1/mgmt/`.

### Management Users

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| GET | `/mgmt/users` | List management users | `mgmt.users.list` |
| POST | `/mgmt/users` | Create management user | `mgmt.users.create` |
| GET | `/mgmt/users/{user_id}` | Get user details | `mgmt.users.show` |
| PUT | `/mgmt/users/{user_id}` | Update user | `mgmt.users.update` |
| DELETE | `/mgmt/users/{user_id}` | Delete user (soft) | `mgmt.users.delete` |

**Create User (JSON Body):**
```json
{
  "username": "junior_admin",
  "password": "SecurePass123!",
  "role": "operator",
  "full_name": "Junior Administrator",
  "email": "junior@example.com"
}
```
Only `username` and `password` are required. `role` defaults to `"operator"`.

**Update User (JSON Body):**
```json
{
  "role": "auditor",
  "is_active": true,
  "full_name": "Updated Name"
}
```
All fields are optional. Only provided fields are updated.

### API Keys

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| GET | `/mgmt/keys` | List API keys | `mgmt.keys.list` |
| POST | `/mgmt/keys` | Create API key | `mgmt.keys.create` |
| GET | `/mgmt/keys/{key_id}` | Get key details | `mgmt.keys.show` |
| PUT | `/mgmt/keys/{key_id}` | Update key | `mgmt.keys.update` |
| DELETE | `/mgmt/keys/{key_id}` | Delete key | `mgmt.keys.delete` |
| POST | `/mgmt/keys/{key_id}/rotate` | Rotate key | `mgmt.keys.rotate` |

**Create API Key (JSON Body):**
```json
{
  "user_id": 4,
  "name": "junior-admin-key",
  "role": "Junior Admin",
  "expires_days": 90
}
```
`user_id` and `name` are required. `role` defaults to `"operator"`. `expires_days` is optional (no expiry if omitted).

**Update API Key (JSON Body):**
```json
{
  "name": "updated-key-name",
  "is_active": true,
  "expires_days": 30
}
```
All fields are optional. `expires_days` resets the expiry to N days from now.

**Important:** The plaintext API key is returned only once on creation and rotation. Subsequent requests show only a truncated hash.

### Roles

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| GET | `/mgmt/roles` | List all roles | `mgmt.roles.list` |
| GET | `/mgmt/roles/{role_name}` | Get role details | `mgmt.roles.list` |
| POST | `/mgmt/roles` | Create custom role | `mgmt.roles.create` |
| PUT | `/mgmt/roles/{role_name}` | Update role | `mgmt.roles.update` |
| DELETE | `/mgmt/roles/{role_name}` | Delete custom role | `mgmt.roles.delete` |

Built-in roles (`admin`, `operator`, `auditor`) cannot be renamed or deleted.

**Create Role Body:**
```json
{
  "name": "dns-admin",
  "description": "DNS administrator",
  "permissions": ["dns.zonecreate", "dns.zonedelete", "dns.recordcreate", "dns.recorddelete", "dns.recordupdate"]
}
```

**Update Role Body:**
```json
{
  "name": "dns-admin-v2",
  "description": "DNS administrator (updated)",
  "permissions": ["dns.zonecreate", "dns.zonedelete", "dns.recordcreate", "dns.recorddelete", "dns.recordupdate", "dns.zonelist"]
}
```

All fields are optional. The `name` field is used to rename a role. When renaming, the system also updates all references in `mgmt_users` and `mgmt_api_keys` tables to reflect the new role name.

**List Management Users Parameters:** `role` (filter by role), `is_active` (filter by active status), `offset`, `limit`

### Permissions

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| GET | `/mgmt/permissions` | List all permissions | `mgmt.perms.list` |
| POST | `/mgmt/permissions/assign` | Assign permissions to role | `mgmt.perms.assign` |
| POST | `/mgmt/permissions/revoke` | Revoke permissions from role | `mgmt.perms.revoke` |

### Audit Log

```http
GET /api/v1/mgmt/audit
```

**Required Permission:** `mgmt.audit.view`

**Query Parameters:** `user_id`, `action`, `endpoint`, `offset`, `limit`

---

## Dashboard

### Full AD Dashboard

```http
GET /api/v1/dashboard/full
```

**Required Permission:** `dashboard.full`

Fetches 8 data sources in parallel: users, groups, computers, contacts, OUs, GPOs, domain info, FSMO. Cached for 10 seconds.

### AD + System Overview

```http
GET /api/v1/dashboard/overview
```

Combines AD data with system metrics (CPU, memory, disk, uptime) and Samba stats. Cached for 30 seconds.

---

## Task Management

### Get Task Status

```http
GET /api/v1/tasks/{task_id}
```

**Required Permission:** `tasks.view`

**Response:**
```json
{
  "task_id": "abc-123",
  "status": "COMPLETED",
  "output": "...",
  "error": null,
  "created_at": "2026-05-16T10:00:00Z",
  "completed_at": "2026-05-16T10:00:05Z"
}
```

Task statuses: `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`

### List All Tasks

```http
GET /api/v1/tasks
```

**Required Permission:** `tasks.list`

---

## Data Models Reference

### Common Models

#### APIResponse
```json
{
  "status": "string",
  "message": "string"
}
```

#### SuccessResponse
```json
{
  "status": "ok",
  "message": "string"
}
```

#### ErrorResponse
```json
{
  "status": "error",
  "message": "string",
  "details": "any (optional)"
}
```

#### PaginatedResponse
```json
{
  "status": "ok",
  "message": "string",
  "items": [],
  "total": 150,
  "offset": 0,
  "limit": 100
}
```

#### TaskResponse
```json
{
  "message": "string",
  "task_id": "uuid",
  "result_url": "/api/v1/tasks/{task_id}"
}
```

#### LoginRequest
```json
{
  "username": "string (required)",
  "password": "string (required)"
}
```

#### TokenResponse
```json
{
  "access_token": "string",
  "refresh_token": "string",
  "token_type": "bearer",
  "expires_in": 1800,
  "role": "string",
  "permissions": ["string"]
}
```

#### MeResponse
```json
{
  "status": "ok",
  "auth_method": "jwt|api_key|credentials",
  "username": "string",
  "role": "string",
  "permissions": ["string"],
  "expires_at": "ISO-8601"
}
```

---

## Permissions Reference

Complete list of all 150+ permissions organized by category:

### Users (21 permissions)
| Permission | Description |
|-----------|-------------|
| `user.full` | Access /full fast endpoint |
| `user.list` | List all users |
| `user.create` | Create user accounts |
| `user.show` | View user details |
| `user.delete` | Delete user accounts |
| `user.enable` | Enable user accounts |
| `user.disable` | Disable user accounts |
| `user.unlock` | Unlock user accounts |
| `user.setpassword` | Set user passwords |
| `user.getpassword` | Retrieve user passwords |
| `user.getgroups` | View user group membership |
| `user.setexpiry` | Set account expiry |
| `user.setprimarygroup` | Change primary group |
| `user.addunixattrs` | Add Unix attributes |
| `user.sensitive` | Set sensitive flag |
| `user.move` | Move user to different OU |
| `user.rename` | Rename user account |
| `user.getkerberosticket` | Get Kerberos ticket |
| `user.search` | Search users |
| `user.import` | Import users from CSV |
| `user.export` | Export users |

### Groups (11 permissions)
| Permission | Description |
|-----------|-------------|
| `group.full` | Access /full fast endpoint |
| `group.list` | List all groups |
| `group.create` | Create groups |
| `group.show` | View group details |
| `group.delete` | Delete groups |
| `group.stats` | View group statistics |
| `group.addmembers` | Add members to group |
| `group.removemembers` | Remove members from group |
| `group.listmembers` | List group members |
| `group.move` | Move group to different OU |
| `group.rename` | Rename group |

### Computers (6 permissions)
`computer.full`, `computer.list`, `computer.create`, `computer.show`, `computer.delete`, `computer.move`

### Contacts (8 permissions)
`contact.full`, `contact.list`, `contact.create`, `contact.show`, `contact.delete`, `contact.move`, `contact.rename`, `contact.search`

### OUs (10 permissions)
`ou.full`, `ou.list`, `ou.create`, `ou.delete`, `ou.move`, `ou.rename`, `ou.listobjects`, `ou.tree`, `ou.stats`, `ou.search`

### DNS (11 permissions)
`dns.serverinfo`, `dns.zonelist`, `dns.zoneinfo`, `dns.zonecreate`, `dns.zonedelete`, `dns.recordlist`, `dns.recordcreate`, `dns.recorddelete`, `dns.recordupdate`, `dns.rorecords`, `dns.zoneoptions`

### GPO (14 permissions)
`gpo.full`, `gpo.list`, `gpo.create`, `gpo.show`, `gpo.delete`, `gpo.deletebyname`, `gpo.link`, `gpo.unlink`, `gpo.getinherit`, `gpo.setinherit`, `gpo.backup`, `gpo.restore`, `gpo.fetch`

### Domain (12 permissions)
`domain.full`, `domain.info`, `domain.level`, `domain.passwordsettings`, `domain.schemas`, `domain.provision`, `domain.join`, `domain.demote`, `domain.rename`, `domain.trustlist`, `domain.trustcreate`, `domain.trustdelete`

### DRS (5 permissions)
`drs.showrepl`, `drs.bind`, `drs.unbind`, `drs.options`, `drs.kcc`

### Sites (5 permissions)
`sites.list`, `sites.create`, `sites.show`, `sites.delete`, `sites.subnetlist`

### FSMO (5 permissions)
`fsmo.full`, `fsmo.show`, `fsmo.seize`, `fsmo.transfer`, `fsmo.roles`

### Schema (3 permissions)
`schema.list`, `schema.show`, `schema.query`

### Delegation (3 permissions)
`delegation.list`, `delegation.set`, `delegation.delete`

### Service Accounts (4 permissions)
`serviceaccount.list`, `serviceaccount.create`, `serviceaccount.show`, `serviceaccount.delete`

### Auth Policies (5 permissions)
`authpolicy.list`, `authpolicy.show`, `authpolicy.create`, `authpolicy.delete`, `authpolicy.update`

### Shell (2 permissions)
`shell.execute`, `shell.sudo`

### Shell Project (7 permissions)
`shell.projet.create`, `shell.projet.run`, `shell.projet.show`, `shell.projet.list`, `shell.projet.delete`, `shell.projet.upload`, `shell.projet.abort`

### Batch (2 permissions)
`batch.execute`, `batch.status`

### Management (17 permissions)
`mgmt.users.list`, `mgmt.users.create`, `mgmt.users.show`, `mgmt.users.update`, `mgmt.users.delete`, `mgmt.keys.list`, `mgmt.keys.create`, `mgmt.keys.show`, `mgmt.keys.update`, `mgmt.keys.delete`, `mgmt.keys.rotate`, `mgmt.audit.view`, `mgmt.roles.list`, `mgmt.roles.create`, `mgmt.roles.update`, `mgmt.roles.delete`, `mgmt.perms.list`, `mgmt.perms.assign`, `mgmt.perms.revoke`

### Dashboard (1 permission)
`dashboard.full`

### System (4 permissions)
`system.health`, `system.stats`, `system.metrics`, `system.tasks`

### Tasks (2 permissions)
`tasks.list`, `tasks.view`

### Auth (2 permissions)
`auth.me`, `auth.check`

### Misc (3 permissions)
`misc.time`, `misc.processes`, `misc.testparm`

---

## Default Role Permissions

### Admin
All 180+ permissions — full system access.

### Operator (Read-only)
All read permissions including:
- All `/full` fast endpoints
- All `list`, `show`, `get`, `stats`, `tree`, `search` operations
- System health, stats, metrics
- Task listing and viewing
- Auth me/check
- Misc time, processes, testparm

### Auditor
Same as Operator plus `mgmt.audit.view` (access to audit log).

---

## Quick Start

### 1. Start the Server

```bash
# Set required environment variables
export SAMBA_API_KEY="your-secret-api-key"

# Optional: configure JWT, CORS, etc.
export SAMBA_JWT_SECRET_KEY="your-jwt-secret"
export SAMBA_CORS_ORIGINS="https://admin.example.com"

# Run the server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8099
```

### 2. Test Health

```bash
curl http://localhost:8099/health
```

### 3. Authenticate

```bash
# API Key
curl -H "X-API-Key: your-secret-api-key" http://localhost:8099/api/v1/users/

# JWT Login
TOKEN=$(curl -s -X POST http://localhost:8099/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-secret-api-key"}' | jq -r '.access_token')

curl -H "Authorization: Bearer $TOKEN" http://localhost:8099/api/v1/users/
```

### 4. Common Operations

```bash
# List users
curl -H "X-API-Key: $KEY" http://localhost:8099/api/v1/users/

# Create a user
curl -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  http://localhost:8099/api/v1/users/ \
  -d '{"username":"jdoe","password":"P@ssw0rd"}'

# Get domain info
curl -H "X-API-Key: $KEY" http://localhost:8099/api/v1/domain/info

# Full dashboard
curl -H "X-API-Key: $KEY" http://localhost:8099/api/v1/dashboard/overview
```

---

*Documentation generated from source code analysis of Samba API Server v pr-a.1.1*
