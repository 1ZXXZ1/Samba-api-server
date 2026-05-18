---
name: api-modules
description: >
  Comprehensive AI skill for the Samba AD DC Management REST API (v1.9.6-7).
  Covers all 19 API modules with 230+ endpoints for administering a Samba Active Directory
  Domain Controller via the REST API on 127.0.0.1:8099. Each module document provides
  endpoint tables, parameter references, batch method mappings, usage examples with curl,
  and operational notes. This skill enables an AI agent to construct correct API requests,
  understand permissions, handle rate limits, and use batch operations for complex workflows.
---

## Trigger

Activate this skill when the user needs to:
- Manage a Samba AD DC via the REST API (not CLI)
- Create, read, update, or delete AD objects (users, groups, computers, contacts, OUs)
- Configure DNS zones and records through the API
- Manage Group Policy Objects (GPOs), FSMO roles, or DRS replication
- Configure domain settings, trusts, password policies, or functional levels
- Manage sites, subnets, schema, delegations, or service accounts
- Configure authentication policies and silos
- Execute shell commands or manage shell projects via the API
- Perform batch (multi-step) operations with rollback
- Interact with the AI assistant or chat endpoints
- Manage API keys, roles, permissions, or audit logs
- Monitor system health, metrics, or dashboard data
- Any task involving `127.0.0.1:8099/api/v1/*` endpoints

## API Quick Reference

| Property | Value |
|----------|-------|
| **Base URL** | `http://127.0.0.1:8099/api/v1` |
| **Version** | api_v1.9.6-7 |
| **Auth** | `X-API-Key` header or `Authorization: Bearer <JWT>` |
| **Format** | JSON (request/response) |
| **Rate Limits** | Auth: 10/min, Read: 100/min, Write: 60/min, Shell: 120/min |
| **Cache** | TTL 3s (default), 30s (/full endpoints), 300s (DNS server) |

## Module Reference Files

Each module is documented in a separate file with full endpoint details, parameters, examples, and batch method mappings:

| # | Module | File | Endpoints | Description |
|---|--------|------|-----------|-------------|
| 01 | System | `01-system.md` | 4 | Health checks, metrics, system stats |
| 02 | Auth | `02-auth.md` | 4 | JWT login, refresh, current user, credential check |
| 03 | Users | `03-users.md` | 22 | Full user CRUD, password, groups, move, rename, Kerberos, import/export |
| 04 | Groups | `04-groups.md` | 10 | Group CRUD, members, stats, move |
| 05 | Computers | `05-computers.md` | 6 | Computer CRUD, move |
| 06 | Contacts | `06-contacts.md` | 7 | Contact CRUD, move, rename |
| 07 | OUs | `07-ous.md` | 11 | OU CRUD, tree, search, stats, objects |
| 08 | Domain | `08-domain.md` | 19 | Domain info, level, password settings, trusts, backup, KDS, keytab, join/leave |
| 09 | DNS | `09-dns.md` | 12 | DNS server info, zones, records, query, options |
| 10 | GPO | `10-gpo.md` | 13 | GPO CRUD, link/unlink, inheritance, backup/restore, fetch |
| 11 | FSMO | `11-fsmo.md` | 4 | FSMO show, transfer, seize |
| 12 | DRS | `12-drs.md` | 6 | Show replication, replicate, uptodateness, bind, options |
| 13 | Sites | `13-sites.md` | 9 | Sites and subnets CRUD |
| 14 | Schema | `14-schema.md` | 2 | Schema attribute and class queries |
| 15 | Delegation | `15-delegation.md` | 3 | Add/remove delegations, show for account |
| 16 | Service Accounts | `16-service-accounts.md` | 7 | Service accounts, gMSA members |
| 17 | Auth Policies | `17-auth-policies.md` | 10 | Authentication silos and policies |
| 18 | Misc | `18-misc.md` | 11 | dbcheck, ntacl, testparm, processes, time, SPN |
| 19 | Batch | `19-batch.md` | 1 | Multi-step sequential operations (60+ methods) |

**Total: 230+ endpoints across 19 modules**

## Authentication Patterns

### API Key (Static)
```bash
curl -s -H "X-API-Key: your-api-key" \
  http://127.0.0.1:8099/api/v1/users
```

### JWT Bearer Token
```bash
# Step 1: Login
TOKEN=$(curl -s -X POST http://127.0.0.1:8099/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "administrator", "password": "S3cur3P@ss"}' | jq -r '.access_token')

# Step 2: Use token
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8099/api/v1/users
```

## Permission System

All endpoints (except public) require permissions in `resource.action` format:

| Built-in Role | Access Level |
|---------------|-------------|
| `admin` | All 150+ permissions |
| `operator` | All read permissions |
| `auditor` | Read + audit log |

Custom roles can be created via `POST /api/v1/mgmt/roles`.

## Rate Limiting

| Category | Limit | Scope |
|----------|-------|-------|
| Auth | 10 req/min | Per IP |
| Read (GET) | 100 req/min | Per user |
| Write (POST/PUT/DELETE) | 60 req/min | Per user |
| Shell Project | 120 req/min | Per user |

On 429: wait for `Retry-After` header, then retry.

## Batch Operations

The batch endpoint (`POST /api/v1/batch`) supports 60+ methods across all modules. Key features:

- **Sequential execution** with template resolution: `{{ step_id.field }}`
- **Best-effort rollback** on failure (optional)
- **Max 100 actions** per batch request

```json
{
  "actions": [
    {"id": "step1", "method": "user.create", "params": {"username": "jdoe", "password": "P@ssw0rd1"}},
    {"id": "step2", "method": "group.add_members", "params": {"groupname": "DevOps", "members": ["{{ step1.username }}"]}}
  ],
  "rollback": true
}
```

Blocked in batch: `domain.backup_*`, `domain.join/leave/demote`, `gpo.backup/restore`, `misc.dbcheck*`, `misc.testparm`, `misc.ntacl_sysvolreset`.

## Background Tasks

Long operations run as background tasks (returns `task_id`):
- Domain backup (online/offline)
- GPO delete, backup, restore
- DRS replicate
- dbcheck, dbcheck_fix, testparm, sysvolreset
- User import from CSV
- Shell project commands

Poll status: `GET /api/v1/tasks/{task_id}` or subscribe via WebSocket: `ws://127.0.0.1:8099/ws/tasks/{task_id}`.

## Common Error Handling

| HTTP Code | Meaning | Action |
|-----------|---------|--------|
| 400 | Bad Request | Check request body format and parameters |
| 401 | Unauthorized | Verify API key or refresh JWT token |
| 403 | Forbidden | Check role permissions for the endpoint |
| 404 | Not Found | Verify resource name (sAMAccountName, DN, etc.) |
| 409 | Conflict | Resource already exists — use overwrite flag |
| 422 | Validation Error | Check Pydantic model constraints |
| 429 | Rate Limited | Wait for `Retry-After` header, then retry |
| 500 | Internal Error | Check server logs, retry once |
| 504 | Gateway Timeout | DNS/DRS/GPO RPC timeout — retry after delay |
| 507 | Insufficient Storage | DRS/GPO quota exceeded |

## Known Issues (v1.9.6-7)

1. **DNS zone creation**: May timeout in single-DC environments due to RPC server unavailability. Retry with exponential backoff (4 attempts).
2. **GPO creation**: Uses LDAPI bypass for CLDAP `finddc()` bug. Ensure `SAMBA_LDAPI_URL` is configured.
3. **DRS operations**: All timeout in single-DC environments (no replication partner). Expected behavior.
4. **Domain level validation**: Now restricted to valid values (2000, 2003, 2008, 2008_R2, 2012, 2012_R2, 2016).

## Related Skills

This API skill works alongside these CLI skills for deeper Samba AD administration:

| Skill | Description |
|-------|-------------|
| `samba-tool-alt-linux-cli` | Full samba-tool CLI reference (Samba 4.21.9-alt1) |
| `alt-domain-cli-skill` | ALT Domain 11.1 CLI reference |
| `smbclient-alt-linux-cli` | smbclient CLI for file share access |
| `rpcclient-alt-linux-cli` | rpcclient CLI for MS-RPC operations |
| `wbinfo-alt-linux-cli` | wbinfo CLI for Winbind queries |
| `ldbsearch-tool-alt-linux-cli` | ldbsearch CLI for direct LDB queries |
| `xlsx` | Spreadsheet creation and data export |
| `file-organizer` | File organization utility |

## Notes

- **Fast Read Path**: All `GET` endpoints and `/full` variants use `ldbsearch` (direct LDB/TDB access) for 10-100x faster queries vs `samba-tool`.
- **Direct SamDB Writes**: Write operations attempt direct SamDB API calls first (~1-2s), falling back to `samba-tool` subprocess.
- **Caching**: Responses cached with TTL 3s (default), 30s (/full endpoints), 300s (DNS server info). Cache auto-invalidated on writes.
- **Environment**: This API runs on `127.0.0.1:8099` with PostgreSQL backend, 4 worker threads, Python 3.12.
- **Management DB**: All users, API keys, roles, audit logs, and AI chat sessions stored in PostgreSQL (migrated from SQLite in v1.8.5).
