# Miscellaneous — AI Skill Reference

> Module: `misc` | Router: `app/routers/misc.py` | Version: api_v1.9.6-7

## Overview

Provides miscellaneous system and AD management utilities that don't fit neatly into other modules. Covers database consistency checks, NTACL management, Samba configuration testing, process monitoring, time synchronization, and Service Principal Name (SPN) management. Several operations run as background tasks. The time endpoint uses a 4-method fallback chain for reliability.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/api/v1/misc/dbcheck` | `misc.dbcheck` | Run database consistency check (background task) |
| POST | `/api/v1/misc/dbcheck/fix` | `misc.dbcheck` | Run database check and fix errors (background task) |
| GET | `/api/v1/misc/ntacl` | `misc.ntacl_get` | Get NT ACL for a file/path |
| POST | `/api/v1/misc/ntacl` | `misc.ntacl_set` | Set NT ACL for a file/path |
| POST | `/api/v1/misc/ntacl/sysvolreset` | `misc.ntacl_sysvolreset` | Reset SysVol NT ACLs to defaults |
| POST | `/api/v1/misc/testparm` | `misc.testparm` | Test Samba configuration (background task) |
| GET | `/api/v1/misc/processes` | `misc.processes` | List Samba-related processes |
| GET | `/api/v1/misc/time` | `misc.time` | Get current time (4 fallback methods) |
| GET | `/api/v1/misc/spn` | `misc.spn_list` | List SPNs for an account |
| POST | `/api/v1/misc/spn` | `misc.spn_add` | Add an SPN to an account |
| DELETE | `/api/v1/misc/spn` | `misc.spn_delete` | Delete an SPN from an account |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `path` | string | `/ntacl` (get/set) | File or directory path for NTACL operations |
| `acl` | string/object | `/ntacl` (set) | ACL specification to apply |
| `account` | string | `/spn` | Target account sAMAccountName |
| `spn` | string | `/spn` (add/delete) | Service Principal Name (e.g., `HTTP/server.example.com`) |
| `fix` | bool | `/dbcheck/fix` | Whether to auto-fix detected errors |

## Usage Examples

```bash
# Run a database consistency check
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/misc/dbcheck

# Get the current AD time
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/misc/time

# Add an SPN to a user account
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/misc/spn \
  -d '{"account": "svc-webapp", "spn": "HTTP/webapp.example.com"}'

# Reset SysVol ACLs
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/misc/ntacl/sysvolreset
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `misc.dbcheck` | — | Database check (background) |
| `misc.ntacl_get` | `path` | Get NT ACL |
| `misc.ntacl_set` | `path`, `acl` | Set NT ACL |
| `misc.processes` | — | List processes |
| `misc.time` | — | Get current time |
| `misc.spn_list` | `account` | List SPNs |
| `misc.spn_add` | `account`, `spn` | Add SPN |
| `misc.spn_delete` | `account`, `spn` | Delete SPN |

> **Blocked in batch:** `dbcheck/fix`, `testparm`, `ntacl/sysvolreset` — these are background or system-altering operations.

## Notes

- **Time fallback chain:** The `/time` endpoint tries 4 methods in order: (1) ldbsearch tdb → (2) samba-tool → (3) CLDAP → (4) system clock. If one method fails, the next is attempted automatically.
- **dbcheck/fix** is a background task that can take significant time on large databases. Always run `dbcheck` (read-only) first to assess issues before running `dbcheck/fix`.
- **NTACL operations** require careful handling — incorrect ACLs can break Samba file sharing and SysVol replication.
- **sysvolreset** resets all SysVol ACLs to their default values. Use with caution as custom ACLs will be overwritten.
- **SPN management** is critical for Kerberos authentication — duplicate SPNs will cause authentication failures. Use `spn_list` to check for duplicates before adding.
- **testparm** runs as a background task and validates the `smb.conf` configuration file.
