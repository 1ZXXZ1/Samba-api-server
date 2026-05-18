# Group Policy Management — AI Skill Reference

> Module: `gpo` | Router: `app/routers/gpo.py` | Version: api_v1.9.6-7

## Overview

Manages Group Policy Objects (GPOs) in the Samba AD domain. Supports full GPO lifecycle including creation with overwrite for idempotency, linking/unlinking to OUs, inheritance control, and backup/restore operations. Several operations run as background tasks. The module includes workarounds for known Samba issues such as the CLDAP finddc bug (bypassed via LDAPI).

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/gpo` | `gpo.list` | List GPOs (via ldbsearch) |
| GET | `/api/v1/gpo/full` | `gpo.list` | Full GPO list with all attributes |
| POST | `/api/v1/gpo` | `gpo.create` | Create a GPO (with overwrite for idempotency) |
| GET | `/api/v1/gpo/{gpo_id}` | `gpo.show` | Show GPO details (via ldbsearch) |
| DELETE | `/api/v1/gpo/{gpo_id}` | `gpo.delete` | Delete a GPO (background task) |
| DELETE | `/api/v1/gpo/name/{name}` | `gpo.delete` | Delete a GPO by display name |
| POST | `/api/v1/gpo/{gpo_id}/link` | `gpo.link` | Link a GPO to an OU |
| POST | `/api/v1/gpo/{gpo_id}/unlink` | `gpo.unlink` | Unlink a GPO from an OU |
| GET | `/api/v1/gpo/{gpo_id}/inheritance` | `gpo.get_inheritance` | Get GPO inheritance status |
| POST | `/api/v1/gpo/{gpo_id}/inheritance` | `gpo.set_inheritance` | Set GPO inheritance (block/enabled) |
| POST | `/api/v1/gpo/{gpo_id}/backup` | `gpo.backup` | Backup a GPO (background task) |
| POST | `/api/v1/gpo/{gpo_id}/restore` | `gpo.restore` | Restore a GPO (background task) |
| GET | `/api/v1/gpo/{gpo_id}/fetch` | `gpo.fetch` | Fetch GPO content/details |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `gpo_id` | path | Most endpoints | GPO GUID (e.g., `{31B2F340-016D-11D2-945F-00C04FB984F9}`) |
| `name` | string | `/create`, `/name/{name}` | GPO display name |
| `overwrite` | bool | `/create` | Overwrite existing GPO for idempotency |
| `ou` | string | `/link`, `/unlink` | Target OU distinguished name |
| `enabled` | bool | `/link` | Enable/disable the GPO link |
| `enforced` | bool | `/link` | Enforce the GPO link (no override) |
| `block_inheritance` | bool | `/inheritance` | Block inheritance on the OU |
| `backup_dir` | string | `/backup`, `/restore` | Directory path for backup/restore |

## Usage Examples

```bash
# Create a new GPO with idempotent overwrite
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/gpo \
  -d '{"name": "Desktop Lockdown Policy", "overwrite": true}'

# Link a GPO to an OU
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/gpo/{31B2F340-016D-11D2-945F-00C04FB984F9}/link \
  -d '{"ou": "OU=Workstations,DC=example,DC=com", "enabled": true, "enforced": false}'

# Backup a GPO (background task)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/gpo/{31B2F340-016D-11D2-945F-00C04FB984F9}/backup \
  -d '{"backup_dir": "/var/backups/gpo"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `gpo.list` | `page`, `page_size` | List GPOs |
| `gpo.create` | `name`, `overwrite` | Create GPO |
| `gpo.show` | `gpo_id` | Show GPO details |
| `gpo.delete` | `gpo_id` | Delete GPO |
| `gpo.link` | `gpo_id`, `ou`, `enabled`, `enforced` | Link GPO to OU |
| `gpo.unlink` | `gpo_id`, `ou` | Unlink GPO from OU |
| `gpo.get_inheritance` | `gpo_id` | Get inheritance |
| `gpo.set_inheritance` | `gpo_id`, `block_inheritance` | Set inheritance |

> **Blocked in batch:** `gpo.backup`, `gpo.restore` — these are background tasks.

## Notes

- **LDAPI bypass:** GPO creation uses LDAPI (LDAP over IPC) instead of CLDAP to work around a known Samba CLDAP `finddc` bug. This ensures reliable GPO creation.
- **Device Timeout → 504:** If a GPO operation times out due to device communication issues, the API returns HTTP 504 Gateway Timeout.
- **Background tasks:** Delete, backup, and restore run as background tasks. Check the task status endpoint for completion.
- **GPO ID format:** GPOs are identified by their GUID — always include the curly braces (e.g., `{GUID}`).
- **Delete by name** is a convenience endpoint for cases where only the display name is known and looking up the GUID is impractical.
- **Overwrite flag** on create makes the operation idempotent — if a GPO with the same name exists, it is replaced rather than creating a duplicate.
