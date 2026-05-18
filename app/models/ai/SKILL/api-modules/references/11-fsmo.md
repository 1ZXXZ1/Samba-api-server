# FSMO Roles — AI Skill Reference

> Module: `fsmo` | Router: `app/routers/fsmo.py` | Version: api_v1.9.6-7

## Overview

Manages Flexible Single Master Operations (FSMO) roles in the Samba AD domain. FSMO roles are specialized domain controller responsibilities that must be held by exactly one DC at a time. Supports viewing, transferring (graceful), and seizing (forceful takeover) of the five FSMO roles. Role information from the "full" endpoint is cached for 30 seconds.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/fsmo` | `fsmo.show` | Show FSMO role assignments (via ldbsearch) |
| GET | `/api/v1/fsmo/full` | `fsmo.show` | Full FSMO info with all details (cached 30s) |
| POST | `/api/v1/fsmo/transfer` | `fsmo.transfer` | Transfer a FSMO role to another DC (graceful) |
| POST | `/api/v1/fsmo/seize` | `fsmo.seize` | Seize a FSMO role (forceful — use when current holder is offline) |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `role` | string | `/transfer`, `/seize` | FSMO role name: `ridalloc`, `pdc`, `infrastructure`, `naming`, `schema` |
| `target_dc` | string | `/transfer`, `/seize` | Target DC hostname to receive the role |

### FSMO Roles Reference

| Role | LDAP Location | Scope | Description |
|------|---------------|-------|-------------|
| `ridalloc` | RID Manager | Domain | Allocates RID pools to DCs |
| `pdc` | PDC Emulator | Domain | Primary domain controller emulator |
| `infrastructure` | Infrastructure Master | Domain | Maintains cross-domain references |
| `naming` | Domain Naming Master | Forest | Controls domain additions/renames |
| `schema` | Schema Master | Forest | Controls schema modifications |

## Usage Examples

```bash
# View current FSMO role holders
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/fsmo

# Transfer the PDC Emulator role
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/fsmo/transfer \
  -d '{"role": "pdc", "target_dc": "dc2.example.com"}'

# Seize the RID Allocator role (emergency — current holder offline)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/fsmo/seize \
  -d '{"role": "ridalloc", "target_dc": "dc1.example.com"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `fsmo.show` | — | Show FSMO role assignments |
| `fsmo.transfer` | `role`, `target_dc` | Transfer a FSMO role |
| `fsmo.seize` | `role`, `target_dc` | Seize a FSMO role |

## Notes

- **Transfer vs. Seize:** Transfer is the safe method — the current role holder must be online. Seize is forceful and should only be used when the current holder is permanently offline.
- **Seizing is dangerous:** After seizing a role, the previous holder must never be brought back online without a full metadata cleanup.
- **Forest-level roles** (`naming`, `schema`) affect the entire forest — changes require Enterprise Admin privileges.
- **Caching:** The `/full` endpoint caches results for 30 seconds to reduce ldbsearch overhead.
- **Role validation:** The API validates that the specified role name is one of the five supported FSMO roles.
- In single-DC environments, all five roles are held by the same DC — there is typically no need to transfer.
