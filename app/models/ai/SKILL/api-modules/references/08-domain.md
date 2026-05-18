# Domain Management — AI Skill Reference

> Module: `domain` | Router: `app/routers/domain.py` | Version: api_v1.9.6-7

## Overview

Comprehensive domain-level management for Samba AD DC. Covers domain information, functional level management, password policies, trust relationships, backup operations, KDS root keys, keytab export, and domain join/leave/demote operations. This is the most critical module — several operations are destructive and require explicit force flags.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/domain/info` | `domain.info` | Get domain info (via ldbsearch) |
| GET | `/api/v1/domain/full` | `domain.info` | Full domain info with all attributes |
| GET | `/api/v1/domain/level` | `domain.level_get` | Get current domain functional level |
| POST | `/api/v1/domain/level` | `domain.level_set` | Set domain functional level (2000–2016, validated) |
| GET | `/api/v1/domain/password-settings` | `domain.password_settings_get` | Get domain password policy |
| POST | `/api/v1/domain/password-settings` | `domain.password_settings_set` | Set domain password policy |
| GET | `/api/v1/domain/trusts` | `domain.trust_list` | List domain trusts |
| POST | `/api/v1/domain/trusts` | `domain.trust_create` | Create a trust (with DNS SRV pre-check) |
| DELETE | `/api/v1/domain/trusts/{trust}` | `domain.trust_delete` | Delete a trust relationship |
| GET | `/api/v1/domain/trusts/namespaces` | `domain.trust_namespaces` | List trust namespaces |
| POST | `/api/v1/domain/trusts/validate` | `domain.trust_validate` | Validate a trust relationship |
| POST | `/api/v1/domain/backup/online` | `domain.backup_online` | Online backup (background task) |
| POST | `/api/v1/domain/backup/offline` | `domain.backup_offline` | Offline backup (background task) |
| POST | `/api/v1/domain/kds-root-key` | `domain.kds_create` | Create a KDS root key |
| GET | `/api/v1/domain/kds-root-key` | `domain.kds_list` | List KDS root keys |
| POST | `/api/v1/domain/export-keytab` | `domain.export_keytab` | Export keytab file (rejects computer accounts) |
| POST | `/api/v1/domain/join` | `domain.join` | Join domain (dangerous, force required) |
| POST | `/api/v1/domain/leave` | `domain.leave` | Leave domain (dangerous, force required) |
| POST | `/api/v1/domain/demote` | `domain.demote` | Demote DC (dangerous, force required) |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `level` | integer | `/level` | Domain functional level: 2000, 2003, 2008, 2008R2, 2012, 2012R2, 2016 |
| `trust_domain` | string | `/trusts` | Trusted domain FQDN |
| `trust_type` | string | `/trusts` | Trust type: `forest`, `external`, `realm` |
| `trust_direction` | string | `/trusts` | Direction: `inbound`, `outbound`, `bidirectional` |
| `trust_password` | string | `/trusts` | Trust password |
| `force` | bool | `/join`, `/leave`, `/demote` | **Required** — acknowledges destructive operation |
| `principal` | string | `/export-keytab` | Principal name for keytab export |
| `keytab_password` | string | `/export-keytab` | Password for keytab encryption |

## Usage Examples

```bash
# Get domain info
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/domain/info

# Set domain functional level to 2016
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/domain/level \
  -d '{"level": 2016}'

# Create a forest trust with DNS SRV pre-check
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/domain/trusts \
  -d '{"trust_domain": "partner.example.com", "trust_type": "forest", "trust_direction": "bidirectional", "trust_password": "Tr0stP@ss!"}'

# Export keytab for a user principal
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/domain/export-keytab \
  -d '{"principal": "HTTP/webapp.example.com"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `domain.info` | — | Get domain info |
| `domain.level_get` | — | Get functional level |
| `domain.level_set` | `level` | Set functional level |
| `domain.password_settings_get` | — | Get password policy |
| `domain.password_settings_set` | settings object | Set password policy |
| `domain.trust_list` | — | List trusts |
| `domain.trust_create` | `trust_domain`, `trust_type`, `trust_direction`, `trust_password` | Create trust |
| `domain.trust_delete` | `trust` | Delete trust |
| `domain.kds_create` | — | Create KDS root key |
| `domain.kds_list` | — | List KDS root keys |
| `domain.export_keytab` | `principal` | Export keytab |

> **Blocked in batch:** `backup`, `join`, `leave`, `demote` — these are background or destructive operations.

## Notes

- **Functional level validation:** Only levels 2000–2016 are accepted. Raising the level is irreversible — ensure all DCs support the target level.
- **Trust creation** performs a DNS SRV record pre-check before attempting the trust. If the SRV record is missing, the operation fails with a descriptive error.
- **Backup operations** run as background tasks — check task status via the task tracking endpoint. Online backup runs while the DC is active; offline requires the DC service to be stopped.
- **Export keytab** rejects computer accounts (`$` suffix) — use user or service principals only.
- **Join/Leave/Demote** are extremely dangerous operations. They require `force: true` in the request body and should only be used in controlled maintenance windows.
- **KDS root keys** are required for Group Managed Service Accounts (gMSA). Allow 10+ hours after creation before using gMSA features to ensure replication.
