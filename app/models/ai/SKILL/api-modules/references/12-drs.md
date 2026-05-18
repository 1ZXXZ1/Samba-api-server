# DRS Replication — AI Skill Reference

> Module: `drs` | Router: `app/routers/drs.py` | Version: api_v1.9.6-7

## Overview

Manages Directory Replication Services (DRS) for Samba AD. Uses the DRSUAPI RPC protocol for replication operations. Supports viewing replication status, triggering replication (as a background task), checking uptodateness vector, and managing DRS bindings and options. Localhost references in commands are automatically replaced with the real DC hostname.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/drs/showrepl` | `drs.showrepl` | Show replication status (Device Timeout → 504, Quota → 507) |
| POST | `/api/v1/drs/replicate` | `drs.replicate` | Trigger replication (background task) |
| GET | `/api/v1/drs/uptodateness` | `drs.uptodateness` | Get uptodateness vector |
| POST | `/api/v1/drs/bind` | `drs.bind` | DRS bind operation |
| GET | `/api/v1/drs/options` | `drs.options` | Get DRS options |
| POST | `/api/v1/drs/options` | `drs.options_set` | Set DRS options |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `source_dc` | string | `/replicate` | Source DC for replication |
| `destination_dc` | string | `/replicate` | Destination DC for replication |
| `partition` | string | `/replicate` | Partition DN to replicate (e.g., `DC=example,DC=com`) |
| `full_sync` | bool | `/replicate` | Force full synchronization instead of delta |

## Usage Examples

```bash
# Show replication status
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/drs/showrepl

# Trigger replication from DC1 to DC2
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/drs/replicate \
  -d '{"source_dc": "dc1.example.com", "destination_dc": "dc2.example.com", "partition": "DC=example,DC=com"}'

# Check uptodateness vector
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/drs/uptodateness
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `drs.showrepl` | — | Show replication status |
| `drs.replicate` | `source_dc`, `destination_dc`, `partition`, `full_sync` | Trigger replication |
| `drs.uptodateness` | — | Get uptodateness vector |
| `drs.bind` | — | DRS bind |
| `drs.options` | — | Get DRS options |

## Notes

- **Device Timeout → 504:** If the DRS operation times out (typically when a DC is unreachable), the API returns HTTP 504 Gateway Timeout.
- **Quota → 507:** If a replication quota is exceeded, the API returns HTTP 507 Insufficient Storage.
- **Localhost auto-replacement:** Any `localhost` or `127.0.0.1` references in source/destination DC parameters are automatically replaced with the real DC hostname to ensure proper DRS binding.
- **DRSUAPI RPC:** This module uses the DRSUAPI RPC protocol over SMB — ensure Kerberos authentication and network connectivity to all DCs.
- **Replication is a background task:** The `/replicate` endpoint starts a background task. Check the task status endpoint for completion and results.
- **showrepl output** may be large in multi-DC environments — consider pagination or filtering if available.
