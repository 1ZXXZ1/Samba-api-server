# DNS Management — AI Skill Reference

> Module: `dns` | Router: `app/routers/dns.py` | Version: api_v1.9.6-7

## Overview

Manages DNS zones and records on the Samba AD DC using DCE/RPC over SMB with Kerberos authentication. Supports zone lifecycle management with 8 type filters, record CRUD operations, and zone option configuration. Includes automatic retry logic with exponential backoff for transient timeout errors, while non-transient errors (zone not found, object name not found) skip retry.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/dns/server` | `dns.server` | Get DNS server info (cached 300s) |
| GET | `/api/v1/dns/zones` | `dns.zone_list` | List DNS zones (8 type filters available) |
| GET | `/api/v1/dns/zones/{zone}` | `dns.zone_info` | Get zone information |
| POST | `/api/v1/dns/zones` | `dns.zone_create` | Create a zone (with overwrite for idempotency) |
| DELETE | `/api/v1/dns/zones/{zone}` | `dns.zone_delete` | Delete a zone |
| GET | `/api/v1/dns/zones/{zone}/records` | `dns.record_list` | List records in a zone |
| POST | `/api/v1/dns/zones/{zone}/records` | `dns.record_create` | Create a DNS record |
| DELETE | `/api/v1/dns/zones/{zone}/records` | `dns.record_delete` | Delete a DNS record |
| PUT | `/api/v1/dns/zones/{zone}/records` | `dns.record_update` | Update a DNS record |
| GET | `/api/v1/dns/zones/{zone}/query` | `dns.record_query` | Read-only query for specific records |
| GET | `/api/v1/dns/zones/{zone}/options` | `dns.zone_options` | Get zone options |
| PUT | `/api/v1/dns/zones/{zone}/options` | `dns.zone_options_set` | Set zone options |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `zone` | path | Zone/record endpoints | DNS zone name (e.g., `example.com`) |
| `zone_type` | string | `/zones` (list) | Filter: `primary`, `secondary`, `stub`, `forward`, `reverse`, `forest`, `domain`, `msdcs` |
| `overwrite` | bool | `/zones` (create) | Overwrite existing zone for idempotency |
| `name` | string | Record endpoints | Record name (relative to zone) |
| `type` | string | Record endpoints | Record type: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SRV`, `TXT`, `PTR`, `SOA` |
| `data` | string | Record endpoints | Record data/value |
| `ttl` | integer | Record endpoints | Time-to-live in seconds |

## Usage Examples

```bash
# List all primary DNS zones
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://dc.example.com/api/v1/dns/zones?zone_type=primary"

# Create an A record
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/dns/zones/example.com/records \
  -d '{"name": "webserver", "type": "A", "data": "192.168.1.100", "ttl": 3600}'

# Create a zone with overwrite (idempotent)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/dns/zones \
  -d '{"zone": "newzone.example.com", "zone_type": "primary", "overwrite": true}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `dns.zone_list` | `zone_type` | List zones |
| `dns.zone_create` | `zone`, `zone_type`, `overwrite` | Create zone |
| `dns.zone_info` | `zone` | Get zone info |
| `dns.zone_delete` | `zone` | Delete zone |
| `dns.record_list` | `zone` | List records |
| `dns.record_create` | `zone`, `name`, `type`, `data`, `ttl` | Create record |
| `dns.record_delete` | `zone`, `name`, `type`, `data` | Delete record |
| `dns.record_update` | `zone`, `name`, `type`, `data`, `ttl` | Update record |

## Notes

- **DCE/RPC over SMB with Kerberos:** DNS operations use RPC calls over SMB, requiring valid Kerberos tickets. Ensure time synchronization is correct.
- **Retry logic:** Transient timeout errors trigger exponential backoff retries. Non-transient errors like "zone not found" or "object name not found" skip retry and return immediately.
- **Server info caching:** The `/dns/server` response is cached for 300 seconds to reduce RPC overhead.
- **Zone type filters:** 8 filter types are available when listing zones — useful for separating forward/reverse zones or AD-integrated zones.
- **Record queries** are read-only via `/query` and do not support modifications — use the record CRUD endpoints for changes.
- **SOA records** are auto-managed for AD-integrated zones — manual SOA edits may be overwritten.
