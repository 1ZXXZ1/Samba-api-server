# Sites & Subnets — AI Skill Reference

> Module: `sites` | Router: `app/routers/sites.py` | Version: api_v1.9.6-7

## Overview

Manages Active Directory sites and subnets for replication topology and client logon optimization. Sites define physical network locations, and subnets map IP ranges to sites for efficient DC discovery. Uses `build_samba_command_deep` with JSON auto-mode for structured command execution.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/sites` | `sites.list` | List all sites |
| GET | `/api/v1/sites/{sitename}` | `sites.show` | View site details |
| POST | `/api/v1/sites` | `sites.create` | Create a new site |
| DELETE | `/api/v1/sites/{sitename}` | `sites.delete` | Delete a site |
| GET | `/api/v1/subnets` | `sites.subnet_list` | List all subnets |
| GET | `/api/v1/subnets/{subnet}` | `sites.subnet_show` | View subnet details |
| POST | `/api/v1/subnets` | `sites.subnet_create` | Create a subnet |
| DELETE | `/api/v1/subnets/{subnet}` | `sites.subnet_delete` | Delete a subnet |
| PUT | `/api/v1/subnets/{subnet}/site` | `sites.subnet_set_site` | Assign a subnet to a site |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `sitename` | path/string | Site endpoints | Site name (e.g., `HQ`, `Branch-Office`) |
| `subnet` | path/string | Subnet endpoints | Subnet in CIDR notation (e.g., `192.168.1.0/24`) |
| `site` | string | `/subnets`, `/subnets/{subnet}/site` | Site name to associate with a subnet |
| `description` | string | `/subnets` (create) | Subnet description |
| `location` | string | `/sites` (create) | Site location description |

## Usage Examples

```bash
# List all sites
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/sites

# Create a new site
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/sites \
  -d '{"sitename": "Branch-Office", "location": "Building C, Floor 2"}'

# Create a subnet and assign it to a site
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/subnets \
  -d '{"subnet": "10.0.50.0/24", "site": "Branch-Office", "description": "Branch office VLAN 50"}'

# Reassign a subnet to a different site
curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/subnets/10.0.50.0%2F24/site \
  -d '{"site": "HQ"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `sites.list` | — | List sites |
| `sites.show` | `sitename` | View site |
| `sites.create` | `sitename`, `location` | Create site |
| `sites.delete` | `sitename` | Delete site |
| `sites.subnet_list` | — | List subnets |
| `sites.subnet_show` | `subnet` | View subnet |
| `sites.subnet_create` | `subnet`, `site`, `description` | Create subnet |
| `sites.subnet_delete` | `subnet` | Delete subnet |
| `sites.subnet_set_site` | `subnet`, `site` | Assign subnet to site |

## Notes

- **CIDR notation required:** Subnets must be specified in CIDR format (e.g., `192.168.1.0/24`). The API does not accept netmask format.
- **Site deletion** will fail if the site contains subnets or server objects — remove associations first.
- **Subnet-to-site mapping** is critical for client DC discovery — incorrect mappings cause clients to authenticate against distant DCs.
- Uses `build_samba_command_deep` with JSON auto-mode for structured samba-tool command building.
- URL-encode the CIDR slash (`%2F`) when using subnet values in URL paths (e.g., `10.0.50.0%2F24`).
