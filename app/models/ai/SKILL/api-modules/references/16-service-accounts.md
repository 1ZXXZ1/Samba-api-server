# Service Accounts — AI Skill Reference

> Module: `service-accounts` | Router: `app/routers/service_accounts.py` | Version: api_v1.9.6-7

## Overview

Manages Group Managed Service Accounts (gMSA) and standalone managed service accounts in Active Directory. gMSA accounts provide automatic password management for services running across multiple servers. Supports full CRUD operations and gMSA principal membership management. The `--name` and `--dns-host-name` parameters are required for creation.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/service-accounts` | `service-account.list` | List service accounts |
| POST | `/api/v1/service-accounts` | `service-account.create` | Create a service account |
| GET | `/api/v1/service-accounts/{name}` | `service-account.show` | Show service account details |
| DELETE | `/api/v1/service-accounts/{name}` | `service-account.delete` | Delete a service account |
| POST | `/api/v1/service-accounts/{name}/members/add` | `service-account.gmsa_members` | Add a principal to gMSA membership |
| POST | `/api/v1/service-accounts/{name}/members/remove` | `service-account.gmsa_members` | Remove a principal from gMSA membership |
| GET | `/api/v1/service-accounts/{name}/members` | `service-account.gmsa_members` | List gMSA members |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `name` | path/string | Most endpoints | Service account name (sAMAccountName without `$` suffix) |
| `dns_host_name` | string | `/create` | **Required** — DNS hostname for the service account (e.g., `webapp.example.com`) |
| `principal` | string | `/members/add`, `/members/remove` | Principal to add/remove (sAMAccountName or DN) |
| `description` | string | `/create` | Account description |

## Usage Examples

```bash
# Create a gMSA
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/service-accounts \
  -d '{"name": "svc-webapp", "dns_host_name": "webapp.example.com", "description": "Web application service account"}'

# Add a computer as gMSA principal (allowed to retrieve password)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/service-accounts/svc-webapp/members/add \
  -d '{"principal": "WEBSERVER01$"}'

# List gMSA principals
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/service-accounts/svc-webapp/members
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `service-account.list` | — | List service accounts |
| `service-account.create` | `name`, `dns_host_name`, `description` | Create service account |
| `service-account.show` | `name` | Show service account |
| `service-account.delete` | `name` | Delete service account |
| `service-account.gmsa_members_add` | `name`, `principal` | Add gMSA member |
| `service-account.gmsa_members_remove` | `name`, `principal` | Remove gMSA member |
| `service-account.gmsa_members_list` | `name` | List gMSA members |

## Notes

- **Required fields:** Both `--name` and `--dns-host-name` are required for creation. The DNS hostname must be a valid FQDN within the domain.
- **KDS root key prerequisite:** A KDS root key must exist (see Domain module) before creating gMSA accounts. Allow 10+ hours after KDS key creation for replication.
- **gMSA members** are the security principals (typically computer accounts) authorized to retrieve the gMSA password from AD.
- **Computer accounts as principals** should include the `$` suffix (e.g., `WEBSERVER01$`).
- Standalone managed service accounts (sMSA) are limited to a single computer and are being deprecated in favor of gMSA.
