# Delegation — AI Skill Reference

> Module: `delegation` | Router: `app/routers/delegation.py` | Version: api_v1.9.6-7

## Overview

Manages service account delegation in Active Directory. Controls which services an account can act on behalf of (constrained delegation). Supports adding, removing, and viewing delegation settings for individual accounts. There is no list command — query specific accounts using the `show` endpoint.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/api/v1/delegation/add` | `delegation.add` | Add delegation for an account |
| POST | `/api/v1/delegation/remove` | `delegation.remove` | Remove delegation from an account |
| GET | `/api/v1/delegation/show/{account}` | `delegation.show` | Show delegation settings for an account |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `account` | path/string | `/show/{account}` | Target account sAMAccountName |
| `account_name` | string | `/add`, `/remove` | Target account sAMAccountName |
| `service` | string | `/add`, `/remove` | Service principal to delegate to (SPN format) |
| `delegation_type` | string | `/add` | Delegation type: `constrained` (most common) |

## Usage Examples

```bash
# Show delegation for an account
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/delegation/show/svc-webapp

# Add constrained delegation
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/delegation/add \
  -d '{"account_name": "svc-webapp", "service": "HTTP/db.example.com", "delegation_type": "constrained"}'

# Remove a delegation
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/delegation/remove \
  -d '{"account_name": "svc-webapp", "service": "HTTP/db.example.com"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `delegation.add` | `account_name`, `service`, `delegation_type` | Add delegation |
| `delegation.remove` | `account_name`, `service` | Remove delegation |
| `delegation.show` | `account` | Show delegation for account |

## Notes

- **No list command:** There is no way to list all accounts with delegation configured. You must query individual accounts via `show`.
- **SPN format required:** The `service` parameter must be a valid Service Principal Name (e.g., `HTTP/server.example.com`, `cifs/fileserver.example.com`).
- **Constrained delegation** is the recommended approach — unconstrained delegation is a significant security risk and should be avoided.
- **Protocol transition:** Constrained delegation with protocol transition (Kerberos-only vs. any authentication) is controlled via the `delegation_type` parameter and AD attribute `msDS-AllowedToDelegateTo`.
- Delegation changes may require Kerberos ticket renewal to take effect for existing sessions.
