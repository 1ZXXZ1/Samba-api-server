# Authentication Policies — AI Skill Reference

> Module: `auth-policies` | Router: `app/routers/auth_policies.py` | Version: api_v1.9.6-7

## Overview

Manages Authentication Silos and Policies for fine-grained authentication control in Samba AD. Authentication Silos group accounts with specific authentication policies, while policies define access conditions (e.g., "require MFA," "limit to specific devices"). Uses the `domain auth silo` and `domain auth policy` samba-tool sub-commands.

## Endpoints

### Authentication Silos

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/auth/silos` | `auth.list` | List authentication silos |
| POST | `/api/v1/auth/silos` | `auth.create` | Create an authentication silo |
| GET | `/api/v1/auth/silos/{name}` | `auth.show` | Show silo details |
| DELETE | `/api/v1/auth/silos/{name}` | `auth.delete` | Delete an authentication silo |
| POST | `/api/v1/auth/silos/{name}/members/add` | `auth.grant` | Add/grant a principal to the silo |
| POST | `/api/v1/auth/silos/{name}/members/remove` | `auth.revoke` | Remove/revoke a principal from the silo |

### Authentication Policies

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/auth/policies` | `auth.list` | List authentication policies |
| POST | `/api/v1/auth/policies` | `auth.create` | Create an authentication policy |
| GET | `/api/v1/auth/policies/{name}` | `auth.show` | Show policy details |
| DELETE | `/api/v1/auth/policies/{name}` | `auth.delete` | Delete an authentication policy |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `name` | path/string | Most endpoints | Silo or policy name |
| `description` | string | `/create` (silo/policy) | Description |
| `principal` | string | `/members/add`, `/members/remove` | Account to add/remove from silo |
| `policy_type` | string | `/create` (policy) | Policy type (e.g., `TgtLifetime`, `Device`) |
| `policy_value` | string | `/create` (policy) | Policy value/setting |

## Usage Examples

```bash
# List authentication silos
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/auth/silos

# Create an authentication silo
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/auth/silos \
  -d '{"name": "HighSecurity-Silo", "description": "High-security accounts requiring strict auth policies"}'

# Grant a user membership in a silo
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/auth/silos/HighSecurity-Silo/members/add \
  -d '{"principal": "admin-user"}'

# Create an authentication policy
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/auth/policies \
  -d '{"name": "StrictTgtPolicy", "policy_type": "TgtLifetime", "policy_value": "3600"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `auth.silo_list` | — | List silos |
| `auth.silo_create` | `name`, `description` | Create silo |
| `auth.silo_show` | `name` | Show silo |
| `auth.silo_delete` | `name` | Delete silo |
| `auth.silo_members_add` | `name`, `principal` | Add principal to silo |
| `auth.silo_members_remove` | `name`, `principal` | Remove principal from silo |
| `auth.policy_list` | — | List policies |
| `auth.policy_create` | `name`, `policy_type`, `policy_value` | Create policy |
| `auth.policy_show` | `name` | Show policy |
| `auth.policy_delete` | `name` | Delete policy |

## Notes

- **Domain functional level requirement:** Authentication silos and policies require Windows Server 2012 R2 domain functional level or higher.
- **Silo vs. Policy:** Silos are containers that assign policies to groups of accounts. Policies define the actual authentication constraints.
- **Grant/Revoke terminology:** "Add" and "grant" are synonymous for silo membership; "remove" and "revoke" are synonymous.
- **No list for silo members:** Use the `show` endpoint on a silo to view its assigned members.
- This module uses `domain auth silo` and `domain auth policy` samba-tool sub-commands.
