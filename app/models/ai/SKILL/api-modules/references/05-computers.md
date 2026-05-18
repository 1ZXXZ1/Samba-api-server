# Computer Management — AI Skill Reference

> Module: `computers` | Router: `app/routers/computers.py` | Version: api_v1.9.6-7

## Overview

Manages computer accounts in the Active Directory domain. Supports listing, creation, viewing, deletion, and moving computer objects between OUs. The `/full` endpoint uses ldbsearch for complete attribute retrieval. Computer accounts are essential for domain-joined machines and service principal name (SPN) management.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/computers` | `computer.list` | List computer accounts (paginated, filterable) |
| GET | `/api/v1/computers/full` | `computer.list` | Full computer list via ldbsearch (all LDAP attributes) |
| POST | `/api/v1/computers` | `computer.create` | Create a new computer account |
| GET | `/api/v1/computers/{computername}` | `computer.show` | Show computer account details |
| DELETE | `/api/v1/computers/{computername}` | `computer.delete` | Delete a computer account |
| POST | `/api/v1/computers/{computername}/move` | `computer.move` | Move computer to a different OU |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `computername` | path | Most endpoints | sAMAccountName of the computer (typically ends with `$`) |
| `ou` | string | `/create`, `/move` | Target OU distinguished name |
| `description` | string | `/create` | Computer account description |

## Usage Examples

```bash
# List all computer accounts
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/computers

# Create a new computer account
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/computers \
  -d '{"computername": "WORKSTATION01", "ou": "OU=Computers,DC=example,DC=com"}'

# Move a computer to a different OU
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/computers/WORKSTATION01/move \
  -d '{"ou": "OU=Servers,DC=example,DC=com"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `computer.list` | `page`, `page_size`, `filter` | List computers |
| `computer.create` | `computername`, `ou`, `description` | Create computer |
| `computer.show` | `computername` | Show computer details |
| `computer.delete` | `computername` | Delete computer |
| `computer.move` | `computername`, `ou` | Move computer to OU |

## Notes

- Computer sAMAccountNames conventionally end with `$` (e.g., `WORKSTATION01$`). The API handles this transparently.
- Deleting a computer account will break domain trust for that machine — ensure the computer is disjoined first.
- The `/full` endpoint returns all LDAP attributes including `operatingSystem`, `operatingSystemVersion`, `lastLogonTimestamp`, etc.
- There is no rename endpoint for computers — use move to reorganize and create a new account if the name must change.
