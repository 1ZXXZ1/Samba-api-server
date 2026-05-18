# Group Management — AI Skill Reference

> Module: `groups` | Router: `app/routers/groups.py` | Version: api_v1.9.6-7

## Overview

Manages Active Directory security and distribution groups. Supports full CRUD operations, member management, and group statistics. The `/full` endpoint uses ldbsearch for complete LDAP attribute data. Group membership changes are reflected immediately in Kerberos tokens after next logon.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/groups` | `group.list` | List groups (paginated, filterable) |
| GET | `/api/v1/groups/full` | `group.list` | Full group list via ldbsearch (all LDAP attributes) |
| POST | `/api/v1/groups` | `group.create` | Create a new group |
| GET | `/api/v1/groups/stats` | `group.stats` | Group statistics (counts by type, scope) |
| GET | `/api/v1/groups/{groupname}` | `group.show` | Show group details |
| DELETE | `/api/v1/groups/{groupname}` | `group.delete` | Delete a group |
| POST | `/api/v1/groups/{groupname}/members` | `group.add_members` | Add members to the group |
| DELETE | `/api/v1/groups/{groupname}/members` | `group.remove_members` | Remove members from the group |
| GET | `/api/v1/groups/{groupname}/members` | `group.list_members` | List group members |
| POST | `/api/v1/groups/{groupname}/move` | `group.move` | Move group to a different OU |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `groupname` | path | Most endpoints | sAMAccountName of the target group |
| `ou` | string | `/create`, `/move` | Target OU distinguished name |
| `group_type` | string | `/create` | Group type: `security` (default) or `distribution` |
| `group_scope` | string | `/create` | Group scope: `global`, `domainlocal`, `universal` |
| `members` | array | `/members` (add/remove) | List of sAMAccountNames to add or remove |
| `description` | string | `/create` | Group description |

## Usage Examples

```bash
# Create a security group
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/groups \
  -d '{"groupname": "DevOps-Team", "group_scope": "global", "description": "DevOps team members"}'

# Add members to a group
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/groups/DevOps-Team/members \
  -d '{"members": ["jdoe", "asmith", "bwong"]}'

# Get group statistics
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/groups/stats
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `group.list` | `page`, `page_size`, `filter` | List groups |
| `group.create` | `groupname`, `ou`, `group_scope`, `group_type`, `description` | Create group |
| `group.show` | `groupname` | Show group details |
| `group.delete` | `groupname` | Delete group |
| `group.add_members` | `groupname`, `members` | Add members |
| `group.remove_members` | `groupname`, `members` | Remove members |
| `group.list_members` | `groupname` | List members |
| `group.move` | `groupname`, `ou` | Move group to OU |

## Notes

- Removing the last member does not delete the group.
- Group scope changes have domain functional level requirements (e.g., Universal groups require Windows 2000 native or higher).
- `/full` uses ldbsearch and returns raw LDAP attributes — slower but more complete than the standard list.
- Membership changes take effect in new Kerberos tickets; existing sessions retain old group memberships until ticket renewal.
- The `/stats` endpoint provides aggregate counts useful for dashboard displays.
