# Organizational Unit Management — AI Skill Reference

> Module: `ous` | Router: `app/routers/ous.py` | Version: api_v1.9.6-7

## Overview

Manages Organizational Units (OUs) in the Active Directory domain. OUs are container objects used for delegating administration, applying Group Policy, and organizing directory objects. Extended endpoints provide tree visualization, search, statistics, and sub-tree enumeration for navigating the OU hierarchy.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/ous` | `ou.list` | List OUs (paginated, filterable) |
| GET | `/api/v1/ous/full` | `ou.list` | Full OU list via ldbsearch (all LDAP attributes) |
| POST | `/api/v1/ous` | `ou.create` | Create a new OU |
| DELETE | `/api/v1/ous/{ouname}` | `ou.delete` | Delete an OU |
| POST | `/api/v1/ous/{ouname}/move` | `ou.move` | Move an OU to a different parent |
| POST | `/api/v1/ous/{ouname}/rename` | `ou.rename` | Rename an OU |
| GET | `/api/v1/ous/{ouname}/objects` | `ou.list_objects` | List objects within an OU |
| GET | `/api/v1/ous/tree` | `ou.tree` | Get the OU tree structure (hierarchical) |
| GET | `/api/v1/ous/search` | `ou.search` | Search OUs by filter |
| GET | `/api/v1/ous/stats` | `ou.stats` | OU statistics (counts, depth) |
| GET | `/api/v1/ous/{ouname}/sub-tree` | `ou.sub_tree` | Get sub-tree of an OU with all descendant objects |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `ouname` | path | Most endpoints | CN of the target OU |
| `parent_ou` | string | `/create`, `/move` | Parent OU distinguished name |
| `new_name` | string | `/rename` | New OU name |
| `filter` | string | `/search`, `/objects` | LDAP filter expression |
| `recursive` | bool | `/objects`, `/sub-tree` | Include child OU objects |

## Usage Examples

```bash
# Create an OU under a specific parent
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/ous \
  -d '{"ouname": "Engineering", "parent_ou": "OU=Departments,DC=example,DC=com"}'

# Get the full OU tree structure
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/ous/tree

# Get OU statistics
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/ous/stats
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `ou.list` | `page`, `page_size`, `filter` | List OUs |
| `ou.create` | `ouname`, `parent_ou` | Create OU |
| `ou.delete` | `ouname` | Delete OU |
| `ou.move` | `ouname`, `parent_ou` | Move OU |
| `ou.rename` | `ouname`, `new_name` | Rename OU |
| `ou.list_objects` | `ouname`, `filter`, `recursive` | List objects in OU |

## Notes

- Deleting an OU that contains objects will fail unless all child objects are removed first (or the API handles recursive deletion).
- OUs are the primary scope for Group Policy linking — use the GPO module to manage links.
- The `/tree` endpoint returns a hierarchical JSON structure useful for tree-view UI components.
- `/sub-tree` returns the full subtree including all descendant objects — can be slow for large OUs.
- OU protection from accidental deletion is recommended — check if your samba-tool supports the `--protect-deletion` flag.
