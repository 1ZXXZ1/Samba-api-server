# Batch Operations — AI Skill Reference

> Module: `batch` | Router: `app/routers/batch.py` | Version: api_v1.9.6-7

## Overview

Provides a unified batch execution endpoint for chaining multiple API operations sequentially. Supports template resolution using `{{ step_id.field }}` syntax to pass results between steps, and best-effort rollback on failure. With 60+ methods available across all modules, this is the most powerful endpoint for complex multi-step operations. Maximum of 100 actions per batch request.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/api/v1/batch` | `batch.execute` | Execute a batch of sequential actions with template resolution |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `actions` | array | `/batch` | Ordered list of actions to execute (max 100) |
| `actions[].method` | string | `/batch` | Batch method name (e.g., `user.create`, `group.add_members`) |
| `actions[].params` | object | `/batch` | Parameters for the action |
| `actions[].id` | string | `/batch` | Step identifier for template references |
| `rollback` | bool | `/batch` | Enable best-effort rollback on failure (default: false) |

### Template Resolution

Reference outputs from previous steps using: `{{ step_id.field }}`

```json
{
  "actions": [
    {
      "id": "create_user",
      "method": "user.create",
      "params": {"username": "jdoe", "password": "P@ssw0rd1"}
    },
    {
      "id": "add_to_group",
      "method": "group.add_members",
      "params": {
        "groupname": "DevOps-Team",
        "members": ["{{ create_user.username }}"]
      }
    }
  ]
}
```

## Available Batch Methods (60+)

### User Operations
| Method | Key Parameters |
|--------|---------------|
| `user.list` | `page`, `page_size`, `filter` |
| `user.create` | `username`, `password`, `ou`, `display_name` |
| `user.show` | `username` |
| `user.delete` | `username` |
| `user.enable` | `username` |
| `user.disable` | `username` |
| `user.unlock` | `username` |
| `user.set_password` | `username`, `password`, `must_change_pwd` |
| `user.get_groups` | `username` |
| `user.set_expiry` | `username`, `expiry_date` |
| `user.set_primary_group` | `username`, `primary_group` |
| `user.add_unix_attrs` | `username`, `uid_number`, `gid_number`, `shell`, `homedir` |
| `user.move` | `username`, `ou` |
| `user.rename` | `username`, `new_name` |
| `user.edit` | `username`, `attributes` |

### Group Operations
| Method | Key Parameters |
|--------|---------------|
| `group.list` | `page`, `page_size`, `filter` |
| `group.create` | `groupname`, `ou`, `group_scope`, `group_type` |
| `group.show` | `groupname` |
| `group.delete` | `groupname` |
| `group.add_members` | `groupname`, `members` |
| `group.remove_members` | `groupname`, `members` |
| `group.list_members` | `groupname` |
| `group.move` | `groupname`, `ou` |

### Computer Operations
| Method | Key Parameters |
|--------|---------------|
| `computer.list` | `page`, `page_size`, `filter` |
| `computer.create` | `computername`, `ou` |
| `computer.show` | `computername` |
| `computer.delete` | `computername` |
| `computer.move` | `computername`, `ou` |

### Contact Operations
| Method | Key Parameters |
|--------|---------------|
| `contact.list` | `page`, `page_size` |
| `contact.create` | `contactname`, `ou`, `display_name` |
| `contact.show` | `contactname` |
| `contact.delete` | `contactname` |
| `contact.move` | `contactname`, `ou` |
| `contact.rename` | `contactname`, `new_name` |

### OU Operations
| Method | Key Parameters |
|--------|---------------|
| `ou.list` | `page`, `page_size` |
| `ou.create` | `ouname`, `parent_ou` |
| `ou.delete` | `ouname` |
| `ou.move` | `ouname`, `parent_ou` |
| `ou.rename` | `ouname`, `new_name` |
| `ou.list_objects` | `ouname`, `filter`, `recursive` |

### Domain Operations
| Method | Key Parameters |
|--------|---------------|
| `domain.info` | — |
| `domain.level_get` | — |
| `domain.level_set` | `level` |
| `domain.password_settings_get` | — |
| `domain.password_settings_set` | settings object |
| `domain.trust_list` | — |
| `domain.trust_create` | `trust_domain`, `trust_type`, `trust_direction`, `trust_password` |
| `domain.trust_delete` | `trust` |
| `domain.kds_create` | — |
| `domain.kds_list` | — |
| `domain.export_keytab` | `principal` |

### DNS Operations
| Method | Key Parameters |
|--------|---------------|
| `dns.zone_list` | `zone_type` |
| `dns.zone_create` | `zone`, `zone_type`, `overwrite` |
| `dns.zone_info` | `zone` |
| `dns.zone_delete` | `zone` |
| `dns.record_list` | `zone` |
| `dns.record_create` | `zone`, `name`, `type`, `data`, `ttl` |
| `dns.record_delete` | `zone`, `name`, `type`, `data` |
| `dns.record_update` | `zone`, `name`, `type`, `data`, `ttl` |

### GPO Operations
| Method | Key Parameters |
|--------|---------------|
| `gpo.list` | `page`, `page_size` |
| `gpo.create` | `name`, `overwrite` |
| `gpo.show` | `gpo_id` |
| `gpo.delete` | `gpo_id` |
| `gpo.link` | `gpo_id`, `ou`, `enabled`, `enforced` |
| `gpo.unlink` | `gpo_id`, `ou` |
| `gpo.get_inheritance` | `gpo_id` |
| `gpo.set_inheritance` | `gpo_id`, `block_inheritance` |

### FSMO Operations
| Method | Key Parameters |
|--------|---------------|
| `fsmo.show` | — |
| `fsmo.transfer` | `role`, `target_dc` |
| `fsmo.seize` | `role`, `target_dc` |

### DRS Operations
| Method | Key Parameters |
|--------|---------------|
| `drs.showrepl` | — |
| `drs.replicate` | `source_dc`, `destination_dc`, `partition` |
| `drs.uptodateness` | — |
| `drs.bind` | — |
| `drs.options` | — |

### Sites & Subnets
| Method | Key Parameters |
|--------|---------------|
| `sites.list` | — |
| `sites.show` | `sitename` |
| `sites.create` | `sitename`, `location` |
| `sites.delete` | `sitename` |
| `sites.subnet_list` | — |
| `sites.subnet_show` | `subnet` |
| `sites.subnet_create` | `subnet`, `site`, `description` |
| `sites.subnet_delete` | `subnet` |
| `sites.subnet_set_site` | `subnet`, `site` |

### Schema, Delegation, Service Accounts, Auth Policies, Misc
| Method | Key Parameters |
|--------|---------------|
| `schema.attribute_show` | `name` |
| `schema.class_show` | `name` |
| `delegation.add` | `account_name`, `service` |
| `delegation.remove` | `account_name`, `service` |
| `delegation.show` | `account` |
| `service-account.list` | — |
| `service-account.create` | `name`, `dns_host_name` |
| `service-account.show` | `name` |
| `service-account.delete` | `name` |
| `service-account.gmsa_members_add` | `name`, `principal` |
| `service-account.gmsa_members_remove` | `name`, `principal` |
| `auth.silo_list` | — |
| `auth.silo_create` | `name` |
| `auth.silo_show` | `name` |
| `auth.silo_delete` | `name` |
| `auth.silo_members_add` | `name`, `principal` |
| `auth.silo_members_remove` | `name`, `principal` |
| `auth.policy_list` | — |
| `auth.policy_create` | `name`, `policy_type`, `policy_value` |
| `auth.policy_show` | `name` |
| `auth.policy_delete` | `name` |
| `misc.ntacl_get` | `path` |
| `misc.ntacl_set` | `path`, `acl` |
| `misc.processes` | — |
| `misc.time` | — |
| `misc.spn_list` | `account` |
| `misc.spn_add` | `account`, `spn` |
| `misc.spn_delete` | `account`, `spn` |

## Blocked Methods

The following methods are **not available** in batch operations due to their destructive, long-running, or system-critical nature:

- `domain.backup_online`, `domain.backup_offline` — background tasks
- `domain.join`, `domain.leave`, `domain.demote` — destructive operations
- `gpo.backup`, `gpo.restore` — background tasks
- `misc.dbcheck`, `misc.dbcheck_fix`, `misc.testparm` — background tasks
- `misc.ntacl_sysvolreset` — system-critical operation

## Usage Examples

```bash
# Create a user and add to group in one batch
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/batch \
  -d '{
    "actions": [
      {
        "id": "create_user",
        "method": "user.create",
        "params": {"username": "jdoe", "password": "P@ssw0rd1", "display_name": "John Doe"}
      },
      {
        "id": "add_to_devops",
        "method": "group.add_members",
        "params": {"groupname": "DevOps-Team", "members": ["jdoe"]}
      },
      {
        "id": "set_expiry",
        "method": "user.set_expiry",
        "params": {"username": "jdoe", "expiry_date": "2025-12-31"}
      }
    ]
  }'

# Template resolution — pass output from step to step
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/batch \
  -d '{
    "actions": [
      {
        "id": "create_group",
        "method": "group.create",
        "params": {"groupname": "NewProject-Team", "group_scope": "global"}
      },
      {
        "id": "create_ou",
        "method": "ou.create",
        "params": {"ouname": "NewProject", "parent_ou": "OU=Departments,DC=example,DC=com"}
      }
    ]
  }'

# Batch with rollback enabled
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/batch \
  -d '{
    "rollback": true,
    "actions": [
      {"id": "step1", "method": "user.create", "params": {"username": "temp1", "password": "P@ss1"}},
      {"id": "step2", "method": "user.create", "params": {"username": "temp2", "password": "P@ss2"}},
      {"id": "step3", "method": "group.add_members", "params": {"groupname": "Team", "members": ["temp1", "temp2"]}}
    ]
  }'
```

## Notes

- **Sequential execution:** Actions are executed in order. If any action fails, subsequent actions are skipped (unless rollback is enabled).
- **Template resolution:** Use `{{ step_id.field }}` to reference output from a previous step. The template is resolved before the action is executed.
- **Best-effort rollback:** When rollback is enabled and an action fails, the system attempts to reverse all previously completed actions. Rollback is not guaranteed — some operations (e.g., deletions) cannot be reversed.
- **Max 100 actions:** Each batch request supports up to 100 actions. For larger operations, split into multiple batch requests.
- **Blocked methods:** Background tasks (`backup`, `dbcheck`, `testparm`, `gpo backup/restore`) and destructive operations (`join`, `leave`, `demote`, `sysvolreset`) cannot be executed in batch mode.
- **Permission checks:** Each action in the batch is subject to the same permission checks as the individual endpoint. If any action fails permission check, the entire batch is rejected.
- **No parallelism:** All actions execute sequentially within a single batch. There is no support for parallel execution within a batch request.
