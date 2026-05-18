# samba-tool ou — Organizational Units (OU) Management

Manage Organizational Units in the Active Directory domain.

## Subcommands

### ou add
Add a new organizational unit.

```bash
samba-tool ou add <ou_dn> [options]
```

The name of the organizational unit can be specified as a full DN or without the domainDN component.

**Options:**

| Option | Description |
|--------|-------------|
| `--description=DESCRIPTION` | Specify the OU's description |

**Examples:**
```bash
# Add an OU (without domainDN)
samba-tool ou add "OU=Servers"

# Add an OU (full DN)
samba-tool ou add "OU=Servers,DC=example,DC=com"

# Add nested OU
samba-tool ou add "OU=Production,OU=Servers,DC=example,DC=com"

# Add with description
samba-tool ou add "OU=Servers" --description="All server computer accounts"
```

### ou create
Add a new organizational unit. This is a **synonym** for `samba-tool ou add` and is available for compatibility reasons only. Use `samba-tool ou add` instead.

```bash
samba-tool ou create <ou_dn> [options]
```

Same options as `ou add`.

### ou delete
Delete an organizational unit.

```bash
samba-tool ou delete <ou_dn> [options]
```

The name of the organizational unit can be specified as a full DN or without the domainDN component.

**Options:**

| Option | Description |
|--------|-------------|
| `--force-subtree-delete` | Delete organizational unit and all children recursively |

> **Warning**: By default, an OU cannot be deleted if it contains child objects. Use `--force-subtree-delete` to force deletion of the OU and all its contents. This is a destructive operation.

**Examples:**
```bash
# Delete empty OU
samba-tool ou delete "OU=OldDepartment"

# Force delete OU with children
samba-tool ou delete "OU=OldDepartment" --force-subtree-delete
```

### ou list
List all organizational units.

```bash
samba-tool ou list [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--full-dn` | Display DNs including the base DN |

**Examples:**
```bash
# List all OUs
samba-tool ou list

# List with full DNs
samba-tool ou list --full-dn
```

### ou listobjects
List all objects in an organizational unit.

```bash
samba-tool ou listobjects <ou_dn> [options]
```

The name of the organizational unit can be specified as a full DN or without the domainDN component.

**Options:**

| Option | Description |
|--------|-------------|
| `--full-dn` | Display DNs including the base DN |
| `-r, --recursive` | List objects recursively |

**Examples:**
```bash
# List objects in an OU
samba-tool ou listobjects "OU=Servers"

# List with full DNs recursively
samba-tool ou listobjects "OU=Servers" --full-dn --recursive
```

### ou move
Move an organizational unit to a new parent.

```bash
samba-tool ou move <old_ou_dn> <new_parent_dn> [options]
```

The name of the organizational units can be specified as a full DN or without the domainDN component.

**Examples:**
```bash
samba-tool ou move "OU=TestServers" "OU=Decommissioned"
samba-tool ou move "OU=OldOU,DC=example,DC=com" "OU=Archive,DC=example,DC=com"
```

### ou rename
Rename an organizational unit.

```bash
samba-tool ou rename <old_ou_dn> <new_ou_dn> [options]
```

The name of the organizational units can be specified as a full DN or without the domainDN component.

**Examples:**
```bash
samba-tool ou rename "OU=OldName" "OU=NewName"
samba-tool ou rename "OU=OldName,DC=example,DC=com" "OU=NewName,DC=example,DC=com"
```

## Typical Workflows

### Create OU structure for an organization
```bash
# Create top-level OUs
samba-tool ou add "OU=Servers" --description="All server accounts"
samba-tool ou add "OU=Workstations" --description="All workstation accounts"
samba-tool ou add "OU=Groups" --description="Security and distribution groups"
samba-tool ou add "OU=Users" --description="User accounts"

# Create sub-OUs
samba-tool ou add "OU=Production,OU=Servers" --description="Production servers"
samba-tool ou add "OU=Development,OU=Servers" --description="Development servers"
samba-tool ou add "OU=Web,OU=Production,OU=Servers" --description="Web servers"
samba-tool ou add "OU=DB,OU=Production,OU=Servers" --description="Database servers"
```

### Move computer to specific OU
```bash
# 1. Create target OU if not exists
samba-tool ou add "OU=NewServers"

# 2. Move the computer
samba-tool computer move SERVER01 "OU=NewServers"
```

### Decommission and clean up OU
```bash
# 1. List objects in the OU
samba-tool ou listobjects "OU=OldDepartment" --recursive

# 2. Delete the OU and all its contents
samba-tool ou delete "OU=OldDepartment" --force-subtree-delete
```
