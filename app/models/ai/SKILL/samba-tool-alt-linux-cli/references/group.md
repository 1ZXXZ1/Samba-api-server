# samba-tool group — Group Management

Manage groups in the Active Directory domain.

## Subcommands

### group add
Create a new AD group.

```bash
samba-tool group add <groupname> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--groupou=GROUP_OU` | DN of alternative location (with or without domainDN) to default `CN=Users` where the group will be created. E.g. `OU=Groups` |
| `--group-scope=SCOPE` | Group scope: `DomainLocal`, `Global`, `Universal` |
| `--group-type=TYPE` | Group type: `Security` (default) or `Distribution` |
| `--description=DESCRIPTION` | Group description |
| `--mail-address=MAIL_ADDRESS` | Group email address |
| `--notes=NOTES` | Group notes |

**Examples:**
```bash
# Create a global security group
samba-tool group add "Server Admins"

# Create a domain local security group
samba-tool group add "File Share Access" --group-scope=DomainLocal

# Create a universal distribution group
samba-tool group add "All Staff" --group-type=Distribution --group-scope=Universal

# Create group in specific OU
samba-tool group add "Web Admins" --groupou="OU=Groups"

# Create with description and email
samba-tool group add "DB Admins" --description="Database Administrators" --mail-address=dbadmins@example.com
```

### group create
Add a new AD group. This is a **synonym** for `samba-tool group add` and is available for compatibility reasons only. Use `samba-tool group add` instead.

```bash
samba-tool group create <groupname> [options]
```

### group delete
Delete an AD group.

```bash
samba-tool group delete <groupname> [options]
```

**Examples:**
```bash
samba-tool group delete "Old Group"
```

### group edit
Edit a group AD object interactively.

```bash
samba-tool group edit <groupname> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--editor=EDITOR` | Specifies the editor to use instead of the system default, or `vi` if no system default is set |

**Examples:**
```bash
samba-tool group edit "Server Admins"
samba-tool group edit "Server Admins" --editor=nano
```

### group list
List all groups in the domain.

```bash
samba-tool group list [options]
```

**Examples:**
```bash
samba-tool group list
```

### group listmembers
List all members of the specified AD group.

```bash
samba-tool group listmembers <groupname> [options]
```

By default, the `sAMAccountNames` are listed. If no `sAMAccountName` is available, the CN will be used instead.

**Options:**

| Option | Description |
|--------|-------------|
| `--full-dn` | List the distinguished names instead of the sAMAccountNames |
| `--hide-expired` | Do not list expired group members |
| `--hide-disabled` | Do not list disabled group members |

**Examples:**
```bash
# List members
samba-tool group listmembers "Domain Admins"

# List members as full DNs
samba-tool group listmembers "Server Admins" --full-dn

# Exclude disabled and expired members
samba-tool group listmembers "All Staff" --hide-disabled --hide-expired
```

### group addmembers
Add members to an AD group.

```bash
samba-tool group addmembers <groupname> <members> [options]
```

Members can be specified as a comma-separated list of usernames or DNs.

**Examples:**
```bash
# Add a single member
samba-tool group addmembers "Server Admins" jdoe

# Add multiple members (comma-separated)
samba-tool group addmembers "Server Admins" jdoe,asmith,bwilson

# Add by DN
samba-tool group addmembers "Server Admins" "CN=John Doe,CN=Users,DC=example,DC=com"
```

### group removemembers
Remove members from the specified AD group.

```bash
samba-tool group removemembers <groupname> <members> [options]
```

**Examples:**
```bash
# Remove a single member
samba-tool group removemembers "Server Admins" jdoe

# Remove multiple members
samba-tool group removemembers "Server Admins" jdoe,asmith
```

### group move
Move a group into the specified organizational unit or container.

```bash
samba-tool group move <groupname> <new_parent_dn> [options]
```

The `groupname` is the `sAMAccountName`. The `new_parent_dn` can be specified as a full DN or without the domainDN component.

**Examples:**
```bash
samba-tool group move "Server Admins" "OU=Security Groups"
samba-tool group move "Old Group" "OU=Archived,DC=example,DC=com"
```

### group show
Show a group object and its attributes.

```bash
samba-tool group show <groupname> [options]
```

**Examples:**
```bash
samba-tool group show "Domain Admins"
samba-tool group show "Server Admins"
```

### group stats
Show statistics for overall groups and group memberships.

```bash
samba-tool group stats [options]
```

**Examples:**
```bash
samba-tool group stats
```

### group rename
Rename a group and related attributes.

```bash
samba-tool group rename <groupname> [options]
```

This command allows setting the group's name related attributes. The group's CN will be renamed automatically. The new CN will be the `sAMAccountName`. Use `--force-new-cn` to specify the new CN manually and `--reset-cn` to reset this change.

Use an empty attribute value to remove the specified attribute.

The `groupname` specified on the command is the `sAMAccountName`.

**Options:**

| Option | Description |
|--------|-------------|
| `--force-new-cn=NEW_CN` | Specify a new CN (RDN) instead of using the sAMAccountName |
| `--reset-cn` | Set the CN to the sAMAccountName |
| `--mail-address=MAIL_ADDRESS` | New mail address |
| `--samaccountname=SAMACCOUNTNAME` | New account name (sAMAccountName/logon name) |

**Examples:**
```bash
# Rename the group's sAMAccountName
samba-tool group rename "Old Admins" --samaccountname="Server Admins"

# Force a specific CN
samba-tool group rename "Server Admins" --force-new-cn="ServerAdministrators"

# Reset CN to match sAMAccountName
samba-tool group rename "Server Admins" --reset-cn

# Change email
samba-tool group rename "Server Admins" --mail-address=server-admins@example.com
```

## Group Scope and Type Reference

### Group Scopes

| Scope | Description |
|-------|-------------|
| `DomainLocal` | Can contain accounts from any domain, but only used for permissions within the same domain |
| `Global` | Can only contain accounts from the same domain, but can be used for permissions in any domain |
| `Universal` | Can contain accounts from any domain and be used for permissions in any domain (forest-level) |

### Group Types

| Type | Description |
|------|-------------|
| `Security` | Used for permission assignment (default) |
| `Distribution` | Used only for email distribution lists, no security context |

## Typical Workflows

### Create a security group and add members
```bash
# 1. Create the group
samba-tool group add "Web Server Admins" \
  --group-scope=Global \
  --description="Administrators of web servers"

# 2. Add members
samba-tool group addmembers "Web Server Admins" jdoe,asmith

# 3. Verify membership
samba-tool group listmembers "Web Server Admins"

# 4. Verify group attributes
samba-tool group show "Web Server Admins"
```

### Create nested group structure
```bash
# Create global groups
samba-tool group add "EU Server Admins" --group-scope=Global
samba-tool group add "US Server Admins" --group-scope=Global

# Create universal group
samba-tool group add "All Server Admins" --group-scope=Universal

# Nest the global groups in the universal group
samba-tool group addmembers "All Server Admins" "EU Server Admins"
samba-tool group addmembers "All Server Admins" "US Server Admins"
```
