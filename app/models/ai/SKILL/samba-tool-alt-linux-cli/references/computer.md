# samba-tool computer — Computer Account Management

Manage computer accounts in the Active Directory domain.

## Subcommands

### computer add
Add a new computer to the Active Directory Domain.

```bash
samba-tool computer add <computername> [options]
```

The computer name is the `sAMAccountName`, with or without the trailing dollar sign (`$`).

**Options:**

| Option | Description |
|--------|-------------|
| `--computerou=COMPUTEROU` | DN of alternative location (with or without domainDN counterpart) to default `CN=Computers` in which new computer object will be created. E.g. `OU=Servers` or `OU=Servers,DC=example,DC=com` |
| `--description=DESCRIPTION` | The new computer's description |
| `--ip-address=IP_ADDRESS_LIST` | IPv4 address for the computer's A record, or IPv6 address for AAAA record. Can be provided multiple times |
| `--service-principal-name=SERVICE_PRINCIPAL_NAME_LIST` | Computer's Service Principal Name. Can be provided multiple times |
| `--prepare-oldjoin` | Prepare enabled machine account for oldjoin mechanism |

**Examples:**
```bash
# Add a basic computer
samba-tool computer add WORKSTATION01

# Add with trailing dollar sign
samba-tool computer add WORKSTATION01$

# Add computer in specific OU with description
samba-tool computer add SERVER01 --computerou="OU=Servers" --description="File Server"

# Add computer with DNS records and SPNs
samba-tool computer add WEB01 \
  --ip-address=192.168.1.50 \
  --service-principal-name=HTTP/web01.example.com \
  --service-principal-name=HTTPS/web01.example.com

# Prepare computer for oldjoin
samba-tool computer add WORKSTATION01 --prepare-oldjoin
```

### computer create
Add a new computer. This is a **synonym** for `samba-tool computer add` and is available for compatibility reasons only. Use `samba-tool computer add` instead.

```bash
samba-tool computer create <computername> [options]
```

Same options as `computer add`.

### computer delete
Delete an existing computer account.

```bash
samba-tool computer delete <computername> [options]
```

The computer name is the `sAMAccountName`, with or without the trailing dollar sign.

**Examples:**
```bash
samba-tool computer delete WORKSTATION01
samba-tool computer delete SERVER01$
```

### computer edit
Edit a computer AD object interactively using a text editor.

```bash
samba-tool computer edit <computername> [options]
```

The computer name is the `sAMAccountName`, with or without the trailing dollar sign.

**Options:**

| Option | Description |
|--------|-------------|
| `--editor=EDITOR` | Specifies the editor to use instead of the system default, or `vi` if no system default is set |

**Examples:**
```bash
samba-tool computer edit SERVER01
samba-tool computer edit SERVER01 --editor=nano
```

### computer list
List all computers in the domain.

```bash
samba-tool computer list [options]
```

**Examples:**
```bash
samba-tool computer list
```

### computer move
Move a computer account into the specified organizational unit or container.

```bash
samba-tool computer move <computername> <new_parent_dn> [options]
```

- The `computername` is the `sAMAccountName`, with or without the trailing dollar sign.
- The `new_parent_dn` can be specified as a full DN or without the domainDN component.

**Examples:**
```bash
# Move computer to Servers OU
samba-tool computer move WORKSTATION01 "OU=Servers"

# Move using full DN
samba-tool computer move SERVER01 "OU=Decommissioned,DC=example,DC=com"
```

### computer show
Display a computer AD object's attributes.

```bash
samba-tool computer show <computername> [options]
```

The computer name is the `sAMAccountName`, with or without the trailing dollar sign.

**Options:**

| Option | Description |
|--------|-------------|
| `--attributes=USER_ATTRS` | Comma separated list of attributes to print |

**Examples:**
```bash
# Show all attributes
samba-tool computer show SERVER01

# Show specific attributes
samba-tool computer show SERVER01 --attributes=dn,sAMAccountName,description,operatingSystem,objectClass
```

## Common Global Options

All `computer` subcommands accept the standard global options (`-H`, `-U`, `--password`, etc.).

## Typical Workflows

### Adding a computer and joining to domain
```bash
# 1. Create the computer account
samba-tool computer add WORKSTATION01 --computerou="OU=Workstations"

# 2. On the workstation, join the domain
# (using net ads join or realm join on the client side)
```

### Decommissioning a computer
```bash
# 1. Move to decommissioned OU
samba-tool computer move OLDSERVER "OU=Decommissioned"

# 2. Delete the computer account
samba-tool computer delete OLDSERVER
```
