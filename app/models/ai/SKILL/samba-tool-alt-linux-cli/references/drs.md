# samba-tool drs — Directory Replication Services (DRS) Management

Manage Directory Replication Services for the Samba AD domain.

## Subcommands

### drs bind
Show DRS capabilities of a server.

```bash
samba-tool drs bind [options]
```

Displays the DRS (Directory Replication Service) capabilities and supported extensions of a domain controller.

**Examples:**
```bash
samba-tool drs bind -H ldap://dc1.example.com
```

### drs kcc
Trigger Knowledge Consistency Checker (KCC) run.

```bash
samba-tool drs kcc [options]
```

The KCC automatically generates and maintains the replication topology for the domain. Running this command triggers an immediate KCC computation.

**Examples:**
```bash
samba-tool drs kcc -H ldap://dc1.example.com
```

### drs options
Query or change options for the NTDS Settings object of a domain controller.

```bash
samba-tool drs options [options]
```

**Examples:**
```bash
# Query current DRS options
samba-tool drs options -H ldap://dc1.example.com
```

### drs replicate
Replicate a naming context (partition) between two domain controllers.

```bash
samba-tool drs replicate <destination_DC> <source_DC> <NC> [options]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `destination_DC` | The DC to replicate TO |
| `source_DC` | The DC to replicate FROM |
| `NC` | Naming Context (partition DN) to replicate |

**Options:**

| Option | Description |
|--------|-------------|
| `--sync` | Force full sync instead of delta |
| `--async-op` | Asynchronous operation |
| `--single-object` | Replicate a single object |
| `--partial` | Partial attribute set (GC replication) |
| `--no-repl-aux` | Do not replicate auxiliary classes |

**Examples:**
```bash
# Replicate the domain partition
samba-tool drs replicate dc2.example.com dc1.example.com DC=example,DC=com

# Replicate the configuration partition
samba-tool drs replicate dc2.example.com dc1.example.com CN=Configuration,DC=example,DC=com

# Replicate the schema partition
samba-tool drs replicate dc2.example.com dc1.example.com CN=Schema,CN=Configuration,DC=example,DC=com

# Force full sync
samba-tool drs replicate dc2.example.com dc1.example.com DC=example,DC=com --sync
```

### drs showrepl
Show replication status for the domain controller.

```bash
samba-tool drs showrepl [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format |
| `--summary` | Produce minimal output when replication seems healthy |

**Examples:**
```bash
# Show full replication status
samba-tool drs showrepl

# JSON output
samba-tool drs showrepl --json

# Summary mode (quiet when healthy)
samba-tool drs showrepl --summary

# Check remote DC
samba-tool drs showrepl -H ldap://dc2.example.com
```

## Typical Workflows

### Force replication between DCs
```bash
# Replicate all partitions from dc1 to dc2
samba-tool drs replicate dc2.example.com dc1.example.com DC=example,DC=com
samba-tool drs replicate dc2.example.com dc1.example.com CN=Configuration,DC=example,DC=com
samba-tool drs replicate dc2.example.com dc1.example.com CN=Schema,CN=Configuration,DC=example,DC=com
```

### Diagnose replication issues
```bash
# 1. Check replication status
samba-tool drs showrepl

# 2. Trigger KCC to rebuild topology
samba-tool drs kcc

# 3. Force replication
samba-tool drs replicate dc2.example.com dc1.example.com DC=example,DC=com

# 4. Re-check status
samba-tool drs showrepl --summary
```

### Check DRS capabilities
```bash
samba-tool drs bind -H ldap://dc1.example.com
```
