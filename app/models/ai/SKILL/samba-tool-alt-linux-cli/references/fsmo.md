# samba-tool fsmo — Flexible Single Master Operations (FSMO) Roles Management

Manage the FSMO (Flexible Single Master Operations) roles in the Active Directory domain. FSMO roles are specialized domain controller tasks that must be performed by a single DC.

## FSMO Roles

| Role | Abbreviation | Description |
|------|-------------|-------------|
| Schema Master | `schema` | Controls all schema modifications |
| Domain Naming Master | `naming` | Controls addition/removal of domains in the forest |
| Infrastructure Master | `infrastructure` | Maintains SID-to-name references for cross-domain objects |
| Relative ID (RID) Master | `rid` | Allocates RID pools to DCs |
| PDC Emulator | `pdc` | Acts as primary DC for time sync, password changes, GPO edits |

## Subcommands

### fsmo show
Show the current FSMO role holders.

```bash
samba-tool fsmo show [options]
```

**Examples:**
```bash
# Show FSMO role holders
samba-tool fsmo show

# Query remote server
samba-tool fsmo show -H ldap://dc1.example.com -U Administrator
```

**Sample Output:**
```
InfrastructureMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com
RidAllocationMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com
PdcEmulationMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com
DomainNamingMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com
SchemaMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com
```

### fsmo transfer
Transfer an FSMO role to another domain controller. The current role holder must be available for a transfer.

```bash
samba-tool fsmo transfer --role=<role> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--role=ROLE` | FSMO role to transfer: `schema`, `naming`, `infrastructure`, `rid`, `pdc`, or `all` |

**Examples:**
```bash
# Transfer PDC Emulator role to this DC
samba-tool fsmo transfer --role=pdc

# Transfer RID Master role
samba-tool fsmo transfer --role=rid

# Transfer all roles to this DC
samba-tool fsmo transfer --role=all

# Transfer with authentication
samba-tool fsmo transfer --role=infrastructure -U Administrator -H ldap://dc2.example.com
```

### fsmo seize
Seize an FSMO role. Use this when the current role holder is permanently unavailable (e.g., failed DC). This is a forced operation.

```bash
samba-tool fsmo seize --role=<role> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--role=ROLE` | FSMO role to seize: `schema`, `naming`, `infrastructure`, `rid`, `pdc`, or `all` |

> **Warning**: Seizing FSMO roles should only be done when the current role holder is permanently offline. If the original role holder comes back online after a seize, it may cause conflicts. The original DC must never be reconnected to the network without a full metadata cleanup.

**Examples:**
```bash
# Seize PDC Emulator (when current holder is down)
samba-tool fsmo seize --role=pdc

# Seize all roles (emergency recovery)
samba-tool fsmo seize --role=all

# Seize Schema Master
samba-tool fsmo seize --role=schema
```

## Typical Workflows

### Transfer FSMO roles during DC maintenance
```bash
# 1. Check current role holders
samba-tool fsmo show

# 2. Transfer roles to another DC
samba-tool fsmo transfer --role=pdc -H ldap://dc2.example.com
samba-tool fsmo transfer --role=rid -H ldap://dc2.example.com
samba-tool fsmo transfer --role=infrastructure -H ldap://dc2.example.com
samba-tool fsmo transfer --role=naming -H ldap://dc2.example.com
samba-tool fsmo transfer --role=schema -H ldap://dc2.example.com

# 3. Verify
samba-tool fsmo show
```

### Emergency FSMO seizure (DC failure)
```bash
# 1. Verify the original DC is truly offline
ping dc1.example.com

# 2. Seize all roles
samba-tool fsmo seize --role=all

# 3. Verify
samba-tool fsmo show

# 4. Clean up metadata for the failed DC
# (see domain demote or manual metadata cleanup)
```
