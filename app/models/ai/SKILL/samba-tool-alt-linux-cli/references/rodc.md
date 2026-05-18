# samba-tool rodc — Read-Only Domain Controller (RODC) Management

Manage Read-Only Domain Controllers in the Samba Active Directory domain.

## Subcommands

### rodc preload
Preload one account for an RODC.

```bash
samba-tool rodc preload <SID|DN|accountname> [options]
```

Preloading an account caches its credentials on the RODC so that the RODC can authenticate the account even when the WAN link to the writable DC is unavailable.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `SID` | Security Identifier of the account |
| `DN` | Distinguished Name of the account |
| `accountname` | sAMAccountName of the account |

**Options:**

| Option | Description |
|--------|-------------|
| `--server=SERVER` | The RODC server to preload the account on |

**Examples:**
```bash
# Preload a user by account name
samba-tool rodc preload jdoe --server=rodc1.example.com

# Preload a user by DN
samba-tool rodc preload "CN=John Doe,CN=Users,DC=example,DC=com" --server=rodc1.example.com

# Preload a user by SID
samba-tool rodc preload S-1-5-21-3623811015-3361044348-30300820-1105 --server=rodc1.example.com

# Preload a computer account
samba-tool rodc preload WORKSTATION01$ --server=rodc1.example.com
```

## RODC Concepts

### What is an RODC?
A Read-Only Domain Controller holds a read-only copy of the Active Directory database. It is designed for deployment in locations where physical security cannot be guaranteed (branch offices, DMZ, etc.).

### Key RODC Features
- **Read-only AD database**: No writes are possible on the RODC
- **Credential caching**: Selective caching of user/computer credentials
- **Filtered Attribute Set (FAS)**: Sensitive attributes are not replicated to RODCs
- **Admin role separation**: Local administrators on the RODC do not have domain admin privileges

### Password Replication Policy (PRP)
The PRP controls which accounts can have their credentials cached on the RODC:
- **Allowed List**: Accounts whose credentials CAN be cached
- **Denied List**: Accounts whose credentials CANNOT be cached (takes precedence)

## Typical Workflows

### Preload accounts for branch office RODC
```bash
# Preload users who need to authenticate at the branch
samba-tool rodc preload jdoe --server=rodc1.example.com
samba-tool rodc preload asmith --server=rodc1.example.com

# Preload computer accounts
samba-tool rodc preload BRANCH-PC01$ --server=rodc1.example.com
samba-tool rodc preload BRANCH-PC02$ --server=rodc1.example.com
```

### Set up RODC in the domain
```bash
# 1. Join as RODC
samba-tool domain join example.com RODC -U Administrator

# 2. Preload critical accounts
samba-tool rodc preload jdoe --server=rodc1.example.com

# 3. Verify replication
samba-tool drs showrepl
```
