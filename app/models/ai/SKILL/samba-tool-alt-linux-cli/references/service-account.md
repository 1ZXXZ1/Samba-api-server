# samba-tool service-account — Service Account and Group Managed Service Account Management

Manage Service Accounts and Group Managed Service Accounts (gMSA) in the Samba Active Directory domain.

## Subcommands

### service-account list
List service accounts on the domain.

```bash
samba-tool service-account list [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--json` | View service accounts as JSON instead of a list |

**Examples:**
```bash
samba-tool service-account list
samba-tool service-account list --json
```

### service-account view
View a single service account on the domain.

```bash
samba-tool service-account view [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Account name of service account to view (required) |

**Examples:**
```bash
samba-tool service-account view --name=svc_web$
samba-tool service-account view --name=gmsa_sql$
```

### service-account create
Create a new service account (Group Managed Service Account) on the domain.

```bash
samba-tool service-account create [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Account name of service account (required) |
| `--dns-host-name=FQDN` | DNS hostname of this service account (required) |
| `--group-msa-membership=SDDL` | Optional Group MSA Membership SDDL (controls which computers can retrieve the password) |
| `--managed-password-interval=DAYS` | Managed password refresh interval in days |

**Examples:**
```bash
# Create a basic gMSA
samba-tool service-account create \
  --name=svc_web$ \
  --dns-host-name=web.example.com

# Create gMSA with password interval and membership
samba-tool service-account create \
  --name=gmsa_sql$ \
  --dns-host-name=sql.example.com \
  --managed-password-interval=30 \
  --group-msa-membership="O:SYG:SYD:(A;;RC;;;S-1-5-21-...-1105)"
```

### service-account modify
Modify an existing service account on the domain.

```bash
samba-tool service-account modify [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Account name of service account (required) |
| `--dns-host-name=FQDN` | Update DNS hostname of this service account |
| `--group-msa-membership=SDDL` | Update Group MSA Membership SDDL |

**Examples:**
```bash
# Update DNS hostname
samba-tool service-account modify --name=svc_web$ --dns-host-name=web2.example.com

# Update group MSA membership
samba-tool service-account modify --name=gmsa_sql$ --group-msa-membership="O:SYG:SYD:(A;;RC;;;S-1-5-21-...-1106)"
```

### service-account delete
Delete a service account on the domain.

```bash
samba-tool service-account delete [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Account name of service account to delete |

**Examples:**
```bash
samba-tool service-account delete --name=svc_web$
```

### service-account group-msa-membership
Manage Group MSA Membership for a service account.

#### service-account group-msa-membership show
Display Group MSA Membership for a service account.

```bash
samba-tool service-account group-msa-membership show [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Account name of service account (required) |
| `--json` | Return as JSON instead of a list |

**Examples:**
```bash
samba-tool service-account group-msa-membership show --name=gmsa_sql$
samba-tool service-account group-msa-membership show --name=gmsa_sql$ --json
```

#### service-account group-msa-membership add
Add a principal to Group MSA Membership for a service account.

```bash
samba-tool service-account group-msa-membership add [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Account name of service account (required) |
| `--principal=PRINCIPAL` | Name, DN or SID of principal to add |

**Examples:**
```bash
# Add a computer to gMSA membership
samba-tool service-account group-msa-membership add \
  --name=gmsa_sql$ \
  --principal=SQLSERVER01$

# Add by DN
samba-tool service-account group-msa-membership add \
  --name=gmsa_sql$ \
  --principal="CN=SQLSERVER01,CN=Computers,DC=example,DC=com"
```

#### service-account group-msa-membership remove
Remove a principal from Group MSA Membership for a service account.

```bash
samba-tool service-account group-msa-membership remove [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Account name of service account (required) |
| `--principal=PRINCIPAL` | Name, DN or SID of principal to remove |

**Examples:**
```bash
samba-tool service-account group-msa-membership remove \
  --name=gmsa_sql$ \
  --principal=SQLSERVER01$
```

## gMSA Concepts

### What is a Group Managed Service Account (gMSA)?
A gMSA is a special type of account that provides automatic password management for services running on one or more servers. The password is automatically rotated by Active Directory at a configurable interval.

### Key Benefits
- **Automatic password management**: No manual password changes needed
- **Centralized management**: Password is stored in AD and distributed to authorized computers
- **Multiple server support**: Unlike standalone MSA, gMSA can be used on multiple servers
- **No password knowledge**: Administrators never know the password

### Typical Use Cases
- IIS Application Pools
- SQL Server services
- Scheduled tasks
- Windows services
- Any service requiring a domain account

## Typical Workflows

### Create and configure a gMSA for SQL Server
```bash
# 1. Create the gMSA
samba-tool service-account create \
  --name=gmsa_sql$ \
  --dns-host-name=sql.example.com \
  --managed-password-interval=30

# 2. Add the SQL server computer to the gMSA membership
samba-tool service-account group-msa-membership add \
  --name=gmsa_sql$ \
  --principal=SQLSERVER01$

# 3. Verify membership
samba-tool service-account group-msa-membership show --name=gmsa_sql$

# 4. View account details
samba-tool service-account view --name=gmsa_sql$
```

### Add a second server to existing gMSA
```bash
# Add the second server
samba-tool service-account group-msa-membership add \
  --name=gmsa_sql$ \
  --principal=SQLSERVER02$
```

### Decommission a gMSA
```bash
# 1. Remove servers from membership
samba-tool service-account group-msa-membership remove \
  --name=gmsa_sql$ --principal=SQLSERVER01$

# 2. Delete the gMSA
samba-tool service-account delete --name=gmsa_sql$
```
