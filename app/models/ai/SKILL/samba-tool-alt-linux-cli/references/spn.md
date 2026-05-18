# samba-tool spn — Service Principal Name (SPN) Management

Manage Service Principal Names in the Active Directory domain.

## Subcommands

### spn add
Create a new SPN for a user or computer account.

```bash
samba-tool spn add <name> <user> [options]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | SPN to add (e.g., `HTTP/server.example.com`) |
| `user` | Account to assign the SPN to (username or DN) |

**Examples:**
```bash
# Add HTTP SPN for a service account
samba-tool spn add HTTP/web.example.com svc_web$

# Add multiple SPNs for a computer
samba-tool spn add cifs/fileserver.example.com FILESERVER01$
samba-tool spn add HOST/fileserver.example.com FILESERVER01$

# Add SPN for a user account
samba-tool spn add MSSQLSvc/db.example.com:1433 sqladmin
```

### spn delete
Delete an existing SPN.

```bash
samba-tool spn delete <name> [user] [options]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | SPN to delete |
| `user` | Optional: account to remove the SPN from. If not specified, the SPN is removed from whichever account holds it |

**Examples:**
```bash
# Delete a specific SPN
samba-tool spn delete HTTP/web.example.com svc_web$

# Delete SPN without specifying account
samba-tool spn delete HTTP/oldweb.example.com
```

### spn list
List SPNs of a given user or computer account.

```bash
samba-tool spn list <user> [options]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `user` | Account to list SPNs for (username or DN) |

**Examples:**
```bash
# List SPNs for a computer
samba-tool spn list FILESERVER01$

# List SPNs for a service account
samba-tool spn list svc_web$

# List SPNs for a user
samba-tool spn list sqladmin
```

## Common Options

All SPN subcommands accept:

| Option | Description |
|--------|-------------|
| `-H, --URL=URL` | LDB URL for database or target server |
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## SPN Concepts

### What is an SPN?
A Service Principal Name (SPN) is a unique identifier that Kerberos uses to associate a service instance with a service account. SPNs are essential for Kerberos authentication to work correctly.

### SPN Format
```
<serviceclass>/<host>:<port> <serviceclass>/<host>
```

**Common SPN classes:**

| Service Class | Description | Example |
|--------------|-------------|---------|
| `HTTP` | Web services | `HTTP/web.example.com` |
| `cifs` | File sharing (SMB) | `cifs/fileserver.example.com` |
| `HOST` | Generic host service | `HOST/server.example.com` |
| `MSSQLSvc` | SQL Server | `MSSQLSvc/db.example.com:1433` |
| `ldap` | LDAP directory | `ldap/dc1.example.com` |
| `krbtgt` | Kerberos Ticket Granting | `krbtgt/EXAMPLE.COM` |
| `imap` | IMAP mail | `imap/mail.example.com` |
| `smtp` | SMTP mail | `smtp/mail.example.com` |
| `nfs` | NFS file sharing | `nfs/fileserver.example.com` |

### Important SPN Rules
1. **SPNs must be unique** — An SPN can only be assigned to one account in the domain
2. **Duplicate SPNs break Kerberos** — If two accounts have the same SPN, Kerberos authentication will fail
3. **Use FQDNs** — Always use fully qualified domain names, not short names or IP addresses
4. **PORT is optional** — For non-standard ports, include the port number

## Typical Workflows

### Set up SPNs for a web service
```bash
# 1. Create the service account
samba-tool user add svc_web --random-password

# 2. Add SPNs for the web service
samba-tool spn add HTTP/web.example.com svc_web
samba-tool spn add HTTP/web svc_web
samba-tool spn add HTTP/web.example.com:8080 svc_web

# 3. Verify SPNs
samba-tool spn list svc_web

# 4. Set up constrained delegation if needed
samba-tool delegation add-service svc_web cifs/dbserver.example.com
```

### Troubleshoot duplicate SPNs
```bash
# 1. List SPNs on both accounts
samba-tool spn list FILESERVER01$
samba-tool spn list FILESERVER02$

# 2. If duplicate found, remove from wrong account
samba-tool spn delete cifs/fileserver.example.com FILESERVER02$

# 3. Verify
samba-tool spn list FILESERVER01$
```

### Configure SPNs for SQL Server
```bash
# Add SPNs for SQL Server instance
samba-tool spn add MSSQLSvc/sql.example.com:1433 sqlsvc
samba-tool spn add MSSQLSvc/sql.example.com sqlsvc

# Verify
samba-tool spn list sqlsvc
```
