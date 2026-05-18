# samba-tool domain — Domain Management

Manage the Samba Active Directory domain. This is the largest command group with many subcommands.

## Subcommands

### domain backup
Create or restore a backup of the domain.

#### domain backup offline
Backup (with proper locking) local domain directories into a tar file.

```bash
samba-tool domain backup offline [options]
```

This command stops Samba services briefly to get a consistent backup of the domain databases.

#### domain backup online
Copy a running DC's current DB into a backup tar file.

```bash
samba-tool domain backup online [options]
```

This creates a backup without stopping Samba services.

#### domain backup rename
Copy a running DC's DB to backup file, renaming the domain in the process.

```bash
samba-tool domain backup rename [options]
```

Used for domain rename scenarios.

#### domain backup restore
Restore the domain's DB from a backup file.

```bash
samba-tool domain backup restore [options]
```

---

### domain auth policy
Manage authentication policies.

#### domain auth policy list
List authentication policies on the domain.

```bash
samba-tool domain auth policy list [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--json` | View as JSON instead of a list |

#### domain auth policy view
View an authentication policy.

```bash
samba-tool domain auth policy view [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of the authentication policy to view (required) |

#### domain auth policy create
Create an authentication policy.

```bash
samba-tool domain auth policy create [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of the authentication policy (required) |
| `--description=DESC` | Optional description |
| `--protect` | Protect from accidental deletion (mutually exclusive with `--unprotect`) |
| `--unprotect` | Unprotect from accidental deletion (mutually exclusive with `--protect`) |
| `--audit` | Audit-only mode (mutually exclusive with `--enforce`) |
| `--enforce` | Enforce mode (mutually exclusive with `--audit`) |
| `--strong-ntlm-policy=POLICY` | Strong NTLM Policy: `Disabled`, `Optional`, `Required` |
| `--user-tgt-lifetime-mins=MINS` | TGT lifetime for user accounts |
| `--user-allow-ntlm-auth` | Allow NTLM for users despite allowed-to-authenticate-from |
| `--user-allowed-to-authenticate-from=SDDL` | SDDL for device conditions for user auth (no Device keywords) |
| `--user-allowed-to-authenticate-to=SDDL` | SDDL restricting which accounts may access a user service |
| `--service-tgt-lifetime-mins=MINS` | TGT lifetime for service accounts |
| `--service-allow-ntlm-auth` | Allow NTLM for services when restricted to selected devices |
| `--service-allowed-to-authenticate-from=SDDL` | SDDL for device conditions for service auth |
| `--service-allowed-to-authenticate-to=SDDL` | SDDL restricting which accounts may access a service |
| `--computer-tgt-lifetime-mins=MINS` | TGT lifetime for computer accounts |
| `--computer-allowed-to-authenticate-to=SDDL` | SDDL restricting which accounts may access a computer |

**SDDL Examples:**
```
O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AU)}))
O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))
```

#### domain auth policy modify
Modify an authentication policy. Same options as `domain auth policy create`.

```bash
samba-tool domain auth policy modify [options]
```

#### domain auth policy delete
Delete an authentication policy.

```bash
samba-tool domain auth policy delete [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication policy to delete (required) |
| `--force` | Force delete even if protected |

#### domain auth policy user-allowed-to-authenticate-from set
Set the user-allowed-to-authenticate-from property by scenario.

```bash
samba-tool domain auth policy user-allowed-to-authenticate-from set [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication policy |
| `--by-group=GROUP` | User can authenticate if device is member of GROUP |
| `--silo=SILO` | User can authenticate if device is assigned to SILO |

#### domain auth policy user-allowed-to-authenticate-to set
Set the user-allowed-to-authenticate-to property by scenario.

```bash
samba-tool domain auth policy user-allowed-to-authenticate-to set [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication policy |
| `--group=GROUP` | Only allow access from members of GROUP |
| `--silo=SILO` | Only allow access from accounts assigned to SILO |

#### domain auth policy service-allowed-to-authenticate-from set
Set the service-allowed-to-authenticate-from property by scenario.

```bash
samba-tool domain auth policy service-allowed-to-authenticate-from set [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication policy |
| `--group=GROUP` | Service can authenticate if device is member of GROUP |
| `--silo=SILO` | Service can authenticate if device is assigned to SILO |

#### domain auth policy service-allowed-to-authenticate-to set
Set the service-allowed-to-authenticate-to property by scenario.

```bash
samba-tool domain auth policy service-allowed-to-authenticate-to set [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication policy |
| `--group=GROUP` | Only allow access from members of GROUP |
| `--silo=SILO` | Only allow access from accounts assigned to SILO |

#### domain auth policy computer-allowed-to-authenticate-to set
Set the computer-allowed-to-authenticate-to property by scenario.

```bash
samba-tool domain auth policy computer-allowed-to-authenticate-to set [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication policy |
| `--group=GROUP` | Only allow access from members of GROUP |
| `--silo=SILO` | Only allow access from accounts assigned to SILO |

---

### domain auth silo
Manage authentication silos.

#### domain auth silo list
List authentication silos on the domain.

```bash
samba-tool domain auth silo list [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--json` | View as JSON instead of a list |

#### domain auth silo view
View an authentication silo.

```bash
samba-tool domain auth silo view [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of the authentication silo to view (required) |

#### domain auth silo create
Create an authentication silo.

```bash
samba-tool domain auth silo create [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of the authentication silo (required) |
| `--description=DESC` | Optional description |
| `--user-authentication-policy=POLICY` | User account authentication policy |
| `--service-authentication-policy=POLICY` | Managed service account authentication policy |
| `--computer-authentication-policy=POLICY` | Computer authentication policy |
| `--protect` | Protect from accidental deletion (mutually exclusive with `--unprotect`) |
| `--unprotect` | Unprotect from accidental deletion (mutually exclusive with `--protect`) |
| `--audit` | Audit-only mode (mutually exclusive with `--enforce`) |
| `--enforce` | Enforce mode (mutually exclusive with `--audit`) |

#### domain auth silo modify
Modify an authentication silo. Same options as `domain auth silo create`.

```bash
samba-tool domain auth silo modify [options]
```

#### domain auth silo delete
Delete an authentication silo.

```bash
samba-tool domain auth silo delete [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication silo to delete (required) |
| `--force` | Force delete even if protected |

#### domain auth silo member grant
Grant a member access to an authentication silo.

```bash
samba-tool domain auth silo member grant [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication silo (required) |
| `--member=MEMBER` | Member to grant access (DN or account name) |

#### domain auth silo member list
List members in an authentication silo.

```bash
samba-tool domain auth silo member list [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication silo (required) |
| `--json` | View as JSON instead of a list |

#### domain auth silo member revoke
Revoke a member from an authentication silo.

```bash
samba-tool domain auth silo member revoke [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Name of authentication silo (required) |
| `--member=MEMBER` | Member to revoke (DN or account name) |

---

### domain claim claim-type
Manage claim types for conditional access policies.

#### domain claim claim-type list
List claim types on the domain.

```bash
samba-tool domain claim claim-type list [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--json` | View as JSON instead of a list |

#### domain claim claim-type view
View a single claim type.

```bash
samba-tool domain claim claim-type view [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Display name of claim type to view (required) |

#### domain claim claim-type create
Create a claim type.

```bash
samba-tool domain claim claim-type create [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--attribute=ATTR` | Attribute of claim type to create (required) |
| `--class=CLASS` | Object classes to set claim type to. Can be specified multiple times. E.g. `--class=user --class=computer` |
| `--name=NAME` | Optional display name or use attribute name |
| `--description=DESC` | Optional description or use from attribute |
| `--enable` | Enable claim type (mutually exclusive with `--disable`) |
| `--disable` | Disable claim type (mutually exclusive with `--enable`) |
| `--protect` | Protect from accidental deletion (mutually exclusive with `--unprotect`) |
| `--unprotect` | Unprotect from accidental deletion (mutually exclusive with `--protect`) |

#### domain claim claim-type modify
Modify a claim type.

```bash
samba-tool domain claim claim-type modify [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Display name of claim type to modify (required) |
| `--class=CLASS` | Object classes to set claim type to |
| `--description=DESC` | Set the claim type description |
| `--enable` | Enable claim type (mutually exclusive with `--disable`) |
| `--disable` | Disable claim type (mutually exclusive with `--enable`) |
| `--protect` | Protect from accidental deletion (mutually exclusive with `--unprotect`) |
| `--unprotect` | Unprotect from accidental deletion (mutually exclusive with `--protect`) |

#### domain claim claim-type delete
Delete a claim type.

```bash
samba-tool domain claim claim-type delete [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Display name of claim type to delete (required) |
| `--force` | Force delete even if protected |

### domain claim value-type
Manage claim value types.

#### domain claim value-type list
List claim value types on the domain.

```bash
samba-tool domain claim value-type list [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--json` | View as JSON instead of a list |

#### domain claim value-type view
View a single claim value type.

```bash
samba-tool domain claim value-type view [options]
```

| Option | Description |
|--------|-------------|
| `-H, --URL` | LDB URL for database or target server |
| `--name=NAME` | Display name of claim value type to view (required) |

---

### domain classicupgrade
Upgrade from Samba classic (NT4-like) database to Samba AD DC database.

```bash
samba-tool domain classicupgrade [options] <classic_smb_conf>
```

### domain dcpromo
Promote an existing domain member or NT4 PDC to an AD DC.

```bash
samba-tool domain dcpromo <dnsdomain> [DC|RODC] [options]
```

### domain demote
Demote ourselves from the role of domain controller.

```bash
samba-tool domain demote [options]
```

### domain exportkeytab
Dumps Kerberos keys of the domain into a keytab file.

```bash
samba-tool domain exportkeytab <keytab> [options]
```

**Examples:**
```bash
# Export all domain keys
samba-tool domain exportkeytab /etc/krb5.keytab

# Export keys for a specific principal
samba-tool domain exportkeytab /tmp/http.keytab --principal=HTTP/web.example.com
```

### domain info
Print basic info about a domain and the specified DC.

```bash
samba-tool domain info <ip_address> [options]
```

**Examples:**
```bash
samba-tool domain info 192.168.1.1
```

### domain join
Join a domain as either member or backup domain controller.

```bash
samba-tool domain join <dnsdomain> [DC|RODC|MEMBER|SUBDOMAIN] [options]
```

**Examples:**
```bash
# Join as DC
samba-tool domain join example.com DC -U Administrator

# Join as RODC
samba-tool domain join example.com RODC -U Administrator

# Join as member server
samba-tool domain join example.com MEMBER -U Administrator
```

### domain level
Show/raise domain and forest function levels.

```bash
samba-tool domain level show [options]
samba-tool domain level raise [options]
```

**Examples:**
```bash
# Show current levels
samba-tool domain level show

# Raise to Windows Server 2016
samba-tool domain level raise --domain-level=7 --forest-level=7
```

### domain passwordsettings
Show/set password settings for the domain.

```bash
samba-tool domain passwordsettings show [options]
samba-tool domain passwordsettings set [options]
```

**Set Options:**

| Option | Description |
|--------|-------------|
| `--min-pwd-length=LENGTH` | Minimum password length |
| `--min-pwd-age=AGE` | Minimum password age (days) |
| `--max-pwd-age=AGE` | Maximum password age (days) |
| `--pwd-history-length=LENGTH` | Password history length |
| `--pwd-complexity=on\|off` | Password complexity |
| `--store-plaintext=on\|off` | Store passwords using reversible encryption |

**Examples:**
```bash
# Show current password settings
samba-tool domain passwordsettings show

# Set minimum password length
samba-tool domain passwordsettings set --min-pwd-length=8

# Enable complexity, set max age
samba-tool domain passwordsettings set --pwd-complexity=on --max-pwd-age=90
```

### domain passwordsettings pso
Manage fine-grained Password Settings Objects (PSOs).

#### domain passwordsettings pso apply
Apply a PSO's password policy to a user or group.

```bash
samba-tool domain passwordsettings pso apply <pso-name> <user-or-group-name> [options]
```

#### domain passwordsettings pso create
Create a new Password Settings Object (PSO).

```bash
samba-tool domain passwordsettings pso create <pso-name> <precedence> [options]
```

#### domain passwordsettings pso delete
Delete a Password Settings Object (PSO).

```bash
samba-tool domain passwordsettings pso delete <pso-name> [options]
```

#### domain passwordsettings pso list
List all Password Settings Objects (PSOs).

```bash
samba-tool domain passwordsettings pso list [options]
```

#### domain passwordsettings pso set
Modify a Password Settings Object (PSO).

```bash
samba-tool domain passwordsettings pso set <pso-name> [options]
```

#### domain passwordsettings pso show
Display a Password Settings Object (PSO).

```bash
samba-tool domain passwordsettings pso show <user-name> [options]
```

#### domain passwordsettings pso show-user
Display the Password Settings that apply to a user.

```bash
samba-tool domain passwordsettings pso show-user <pso-name> [options]
```

#### domain passwordsettings pso unapply
Remove PSO application from a user or group.

```bash
samba-tool domain passwordsettings pso unapply <pso-name> <user-or-group-name> [options]
```

### domain provision
Provision a new Samba AD domain.

```bash
samba-tool domain provision [options]
```

**Key Options:**

| Option | Description |
|--------|-------------|
| `--realm=REALM` | Realm (Kerberos realm, uppercase DNS name) |
| `--domain=DOMAIN` | Domain (NetBIOS name, short name) |
| `--server-role=ROLE` | Server role: `dc`, `member`, `standalone` |
| `--dns-backend=BACKEND` | DNS backend: `SAMBA_INTERNAL`, `BIND9_FLATFILE`, `BIND9_DLZ`, `NONE` |
| `--use-rfc2307` | Use RFC2307 (Unix) attributes |
| `--adminpass=PASSWORD` | Administrator password |
| `--option=OPTION` | Additional smb.conf options |

**Examples:**
```bash
# Basic provision
samba-tool domain provision \
  --realm=EXAMPLE.COM \
  --domain=EXAMPLE \
  --server-role=dc \
  --dns-backend=SAMBA_INTERNAL \
  --adminpass='Secret123!'

# Provision with RFC2307 attributes
samba-tool domain provision \
  --realm=EXAMPLE.COM \
  --domain=EXAMPLE \
  --server-role=dc \
  --dns-backend=SAMBA_INTERNAL \
  --use-rfc2307 \
  --adminpass='Secret123!'
```

### domain trust
Domain and forest trust management.

#### domain trust create
Create a domain or forest trust.

```bash
samba-tool domain trust create <DOMAIN> [options]
```

#### domain trust modify
Modify a domain or forest trust.

```bash
samba-tool domain trust modify <DOMAIN> [options]
```

#### domain trust delete
Delete a domain trust.

```bash
samba-tool domain trust delete <DOMAIN> [options]
```

#### domain trust list
List domain trusts.

```bash
samba-tool domain trust list [options]
```

#### domain trust namespaces
Manage forest trust namespaces.

```bash
samba-tool domain trust namespaces [DOMAIN] [options]
```

#### domain trust show
Show trusted domain details.

```bash
samba-tool domain trust show <DOMAIN> [options]
```

#### domain trust validate
Validate a domain trust.

```bash
samba-tool domain trust validate <DOMAIN> [options]
```
