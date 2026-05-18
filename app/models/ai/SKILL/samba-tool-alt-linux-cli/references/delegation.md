# samba-tool delegation — Delegation Management

Manage delegation settings for Active Directory accounts.

## Subcommands

### delegation add-service
Add a service principal as `msDS-AllowedToDelegateTo` for constrained delegation.

```bash
samba-tool delegation add-service <accountname> <principal> [options]
```

This allows the specified account to delegate authentication to the given service principal.

**Examples:**
```bash
# Allow web service account to delegate to database service
samba-tool delegation add-service WEBSVC$ cifs/dbserver.example.com

# Allow a user to delegate to HTTP service
samba-tool delegation add-service jdoe HTTP/appserver.example.com
```

### delegation del-service
Delete a service principal from `msDS-AllowedToDelegateTo`.

```bash
samba-tool delegation del-service <accountname> <principal> [options]
```

**Examples:**
```bash
samba-tool delegation del-service WEBSVC$ cifs/dbserver.example.com
```

### delegation for-any-protocol
Set or unset `UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (S4U2Proxy / protocol transition) for an account.

```bash
samba-tool delegation for-any-protocol <accountname> [(on|off)] [options]
```

When enabled (on), this allows the account to use protocol transition (S4U2Self) to impersonate any user to any service it is allowed to delegate to. This is required for constrained delegation with protocol transition.

**Examples:**
```bash
# Enable protocol transition
samba-tool delegation for-any-protocol WEBSVC$ on

# Disable protocol transition
samba-tool delegation for-any-protocol WEBSVC$ off
```

### delegation for-any-service
Set or unset `UF_TRUSTED_FOR_DELEGATION` (unconstrained delegation) for an account.

```bash
samba-tool delegation for-any-service <accountname> [(on|off)] [options]
```

When enabled (on), this allows the account to delegate authentication to any service (unconstrained delegation). This is a powerful setting and should be used with caution.

**Examples:**
```bash
# Enable unconstrained delegation
samba-tool delegation for-any-service WEBSVC$ on

# Disable unconstrained delegation
samba-tool delegation for-any-service WEBSVC$ off
```

### delegation show
Show the delegation settings of an account.

```bash
samba-tool delegation show <accountname> [options]
```

Displays the current delegation configuration, including:
- Whether the account is trusted for delegation (unconstrained)
- Whether the account is trusted for protocol transition (S4U2Proxy)
- The list of services the account can delegate to (msDS-AllowedToDelegateTo)

**Examples:**
```bash
samba-tool delegation show WEBSVC$
samba-tool delegation show jdoe
```

## Common Options

All delegation subcommands accept the standard global options:

| Option | Description |
|--------|-------------|
| `-H, --URL=URL` | LDB URL for database or target server |
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## Delegation Types Summary

| Type | Flag | Description |
|------|------|-------------|
| Unconstrained | `UF_TRUSTED_FOR_DELEGATION` | Account can delegate to any service |
| Constrained | `msDS-AllowedToDelegateTo` | Account can delegate only to specified services |
| Protocol Transition | `UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` | Account can use S4U2Self (impersonate any user) |

## Typical Workflows

### Set up constrained delegation with protocol transition
```bash
# 1. Enable protocol transition for the account
samba-tool delegation for-any-protocol WEBSVC$ on

# 2. Add target service principals
samba-tool delegation add-service WEBSVC$ cifs/dbserver.example.com
samba-tool delegation add-service WEBSVC$ HTTP/appserver.example.com

# 3. Verify settings
samba-tool delegation show WEBSVC$
```

### Set up unconstrained delegation
```bash
# Enable unconstrained delegation
samba-tool delegation for-any-service WEBSVC$ on

# Verify
samba-tool delegation show WEBSVC$
```

### Remove all delegation
```bash
# 1. Remove individual service principals
samba-tool delegation del-service WEBSVC$ cifs/dbserver.example.com

# 2. Disable protocol transition
samba-tool delegation for-any-protocol WEBSVC$ off

# 3. Disable unconstrained delegation
samba-tool delegation for-any-service WEBSVC$ off
```
