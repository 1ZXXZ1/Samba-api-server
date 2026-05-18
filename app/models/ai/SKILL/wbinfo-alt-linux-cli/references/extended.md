# wbinfo Extended Reference

## Table of Contents

1. [Authentication Details](#authentication-details)
2. [Domain & Computername Operations](#domain--computername-operations)
3. [SID Mapping Edge Cases](#sid-mapping-edge-cases)
4. [ID Mapping Internals](#id-mapping-internals)
5. [User Groups Behavior](#user-groups-behavior)
6. [WINS/NetBIOS Resolution](#winsnetbios-resolution)
7. [Trust Account Management](#trust-account-management)
8. [Kerberos Specifics](#kerberos-specifics)

---

## Authentication Details

### `-a|--authenticate user%password`

Attempts authentication using both available methods (NTLM and Kerberos if configured). Reports results for each method separately.

**Critical warning:** Do not use this for third-party application authentication. Use `ntlm_auth(1)` instead — it provides a proper interface for external auth integrations.

### `--pam-logon user%password`

Authenticates identically to how `pam_winbind` would process a login. This is the closest simulation of actual PAM-based domain logon behavior, including token generation and group membership evaluation.

### `--ntlmv1` / `--ntlmv2` / `--lanman`

Crypto method selectors for authentication:
- **NTLMv2** — Default and recommended. The `--ntlmv2` flag exists for compat only.
- **NTLMv1** — Legacy, avoid unless required by old servers.
- **lanman** — Oldest, weakest. Only for ancient SMB1/LM environments.

These flags modify subsequent `-a` or `-K` authentication calls.

---

## Domain & Computername Operations

### `--domain name`

Sets the target domain for operations. Three special values:
- **`.`** (dot) — Current domain winbindd belongs to
- **`*`** (asterisk) — Enumerate across ALL domains. Warning: can be very slow and memory-intensive in large multi-domain forests
- **Named domain** — e.g., `CORP`, `CHILD.DOMAIN.COM`

### Domain listing commands

| Command | Scope | Includes Own Domain |
|---------|-------|---------------------|
| `--own-domain` | Own domain only | Yes |
| `--all-domains` | All trusted + own | Yes |
| `-m\|--trusted-domains` | Trusted only | No (excludes PDC domain) |

### DC discovery

- `--getdcname domain` — Returns the name of a domain controller for the specified domain. Uses NetBIOS-based discovery.
- `--dsgetdcname domain` — Uses DsGetDcName API for DC discovery. More modern, supports DNS-based discovery and site-awareness.
- `--dc-info domain` — Shows detailed info about the currently connected DC: name, address, domain GUID, forest, site, etc.

### Computername resolution

The computername (machine NetBIOS name) in AD context is resolved via:

```bash
# Resolve computername to IP via WINS
wbinfo -N MYSERVER

# Resolve IP to computername
wbinfo -I 192.168.1.50
```

The `-N` option queries the WINS server for the IP associated with a NetBIOS name. The `-I` option sends a node status request to get the NetBIOS name for an IP address.

For the local machine's own computername in AD:
```bash
# The trust account name is the machine's computername
wbinfo -t                    # Verify trust (uses computer account)
wbinfo -c                    # Change machine account password
wbinfo --change-secret-at DC # Change at specific DC
```

---

## SID Mapping Edge Cases

### `-G|--gid-to-sid gid`

Only works for GIDs within the idmap gid range configured in `smb.conf`. GIDs outside this range will fail. This ensures only winbind-managed mappings are resolved.

### `-U|--uid-to-sid uid`

Same idmap range restriction as `-G`. UIDs must fall within the configured idmap uid range.

### `-S|--sid-to-uid sid` / `-Y|--sid-to-gid sid`

These convert SIDs to Unix IDs. Failure means the SID has no corresponding Unix mapping in winbind's idmap database. This can happen for:
- Built-in SIDs that were never mapped
- SIDs from domains not covered by idmap configuration
- SIDs that were manually unmapped

### `--sids-to-unix-ids sid1,sid2,...`

Batch version of SID→Unix ID resolution. More efficient than individual calls when resolving multiple SIDs.

### SID format

Always use the Microsoft ASCII format: `S-1-5-21-{AUTH1}-{AUTH2}-{AUTH3}-{RID}`

Common well-known SIDs:
- `S-1-5-32-544` — Built-in Administrators
- `S-1-5-32-545` — Built-in Users
- `S-1-5-32-546` — Built-in Guests
- `S-1-5-21-...-500` — Domain Admin
- `S-1-5-21-...-501` — Domain Guest
- `S-1-5-21-...-512` — Domain Admins group
- `S-1-5-21-...-513` — Domain Users group

---

## ID Mapping Internals

### `--allocate-uid` / `--allocate-gid`

Requests a new UID/GID from the idmap subsystem. Used when you need to pre-allocate a Unix ID for a Windows SID before it's automatically created during first login.

### `--set-uid-mapping UID,SID` / `--set-gid-mapping GID,SID`

Creates explicit bidirectional mappings in the idmap database. Useful for:
- Pre-staging accounts with specific Unix IDs
- Migrating from one idmap backend to another
- Ensuring consistent UID/GID across multiple servers

### `--remove-uid-mapping UID,SID` / `--remove-gid-mapping GID,SID`

Removes existing mappings. Use with caution — active sessions may still reference removed mappings.

---

## User Groups Behavior

### `-r|--user-groups username`

Two scenarios affect results:

1. **Authenticated user** — Returns groups from cached access token. May be outdated if group membership changed after login.
2. **Unauthenticated user** — Queries DC using machine account credentials (limited permissions). Results are normally incomplete and potentially incorrect.

For accurate group membership, ensure the user has been recently authenticated or use SID-based queries.

### `--user-domgroups sid`

Returns domain groups for a user SID. More reliable than `-r` for domain group membership since it queries the DC directly.

### `--user-sids sid`

Returns all SIDs of groups the user belongs to, including nested group memberships.

---

## WINS/NetBIOS Resolution

### `-N|--WINS-by-name name`

Queries the WINS server (configured in `smb.conf`) for the IP address of a NetBIOS name. The name must be registered in WINS.

Common NetBIOS name types:
- `<name>` — Computer name (type 0x00)
- `<name>\0x1c` — Domain controllers
- `<name>\0x1b` — Domain master browser

### `-I|--WINS-by-ip ip`

Sends a node status request to the IP. Returns the NetBIOS name table from that node, which includes the computer name, domain name, and browser roles.

---

## Trust Account Management

### `-t|--check-secret`

Verifies the machine's domain trust account is functional. This is the primary diagnostic for "is this machine properly joined to the domain?" A failure typically means:
- Machine account password is out of sync
- Secure channel is broken
- DC is unreachable

### `-P|--ping-dc`

Lighter-weight alternative to `-t`. Sends a no-effect command to the DC to verify the secure channel is alive. Prefer `-P` for monitoring/health checks as it has less impact.

### `-c|--change-secret`

Changes the machine trust account password. Normally done automatically by `winbindd` at regular intervals. Manual use cases:
- After restoring a machine from backup
- When trust account is out of sync
- Combined with `--domain` to change interdomain trust passwords

---

## Kerberos Specifics

### `-K|--krb5auth user%password`

Performs Kerberos authentication. Requires:
- Working DNS with SRV records for the domain
- Correct `/etc/krb5.conf` configuration
- System clock synchronization (Kerberos is time-sensitive)

### `--krb5ccname CCTYPE`

Specifies the credential cache type for Kerberos auth. Common types:
- `FILE:/path/to/ccache` — File-based cache
- `MEMORY:` — In-memory cache (process-scoped)
- `KCM:` — Kernel Credential Manager

Combined usage:
```bash
wbinfo -K "user%pass" --krb5ccname FILE:/tmp/krb5cc_1000
```
