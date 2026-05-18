---
name: wbinfo-alt-linux-cli
description: Samba winbind CLI query tool for Linux. Use when the user needs to query AD/NT domain info, authenticate users, map SIDs/UIDs/GIDs, check trust accounts, list domains/users/groups, resolve NetBIOS names, or troubleshoot winbind/Samba domain integration on Linux. Triggers on: wbinfo, winbind queries, AD domain info, SID mapping, NT auth from CLI, domain trust check, NetBIOS resolution, domain controller lookup, computername in AD, Linux-Samba-AD integration, uid/gid-to-sid conversion, pam_winbind, ntlm_auth alternatives.
---

# wbinfo — Samba Winbind CLI Reference (ALT Linux)

Part of **Samba 4.21.9-alt1**. Queries the `winbindd(8)` daemon.
**Prereq:** `winbindd` must be running and configured.

## Quick Syntax

```
wbinfo [OPTION] [ARG]
```

Exit: `0` = success, `1` = failure. Fails if `winbindd` is down.

## Command Reference (Compact)

### Authentication

| Flag | Arg | Description |
|------|-----|-------------|
| `-a\|--authenticate` | `user%pass` | Auth user via winbind (both methods). **Do NOT use for app auth — use ntlm_auth(1)** |
| `-K\|--krb5auth` | `user%pass` | Auth via Kerberos |
| `--pam-logon` | `user%pass` | Auth same way as pam_winbind |
| `--ccache-save` | `user%pass` | Store creds for ccache |
| `--krb5ccname` | `CCTYPE` | Request specific kerberos cache type |
| `--lanman` | — | Use lanman crypto |
| `--ntlmv1` | — | Use NTLMv1 crypto |
| `--ntlmv2` | — | Use NTLMv2 crypto (default, kept for compat) |
| `--logoff` | — | Logoff user |
| `--logoff-uid` | `UID` | UID for logoff |
| `--logoff-user` | `USERNAME` | Username for logoff |
| `--change-user-password` | `username` | Change user password (prompted) |

### Domain & DC Info / Computername

| Flag | Arg | Description |
|------|-----|-------------|
| `--domain` | `name` | Set target domain. `.`=current, `*`=all (slow!) |
| `-D\|--domain-info` | `domain` | Show most domain info |
| `--dc-info` | `domain` | Info about current DC for domain |
| `--getdcname` | `domain` | Get DC name for domain |
| `--dsgetdcname` | `domain` | Find a DC for domain |
| `--all-domains` | — | List all domains (trusted + own) |
| `--own-domain` | — | List own domain |
| `-m\|--trusted-domains` | — | List trusted domains (excludes own PDC domain) |
| `--online-status` | `[domain]` | Show if winbind has active connection. Optional domain filter |
| `--separator` | — | Get active winbind separator |

### Trust & Secret

| Flag | Arg | Description |
|------|-----|-------------|
| `-t\|--check-secret` | — | Verify workstation trust account |
| `-c\|--change-secret` | — | Change trust account password. Use with `--domain` for interdomain |
| `--change-secret-at` | `DC` | Change trust pwd at specific DC |
| `--set-auth-user` | `user%pass` | Set winbind auth creds (for Restrict Anonymous domains) |
| `--get-auth-user` | — | Print current auth user/pwd (root only) |

### User Queries

| Flag | Arg | Description |
|------|-----|-------------|
| `-u\|--domain-users` | — | List domain users. `--domain='*'` for all trusted |
| `-i\|--user-info` | `user` | Get user info |
| `--uid-info` | `uid` | User info by UID |
| `-r\|--user-groups` | `user` | List UNIX group IDs for user. Auth'd=user token; unauth'd=limited query |
| `--user-domgroups` | `sid` | User domain groups |
| `--user-sidinfo` | `sid` | User info by SID |
| `--user-sids` | `sid` | User group SIDs |

### Group Queries

| Flag | Arg | Description |
|------|-----|-------------|
| `-g\|--domain-groups` | — | List domain groups. `--domain='*'` for all trusted |
| `--group-info` | `group` | Group info by name |
| `--gid-info` | `gid` | Group info by GID |

### SID Mapping

| Flag | Arg | Description |
|------|-----|-------------|
| `-n\|--name-to-sid` | `name` | Name → SID. Use `DOMAIN\user` or separator syntax |
| `-s\|--sid-to-name` | `sid` | SID → name |
| `-S\|--sid-to-uid` | `sid` | SID → UNIX UID |
| `-Y\|--sid-to-gid` | `sid` | SID → UNIX GID |
| `-G\|--gid-to-sid` | `gid` | GID → SID (must be in idmap range) |
| `-U\|--uid-to-sid` | `uid` | UID → SID (must be in idmap range) |
| `--sid-aliases` | `sid` | Get SID aliases |
| `--sid-to-fullname` | `sid` | SID → `DOMAIN\username` |
| `--sids-to-unix-ids` | `sid1,sid2,...` | SIDs → Unix IDs |
| `--lookup-sids` | `SID1,SID2,...` | Lookup multiple SIDs |
| `-R\|--lookup-rids` | `rid1,rid2,...` | RIDs → names |

### ID Mapping Management

| Flag | Arg | Description |
|------|-----|-------------|
| `--allocate-uid` | — | Get new UID from idmap |
| `--allocate-gid` | — | Get new GID from idmap |
| `--set-uid-mapping` | `UID,SID` | Create UID↔SID mapping |
| `--set-gid-mapping` | `GID,SID` | Create GID↔SID mapping |
| `--remove-uid-mapping` | `UID,SID` | Remove UID↔SID mapping |
| `--remove-gid-mapping` | `GID,SID` | Remove GID↔SID mapping |

### Name Resolution (NetBIOS/WINS) — Computername

| Flag | Arg | Description |
|------|-----|-------------|
| `-N\|--WINS-by-name` | `name` | NetBIOS name → IP via WINS |
| `-I\|--WINS-by-ip` | `ip` | IP → NetBIOS name (node status request) |

### Health & Diagnostics

| Flag | Arg | Description |
|------|-----|-------------|
| `-p\|--ping` | — | Check if winbindd alive → "succeeded"/"failed" |
| `-P\|--ping-dc` | — | No-effect cmd to DC, checks secure channel (lighter than `-t`) |
| `--sequence` | — | **Deprecated.** Use `--online-status` instead |
| `--verbose` | — | Print additional info about query results |

### General

| Flag | Arg | Description |
|------|-----|-------------|
| `-V\|--version` | — | Print version |
| `-?\|--help` | — | Help summary |
| `--usage` | — | Brief usage message |

## Common Usage Patterns

```bash
# Check winbind is alive
wbinfo -p

# List all domain users / groups
wbinfo -u
wbinfo -g

# Check trust account
wbinfo -t

# Authenticate user
wbinfo -a "DOMAIN\\user%password"

# Name ↔ SID
wbinfo -n "DOMAIN\\user"
wbinfo -s S-1-5-21-...-500

# UID/GID ↔ SID
wbinfo -U 1000
wbinfo -G 1000
wbinfo -S S-1-5-21-...-1000
wbinfo -Y S-1-5-21-...-1000

# Domain info & DC
wbinfo -D DOMAIN
wbinfo --getdcname DOMAIN
wbinfo --dc-info DOMAIN

# Computername: NetBIOS name resolution
wbinfo -N COMPUTERNAME      # → IP address
wbinfo -I 192.168.1.10      # → NetBIOS name

# All trusted domains
wbinfo -m
wbinfo --all-domains

# Online status
wbinfo --online-status
wbinfo --online-status DOMAIN

# Kerberos auth
wbinfo -K "user%password" --krb5ccname FILE:/tmp/krb5cc_1000

# Ping DC (lightweight trust check)
wbinfo -P
```

## SID Format

SIDs use Microsoft ASCII format: `S-1-5-21-{SUB1}-{SUB2}-{SUB3}-{RID}`
Example: `S-1-5-21-1455342024-3071081365-2475485837-500`

## See Also

`winbindd(8)`, `ntlm_auth(1)`, `smb.conf(5)`, `samba(7)`

## Detailed Reference

For extended descriptions and edge cases, read `references/extended.md`.
