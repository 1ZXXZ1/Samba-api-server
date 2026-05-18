---
name: samba-tool-alt-linux-cli

description: Comprehensive AI skill for administering Samba AD (Active Directory) on Linux using `samba-tool` CLI. Covers the full samba-tool command set from Samba 4.21.9-alt1 (ALT Linux), including all top-level commands, subcommands, and their complete options. This skill enables an AI to fully manage a Samba AD domain controller — from user/group/computer management to DNS, GPO, replication, FSMO, schema, sites, trusts, and more.
---
## Trigger

Activate this skill when the user needs to:
- Administer a Samba Active Directory domain on Linux via CLI
- Manage users, groups, computers, contacts, or OUs in Samba AD
- Configure DNS records and zones in Samba AD
- Manage Group Policy Objects (GPOs)
- Configure domain trusts, replication, and FSMO roles
- Manage service accounts, SPNs, and delegation
- Check database integrity, manage ACLs, or query schema
- Perform domain backup/restore, provisioning, or joining
- Manage authentication policies and silos
- Visualize replication topology
- Any task related to `samba-tool` or Samba AD administration

## Command Structure

```
samba-tool <global-options> <command> <subcommand> <arguments> [options]
```

## Global Options

All samba-tool commands accept these global options (see `references/global-options.md` for details):

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit |
| `-r, --realm=REALM` | Set the realm for the domain |
| `--simple-bind-dn=DN` | DN to use for a simple bind |
| `--password` | Specify the password on the commandline |
| `-U, --user=[DOMAIN\]USERNAME[%PASSWORD]` | Set SMB username/password |
| `-W, --workgroup=WORKGROUP` | Set the SMB domain |
| `-N, --no-pass` | Suppress password prompt |
| `--use-kerberos=desired\|required\|off` | Kerberos authentication mode |
| `--use-krb5-ccache=CCACHE` | Kerberos credential cache location |
| `-A, --authentication-file=filename` | Read credentials from file |
| `--ipaddress=IPADDRESS` | IP address of the server |
| `--color=always\|never\|auto` | ANSI colour output control |
| `-d, --debuglevel=DEBUGLEVEL` | Debug level (0-10) |
| `--debug-stdout` | Redirect debug output to STDOUT |

## Top-Level Commands

| Command | Description | Reference File |
|---------|-------------|----------------|
| `computer` | Computer account management | `references/computer.md` |
| `contact` | Contact management | `references/contact.md` |
| `dbcheck` | Check local AD database for errors | `references/dbcheck.md` |
| `delegation` | Delegation management | `references/delegation.md` |
| `dns` | Domain Name Service (DNS) management | `references/dns.md` |
| `domain` | Domain management | `references/domain.md` |
| `drs` | Directory Replication Services (DRS) management | `references/drs.md` |
| `dsacl` | DS ACLs manipulation | `references/dsacl.md` |
| `forest` | Forest management | `references/forest.md` |
| `fsmo` | Flexible Single Master Operations (FSMO) roles management | `references/fsmo.md` |
| `gpo` | Group Policy Object (GPO) management | `references/gpo.md` |
| `group` | Group management | `references/group.md` |
| `ldapcmp` | Compare two LDAP databases | `references/ldapcmp.md` |
| `ntacl` | NT ACLs manipulation | `references/ntacl.md` |
| `ou` | Organizational Units (OU) management | `references/ou.md` |
| `processes` | List processes | `references/processes.md` |
| `rodc` | Read-Only Domain Controller (RODC) management | `references/rodc.md` |
| `schema` | Schema querying and management | `references/schema.md` |
| `service-account` | Service Account and gMSA management | `references/service-account.md` |
| `shell` | Open a SAMBA Python shell | `references/shell.md` |
| `sites` | Sites management | `references/sites.md` |
| `spn` | Service Principal Name (SPN) management | `references/spn.md` |
| `testparm` | Syntax check the configuration file | `references/testparm.md` |
| `time` | Retrieve the time on a server | `references/time.md` |
| `user` | User management | `references/user.md` |
| `visualize` | Graphical representations of Samba network state | `references/visualize.md` |

## Common Patterns

### Authentication
```bash
# Using Kerberos (recommended)
export KRB5CCNAME=/tmp/krb5cc_0
kinit Administrator
samba-tool user list

# Using username/password
samba-tool user list -U Administrator --password=Secret123

# Using credentials file
samba-tool user list -A /etc/samba/admin-creds
```

### LDB URL
Many commands accept `-H, --URL` to specify the LDB database path:
```bash
# Local database
samba-tool user list -H /var/lib/samba/private/sam.ldb

# Remote server via LDAP
samba-tool user list -H ldap://dc1.example.com

# Remote server via LDAPS
samba-tool user list -H ldaps://dc1.example.com
```

## Notes

- This skill is based on Samba 4.21.9-alt1 (ALT Linux build)
- The `samba-tool` command must be run with appropriate privileges (typically root or via sudo)
- For Kerberos authentication, always use DNS names instead of IP addresses
- Password handling: prefer `kinit` or credential files over passing passwords on the command line
- The `computer` command accepts computer names with or without trailing `$` sign
- Many commands support `--json` output for programmatic parsing
