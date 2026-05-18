# samba-tool Global Options

All `samba-tool` commands accept the following global options.

## Synopsis

```
samba-tool [global-options] <command> [subcommand] [arguments] [command-options]
```

## Global Options

### `-h, --help`
Show the help message and exit. Can be used at any level:
```bash
samba-tool --help
samba-tool user --help
samba-tool user add --help
```

### `-r, --realm=REALM`
Set the Kerberos realm for the domain. Overrides the `realm` parameter in `/etc/samba/smb.conf`.

```bash
samba-tool -r EXAMPLE.COM user list
```

### `--simple-bind-dn=DN`
DN to use for a simple LDAP bind.

```bash
samba-tool --simple-bind-dn="CN=Admin,CN=Users,DC=example,DC=com" user list
```

### `--password=PASSWORD`
Specify the password on the command line. **Security warning**: the password may be visible in the process list (`ps`). Prefer using `kinit` or credential files instead.

If `--password` is not specified, samba-tool checks:
1. `PASSWD` environment variable
2. `PASSWD_FD` (open file descriptor number)
3. `PASSWD_FILE` (file path containing the password)

```bash
samba-tool user list -U Administrator --password=Secret123
```

### `-U, --user=[DOMAIN\]USERNAME[%PASSWORD]`
Sets the SMB username or username and password. If `%PASSWORD` is not specified, the user will be prompted.

Environment variables checked:
- `USER` (may contain password separated by `%`)
- `LOGNAME` (no password allowed)

```bash
# Prompt for password
samba-tool user list -U Administrator

# Password on command line (not recommended)
samba-tool user list -U Administrator%Secret123

# Domain prefix
samba-tool user list -U EXAMPLE\Administrator
```

### `-W, --workgroup=WORKGROUP`
Set the SMB domain (workgroup) of the username. Overrides the `workgroup` parameter in `/etc/samba/smb.conf`. If the domain specified is the same as the server's NetBIOS name, it causes the client to log on using the server's local SAM.

```bash
samba-tool -W EXAMPLE user list
```

### `-N, --no-pass`
Suppress the normal password prompt. Useful for accessing services that do not require a password. If a password is specified on the command line and this option is also defined, the password will be silently ignored.

```bash
samba-tool user list -U Administrator -N
```

### `--use-kerberos=desired|required|off`
Determines whether Samba client tools will try to authenticate using Kerberos.

- `desired` — Try Kerberos, fall back to NTLM
- `required` — Only use Kerberos (fail if unavailable)
- `off` — Do not use Kerberos

For Kerberos authentication, use DNS names instead of IP addresses. Overrides the `client use kerberos` parameter in `/etc/samba/smb.conf`.

```bash
samba-tool user list --use-kerberos=required
```

### `--use-krb5-ccache=CCACHE`
Specifies the credential cache location for Kerberos authentication. This automatically sets `--use-kerberos=required`.

```bash
samba-tool user list --use-krb5-ccache=/tmp/krb5cc_0
```

### `-A, --authentication-file=filename`
Read username and password from a file. The file format is:
```
username = Administrator
password = Secret123
domain   = EXAMPLE
```
Ensure file permissions restrict access: `chmod 600 /path/to/creds`

```bash
samba-tool user list -A /etc/samba/admin-creds
```

### `--ipaddress=IPADDRESS`
IP address of the server to connect to.

```bash
samba-tool user list --ipaddress=192.168.1.10
```

### `--color=always|never|auto`
Control ANSI colour codes in output.

- `always` (synonyms: `yes`, `force`) — Always use colour
- `never` (synonyms: `no`, `none`) — Never use colour
- `auto` (synonyms: `tty`, `if-tty`) — Use colour when output is a terminal (default)

If the `NO_COLOR` environment variable is set and non-empty, colour is disabled.

```bash
samba-tool user list --color=always
```

### `-d, --debuglevel=DEBUGLEVEL`
Set the debug level (integer 0-10). Default is 1 for client applications.

| Level | Purpose |
|-------|---------|
| 0 | Critical errors and serious warnings only |
| 1 | Day-to-day running (small amount of info) |
| 2-3 | Investigation of problems |
| 4+ | Developer use only (extremely verbose) |

Overrides the `log level` parameter in `/etc/samba/smb.conf`.

```bash
samba-tool user list -d 3
```

### `--debug-stdout`
Redirect debug output to STDOUT instead of STDERR (the default).

```bash
samba-tool user list --debug-stdout -d 3
```

## Common LDB URL Option (`-H, --URL`)

Many subcommands accept the `-H` or `--URL` option to specify the LDB database or target server:

| URL Format | Description |
|------------|-------------|
| `/var/lib/samba/private/sam.ldb` | Local SAM database |
| `/var/lib/samba/private/secrets.ldb` | Local secrets database |
| `ldap://dc1.example.com` | Remote server via LDAP |
| `ldaps://dc1.example.com` | Remote server via LDAPS |
| `ldapi://%2Fvar%2Flib%2Fsamba%2Fprivate%2Fsam.ldb` | Local LDB via LDAPI |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KRB5CCNAME` | Kerberos credential cache location |
| `USER` | Default username (may include `%password`) |
| `LOGNAME` | Default username (no password) |
| `PASSWD` | Default password |
| `PASSWD_FILE` | File containing password |
| `PASSWD_FD` | File descriptor for password |
| `NO_COLOR` | Disable colour output (if set and non-empty) |
