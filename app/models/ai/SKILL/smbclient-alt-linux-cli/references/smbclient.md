# smbclient Reference — Token-Optimized (Samba 4.21.9-alt1)

## CONNECTION OPTIONS

| Short | Long | Value | Description |
|-------|------|-------|-------------|
| | servicename | //server/service | NetBIOS server name + service name |
| | password | string | Access password; implies -N |
| -M | --message | HOST | Send WinPopup message (^D to end, max 1600B) |
| -I | --ip-address | IP | Force server IP (a.b.c.d), skip NetBIOS resolve |
| -E | --stderr | | Log to stderr instead of stdout |
| -L | --list | HOST | List services on server |
| -T | --tar | opts | Tar backup/restore (see TAR section) |
| -D | --directory | DIR | Start in DIR on server |
| -b | --send-buffer | BYTES | Transfer buffer (0=default=optimal, max 16776960) |
| -t | --timeout | SEC | Per-request timeout (default 20) |
| -p | --port | PORT | TCP port (default 139) |
| -g | --grepable | | Parseable -L output for grep/cut |
| -q | --quiet | | Quiet mode |
| -B | --browse | | Browse SMB servers via DNS |
| -c | --command | STRING | Semicolon-separated cmds, implies -N |
| -? | --help | | Print options summary |
| | --usage | | Brief usage |

## AUTHENTICATION & IDENTITY OPTIONS

| Short | Long | Value | Description |
|-------|------|-------|-------------|
| -U | --user | [DOMAIN\]USER[%PASS] | Username/password; env: USER, LOGNAME |
| -N | --no-pass | | Suppress password prompt |
| | --password | STRING | Password on cmdline (env fallback: PASSWD, PASSWD_FD, PASSWD_FILE) |
| | --pw-nt-hash | | Password is NT hash |
| -A | --authentication-file | FILE | File: username/password/domain lines |
| -P | --machine-pass | | Use machine account password |
| | --simple-bind-dn | DN | DN for simple LDAP bind |
| | --use-kerberos | desired\|required\|off | Kerberos auth (use DNS names, not IP) |
| | --use-krb5-ccache | CCACHE | Kerberos cred cache path (implies --use-kerberos=required) |
| | --use-winbind-ccache | | Use winbind credential cache |

## NETBIOS / COMPUTERNAME OPTIONS

| Short | Long | Value | Description |
|-------|------|-------|-------------|
| -n | --netbiosname | NAME | Override local NetBIOS name (default from smb.conf) |
| | --netbios-scope | SCOPE | NetBIOS scope (rare; see RFC1001/1002) |
| -W | --workgroup | WG | Set SMB domain/workgroup (override smb.conf) |
| -r | --realm | REALM | Kerberos realm (override smb.conf) |
| -R | --name-resolve | ORDER | Name resolution order: lmhosts, host, wins, bcast |
| -m | --max-protocol | LEVEL | Max protocol: SMB3(default), SMB2, NT1 |

**Name resolve methods:**
- `lmhosts` — Samba lmhosts file lookup
- `host` — /etc/hosts, NIS, DNS (only for 0x20 name type)
- `wins` — WINS server query
- `bcast` — Broadcast on local interfaces (least reliable)

**Default order:** lmhosts → host → wins → bcast

## NETWORK & PROTOCOL OPTIONS

| Short | Long | Value | Description |
|-------|------|-------|-------------|
| -O | --socket-options | OPTS | TCP socket options (see smb.conf) |
| | --client-protection | sign\|encrypt\|off | Connection protection level |
| | --option | name=value | Set smb.conf option inline |
| -V | --version | | Print version |

## DEBUG & LOG OPTIONS

| Short | Long | Value | Description |
|-------|------|-------|-------------|
| -d | --debuglevel | 0-10 | Debug level (default 1; >3 = huge output) |
| | --debug-stdout | | Debug to STDOUT instead of STDERR |
| -s | --configfile | FILE | Config file path (default compiled-in) |
| -l | --log-basename | DIR | Log file base directory |
| | --leak-report | | talloc leak report on exit |
| | --leak-report-full | | Full talloc leak report on exit |

## INTERACTIVE COMMANDS (prompt: `smb:\>`)

### Navigation & Info

| Cmd | Args | Description |
|-----|------|-------------|
| cd | [DIR] | Change/show remote directory |
| lcd | [DIR] | Change/show local directory |
| ls/dir | [mask] | List files matching mask |
| du | [file] | Disk usage and free space |
| pwd | | Show current remote dir (shown in prompt) |
| volume | | Print share volume name |
| listconnect | | Show DFS connections |
| showconnect | | Show active connection |

### File Transfer

| Cmd | Args | Description |
|-----|------|-------------|
| get | remotefile [localfile] | Download file (binary) |
| mget | mask | Download multiple files |
| put | localfile [remotefile] | Upload file (binary) |
| mput | mask | Upload multiple files |
| more | file | View remote file via $PAGER |
| recurse | | Toggle recursion for mget/mput |
| mask | mask | File filter for recursive mget/mput (default "*") |
| prompt | | Toggle confirm prompt for mget/mput |
| lowercase | | Toggle lowercase local filenames for get/mget |

### File Management

| Cmd | Args | Description |
|-----|------|-------------|
| mkdir/md | dir | Create remote directory |
| rmdir/rd | dir | Remove remote directory |
| rm | mask | Delete files matching mask |
| del | mask | Delete files matching mask |
| deltree | mask | Recursive delete files+dirs |
| rename | old new [-f] | Rename file (-f = overwrite dest) |
| chmod | file octal_mode | Change UNIX perms (requires CIFS UNIX ext) |
| chown | file uid gid | Change UNIX owner (requires CIFS UNIX ext) |
| setmode | file perm=[+\-]rsha | DOS attrib (r=readonly, s=system, h=hidden, a=archive) |
| archive | 0\|1\|2\|3 | Archive bit mode (0=ignore, 1=only set, 2=set+reset, 3=all+reset) |
| utimes | file create access write change | Set timestamps (YYYY:MM:DD-HH:MM:SS or -1) |

### File Inspection

| Cmd | Args | Description |
|-----|------|-------------|
| allinfo | file | All known file info (including streams) |
| altname | file | 8.3 short name |
| stat | file | UNIX stat info (requires CIFS UNIX ext) |
| getfacl | file | POSIX ACL (requires CIFS UNIX ext) |
| iosize | bytes | Set transfer buffer (0=server-controlled, max 16776960) |

### Links

| Cmd | Args | Description |
|-----|------|-------------|
| hardlink | src dest | Windows CIFS hardlink |
| link | target linkname | POSIX hardlink (requires CIFS UNIX ext) |
| symlink | target linkname | Symbolic link (requires CIFS UNIX ext; must stay within share) |
| readlink | symlinkname | Read symlink target (requires CIFS UNIX ext) |
| scopy | src dest | Server-side copy (falls back to read+write) |

### Printing

| Cmd | Args | Description |
|-----|------|-------------|
| print | file | Print local file via server |
| queue | | Show print queue |
| cancel | jobid [jobid...] | Cancel print jobs |

### POSIX Extensions (require CIFS UNIX ext)

| Cmd | Args | Description |
|-----|------|-------------|
| posix | | Query UNIX ext support + enable POSIX mode |
| posix_open | file octal_mode | Open file, returns fileid |
| posix_mkdir | dir octal_mode | Create directory with mode |
| posix_rmdir | dir | Remove directory |
| posix_unlink | file | Remove file |
| posix_encrypt | domain user pass | Negotiate SMB encryption |
| posix_whoami | | Show guest/user/group/SID info |
| case_sensitive | | Toggle case-sensitive filenames (default OFF) |

### Session & Connection (testing/internal)

| Cmd | Args | Description |
|-----|------|-------------|
| logon | user pass | New session, prints vuid |
| logoff | | End session |
| vuid | [number] | Change/show virtual user id |
| tcon | sharename | New tree connect, prints tid |
| tdis | | Tree disconnect |
| tid | [number] | Change/show tree id |
| close | fileid | Close opened file |
| lock | filenum r\|w hex-start hex-len | POSIX fcntl lock |
| unlock | filenum hex-start hex-len | POSIX fcntl unlock |
| echo | num data | SMBecho ping |

### General

| Cmd | Args | Description |
|-----|------|-------------|
| ?/help | [cmd] | Help on command |
| ! | [shellcmd] | Run local shell command |
| history | | Command history |
| exit/quit | | Disconnect and exit |
| backup | | Toggle "backup intent" flag (bypass FS checks with SE_BACKUP) |
| notify | dir | Watch dir for changes (runs forever) |

### TAR OPERATIONS

**CLI flag:** `-T|--tar <flags>`

**Interactive cmd:** `tar <c|x>[IXbgNa]`

| Flag | Name | Description |
|------|------|-------------|
| c | Create | Create tar archive (mutually exclusive with x) |
| n | Dry run | Preview creation without writing |
| x | Extract | Restore tar to share (mutually exclusive with c) |
| I | Include | Include files/dirs (default when names given) |
| X | Exclude | Exclude files/dirs |
| F | File list | Read file list from a file |
| b | Blocksize | Set blocksize in TBLOCK (512B) units |
| g | Incremental | Only files with archive bit set |
| v | Verbose | Print files processed |
| r | Wildcard | Wildcard matching (deprecated) |
| N | Newer | Only files newer than reference file |
| a | Archive reset | Reset archive bit after backup |

**blocksize N** — tar blocksize (default 20, in 512B units)

**tarmode** modes (can combine):
- `full`/`inc` — full backup vs incremental (archive bit)
- `reset`/`noreset` — reset archive bit after backup
- `system`/`nosystem` — include/exclude system files (default: on)
- `hidden`/`nohidden` — include/exclude hidden files (default: on)
- `verbose`/`noverbose` — tar verbosity

**Examples:**
```bash
smbclient //mypc/myshare "" -N -Tx backup.tar              # restore all
smbclient //mypc/myshare "" -N -TXx backup.tar users/docs  # restore excl. users/docs
smbclient //mypc/myshare "" -N -Tc backup.tar users/docs   # backup dir
smbclient //mypc/myshare "" -N -TcF backup.tar tarlist     # backup from file list
smbclient //mypc/myshare "" -N -Tc backup.tar *            # backup entire share
```

## AUTHENTICATION FILE FORMAT (-A)

```ini
username = value
password = value
domain   = value
```

## ENVIRONMENT VARIABLES

| Variable | Description |
|----------|-------------|
| USER | Username (may include %password) |
| LOGNAME | Username (no password allowed) |
| PASSWD | Password fallback |
| PASSWD_FD | File descriptor containing password |
| PASSWD_FILE | File path containing password |
| PAGER | Pager for `more` command |

## NOTES

- Server name = NetBIOS name, not necessarily DNS hostname
- Some servers require uppercase usernames/passwords/share names
- OS/2 LanManager may require -n with valid NetBIOS name
- All transfers are binary
- Long file names supported with LANMAN2+ protocol
- Security: avoid passwords in scripts; prefer -A file or kinit

## COMMON PATTERNS

```bash
# List shares anonymously
smbclient -L //server -N

# List shares with grepable output
smbclient -L //server -U user%pass -g

# Connect with specific IP (NetBIOS != DNS)
smbclient //SERVER/share -I 192.168.1.10 -U user%pass

# Connect with specific protocol
smbclient //SERVER/share -m SMB2 -U user%pass

# Kerberos auth
smbclient //server.example.com/share --use-kerberos=required

# Encrypted connection
smbclient //SERVER/share --client-protection=encrypt -U user%pass

# Set custom NetBIOS name (computername)
smbclient //SERVER/share -n MYCLIENT -U user%pass

# Custom name resolution
smbclient //SERVER/share -R "wins host bcast" -U user%pass

# Non-recursive download all .txt files
smbclient //SERVER/share -U user%pass -c "mget *.txt"

# Recursive download with mask
smbclient //SERVER/share -U user%pass -c "recurse; mask *.c; mget source*"

# Upload file
smbclient //SERVER/share -U user%pass -c "put localfile remotefile"

# Create directory and upload
smbclient //SERVER/share -U user%pass -c "mkdir newdir; cd newdir; put file.txt"

# Backup share to tar
smbclient //SERVER/share -U user%pass -Tc backup.tar *

# Restore tar to share
smbclient //SERVER/share -U user%pass -Tx backup.tar

# Set DOS attributes
smbclient //SERVER/share -U user%pass -c "setmode myfile +r"

# WinPopup message
smbclient -M FRED < message.txt

# Using authentication file
smbclient //SERVER/share -A /path/to/authfile
```
