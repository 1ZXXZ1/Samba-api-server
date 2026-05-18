# samba-tool ntacl — NT ACLs Manipulation

Manage NT Access Control Lists on files and directories in the Samba AD environment.

## Subcommands

### ntacl get
Get ACLs on a file or directory.

```bash
samba-tool ntacl get <file> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--use-ntvfs` | Get ACLs directly from TDB or xattr (POSIX permissions not used) |
| `--service=SERVICE` | Specify the smb.conf service name (required with `--use-s3fs`) |
| `--use-s3fs` | Get ACLs via the VFS layer for the default s3fs file server |
| `--xattr-backend=[native\|tdb]` | Specify the xattr backend type |
| `--eadb-file=EADB_FILE` | Name of the tdb file where attributes are stored |

**Examples:**
```bash
# Get ACL on a file
samba-tool ntacl get /var/lib/samba/sysvol/example.com/Policies/{GUID}

# Get ACL using ntvfs
samba-tool ntacl get /path/to/file --use-ntvfs

# Get ACL using s3fs
samba-tool ntacl get /path/to/file --use-s3fs --service=sysvol
```

### ntacl set
Set ACLs on a file or directory.

```bash
samba-tool ntacl set <acl> <file> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--use-ntvfs` | Set ACLs directly to TDB or xattr. POSIX permissions will NOT be changed |
| `--service=SERVICE` | Specify the smb.conf service name (required with `--use-s3fs`) |
| `--use-s3fs` | Set ACLs via the VFS layer for the default s3fs file server |
| `--xattr-backend=[native\|tdb]` | Specify the xattr backend type |
| `--eadb-file=EADB_FILE` | Name of the tdb file where attributes are stored |

**Examples:**
```bash
# Set ACL on a file
samba-tool ntacl set "D:P(A;;FA;;;SY)(A;;FA;;;BA)" /path/to/file

# Set ACL using s3fs
samba-tool ntacl set "D:P(A;;FA;;;SY)(A;;FA;;;BA)" /path/to/file --use-s3fs --service=sysvol
```

### ntacl changedomsid
Change the domain SID for ACLs. Useful when the machine's SID has changed, or when data has been copied to another machine via backup/restore or rsync.

```bash
samba-tool ntacl changedomsid <original-domain-SID> <new-domain-SID> <file> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--use-ntvfs` | Set ACLs directly to TDB or xattr. POSIX permissions will NOT be changed |
| `--service=SERVICE` | Specify the smb.conf service name (required with `--use-s3fs`) |
| `--use-s3fs` | Set ACLs via the VFS layer |
| `--xattr-backend=[native\|tdb]` | Specify the xattr backend type |
| `--eadb-file=EADB_FILE` | Name of the tdb file where attributes are stored |
| `--recursive` | Set ACLs for directories and their contents recursively |
| `--follow-symlinks` | Follow symlinks when `--recursive` is specified |
| `--verbose` | Verbosely list files and ACLs being processed |

**Examples:**
```bash
# Change domain SID on a directory tree
samba-tool ntacl changedomsid S-1-5-21-OLD S-1-5-21-NEW /var/lib/samba/sysvol --recursive --verbose

# Change domain SID with s3fs backend
samba-tool ntacl changedomsid S-1-5-21-OLD S-1-5-21-NEW /data/share --recursive --use-s3fs --service=share1
```

### ntacl sysvolcheck
Check sysvol ACLs match defaults (including correct ACLs on GPOs).

```bash
samba-tool ntacl sysvolcheck [options]
```

**Examples:**
```bash
samba-tool ntacl sysvolcheck
```

### ntacl sysvolreset
Reset sysvol ACLs to defaults (including correct ACLs on GPOs).

```bash
samba-tool ntacl sysvolreset [options]
```

**Examples:**
```bash
samba-tool ntacl sysvolreset
```

## SDDL (Security Descriptor Definition Language) Quick Reference

| Component | Meaning |
|-----------|---------|
| `D:` | DACL (Discretionary ACL) |
| `S:` | SACL (System ACL) |
| `P` | Protected (no inheritance) |
| `A` | Access Allowed ACE |
| `D` | Access Denied ACE |
| `FA` | File All (Full Control) |
| `FR` | File Read |
| `FW` | File Write |
| `FX` | File Execute |
| `SY` | Local System |
| `BA` | Built-in Administrators |
| `BU` | Built-in Users |
| `AU` | Authenticated Users |
| `WD` | Everyone |
| `CO` | Creator Owner |

## Typical Workflows

### Fix sysvol ACLs after migration
```bash
# 1. Check current sysvol ACLs
samba-tool ntacl sysvolcheck

# 2. Reset to defaults
samba-tool ntacl sysvolreset

# 3. Verify
samba-tool ntacl sysvolcheck
```

### Change domain SID after SID change
```bash
# 1. Get current domain SID
samba-tool domain info 127.0.0.1

# 2. Change all ACLs from old SID to new SID
samba-tool ntacl changedomsid S-1-5-21-OLD S-1-5-21-NEW /var/lib/samba/sysvol --recursive --verbose

# 3. Verify with sysvolcheck
samba-tool ntacl sysvolcheck
```
