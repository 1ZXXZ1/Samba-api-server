# samba-tool dbcheck — Check Local AD Database for Errors

Check the local Active Directory database for errors and optionally fix them.

## Synopsis

```bash
samba-tool dbcheck [options]
```

## Description

The `dbcheck` command checks the local AD database (LDB) for inconsistencies, missing attributes, incorrect values, and other errors that can accumulate over time. It can optionally fix detected errors.

## Options

| Option | Description |
|--------|-------------|
| `-H, --URL=URL` | LDB URL for the database to check (default: local SAM) |
| `--scope=SCOPE` | Check only a specific sub-tree |
| `--fix` | Fix errors found during the check |
| `--yes` | Assume 'yes' for all fix prompts |
| `--quiet` | Quiet mode — only show errors |
| `--cross-ncs` | Cross naming context checks |
| `--attrs=ATTRS` | Check only specific attributes |
| `-v, --verbose` | Verbose output |

## Common Usage

### Basic check (read-only, no fixes)
```bash
samba-tool dbcheck -H /var/lib/samba/private/sam.ldb
```

### Check and fix errors interactively
```bash
samba-tool dbcheck -H /var/lib/samba/private/sam.ldb --fix
```

### Fix all errors non-interactively
```bash
samba-tool dbcheck -H /var/lib/samba/private/sam.ldb --fix --yes
```

### Check a specific subtree
```bash
samba-tool dbcheck --scope="DC=example,DC=com"
```

### Cross naming context check
```bash
samba-tool dbcheck --cross-ncs --fix
```

### Check specific attributes only
```bash
samba-tool dbcheck --attrs=objectClass,sAMAccountName
```

## Notes

- Always run `dbcheck` without `--fix` first to see what errors exist before applying fixes
- Back up the database before running with `--fix`
- The command should be run on the domain controller with the SAM database
- Use `-H` to specify the database path if not using the default
- Cross-NC checks (`--cross-ncs`) are important for multi-DC environments
