# samba-tool processes — List Processes

List running Samba processes to aid debugging on systems without `setproctitle`.

## Synopsis

```bash
samba-tool processes [options]
```

## Description

The `processes` command lists the currently running Samba processes. This is useful for debugging on systems that do not support `setproctitle`, where process titles in `ps` output may not reflect the actual Samba process state.

## Options

| Option | Description |
|--------|-------------|
| `-H, --URL=URL` | LDB URL for database or target server |
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## Examples

```bash
# List Samba processes
samba-tool processes

# List with authentication
samba-tool processes -H ldap://dc1.example.com -U Administrator
```

## Notes

- This command is primarily a debugging aid
- On systems with `setproctitle` support, process information is usually visible via standard tools like `ps`
- Useful for identifying stuck or orphaned Samba processes
