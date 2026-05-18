# samba-tool forest — Forest Management

Manage the Active Directory forest configuration.

## Subcommands

### forest directory_service
Manage directory service behaviour for the forest.

#### forest directory_service dsheuristics
Modify dsheuristics directory service configuration for the forest.

```bash
samba-tool forest directory_service dsheuristics <VALUE> [options]
```

The dsHeuristics attribute is a Unicode string where each character position controls a specific directory service behaviour. This is a critical forest-level setting that affects the entire forest.

**Examples:**
```bash
# Set dsHeuristics to allow anonymous access to certain attributes
samba-tool forest directory_service dsheuristics 0000002

# View current setting first
samba-tool forest directory_service show
```

#### forest directory_service show
Show current directory service configuration for the forest.

```bash
samba-tool forest directory_service show [options]
```

**Examples:**
```bash
samba-tool forest directory_service show
samba-tool forest directory_service show -H ldap://dc1.example.com
```

## dsHeuristics Reference

The dsHeuristics attribute is a string of characters where each position (1-based) controls a specific behaviour:

| Position | Value | Description |
|----------|-------|-------------|
| 1 | `0` or `2` | `0` = second hidden attribute not visible; `2` = second hidden attribute visible (list of attributes) |
| 2 | `0` or `1` | `0` = no additional groups in authorization; `1` = include additional groups |
| 3 | `0` or `2` | Anonymous access to AD (0=disabled, 2=enabled) |
| 6 | `0` or `1` | `0` = Exclude or include adminSDHolder |
| 7 | `0` or `1` | `0` = Do not list; `1` = List |
| 9 | `0` or `1` | `1` = Disable adminSDHolder modifications |
| 10 | `0` or `1` | `1` = Include the constructed attributes in the query |
| 15 | `0` or `1` | `1` = Enable SpecifiedCredentialsSupported behavior |

**Common dsHeuristics values:**
- `0000002` — Allow anonymous LDAP access (position 3 = 2)
- `0000000001000000` — Disable adminSDHolder (position 9 = 1)

> **Warning**: Modifying dsHeuristics can have forest-wide security implications. Always verify the current value before making changes.
