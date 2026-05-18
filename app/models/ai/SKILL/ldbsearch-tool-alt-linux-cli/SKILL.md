---
name: ldbsearch-tool-alt-linux-cli
description: Linux CLI tool for searching LDB databases (Samba). Query records via LDAP-style expressions, control scope, base DN, and URL. Use when searching Samba AD, TDB-based LDB stores, or inspecting ldb/sam.ldb contents.
read_when:
  - Searching LDB or Samba databases
  - Querying Samba AD records
  - Inspecting sam.ldb or TDB-based LDB stores
  - LDAP-style search on local LDB files
metadata: {"clawdbot":{"emoji":"🔍","requires":{"bins":["ldbsearch"]}}}
allowed-tools: Bash(ldbsearch:*)
---

# ldbsearch — Search LDB Database Records

## Synopsis

```bash
ldbsearch [-h] [-s base|one|sub] [-b basedn] [-i] [-H LDB-URL] [expression] [attributes]
```

## Options

| Flag | Arg | Description |
|------|-----|-------------|
| `-h` | — | Show available options |
| `-H` | `<ldb-url>` | LDB URL to connect (see ldb(3)); overrides `$LDB_URL` |
| `-s` | `base\|one\|sub` | Search scope: **base**=entry only, **one**=one-level, **sub**=subtree |
| `-b` | `<basedn>` | Base DN for search |
| `-i` | — | Read search expressions from stdin |

## Environment

| Variable | Description |
|----------|-------------|
| `LDB_URL` | Default LDB URL (overridden by `-H`) |

## Expression Syntax

Uses LDAP-style filter expressions (same as `ldapsearch`):

```
(objectClass=user)                          # simple
(&(objectClass=user)(sAMAccountName=admin)) # AND
(|(objectClass=group)(objectClass=user))    # OR
(!(objectClass=computer))                   # NOT
(cn=John*)                                  # wildcard
```

### Operators

| Op | Meaning |
|----|---------|
| `=` | Equality (supports `*` wildcard) |
| `>=` | Greater or equal |
| `<=` | Less or equal |
| `~=` | Approx match |
| `=*` | Presence (attribute exists) |

### Compound Prefixes

| Prefix | Logic |
|--------|-------|
| `&` | AND (all must match) |
| `\|` | OR (any must match) |
| `!` | NOT (negate) |

## Attribute Selection

- Omit → return all attributes
- Specify one or more → return only those:

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(objectClass=user)" cn sAMAccountName
```

## Common LDB URLs

| Path | Purpose |
|------|---------|
| `/var/lib/samba/private/sam.ldb` | Samba AD database |
| `/var/lib/samba/private/secrets.ldb` | Samba secrets |
| `/var/lib/samba/private/privilege.ldb` | Privileges |
| `tdb://<path>` | Explicit TDB backend |
| `ldb://<path>` | Default LDB backend |

## Usage Examples

### List all records (subtree)

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb
```

### Base-scope: single entry

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b "" namingContexts
```

### One-level: direct children

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb -s one -b "CN=Users,DC=example,DC=com"
```

### Find user by name

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=jdoe)"
```

### Get specific attributes

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(objectClass=user)" dn cn mail
```

### AND filter: users in specific OU

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(&(objectClass=user)(ou=Sales))"
```

### OR filter: users and groups

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(|(objectClass=user)(objectClass=group))" cn
```

### NOT filter: non-computer accounts

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(!(objectClass=computer))" cn
```

### Wildcard search

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(cn=Adm*)" cn
```

### Read expression from stdin

```bash
echo "(objectClass=user)" | ldbsearch -i -H /var/lib/samba/private/sam.ldb cn
```

### Use $LDB_URL env var

```bash
export LDB_URL=/var/lib/samba/private/sam.ldb
ldbsearch "(objectClass=user)" cn
```

### Find all groups a user belongs to

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(member=CN=John,DC=example,DC=com)" cn
```

### Count objects by type

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb "(objectClass=computer)" dn | grep -c "^dn:"
```

### List all naming contexts

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b "" namingContexts
```

### Schema query

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb -s sub -b "CN=Schema,CN=Configuration,DC=example,DC=com" "(objectClass=attributeSchema)" lDAPDisplayName
```

## Tips

- Always specify `-H` for reliability; avoid depending on `$LDB_URL`
- Use `-s base` for root DSE queries
- Use `-s sub` (default) for deep searches
- Pipe output through `grep`, `awk`, `wc` for filtering/counting
- Combine with `ldbmodify`, `ldbedit`, `ldbadd` for full CRUD
- Requires root/permissions to access Samba private DB files
