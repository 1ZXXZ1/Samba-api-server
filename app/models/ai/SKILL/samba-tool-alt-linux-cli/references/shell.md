# samba-tool shell — Open a SAMBA Python Shell

Opens an interactive Python shell for direct Samba LDB database manipulation.

## Synopsis

```bash
samba-tool shell [options]
```

## Description

The `shell` command opens an interactive Python shell with a Samba LDB connection. This allows direct manipulation of the Active Directory database using Python and the Samba Python API. This is a powerful tool for advanced administration, debugging, and scripting.

## Options

| Option | Description |
|--------|-------------|
| `-H, --URL=URL` | LDB URL for database or target server |

## Examples

### Open shell with local database
```bash
samba-tool shell -H /var/lib/samba/private/sam.ldb
```

### Open shell with remote server
```bash
samba-tool shell -H ldap://dc1.example.com -U Administrator
```

## Common Shell Operations

Once inside the shell, you can use the `samdb` object to query and modify the database:

### Query examples (Python)
```python
# Search for all users
for msg in samdb.search(expression="(objectClass=user)", attrs=["sAMAccountName", "dn"]):
    print(msg["sAMAccountName"], msg["dn"])

# Search for a specific user
result = samdb.search(expression="(sAMAccountName=jdoe)", attrs=["*"])
for msg in result:
    print(msg)

# Count objects
count = len(list(samdb.search(expression="(objectClass=user)")))
print(f"Total users: {count}")
```

### Modify examples (Python)
```python
# Modify an attribute
from samba.common import dsdb_encode_nt_time
msg = ldb.Message()
msg.dn = ldb.Dn(samdb, "CN=John Doe,CN=Users,DC=example,DC=com")
msg["description"] = ldb.MessageElement("Updated description", ldb.FLAG_MOD_REPLACE, "description")
samdb.modify(msg)
```

## Warning

> **The shell provides direct database access. Changes are immediate and there is no undo.** Always back up the database before making modifications through the shell. Incorrect modifications can corrupt the AD database.

## Notes

- The shell is useful for advanced queries that are not possible with standard `samba-tool` commands
- Requires Python knowledge
- Changes made in the shell bypass normal AD replication constraints
- Use with extreme caution in production environments
