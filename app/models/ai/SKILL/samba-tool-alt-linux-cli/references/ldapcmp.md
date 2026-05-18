# samba-tool ldapcmp — Compare Two LDAP Databases

Compare two LDAP databases to find differences between domain controllers.

## Synopsis

```bash
samba-tool ldapcmp <URL1> <URL2> <domain|configuration|schema|dnsdomain|dnsforest> [options]
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `URL1` | LDB URL for the first database/server |
| `URL2` | LDB URL for the second database/server |
| `domain` | Compare the domain partition |
| `configuration` | Compare the configuration partition |
| `schema` | Compare the schema partition |
| `dnsdomain` | Compare the domain DNS partition |
| `dnsforest` | Compare the forest DNS partition |

## Options

| Option | Description |
|--------|-------------|
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |
| `-s, --sort` | Sort the output |
| `-v, --verbose` | Verbose output |
| `--view` | View differences in detail |

## Examples

### Compare two DCs' domain partitions
```bash
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com domain
```

### Compare configuration partitions
```bash
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com configuration
```

### Compare schema partitions
```bash
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com schema
```

### Compare DNS partitions
```bash
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com dnsdomain
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com dnsforest
```

### Compare local databases
```bash
samba-tool ldapcmp \
  /var/lib/samba/private/sam.ldb \
  /var/lib/samba/private/sam.ldb.bak \
  domain
```

### Verbose comparison
```bash
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com domain --view --verbose
```

## Typical Workflows

### Check replication consistency between DCs
```bash
# Compare all partitions between two DCs
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com domain
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com configuration
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com schema
samba-tool ldapcmp ldap://dc1.example.com ldap://dc2.example.com dnsdomain
```

### Verify backup restore
```bash
# After restoring from backup, compare with a healthy DC
samba-tool ldapcmp /var/lib/samba/private/sam.ldb ldap://dc2.example.com domain --view
```
