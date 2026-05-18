# samba-tool dns — Domain Name Service (DNS) Management

Manage DNS records and zones in the Samba Active Directory domain.

## Subcommands

### dns add
Add a DNS record.

```bash
samba-tool dns add <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SRV|TXT> <data> [options]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `server` | DNS server hostname or IP |
| `zone` | DNS zone name (e.g. `example.com`) |
| `name` | Record name (relative to zone, or `@` for zone root) |
| `A\|AAAA\|PTR\|CNAME\|NS\|MX\|SRV\|TXT` | Record type |
| `data` | Record data (IP address, hostname, text, etc.) |

**Examples:**
```bash
# A record
samba-tool dns add dc1 example.com server01 192.168.1.10

# AAAA record
samba-tool dns add dc1 example.com server01 2001:db8::10

# CNAME record
samba-tool dns add dc1 example.com www server01.example.com

# MX record (priority hostname)
samba-tool dns add dc1 example.com @ "10 mail.example.com"

# SRV record (_service._proto priority weight port target)
samba-tool dns add dc1 example.com _ldap._tcp "0 100 389 dc1.example.com"

# TXT record
samba-tool dns add dc1 example.com @ "v=spf1 mx -all"

# NS record
samba-tool dns add dc1 example.com @ dc2.example.com

# PTR record (in reverse zone)
samba-tool dns add dc1 1.168.192.in-addr.arpa 10 server01.example.com
```

### dns delete
Delete a DNS record.

```bash
samba-tool dns delete <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SRV|TXT> <data> [options]
```

**Parameters:** Same as `dns add`.

**Examples:**
```bash
# Delete A record
samba-tool dns delete dc1 example.com server01 192.168.1.10

# Delete SRV record
samba-tool dns delete dc1 example.com _ldap._tcp "0 100 389 dc1.example.com"
```

### dns query
Query DNS records.

```bash
samba-tool dns query <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SRV|TXT|ALL> [data] [options]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `server` | DNS server hostname or IP |
| `zone` | DNS zone name |
| `name` | Record name or `@` for zone root |
| `A\|AAAA\|PTR\|CNAME\|NS\|MX\|SRV\|TXT\|ALL` | Record type (`ALL` queries all types) |
| `data` | Optional data filter |

**Examples:**
```bash
# Query A records
samba-tool dns query dc1 example.com server01 A

# Query all records for a name
samba-tool dns query dc1 example.com server01 ALL

# Query all records in zone root
samba-tool dns query dc1 example.com @ ALL

# Query SRV records
samba-tool dns query dc1 example.com _ldap._tcp SRV

# Query MX records
samba-tool dns query dc1 example.com @ MX
```

### dns roothints
Query root hints.

```bash
samba-tool dns roothints <server> [name] [options]
```

**Examples:**
```bash
samba-tool dns roothints dc1
samba-tool dns roothints dc1 a.root-servers.net
```

### dns serverinfo
Query DNS server information.

```bash
samba-tool dns serverinfo <server> [options]
```

**Examples:**
```bash
samba-tool dns serverinfo dc1
```

### dns update
Update an existing DNS record (replace old data with new data).

```bash
samba-tool dns update <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SRV|TXT> <olddata> <newdata>
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `server` | DNS server hostname or IP |
| `zone` | DNS zone name |
| `name` | Record name |
| `type` | Record type |
| `olddata` | Current record data (must match exactly) |
| `newdata` | New record data |

**Examples:**
```bash
# Update A record IP address
samba-tool dns update dc1 example.com server01 A 192.168.1.10 192.168.1.20

# Update SRV record
samba-tool dns update dc1 example.com _ldap._tcp SRV "0 100 389 dc1.example.com" "0 100 389 dc2.example.com"
```

### dns zonecreate
Create a new DNS zone.

```bash
samba-tool dns zonecreate <server> <zone> [options]
```

**Examples:**
```bash
# Forward lookup zone
samba-tool dns zonecreate dc1 example.com

# Reverse lookup zone
samba-tool dns zonecreate dc1 1.168.192.in-addr.arpa
```

### dns zonedelete
Delete a DNS zone.

```bash
samba-tool dns zonedelete <server> <zone> [options]
```

**Examples:**
```bash
samba-tool dns zonedelete dc1 oldzone.example.com
```

### dns zoneinfo
Query DNS zone information.

```bash
samba-tool dns zoneinfo <server> <zone> [options]
```

**Examples:**
```bash
samba-tool dns zoneinfo dc1 example.com
```

### dns zonelist
List all DNS zones on the server.

```bash
samba-tool dns zonelist <server> [options]
```

**Examples:**
```bash
samba-tool dns zonelist dc1
```

## Common Options

All DNS subcommands accept:

| Option | Description |
|--------|-------------|
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## DNS Record Types Reference

| Type | Data Format | Example |
|------|-------------|---------|
| A | IPv4 address | `192.168.1.10` |
| AAAA | IPv6 address | `2001:db8::10` |
| CNAME | Hostname | `server01.example.com` |
| MX | `priority hostname` | `10 mail.example.com` |
| NS | Hostname | `ns1.example.com` |
| PTR | Hostname | `server01.example.com` |
| SRV | `priority weight port target` | `0 100 389 dc1.example.com` |
| TXT | Text string | `v=spf1 mx -all` |

## Typical Workflows

### Set up DNS for a new server
```bash
# 1. Add A record
samba-tool dns add dc1 example.com web01 192.168.1.50

# 2. Add CNAME alias
samba-tool dns add dc1 example.com www web01.example.com

# 3. Verify
samba-tool dns query dc1 example.com web01 ALL
```

### Create a new DNS zone
```bash
# 1. Create forward zone
samba-tool dns zonecreate dc1 subdomain.example.com

# 2. Create reverse zone
samba-tool dns zonecreate dc1 10.168.192.in-addr.arpa

# 3. Add initial records
samba-tool dns add dc1 subdomain.example.com @ NS dc1.example.com
samba-tool dns add dc1 subdomain.example.com ns1 192.168.10.1
```

### Migrate DNS record IP
```bash
# 1. Query current record
samba-tool dns query dc1 example.com server01 A

# 2. Update the record
samba-tool dns update dc1 example.com server01 A 192.168.1.10 192.168.1.20

# 3. Verify
samba-tool dns query dc1 example.com server01 A
```
