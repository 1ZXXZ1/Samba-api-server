# samba-tool sites — Sites Management

Manage Active Directory sites and subnets for replication topology.

## Subcommands

### sites list
List all sites in the forest.

```bash
samba-tool sites list [options]
```

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON instead of a list |

**Examples:**
```bash
samba-tool sites list
samba-tool sites list --json
```

### sites view
View details of a specific site.

```bash
samba-tool sites view <site> [options]
```

**Examples:**
```bash
samba-tool sites view "Default-First-Site-Name"
samba-tool sites view "HQ"
```

### sites create
Create a new site.

```bash
samba-tool sites create <site> [options]
```

**Examples:**
```bash
# Create a new site
samba-tool sites create "BranchOffice1"

# Create with a description
samba-tool sites create "BranchOffice1" --description="Branch Office 1 - Moscow"
```

### sites remove
Delete an existing site.

```bash
samba-tool sites remove <site> [options]
```

**Examples:**
```bash
samba-tool sites remove "BranchOffice1"
```

### sites subnet list
List subnets for a site.

```bash
samba-tool sites subnet list <site> [options]
```

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON instead of a list |

**Examples:**
```bash
samba-tool sites subnet list "Default-First-Site-Name"
samba-tool sites subnet list "HQ" --json
```

### sites subnet view
View details of a specific subnet.

```bash
samba-tool sites subnet view <subnet> [options]
```

**Examples:**
```bash
samba-tool sites subnet view "192.168.1.0/24"
samba-tool sites subnet view "10.0.0.0/8"
```

### sites subnet create
Create a new subnet and assign it to a site.

```bash
samba-tool sites subnet create <subnet> <site-of-subnet> [options]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `subnet` | Subnet in CIDR notation (e.g., `192.168.1.0/24`) |
| `site-of-subnet` | Name of the site this subnet belongs to |

**Examples:**
```bash
# Create a subnet for HQ
samba-tool sites subnet create "192.168.1.0/24" "HQ"

# Create a subnet for a branch office
samba-tool sites subnet create "10.10.0.0/16" "BranchOffice1"
```

### sites subnet remove
Delete an existing subnet.

```bash
samba-tool sites subnet remove <subnet> [options]
```

**Examples:**
```bash
samba-tool sites subnet remove "192.168.1.0/24"
```

### sites subnet set-site
Assign a subnet to a different site.

```bash
samba-tool sites subnet set-site <subnet> <site-of-subnet> [options]
```

**Examples:**
```bash
# Move a subnet to a different site
samba-tool sites subnet set-site "192.168.1.0/24" "BranchOffice1"
```

## Common Options

All sites subcommands accept:

| Option | Description |
|--------|-------------|
| `-H, --URL=URL` | LDB URL for database or target server |
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## AD Sites Concepts

### What is a Site?
An Active Directory site represents one or more well-connected IP subnets. Sites are used to:
- Control replication traffic between DCs
- Optimize authentication (clients authenticate to DCs in their site first)
- Manage service location (SRV records are site-aware)

### Site Topology
- Sites are connected by **site links** that define replication schedule and cost
- The **KCC** (Knowledge Consistency Checker) automatically creates replication connections
- Inter-site replication is compressed and can be scheduled
- Intra-site replication uses change notification (rapid replication)

## Typical Workflows

### Set up a multi-site topology
```bash
# 1. Create sites
samba-tool sites create "HQ"
samba-tool sites create "BranchOffice1"
samba-tool sites create "BranchOffice2"

# 2. Create subnets
samba-tool sites subnet create "192.168.1.0/24" "HQ"
samba-tool sites subnet create "10.10.0.0/16" "BranchOffice1"
samba-tool sites subnet create "10.20.0.0/16" "BranchOffice2"

# 3. Verify
samba-tool sites list
samba-tool sites subnet list "HQ"

# 4. Trigger KCC to build replication topology
samba-tool drs kcc
```

### Rename/reassign subnet
```bash
# Move a subnet to a different site
samba-tool sites subnet set-site "10.10.0.0/16" "BranchOffice2"
```

### Decommission a site
```bash
# 1. Move subnets to other sites
samba-tool sites subnet set-site "10.10.0.0/16" "HQ"

# 2. Remove the site
samba-tool sites remove "BranchOffice1"
```
