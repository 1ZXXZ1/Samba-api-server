# samba-tool schema — Schema Querying and Management

Manage and query the Active Directory schema.

## Subcommands

### schema attribute modify
Modify the behaviour of an attribute in the schema.

```bash
samba-tool schema attribute modify <attribute> [options]
```

**Examples:**
```bash
# Modify an attribute in the schema
samba-tool schema attribute modify employeeID --range-upper=20
```

### schema attribute show
Display an attribute schema definition.

```bash
samba-tool schema attribute show <attribute> [options]
```

**Examples:**
```bash
# Show definition of the sAMAccountName attribute
samba-tool schema attribute show sAMAccountName

# Show userPrincipalName attribute
samba-tool schema attribute show userPrincipalName
```

### schema attribute show_oc
Show objectclasses that MAY or MUST contain this attribute.

```bash
samba-tool schema attribute show_oc <attribute> [options]
```

This is useful for understanding which object classes use a particular attribute.

**Examples:**
```bash
# Show which object classes use the mail attribute
samba-tool schema attribute show_oc mail

# Show which object classes require sAMAccountName
samba-tool schema attribute show_oc sAMAccountName
```

### schema objectclass show
Display an objectclass schema definition.

```bash
samba-tool schema objectclass show <objectclass> [options]
```

**Examples:**
```bash
# Show the user object class definition
samba-tool schema objectclass show user

# Show the computer object class definition
samba-tool schema objectclass show computer

# Show the group object class definition
samba-tool schema objectclass show group
```

## Common Options

All schema subcommands accept:

| Option | Description |
|--------|-------------|
| `-H, --URL=URL` | LDB URL for database or target server |
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## Schema Concepts

### What is the Schema?
The Active Directory schema defines all object classes and attributes that can exist in the directory. It is the blueprint that determines:
- What attributes an object can or must have
- What object classes can be containers for other objects
- The syntax and constraints of each attribute

### Schema Partitions
The schema is stored in the Schema naming context:
```
CN=Schema,CN=Configuration,DC=example,DC=com
```

### Schema Master FSMO Role
Schema modifications can only be made on the DC holding the Schema Master FSMO role. Check with:
```bash
samba-tool fsmo show
```

## Typical Workflows

### Query attribute information
```bash
# Find which classes use a specific attribute
samba-tool schema attribute show_oc employeeNumber

# View attribute definition
samba-tool schema attribute show employeeNumber
```

### Query object class information
```bash
# View all attributes for the user class
samba-tool schema objectclass show user

# View computer class definition
samba-tool schema objectclass show computer
```

### Modify a schema attribute
```bash
# Ensure schema master is on the current DC
samba-tool fsmo show

# Modify the attribute
samba-tool schema attribute modify employeeID --range-upper=50
```
