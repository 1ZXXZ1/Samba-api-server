# samba-tool dsacl — DS ACLs Manipulation

Administer Directory Service Access Control Lists (DS ACLs) on Active Directory objects.

## Subcommands

### dsacl delete
Delete an access list entry on a directory object.

```bash
samba-tool dsacl delete [options]
```

Removes a specific ACE (Access Control Entry) from a directory object's ACL.

**Examples:**
```bash
samba-tool dsacl delete \
  --object="OU=Servers,DC=example,DC=com" \
  --trustee="S-1-5-21-..." \
  --flags=CI \
  --mask=GR
```

### dsacl get
Print the access list on a directory object.

```bash
samba-tool dsacl get [options]
```

**Examples:**
```bash
# Get ACL on an OU
samba-tool dsacl get --object="OU=Servers,DC=example,DC=com"

# Get ACL on a specific object
samba-tool dsacl get --object="CN=Admin,CN=Users,DC=example,DC=com"
```

### dsacl set
Modify (add) an access list entry on a directory object.

```bash
samba-tool dsacl set [options]
```

**Common Options:**

| Option | Description |
|--------|-------------|
| `--object=DN` | DN of the directory object |
| `--trustee=SID` | SID of the trustee (the principal being granted/denied access) |
| `--flags=FLAGS` | ACE flags (e.g., `CI` for Container Inherit, `OI` for Object Inherit) |
| `--mask=MASK` | Access mask (e.g., `GR` for Generic Read, `GW` for Generic Write) |
| `--object-type=GUID` | GUID of the object type the ACE applies to |
| `--inherited-object-type=GUID` | GUID of the inherited object type |
| `-H, --URL=URL` | LDB URL for database or target server |

**Examples:**
```bash
# Grant a user full control on an OU
samba-tool dsacl set \
  --object="OU=Servers,DC=example,DC=com" \
  --trustee="S-1-5-21-..." \
  --flags=CI \
  --mask=GA

# Grant read permissions
sambactl dsacl set \
  --object="CN=Users,DC=example,DC=com" \
  --trustee="S-1-5-21-..." \
  --flags=CI \
  --mask=GR
```

## ACE Flags Reference

| Flag | Meaning |
|------|---------|
| `CI` | Container Inherit |
| `OI` | Object Inherit |
| `NP` | No Propagate |
| `IO` | Inherit Only |
| `ID` | Inherited |
| `SA` | Success Access |
| `FA` | Failed Access |

## Access Mask Reference

| Mask | Meaning |
|------|---------|
| `GA` | Generic All (Full Control) |
| `GR` | Generic Read |
| `GW` | Generic Write |
| `GX` | Generic Execute |
| `RC` | Read Control |
| `SD` | Standard Delete |
| `WD` | Write DACL |
| `WO` | Write Owner |
