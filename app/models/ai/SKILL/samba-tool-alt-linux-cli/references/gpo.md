# samba-tool gpo — Group Policy Object (GPO) Management

Manage Group Policy Objects in the Samba Active Directory domain.

## Subcommands

### GPO Core Operations

#### gpo create
Create an empty GPO.

```bash
samba-tool gpo create <displayname> [options]
```

**Examples:**
```bash
samba-tool gpo create "Server Security Policy"
samba-tool gpo create "Workstation Settings" -H ldap://dc1.example.com
```

#### gpo del
Delete a GPO.

```bash
samba-tool gpo del <gpo> [options]
```

**Examples:**
```bash
samba-tool gpo del {31B2F340-016D-11D2-945F-00C04FB984F9}
```

#### gpo show
Show information for a GPO.

```bash
samba-tool gpo show <gpo> [options]
```

**Examples:**
```bash
samba-tool gpo show {31B2F340-016D-11D2-945F-00C04FB984F9}
```

#### gpo listall
List all GPOs.

```bash
samba-tool gpo listall [options]
```

**Examples:**
```bash
samba-tool gpo listall
```

#### gpo list
List GPOs applied to an account.

```bash
samba-tool gpo list <username> [options]
```

**Examples:**
```bash
samba-tool gpo list jdoe
samba-tool gpo list SERVER01$
```

#### gpo fetch
Download a GPO from the sysvol share.

```bash
samba-tool gpo fetch <gpo> [options]
```

**Examples:**
```bash
samba-tool gpo fetch {31B2F340-016D-11D2-945F-00C04FB984F9}
```

### GPO Link Operations

#### gpo setlink
Add or update a GPO link to a container (site, domain, or OU).

```bash
samba-tool gpo setlink <container_dn> <gpo> [options]
```

**Examples:**
```bash
# Link GPO to an OU
samba-tool gpo setlink "OU=Servers,DC=example,DC=com" {31B2F340-016D-11D2-945F-00C04FB984F9}

# Link GPO to domain
samba-tool gpo setlink "DC=example,DC=com" {31B2F340-016D-11D2-945F-00C04FB984F9}
```

#### gpo dellink
Delete a GPO link from a container.

```bash
samba-tool gpo dellink <container_dn> <gpo> [options]
```

**Examples:**
```bash
samba-tool gpo dellink "OU=Servers,DC=example,DC=com" {31B2F340-016D-11D2-945F-00C04FB984F9}
```

#### gpo getlink
List GPO Links for a container.

```bash
samba-tool gpo getlink <container_dn> [options]
```

**Examples:**
```bash
samba-tool gpo getlink "OU=Servers,DC=example,DC=com"
samba-tool gpo getlink "DC=example,DC=com"
```

#### gpo listcontainers
List all linked containers for a GPO.

```bash
samba-tool gpo listcontainers <gpo> [options]
```

**Examples:**
```bash
samba-tool gpo listcontainers {31B2F340-016D-11D2-945F-00C04FB984F9}
```

### GPO Inheritance Operations

#### gpo getinheritance
Get the inheritance flag for a container.

```bash
samba-tool gpo getinheritance <container_dn> [options]
```

**Examples:**
```bash
samba-tool gpo getinheritance "OU=Servers,DC=example,DC=com"
```

#### gpo setinheritance
Set the inheritance flag on a container.

```bash
samba-tool gpo setinheritance <container_dn> <block|inherit> [options]
```

**Examples:**
```bash
# Block inheritance (GPOs from parent containers are not applied)
samba-tool gpo setinheritance "OU=Servers,DC=example,DC=com" block

# Enable inheritance (default — GPOs from parent containers are applied)
samba-tool gpo setinheritance "OU=Servers,DC=example,DC=com" inherit
```

### GPO Manage — VGP/Samba Policies

These subcommands manage VGP (Vintela Group Policy) and Samba-specific policies stored in the sysvol.

#### gpo manage symlink
Manage VGP Symbolic Link Group Policy.

```bash
# List symbolic link policies
samba-tool gpo manage symlink list [options]

# Add symbolic link policy
samba-tool gpo manage symlink add [options]

# Remove symbolic link policy
samba-tool gpo manage symlink remove [options]
```

#### gpo manage files
Manage VGP Files Group Policy.

```bash
# List file policies
samba-tool gpo manage files list [options]

# Add file policy
samba-tool gpo manage files add [options]

# Remove file policy
samba-tool gpo manage files remove [options]
```

#### gpo manage openssh
Manage VGP OpenSSH Group Policy.

```bash
# List OpenSSH policies
samba-tool gpo manage openssh list [options]

# Set OpenSSH policy
samba-tool gpo manage openssh set [options]
```

#### gpo manage sudoers
Manage Samba Sudoers Group Policy.

```bash
# Add sudoers policy
samba-tool gpo manage sudoers add [options]

# List sudoers policies
samba-tool gpo manage sudoers list [options]

# Remove sudoers policy
samba-tool gpo manage sudoers remove [options]
```

#### gpo manage scripts startup
Manage VGP Startup Script Group Policy.

```bash
# List startup script policies
samba-tool gpo manage scripts startup list [options]

# Add startup script policy
samba-tool gpo manage scripts startup add [options]

# Remove startup script policy
samba-tool gpo manage scripts startup remove [options]
```

#### gpo manage motd
Manage VGP MOTD (Message of the Day) Group Policy.

```bash
# List MOTD policies
samba-tool gpo manage motd list [options]

# Set MOTD policy
samba-tool gpo manage motd set [options]
```

#### gpo manage issue
Manage VGP Issue (pre-login banner) Group Policy.

```bash
# List issue policies
samba-tool gpo manage issue list [options]

# Set issue policy
samba-tool gpo manage issue set [options]
```

#### gpo manage access
Manage VGP Host Access Group Policy.

```bash
# Add host access policy
samba-tool gpo manage access add [options]

# List host access policies
samba-tool gpo manage access list [options]

# Remove host access policy
samba-tool gpo manage access remove [options]
```

## Typical Workflows

### Create and link a new GPO
```bash
# 1. Create the GPO
samba-tool gpo create "Linux Server Security"

# 2. Note the GPO GUID from the output

# 3. Link the GPO to an OU
samba-tool gpo setlink "OU=Servers,DC=example,DC=com" {GUID}

# 4. Verify the link
samba-tool gpo getlink "OU=Servers,DC=example,DC=com"
```

### Deploy sudoers policy via GPO
```bash
# 1. Create GPO
samba-tool gpo create "Linux Sudoers Policy"

# 2. Add sudoers entry
samba-tool gpo manage sudoers add --gpo={GUID} --username=jdoe --runas=root --command=ALL

# 3. Link to OU
samba-tool gpo setlink "OU=LinuxServers,DC=example,DC=com" {GUID}

# 4. Verify
samba-tool gpo manage sudoers list --gpo={GUID}
```

### Block GPO inheritance on an OU
```bash
# Block inheritance
samba-tool gpo setinheritance "OU=Secure,DC=example,DC=com" block

# Verify
samba-tool gpo getinheritance "OU=Secure,DC=example,DC=com"
```
