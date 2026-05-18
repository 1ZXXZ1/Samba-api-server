# samba-tool user — User Management

Manage user accounts in the Active Directory domain. This is one of the most frequently used command groups.

## Subcommands

### user add
Add a new user to the Active Directory Domain.

```bash
samba-tool user add <username> [password] [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--surname=SURNAME` | User's surname |
| `--given-name=GIVEN_NAME` | User's given name |
| `--initials=INITIALS` | User's initials |
| `--display-name=DISPLAY_NAME` | User's display name |
| `--job-title=JOB_TITLE` | User's job title |
| `--department=DEPARTMENT` | User's department |
| `--company=COMPANY` | User's company |
| `--description=DESCRIPTION` | User's description |
| `--mail-address=MAIL_ADDRESS` | User's email address |
| `--internet-address=INTERNET_ADDRESS` | User's home page |
| `--telephone-number=TELEPHONE_NUMBER` | User's phone number |
| `--mobile-number=MOBILE_NUMBER` | User's mobile phone number |
| `--physical-delivery-office=OFFICE` | User's office location |
| `--userou=USER_OU` | DN of alternative location (with or without domainDN) to default `CN=Users`. E.g. `OU=Staff` |
| `--use-username-as-cn` | Use the username as the CN (instead of combining given-name and surname) |
| `--random-password` | Generate a random password for the user |
| `--must-change-at-next-login` | Force password change at next logon |
| `--script-path=SCRIPT_PATH` | User's logon script path |
| `--profile-path=PROFILE_PATH` | User's profile path |
| `--home-directory=HOME_DIR` | User's home directory |
| `--home-drive=HOME_DRIVE` | User's home drive letter (e.g., `H:`) |

**Examples:**
```bash
# Add a basic user with password
samba-tool user add jdoe Secret123!

# Add user with random password
samba-tool user add jdoe --random-password

# Add user with full details
samba-tool user add jdoe Secret123! \
  --given-name=John \
  --surname=Doe \
  --display-name="John Doe" \
  --mail-address=jdoe@example.com \
  --department=IT \
  --job-title="System Administrator" \
  --telephone-number="+1-555-0100"

# Add user in specific OU
samba-tool user add jdoe Secret123! --userou="OU=Staff"

# Add user with must-change-password flag
samba-tool user add jdoe Secret123! --must-change-at-next-login
```

### user create
Add a new user. This is a **synonym** for `samba-tool user add` and is available for compatibility reasons only. Use `samba-tool user add` instead.

```bash
samba-tool user create <username> [password] [options]
```

### user delete
Delete an existing user account.

```bash
samba-tool user delete <username> [options]
```

**Examples:**
```bash
samba-tool user delete jdoe
```

### user disable
Disable a user account.

```bash
samba-tool user disable <username>
```

**Examples:**
```bash
samba-tool user disable jdoe
```

### user enable
Enable a user account.

```bash
samba-tool user enable <username>
```

**Examples:**
```bash
samba-tool user enable jdoe
```

### user edit
Edit a user account AD object interactively.

```bash
samba-tool user edit <username> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--editor=EDITOR` | Specifies the editor to use instead of the system default, or `vi` if no system default is set |

**Examples:**
```bash
samba-tool user edit jdoe
samba-tool user edit jdoe --editor=nano
```

### user list
List all users in the domain.

```bash
samba-tool user list [options]
```

By default, the user's `sAMAccountNames` are listed.

**Options:**

| Option | Description |
|--------|-------------|
| `--full-dn` | List distinguished names instead of sAMAccountNames |
| `-b BASE_DN, --base-dn=BASE_DN` | Specify base DN. Only users under this DN will be listed |
| `--hide-expired` | Do not list expired user accounts |
| `--hide-disabled` | Do not list disabled user accounts |
| `--locked-only` | Only list locked user accounts |

**Examples:**
```bash
# List all users
samba-tool user list

# List with full DNs
samba-tool user list --full-dn

# List only active (non-disabled, non-expired) users
samba-tool user list --hide-disabled --hide-expired

# List only locked accounts
samba-tool user list --locked-only

# List users in a specific OU
samba-tool user list --base-dn="OU=Staff,DC=example,DC=com"
```

### user show
Display a user AD object.

```bash
samba-tool user show <username> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--attributes=USER_ATTRS` | Comma separated list of attributes to print |

**Examples:**
```bash
# Show all attributes
samba-tool user show jdoe

# Show specific attributes
samba-tool user show jdoe --attributes=sAMAccountName,mail,department,memberOf
```

### user move
Move a user account into the specified organizational unit or container.

```bash
samba-tool user move <username> <new_parent_dn> [options]
```

The `username` is the `sAMAccountName`. The `new_parent_dn` can be specified as a full DN or without the domainDN component.

**Examples:**
```bash
samba-tool user move jdoe "OU=IT Staff"
samba-tool user move jdoe "OU=Archived,DC=example,DC=com"
```

### user setprimarygroup
Set the primary group of a user account.

```bash
samba-tool user setprimarygroup <username> <primarygroupname>
```

**Examples:**
```bash
# Set primary group to Domain Admins
samba-tool user setprimarygroup jdoe "Domain Admins"

# Set primary group to a custom group
samba-tool user setprimarygroup jdoe "Server Admins"
```

### user getgroups
Get the direct group memberships of a user account.

```bash
samba-tool user getgroups <username>
```

**Examples:**
```bash
samba-tool user getgroups jdoe
```

### user password
Change password for a user account (the one provided in authentication).

```bash
samba-tool user password [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--newpassword=PASSWORD` | New password |
| `--oldpassword=PASSWORD` | Current password |
| `-U, --user=USER` | User whose password to change |

**Examples:**
```bash
# Change own password
samba-tool user password --oldpassword=OldPass123 --newpassword=NewPass456 -U jdoe
```

### user setpassword
Set or reset the password of a user account (admin operation).

```bash
samba-tool user setpassword <username> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--newpassword=PASSWORD` | New password |
| `--must-change-at-next-login` | Force password change at next logon |

**Examples:**
```bash
# Reset a user's password
samba-tool user setpassword jdoe --newpassword=NewSecret123!

# Reset and force password change
samba-tool user setpassword jdoe --newpassword=TempPass123! --must-change-at-next-login
```

### user getpassword
Get the password of a user account (retrieves from AD if stored with reversible encryption).

```bash
samba-tool user getpassword <username> [options]
```

**Examples:**
```bash
samba-tool user getpassword jdoe
```

### user setexpiry
Set the expiration date of a user account.

```bash
samba-tool user setexpiry <username> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--days=DAYS` | Number of days until expiry (from today) |
| `--no-expiry` | Set the account to never expire |

**Examples:**
```bash
# Set expiry in 90 days
samba-tool user setexpiry jdoe --days=90

# Set account to never expire
samba-tool user setexpiry jdoe --no-expiry

# Set expiry for a service account
samba-tool user setexpiry svc_backup --no-expiry
```

### user unlock
Unlock a locked user account.

```bash
samba-tool user unlock <username> [options]
```

**Examples:**
```bash
# Unlock a locked account
samba-tool user unlock jdoe
```

### user rename
Rename a user and related attributes.

```bash
samba-tool user rename <username> [options]
```

This command allows setting the user's name related attributes. The user's CN will be renamed automatically. The new CN will be made up by combining the given-name, initials and surname. A dot (`.`) will be appended to the initials automatically if required. Use `--force-new-cn` to specify the new CN manually and `--reset-cn` to reset this change.

Use an empty attribute value to remove the specified attribute.

The `username` specified on the command is the `sAMAccountName`.

**Options:**

| Option | Description |
|--------|-------------|
| `--surname=SURNAME` | New surname |
| `--given-name=GIVEN_NAME` | New given name |
| `--initials=INITIALS` | New initials |
| `--force-new-cn=NEW_CN` | Specify a new CN (RDN) instead of combining given-name/initials/surname |
| `--reset-cn` | Set the CN to the default combination of given-name, initials and surname |
| `--display-name=DISPLAY_NAME` | New display name |
| `--mail-address=MAIL_ADDRESS` | New email address |
| `--samaccountname=SAMACCOUNTNAME` | New account name (sAMAccountName/logon name) |
| `--upn=UPN` | New user principal name |

**Examples:**
```bash
# Rename by changing name parts
samba-tool user rename jdoe --given-name=Jonathan

# Change sAMAccountName
samba-tool user rename jdoe --samaccountname=jdoe2

# Force a specific CN
samba-tool user rename jdoe --force-new-cn="Jonathan Doe"

# Change UPN
samba-tool user rename jdoe --upn=jonathan.doe@example.com

# Change email
samba-tool user rename jdoe --mail-address=jonathan@example.com
```

### user get-kerberos-ticket
Get a Kerberos Ticket Granting Ticket (TGT) as the user account.

```bash
samba-tool user get-kerberos-ticket <username> [options]
```

**Examples:**
```bash
samba-tool user get-kerberos-ticket jdoe
```

### user syncpasswords
Sync the passwords of all user accounts using an optional script.

```bash
samba-tool user syncpasswords --cache-ldb-initialize [options]
```

> **Note**: This command should run on a single domain controller only (typically the PDC-emulator).

**Examples:**
```bash
# Initialize the password sync cache
samba-tool user syncpasswords --cache-ldb-initialize
```

### user auth policy
Manage authentication policy assignments for user accounts.

#### user auth policy assign
Set assigned authentication policy for a user.

```bash
samba-tool user auth policy assign <username> [options]
```

| Option | Description |
|--------|-------------|
| `--policy=POLICY` | Name of authentication policy to assign, or leave empty to remove |

#### user auth policy remove
Remove assigned authentication policy from a user.

```bash
samba-tool user auth policy remove <username>
```

#### user auth policy view
View the assigned authentication policy for a user.

```bash
samba-tool user auth policy view <username>
```

### user auth silo
Manage authentication silo assignments for user accounts.

#### user auth silo assign
Set assigned authentication silo for a user.

```bash
samba-tool user auth silo assign <username> [options]
```

| Option | Description |
|--------|-------------|
| `--silo=SILO` | Name of authentication silo to assign, or leave empty to remove |

#### user auth silo remove
Remove assigned authentication silo from a user.

```bash
samba-tool user auth silo remove <username>
```

#### user auth silo view
View the assigned authentication silo for a user.

```bash
samba-tool user auth silo view <username>
```

## Typical Workflows

### Create a new user with full details
```bash
samba-tool user add jdoe Secret123! \
  --given-name=John \
  --surname=Doe \
  --display-name="John Doe" \
  --mail-address=jdoe@example.com \
  --department=IT \
  --job-title="Sysadmin" \
  --userou="OU=Staff" \
  --must-change-at-next-login
```

### Onboard a new employee
```bash
# 1. Create user
samba-tool user add jsmith --random-password \
  --given-name=Jane \
  --surname=Smith \
  --mail-address=jsmith@example.com \
  --department=Finance

# 2. Add to groups
samba-tool group addmembers "Finance Team" jsmith
samba-tool group addmembers "Domain Users" jsmith

# 3. Set password
samba-tool user setpassword jsmith --newpassword='InitPass123!' --must-change-at-next-login

# 4. Verify
samba-tool user show jsmith --attributes=sAMAccountName,mail,department,memberOf
```

### Disable and archive a leaving employee
```bash
# 1. Disable account
samba-tool user disable jdoe

# 2. Move to archived OU
samba-tool user move jdoe "OU=Archived Users"

# 3. Set expiry (optional, for cleanup)
samba-tool user setexpiry jdoe --days=30

# 4. Remove from groups (optional)
samba-tool group removemembers "Server Admins" jdoe
```

### Unlock a locked account
```bash
# 1. Check if account is locked
samba-tool user show jdoe --attributes=lockoutTime

# 2. Unlock
samba-tool user unlock jdoe

# 3. Reset password if needed
samba-tool user setpassword jdoe --newpassword=NewPass123!
```

### Bulk user creation (scripted)
```bash
#!/bin/bash
# Create multiple users from a list
while IFS=, read -r username surname givenname dept email; do
  samba-tool user add "$username" --random-password \
    --surname="$surname" \
    --given-name="$givenname" \
    --mail-address="$email" \
    --department="$dept" \
    --userou="OU=Staff"
  echo "Created user: $username"
done < users.csv
```
