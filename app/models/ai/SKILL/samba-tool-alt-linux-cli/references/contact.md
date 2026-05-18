# samba-tool contact — Contact Management

Manage contact objects in the Active Directory domain.

## Subcommands

### contact add
Add a new contact to the Active Directory Domain.

```bash
samba-tool contact add [contactname] [options]
```

The name of the new contact can be specified by the first argument `contactname` or the `--given-name`, `--initial` and `--surname` arguments. If no `contactname` is given, the contact's name will be made up by combining the given-name, initials and surname. Each argument is optional. A dot (`.`) will be appended to the initials automatically.

**Options:**

| Option | Description |
|--------|-------------|
| `--ou=OU` | DN of alternative location (with or without domainDN counterpart) in which the new contact will be created. E.g. `OU=Contacts`. Default is the domain base |
| `--description=DESCRIPTION` | The new contact's description |
| `--surname=SURNAME` | Contact's surname |
| `--given-name=GIVEN_NAME` | Contact's given name |
| `--initials=INITIALS` | Contact's initials |
| `--display-name=DISPLAY_NAME` | Contact's display name |
| `--job-title=JOB_TITLE` | Contact's job title |
| `--department=DEPARTMENT` | Contact's department |
| `--company=COMPANY` | Contact's company |
| `--mail-address=MAIL_ADDRESS` | Contact's email address |
| `--internet-address=INTERNET_ADDRESS` | Contact's home page |
| `--telephone-number=TELEPHONE_NUMBER` | Contact's phone number |
| `--mobile-number=MOBILE_NUMBER` | Contact's mobile phone number |
| `--physical-delivery-office=PHYSICAL_DELIVERY_OFFICE` | Contact's office location |

**Examples:**
```bash
# Add a contact with a simple name
samba-tool contact add "John Smith"

# Add a contact with detailed attributes
samba-tool contact add \
  --given-name=John \
  --surname=Smith \
  --display-name="John Smith" \
  --mail-address=john.smith@example.com \
  --telephone-number="+1-555-0100" \
  --department=IT \
  --company="Example Corp" \
  --job-title="System Administrator"

# Add a contact in specific OU
samba-tool contact add "Jane Doe" --ou="OU=External Contacts" --mail-address=jane@example.com
```

### contact create
Add a new contact. This is a **synonym** for `samba-tool contact add` and is available for compatibility reasons only. Use `samba-tool contact add` instead.

```bash
samba-tool contact create [contactname] [options]
```

Same options as `contact add`.

### contact delete
Delete an existing contact.

```bash
samba-tool contact delete <contactname> [options]
```

The `contactname` is the common name (CN) or the distinguished name (DN) of the contact object. The DN can be specified with or without the domainDN component.

**Examples:**
```bash
samba-tool contact delete "John Smith"
samba-tool contact delete "CN=John Smith,OU=Contacts,DC=example,DC=com"
```

### contact edit
Modify a contact AD object interactively using a text editor.

```bash
samba-tool contact edit <contactname> [options]
```

The `contactname` is the common name (CN) or the distinguished name (DN). The DN can be specified with or without the domainDN component.

**Options:**

| Option | Description |
|--------|-------------|
| `--editor=EDITOR` | Specifies the editor to use instead of the system default, or `vi` if no system default is set |

**Examples:**
```bash
samba-tool contact edit "John Smith"
samba-tool contact edit "John Smith" --editor=nano
```

### contact list
List all contacts.

```bash
samba-tool contact list [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--full-dn` | Display contact's full DN instead of the name |

**Examples:**
```bash
samba-tool contact list
samba-tool contact list --full-dn
```

### contact move
Move a contact into the specified organizational unit or container.

```bash
samba-tool contact move <contactname> <new_parent_dn> [options]
```

The `contactname` is the common name (CN) or the distinguished name (DN). The DN can be specified with or without the domainDN component.

**Examples:**
```bash
samba-tool contact move "John Smith" "OU=External Contacts"
samba-tool contact move "CN=John Smith,OU=Contacts" "OU=Archived,DC=example,DC=com"
```

### contact show
Display a contact AD object.

```bash
samba-tool contact show <contactname> [options]
```

The `contactname` is the common name (CN) or the distinguished name (DN). The DN can be specified with or without the domainDN component.

**Options:**

| Option | Description |
|--------|-------------|
| `--attributes=CONTACT_ATTRS` | Comma separated list of attributes to print |

**Examples:**
```bash
samba-tool contact show "John Smith"
samba-tool contact show "John Smith" --attributes=mail,telephoneNumber,department
```

### contact rename
Rename a contact and related attributes.

```bash
samba-tool contact rename <contactname> [options]
```

This command allows setting the contact's name related attributes. The contact's CN will be renamed automatically. The new CN will be made up by combining the given-name, initials and surname. A dot (`.`) will be appended to the initials automatically if required. Use `--force-new-cn` to specify the new CN manually and `--reset-cn` to reset this change.

Use an empty attribute value to remove the specified attribute.

The `contactname` specified on the command is the CN.

**Options:**

| Option | Description |
|--------|-------------|
| `--surname=SURNAME` | New surname |
| `--given-name=GIVEN_NAME` | New given name |
| `--initials=INITIALS` | New initials |
| `--force-new-cn=NEW_CN` | Specify a new CN (RDN) instead of using a combination of the given name, initials and surname |
| `--reset-cn` | Set the CN to the default combination of given name, initials and surname |
| `--display-name=DISPLAY_NAME` | New display name |
| `--mail-address=MAIL_ADDRESS` | New email address |

**Examples:**
```bash
# Rename by changing name components
samba-tool contact rename "John Smith" --given-name=Jonathan

# Force a specific new CN
samba-tool contact rename "John Smith" --force-new-cn="J. Smith (External)"

# Reset CN to default combination
samba-tool contact rename "J. Smith (External)" --reset-cn

# Change email
samba-tool contact rename "John Smith" --mail-address=jonathan.smith@example.com
```
