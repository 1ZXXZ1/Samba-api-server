# Contact Management — AI Skill Reference

> Module: `contacts` | Router: `app/routers/contacts.py` | Version: api_v1.9.6-7

## Overview

Manages contact objects in Active Directory. Contacts are non-security principals typically used for address book entries, mail-enabled contacts, and external person references. Supports full CRUD plus move and rename operations.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/contacts` | `contact.list` | List contacts (paginated, filterable) |
| GET | `/api/v1/contacts/full` | `contact.list` | Full contact list via ldbsearch (all LDAP attributes) |
| POST | `/api/v1/contacts` | `contact.create` | Create a new contact |
| GET | `/api/v1/contacts/{contactname}` | `contact.show` | Show contact details |
| DELETE | `/api/v1/contacts/{contactname}` | `contact.delete` | Delete a contact |
| POST | `/api/v1/contacts/{contactname}/move` | `contact.move` | Move contact to a different OU |
| POST | `/api/v1/contacts/{contactname}/rename` | `contact.rename` | Rename a contact |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `contactname` | path | Most endpoints | sAMAccountName or CN of the target contact |
| `ou` | string | `/create`, `/move` | Target OU distinguished name |
| `new_name` | string | `/rename` | New name for the contact |
| `display_name` | string | `/create` | Display name of the contact |
| `mail` | string | `/create` | Email address |

## Usage Examples

```bash
# Create a new contact
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/contacts \
  -d '{"contactname": "Jane External", "display_name": "Jane External", "mail": "jane@partner.com", "ou": "OU=Contacts,DC=example,DC=com"}'

# Rename a contact
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/contacts/Jane%20External/rename \
  -d '{"new_name": "Jane Partner"}'

# Move a contact to a different OU
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/contacts/Jane%20Partner/move \
  -d '{"ou": "OU=Partners,DC=example,DC=com"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `contact.list` | `page`, `page_size`, `filter` | List contacts |
| `contact.create` | `contactname`, `ou`, `display_name`, `mail` | Create contact |
| `contact.show` | `contactname` | Show contact details |
| `contact.delete` | `contactname` | Delete contact |
| `contact.move` | `contactname`, `ou` | Move contact to OU |
| `contact.rename` | `contactname`, `new_name` | Rename contact |

## Notes

- Contacts are not security principals — they cannot log in and have no SID-based permissions.
- Contacts are commonly mail-enabled and appear in the Global Address List (GAL).
- Unlike users, contacts do not support password, enable/disable, or group membership management through this module.
- The `/full` endpoint uses ldbsearch and returns all LDAP attributes including `targetAddress`, `proxyAddresses`, etc.
