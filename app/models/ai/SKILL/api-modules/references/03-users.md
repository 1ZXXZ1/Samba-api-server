# User Management — AI Skill Reference

> Module: `users` | Router: `app/routers/users.py` | Version: api_v1.9.6-7

## Overview

Comprehensive user account management for Samba AD. Supports full CRUD operations plus advanced features like Kerberos ticket retrieval, password management, group membership, CSV import/export, and attribute-level editing. Uses `ldbsearch` for the "full" endpoint to provide complete LDAP attribute data.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/users` | `user.list` | List users (paginated, filterable) |
| GET | `/api/v1/users/full` | `user.list` | Full user list via ldbsearch (all LDAP attributes) |
| POST | `/api/v1/users` | `user.create` | Create a new user account |
| GET | `/api/v1/users/{username}` | `user.show` | Show user details |
| DELETE | `/api/v1/users/{username}` | `user.delete` | Delete a user account |
| POST | `/api/v1/users/{username}/enable` | `user.enable` | Enable a disabled user |
| POST | `/api/v1/users/{username}/disable` | `user.disable` | Disable a user account |
| POST | `/api/v1/users/{username}/unlock` | `user.unlock` | Unlock a locked-out user |
| POST | `/api/v1/users/{username}/password` | `user.set_password` | Set user password |
| GET | `/api/v1/users/{username}/password` | `user.get_password` | Get password info (metadata, not plaintext) |
| GET | `/api/v1/users/{username}/groups` | `user.get_groups` | Get user's group memberships |
| POST | `/api/v1/users/{username}/expiry` | `user.set_expiry` | Set account expiry date |
| POST | `/api/v1/users/{username}/primary-group` | `user.set_primary_group` | Set user's primary group |
| POST | `/api/v1/users/{username}/unix-attrs` | `user.add_unix_attrs` | Add Unix attributes (uidNumber, gidNumber, etc.) |
| POST | `/api/v1/users/{username}/sensitive` | `user.set_sensitive` | Mark/unmark account as sensitive |
| POST | `/api/v1/users/{username}/move` | `user.move` | Move user to a different OU |
| POST | `/api/v1/users/{username}/rename` | `user.rename` | Rename a user account |
| GET | `/api/v1/users/{username}/kerberos` | `user.get_kerberos_ticket` | Get Kerberos ticket for user |
| GET | `/api/v1/users/search` | `user.search` | Search users by filter |
| POST | `/api/v1/users/import` | `user.import` | Import users from CSV |
| GET | `/api/v1/users/export` | `user.export` | Export users to CSV |
| PUT | `/api/v1/users/{username}` | `user.edit` | Edit user (22+ attributes) |
| POST | `/api/v1/users/batch-get` | `user.batch_get` | Batch get multiple users |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `username` | path | Most endpoints | sAMAccountName of the target user |
| `password` | string | `/password` | New password for the user |
| `must_change_pwd` | bool | `/password` | Force password change at next logon |
| `expiry_date` | string | `/expiry` | Account expiry date (ISO 8601 or "never") |
| `primary_group` | string | `/primary-group` | Target primary group name or SID |
| `ou` | string | `/move`, `/create` | Target OU distinguished name |
| `new_name` | string | `/rename` | New sAMAccountName |
| `filter` | string | `/search` | LDAP filter expression |
| `attributes` | object | `/edit` | Key-value pairs of LDAP attributes to modify |
| `csv_data` | file | `/import` | CSV file with user records |

## Usage Examples

```bash
# Create a new user
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/users \
  -d '{"username": "jdoe", "password": "P@ssw0rd1", "display_name": "John Doe", "ou": "OU=Users,DC=example,DC=com"}'

# Disable a user account
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/users/jdoe/disable

# Edit multiple attributes
curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://dc.example.com/api/v1/users/jdoe \
  -d '{"mail": "john.doe@example.com", "telephoneNumber": "+1-555-0100", "department": "Engineering"}'
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `user.list` | `page`, `page_size`, `filter` | List users |
| `user.create` | `username`, `password`, `ou`, `display_name`, ... | Create user |
| `user.show` | `username` | Show user details |
| `user.delete` | `username` | Delete user |
| `user.enable` | `username` | Enable user |
| `user.disable` | `username` | Disable user |
| `user.unlock` | `username` | Unlock user |
| `user.set_password` | `username`, `password`, `must_change_pwd` | Set password |
| `user.get_groups` | `username` | Get group memberships |
| `user.set_expiry` | `username`, `expiry_date` | Set account expiry |
| `user.set_primary_group` | `username`, `primary_group` | Set primary group |
| `user.add_unix_attrs` | `username`, `uid_number`, `gid_number`, `shell`, `homedir` | Add Unix attributes |
| `user.move` | `username`, `ou` | Move user to OU |
| `user.rename` | `username`, `new_name` | Rename user |
| `user.edit` | `username`, `attributes` | Edit user attributes |

## Notes

- The `/full` endpoint uses `ldbsearch` directly and returns all LDAP attributes — useful when standard listing misses custom schema attributes.
- `/edit` supports 22+ attributes including `mail`, `telephoneNumber`, `department`, `company`, `title`, `description`, `physicalDeliveryOfficeName`, `wWWHomePage`, `streetAddress`, `l` (city), `st` (state), `postalCode`, `co` (country), `manager`, `thumbnailPhoto`, and more.
- Password operations may be restricted by domain password policies (minimum length, complexity, history).
- `/kerberos` retrieves a Kerberos ticket — useful for delegation scenarios and service account validation.
- CSV import supports a header row mapping to user attributes; required columns: `username`, `password`.
- Batch get (`/batch-get`) accepts a list of usernames and returns details for all in one call.
