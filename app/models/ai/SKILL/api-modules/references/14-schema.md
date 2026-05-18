# Schema — AI Skill Reference

> Module: `schema` | Router: `app/routers/schema.py` | Version: api_v1.9.6-7

## Overview

Provides read access to the Active Directory schema for attribute and class definitions. The samba-tool CLI only supports `show` and `modify` for schema objects — there is no list or add command. To enumerate schema objects, use LDAP queries against `CN=Schema,CN=Configuration,{domain_dn}`.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/schema/attribute/{name}` | `schema.show` | Show schema attribute definition |
| GET | `/api/v1/schema/class/{name}` | `schema.show` | Show schema class definition |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `name` | path | `/attribute`, `/class` | LDAP display name of the attribute or class |

## Usage Examples

```bash
# Show a schema attribute
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/schema/attribute/userPrincipalName

# Show a schema class
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/schema/class/user
```

## Batch Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `schema.attribute_show` | `name` | Show schema attribute |
| `schema.class_show` | `name` | Show schema class |

## Notes

- **No list command:** Samba-tool does not provide a schema list command. To enumerate all attributes or classes, perform an LDAP search against `CN=Schema,CN=Configuration,{base_dn}` with an appropriate filter (e.g., `(objectClass=attributeSchema)` or `(objectClass=classSchema)`).
- **No add command:** Creating new schema objects requires direct LDAP writes to the schema partition. This is an advanced operation that requires Schema Admin privileges and should be done with extreme caution.
- **Schema modifications are forest-wide and irreversible** — schema extensions cannot be removed once added.
- The `name` parameter uses the `lDAPDisplayName` of the schema object, not the CN.
- Schema queries require the requesting user to have sufficient permissions to read the schema partition.
