"""
LDBSearch AD Result Validator (v1.0).

Validates ldbsearch_ad tool results before they are sent to the AI.
The validator checks:
  - Whether the result matches what was requested (object_type, attributes)
  - Whether required attributes are present
  - Whether the result contains errors
  - Whether the result is empty when data was expected

Based on the AD schema from SKILL (schema-compact.yml):
  - Each object_type has MUST and KEY_ATTRS with weights (W5/W3/W1)
  - The validator uses these to approve/reject results
  - On rejection, it provides a clear error description

Usage:
  from app.services._ldb_validator import validate_ldb_result

  verdict = validate_ldb_result(
      object_type="user",
      requested_attrs="sAMAccountName,cn,department",
      result_data={"action": "list", "rows": 15, "columns": ["dn"], "preview": [...]},
  )
  # verdict = {"approved": True, "warnings": [], "errors": []}
  # OR
  # verdict = {"approved": False, "errors": ["No rows returned for object_type=user"], "warnings": [...]}
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  AD Schema Definitions (from SKILL schema-compact.yml)
#  Weight: W5=always request, W3=commonly needed, W1=rare/special
#  Type:  S=string, I=integer, B=boolean(bit), D=DN, T=time,
#         B64=binary, SID=SID
# ═══════════════════════════════════════════════════════════════════════

# Schema per object_type — attributes with weight
# Format: attribute_name : weight
SCHEMA: Dict[str, Dict[str, Any]] = {
    "user": {
        "MUST": ["cn"],
        "KEY_ATTRS": {
            "sAMAccountName": "W5",
            "objectSid": "W5",
            "objectClass": "W5",
            "distinguishedName": "W5",
        },
        "AUTH": {
            "userAccountControl": "W5",
            "pwdLastSet": "W3",
            "accountExpires": "W3",
            "lockoutTime": "W3",
            "badPwdCount": "W3",
            "badPasswordTime": "W1",
        },
        "IDENTITY": {
            "cn": "W5",
            "displayName": "W5",
            "givenName": "W3",
            "sn": "W3",
            "mail": "W3",
            "department": "W1",
            "title": "W3",
            "company": "W1",
            "manager": "W3",
            "employeeID": "W1",
        },
        "PHONE": {
            "telephoneNumber": "W3",
            "mobile": "W3",
        },
        "GROUPS": {
            "memberOf": "W5",
            "primaryGroupID": "W5",
        },
        "KERBEROS": {
            "userPrincipalName": "W3",
            "servicePrincipalName": "W3",
        },
        "LOGON": {
            "lastLogon": "W3",
            "lastLogonTimestamp": "W3",
            "logonCount": "W1",
        },
        "PROFILE": {
            "profilePath": "W3",
            "scriptPath": "W3",
            "homeDirectory": "W3",
            "homeDrive": "W3",
        },
        "SFU_UNIX": {
            "uidNumber": "W3",
            "gidNumber": "W3",
            "loginShell": "W3",
            "unixHomeDirectory": "W3",
        },
    },

    "computer": {
        "MUST": ["cn"],
        "ADDS_OVER_USER": {
            "dNSHostName": "W5",
            "operatingSystem": "W3",
            "operatingSystemVersion": "W3",
            "operatingSystemServicePack": "W1",
            "operatingSystemHotfix": "W1",
            "objectClass": "W5",
            "managedBy": "W3",
            "location": "W1",
            "networkAddress": "W1",
            "rIDSetReferences": "W1",
            "msDS-isRODC": "W3",
            "msDS-isGC": "W1",
            "msDS-SiteName": "W1",
            "msDS-GenerationId": "W1",
            "msDS-AdditionalDnsHostName": "W1",
            "msDS-HostServiceAccount": "W1",
            "physicalLocationObject": "W1",
            "volumeCount": "W1",
            "machineRole": "W1",
            "siteGUID": "W1",
            "cn": "W5",
        },
        "INHERITS_USER_AUTH": {
            "sAMAccountName": "W5",
            "userAccountControl": "W5",
            "servicePrincipalName": "W3",
            "pwdLastSet": "W3",
            "lastLogonTimestamp": "W3",
            "objectSid": "W5",
        },
    },

    "group": {
        "MUST": ["groupType"],
        "KEY_ATTRS": {
            "cn": "W5",
            "sAMAccountName": "W5",
            "member": "W5",
            "memberOf": "W3",
            "groupType": "W5",
            "objectSid": "W5",
            "primaryGroupToken": "W3",
        },
        "META": {
            "description": "W3",
            "mail": "W3",
            "managedBy": "W3",
            "adminCount": "W1",
        },
        "SFU": {
            "gidNumber": "W3",
            "memberUid": "W3",
        },
    },

    "ou": {
        "MUST": ["ou"],
        "KEY_ATTRS": {
            "ou": "W5",
            "distinguishedName": "W5",
            "description": "W3",
            "managedBy": "W3",
        },
        "GPO": {
            "gPLink": "W3",
            "gPOptions": "W3",
        },
    },

    "gpo": {
        "MUST": [],
        "KEY_ATTRS": {
            "cn": "W5",
            "displayName": "W5",
            "gPCFileSysPath": "W3",
            "versionNumber": "W3",
        },
    },

    "dns_zone": {
        "MUST": ["dc"],
        "KEY_ATTRS": {
            "dc": "W5",
            "distinguishedName": "W5",
            "dnsAllowDynamic": "W3",
        },
    },

    "trust": {
        "MUST": [],
        "KEY_ATTRS": {
            "cn": "W5",
            "trustType": "W3",
            "trustDirection": "W5",
            "trustAttributes": "W3",
            "flatName": "W5",
        },
    },

    "site": {
        "MUST": [],
        "KEY_ATTRS": {
            "cn": "W5",
            "location": "W3",
        },
    },

    "contact": {
        "MUST": [],
        "KEY_ATTRS": {
            "cn": "W5",
            "mail": "W3",
            "displayName": "W5",
        },
    },

    "service_account": {
        "MUST": [],
        "KEY_ATTRS": {
            "sAMAccountName": "W5",
            "servicePrincipalName": "W3",
            "objectSid": "W5",
            "userAccountControl": "W3",
        },
    },
}


def _get_all_attrs_for_type(object_type: str) -> Dict[str, str]:
    """Get all attributes and their weights for a given object_type.

    Returns dict: {attribute_name: weight} e.g. {"sAMAccountName": "W5", ...}
    """
    schema = SCHEMA.get(object_type, {})
    result = {}
    # Collect from all categories
    for category_name, attrs in schema.items():
        if category_name == "MUST":
            continue
        if isinstance(attrs, dict):
            result.update(attrs)
    return result


def _get_attrs_by_weight(object_type: str, min_weight: str = "W3") -> Set[str]:
    """Get attribute names that have weight >= min_weight.

    Weight hierarchy: W5 > W3 > W1
    min_weight='W3' → returns W5 + W3 attributes
    min_weight='W5' → returns only W5 attributes
    min_weight='W1' → returns all attributes
    """
    all_attrs = _get_all_attrs_for_type(object_type)
    weight_order = {"W5": 5, "W3": 3, "W1": 1}
    min_val = weight_order.get(min_weight, 3)

    return {
        attr for attr, weight in all_attrs.items()
        if weight_order.get(weight, 1) >= min_val
    }


def validate_ldb_result(
    object_type: str,
    requested_attrs: str,
    result_data: Dict[str, Any],
    action: str = "list",
) -> Dict[str, Any]:
    """Validate an ldbsearch_ad result before sending to AI.

    Checks:
    1. Result contains no errors
    2. Result has data (rows > 0 for list/search/count)
    3. Requested attributes appear in the result
    4. MUST attributes are present for the object_type

    Args:
        object_type: The AD object type (user, computer, group, etc.)
        requested_attrs: Comma-separated attribute names requested by AI
        result_data: Parsed JSON result from ldbsearch_ad
        action: The ldbsearch_ad action (list, search, show, etc.)

    Returns:
        Dict with:
        - approved: bool — True if result is valid, False if rejected
        - errors: List[str] — Error descriptions (non-empty if rejected)
        - warnings: List[str] — Warnings (informational, not blocking)
        - missing_attrs: List[str] — Attributes requested but not in result
        - present_attrs: List[str] — Attributes found in result
        - validation_note: str — Human-readable validation summary
    """
    errors: List[str] = []
    warnings: List[str] = []
    missing_attrs: List[str] = []
    present_attrs: List[str] = []

    # 1. Check for error in result
    if "error" in result_data:
        errors.append(f"ldbsearch_ad вернул ошибку: {result_data['error']}")
        return {
            "approved": False,
            "errors": errors,
            "warnings": warnings,
            "missing_attrs": missing_attrs,
            "present_attrs": present_attrs,
            "validation_note": f"ОТКЛОНЕНО: {result_data['error']}",
        }

    # 2. Check for empty results on data-returning actions
    tabular_actions = {"list", "search", "disabled", "locked"}
    if action in tabular_actions:
        rows = result_data.get("rows", 0)
        if rows == 0:
            errors.append(
                f"Нет данных для object_type={object_type}, action={action}. "
                f"Возможно, таких объектов не существует или фильтр слишком строгий."
            )
        elif rows > 0:
            # Check that preview has data
            preview = result_data.get("preview", [])
            if not preview:
                warnings.append(
                    f"Найдено {rows} записей, но preview пуст — "
                    f"возможно, данные не были распарсены корректно."
                )

    elif action == "show":
        found = result_data.get("found", False)
        if not found:
            name = result_data.get("name", "?")
            errors.append(
                f"Объект '{name}' не найден (object_type={object_type}). "
                f"Проверьте правильность имени."
            )

    elif action == "count":
        count = result_data.get("count", 0)
        if count == 0:
            warnings.append(
                f"Количество объектов object_type={object_type} равно 0."
            )

    # 3. Check requested attributes against result columns
    result_columns = set(result_data.get("columns", []))
    # Also check columns in preview rows (more reliable)
    preview = result_data.get("preview", [])
    if preview and isinstance(preview, list) and len(preview) > 0:
        if isinstance(preview[0], dict):
            result_columns = result_columns.union(set(preview[0].keys()))

    if requested_attrs:
        requested_set = {a.strip() for a in requested_attrs.split(",") if a.strip()}
        for attr in requested_set:
            # Case-insensitive comparison
            found = any(c.lower() == attr.lower() for c in result_columns)
            if found:
                present_attrs.append(attr)
            else:
                missing_attrs.append(attr)

        if missing_attrs:
            # Check if it's a critical MUST attribute
            schema = SCHEMA.get(object_type, {})
            must_attrs = set(schema.get("MUST", []))
            missing_must = [a for a in missing_attrs if a in must_attrs]
            if missing_must:
                errors.append(
                    f"Обязательные атрибуты отсутствуют в результате: {', '.join(missing_must)}. "
                    f"Это может означать проблему с запросом к AD."
                )
            else:
                warnings.append(
                    f"Запрошенные атрибуты не найдены в результате: {', '.join(missing_attrs)}. "
                    f"Возможно, эти атрибуты не заполнены в AD для данных объектов."
                )

    # 4. For computer type, verify objectClass includes "computer"
    if object_type == "computer" and preview:
        for row in preview[:3]:
            obj_class = row.get("objectClass", "")
            if isinstance(obj_class, str):
                if "computer" not in obj_class.lower():
                    warnings.append(
                        f"Найден объект без objectClass=computer: "
                        f"sAMAccountName={row.get('sAMAccountName', '?')}. "
                        f"Это может быть пользователь, а не компьютер."
                    )
                    break
            elif isinstance(obj_class, list):
                if not any("computer" in str(c).lower() for c in obj_class):
                    warnings.append(
                        f"Найден объект без objectClass=computer: "
                        f"sAMAccountName={row.get('sAMAccountName', '?')}. "
                        f"Это может быть пользователь, а не компьютер."
                    )
                    break

    # Build verdict
    approved = len(errors) == 0

    if approved and not warnings and not missing_attrs:
        note = f"ОДОБРЕНО: {result_data.get('rows', '?')} записей для {object_type}"
    elif approved:
        note = f"ОДОБРЕНО С ПРЕДУПРЕЖДЕНИЯМИ: {result_data.get('rows', '?')} записей для {object_type}"
        if missing_attrs:
            note += f" | Отсутствуют атрибуты: {', '.join(missing_attrs)}"
    else:
        note = f"ОТКЛОНЕНО: {'; '.join(errors)}"

    return {
        "approved": approved,
        "errors": errors,
        "warnings": warnings,
        "missing_attrs": missing_attrs,
        "present_attrs": present_attrs,
        "validation_note": note,
    }


def filter_result_by_schema(
    object_type: str,
    rows: List[Dict[str, Any]],
    min_weight: str = "W3",
    extra_attrs: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter ldbsearch result rows to only include schema-relevant attributes.

    This prevents AI from seeing low-value (W1) attributes and raw
    internal fields that waste tokens and provide no useful information.

    Args:
        object_type: The AD object type (user, computer, group, etc.)
        rows: List of parsed ldbsearch rows
        min_weight: Minimum weight to include (W5, W3, W1). Default W3.
        extra_attrs: Comma-separated extra attributes to always include
            (e.g. user-specified attributes)

    Returns:
        Filtered rows with only relevant attributes.
    """
    if not rows or not object_type:
        return rows

    # Get allowed attributes for this object type
    allowed_attrs = _get_attrs_by_weight(object_type, min_weight)

    # Always include dn (needed for identification)
    allowed_attrs.add("dn")

    # Add extra user-specified attributes
    if extra_attrs:
        for attr in extra_attrs.split(","):
            attr = attr.strip()
            if attr:
                allowed_attrs.add(attr)

    # Also add any computed columns (groups, group_count)
    allowed_attrs.update({"groups", "group_count"})

    # Filter each row
    filtered_rows = []
    for row in rows:
        filtered_row = {}
        for key, value in row.items():
            # Case-insensitive match against allowed attrs
            if key in allowed_attrs or any(
                key.lower() == a.lower() for a in allowed_attrs
            ):
                filtered_row[key] = value
        filtered_rows.append(filtered_row)

    return filtered_rows


def get_schema_context_for_ai(object_type: str) -> str:
    """Generate a compact schema context string for the AI system prompt.

    Returns a string describing the relevant attributes and their weights
    for a given object_type, so AI knows what to request.
    """
    schema = SCHEMA.get(object_type)
    if not schema:
        return f"Нет схемы для object_type={object_type}"

    lines = [f"### Схема {object_type} (атрибуты и веса)"]
    lines.append("W5=всегда запрашивать, W3=часто нужно, W1=редко")
    lines.append("")

    must = schema.get("MUST", [])
    if must:
        lines.append(f"MUST: {', '.join(must)}")

    for category, attrs in schema.items():
        if category == "MUST" or not isinstance(attrs, dict):
            continue
        cat_attrs = [f"{k}({v})" for k, v in attrs.items()]
        lines.append(f"{category}: {', '.join(cat_attrs)}")

    return "\n".join(lines)
