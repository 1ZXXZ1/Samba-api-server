"""
Data Masker — Privacy-first PII protection for AI agent (v2.0).

Ensures that real PII (names, logins, emails, etc.) never leaves the
server for the cloud AI (Polza.ai). Instead, the AI receives
unique placeholder tokens, and a backend Dispatcher replaces them
back before returning the answer to the user.

v2.0 Changes (from v1.0):
    - SIMPLIFIED TOKEN FORMAT: ``[P1]``, ``[P2]``, etc. instead of
      ``[MASK_fieldName_N]``. The old format caused AI models to
      corrupt tokens (e.g. ``[MASK_displayName_2]`` →
      ``[MASK_displayName_isplayName_2]``). Numeric-only tokens are
      impossible to corrupt and save ~70% token length.
    - REMOVED range notation — unnecessary with short tokens.
    - JSON field names (cn, displayName, etc.) in tool results already
      provide context about what each token represents, so the field
      name in the token itself is redundant.
    - Much shorter AI context block → saves system prompt tokens.

Key design decisions:
    - Per-request lifecycle: a DataMasker instance is created for each
      user request and lives only for the duration of that request.
      This prevents token leakage between sessions.
    - Unique sequential tokens: ``[P<N>]`` where N is a globally
      incrementing counter within the request.
    - Same field+value → same token (deduplication). Different fields
      with the same value → different tokens (so AI can distinguish).
    - Configurable sensitive fields: only fields listed in
      ``AI_MASK_FIELDS`` (or the default PII_FIELDS) are masked.
      Other fields pass through unchanged.
    - Bidirectional: ``mask_value()`` / ``mask_dict()`` for outbound,
      ``unmask_text()`` for inbound (AI response → user).

Security:
    - The mask_map (token → real value) is NEVER sent to the AI.
    - The mask_map is NEVER persisted to disk or database.
    - The mask_map is garbage-collected when the DataMasker instance
      goes out of scope at the end of the request.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Default PII-sensitive field names
# ═══════════════════════════════════════════════════════════════════════

# Fields that contain Personally Identifiable Information and must
# be masked before sending to the external AI.
DEFAULT_PII_FIELDS: Set[str] = {
    # User identity
    "sAMAccountName",
    "displayName",
    "cn",
    "givenName",
    "sn",
    "initials",
    "name",
    "mail",
    "userPrincipalName",
    "distinguishedName",
    "dn",

    # Contact info
    "telephoneNumber",
    "mobile",
    "homePhone",
    "facsimileTelephoneNumber",
    "pager",
    "info",
    "streetAddress",
    "l",             # city
    "st",            # state
    "postalCode",
    "co",            # country
    "c",             # country code
    "homeDirectory",
    "homeDrive",

    # Organizational
    "manager",
    "secretary",
    "directReports",
    "company",
    "department",
    "title",
    "description",

    # Credentials
    "unicodePwd",
    "userPassword",
    "pwdLastSet",

    # Group membership
    "memberOf",

    # Computer identity
    "dNSHostName",
    "operatingSystem",
    "rIDSetReferences",

    # Service accounts
    "servicePrincipalName",
}


class DataMasker:
    """Privacy-first PII masker for AI agent requests (v2.0).

    Uses simple numeric tokens [P1], [P2], etc. that AI models
    cannot corrupt (unlike the old [MASK_fieldName_N] format).

    Usage::

        masker = DataMasker()

        # Mask outbound data before sending to AI
        masked = masker.mask_dict(raw_ldap_data)
        # → {"sAMAccountName": "[P1]",
        #    "displayName": "[P2]",
        #    "mail": "[P3]"}

        # AI processes the masked data and returns a text response
        ai_response = "User [P1] has name [P2]"

        # Unmask inbound AI response before sending to user
        final = masker.unmask_text(ai_response)
        # → "User asmirnov has name Смирнов"
    """

    def __init__(
        self,
        sensitive_fields: Optional[Set[str]] = None,
    ):
        """Initialize the DataMasker.

        Args:
            sensitive_fields: Set of field names to mask.
                If None, uses DEFAULT_PII_FIELDS.
        """
        self._mask_map: Dict[str, str] = {}       # token → real_value
        self._reverse_map: Dict[str, str] = {}     # "field::value" → token (dedup)
        self._counter: int = 0
        self._sensitive_fields = sensitive_fields or DEFAULT_PII_FIELDS

    @property
    def mask_map(self) -> Dict[str, str]:
        """Read-only access to the mask map (for debugging/logging)."""
        return dict(self._mask_map)

    @property
    def token_count(self) -> int:
        """Number of unique tokens created so far."""
        return self._counter

    # ──────────────────────────────────────────────────────────────
    #  Core masking methods
    # ──────────────────────────────────────────────────────────────

    def mask_value(self, field_name: str, value: Any) -> str:
        """Replace a real value with a unique placeholder token.

        If the same value was already masked for the same field,
        returns the existing token (deduplication).

        Args:
            field_name: The LDAP/AD field name (e.g. 'sAMAccountName').
            value: The real value to mask.

        Returns:
            A placeholder token like '[P1]'.
        """
        if value is None or value == "":
            return ""

        str_value = str(value)

        # Deduplication: same field+value → same token
        dedup_key = f"{field_name}::{str_value}"
        if dedup_key in self._reverse_map:
            return self._reverse_map[dedup_key]

        self._counter += 1
        token = f"[P{self._counter}]"

        self._mask_map[token] = str_value
        self._reverse_map[dedup_key] = token

        logger.debug(
            "[DATA-MASKER] Masked %s=%s → %s",
            field_name, str_value[:50], token,
        )

        return token

    def unmask_text(self, text: str) -> str:
        """Replace placeholder tokens in AI response with real values.

        Replacement is done longest-token-first to avoid partial
        matches (e.g. [P10] must be replaced before [P1]).

        Args:
            text: The AI response text containing placeholder tokens.

        Returns:
            The text with all tokens replaced by real values.
        """
        if not text or not self._mask_map:
            return text

        result = text

        # Sort tokens by length (longest first) to prevent
        # [P10] from being partially matched by [P1]
        sorted_tokens = sorted(self._mask_map.keys(), key=len, reverse=True)

        for token in sorted_tokens:
            real_value = self._mask_map[token]
            result = result.replace(token, real_value)

        return result

    # ──────────────────────────────────────────────────────────────
    #  Dict / List masking
    # ──────────────────────────────────────────────────────────────

    def mask_dict(self, data: dict) -> dict:
        """Mask all sensitive fields in a dictionary, recursively.

        Non-sensitive fields are passed through, but nested dicts and lists
        are recursively processed to find sensitive fields at any depth.

        Args:
            data: A dict with potentially sensitive values.

        Returns:
            A new dict with sensitive values replaced by tokens.
        """
        if not data:
            return data

        masked_data = {}
        for key, value in data.items():
            if key in self._sensitive_fields:
                # This key IS sensitive → mask its value
                if isinstance(value, str):
                    masked_data[key] = self.mask_value(key, value)
                elif isinstance(value, list):
                    masked_data[key] = [
                        self.mask_value(key, str(v)) if not isinstance(v, (dict, list))
                        else self._mask_recursive(v)
                        for v in value
                    ]
                elif value is None:
                    masked_data[key] = None
                else:
                    masked_data[key] = self.mask_value(key, str(value))
            else:
                # Key is NOT sensitive, but value may be a nested structure
                # that contains sensitive fields deeper inside
                masked_data[key] = self._mask_recursive(value)

        return masked_data

    def mask_list_of_dicts(self, data: List[dict]) -> List[dict]:
        """Mask a list of dictionaries (e.g. a list of user records).

        Args:
            data: A list of dicts (e.g. from an LDAP query result).

        Returns:
            A new list of dicts with sensitive values replaced by tokens.
        """
        if not data:
            return data

        return [self.mask_dict(record) for record in data]

    # ──────────────────────────────────────────────────────────────
    #  JSON masking
    # ──────────────────────────────────────────────────────────────

    def mask_json_string(self, json_string: str) -> str:
        """Mask sensitive fields in a JSON string.

        Parses the JSON, masks sensitive fields, and returns a new
        JSON string. Useful for masking API/tool results before
        sending to the AI.

        Args:
            json_string: A JSON string potentially containing PII.

        Returns:
            A JSON string with sensitive values replaced by tokens.
        """
        if not json_string or not json_string.strip():
            return json_string

        try:
            data = json.loads(json_string)
        except (json.JSONDecodeError, TypeError):
            # Not valid JSON — scan as raw text for PII patterns
            return self._mask_pii_in_text(json_string)

        masked = self._mask_recursive(data)
        return json.dumps(masked, ensure_ascii=False, default=str)

    def _mask_recursive(self, data: Any) -> Any:
        """Recursively mask sensitive fields in nested data structures.

        Descends into ALL nested structures (dicts inside lists,
        lists inside dicts, etc.) to find sensitive fields at any depth.
        Also handles raw text strings that may contain PII patterns like
        CN=Name or sAMAccountName: value.
        """
        if isinstance(data, dict):
            return self.mask_dict(data)
        elif isinstance(data, list):
            return [self._mask_recursive(item) for item in data]
        elif isinstance(data, str):
            # Scan raw text for known PII patterns (e.g. ldbsearch output)
            return self._mask_pii_in_text(data)
        else:
            return data

    def _mask_pii_in_text(self, text: str) -> str:
        """Mask PII patterns found in raw text strings.

        Handles common AD/LDAP output patterns like:
        - CN=Смирнов,CN=Users,DC=...
        - sAMAccountName: asmirnov
        - dn: CN=Иванов,OU=Users,DC=...
        - distinguishedName: CN=...

        For each PII field found in the text, the value is replaced with
        a mask token. The regex patterns are designed for ldbsearch/LDIF
        output format and DN (Distinguished Name) components.

        Args:
            text: A raw text string that may contain PII patterns.

        Returns:
            The text with PII values replaced by mask tokens.
        """
        if not text or len(text) < 3:
            return text

        result = text

        # Pattern 1: LDIF/ldbsearch format — "fieldName: value" on its own line
        # e.g. "sAMAccountName: asmirnov" or "cn: Смирнов"
        for field_name in sorted(self._sensitive_fields, key=len, reverse=True):
            # Match "fieldName: value" or "fieldName=value" (LDIF and key=value)
            pattern = re.compile(
                rf'(\b{re.escape(field_name)}\s*[:=]\s*)([^,\n\r]+)',
                re.IGNORECASE
            )

            def make_replacer(fname):
                def replacer(match):
                    prefix = match.group(1)
                    raw_value = match.group(2).strip()
                    if raw_value:
                        token = self.mask_value(fname, raw_value)
                        return prefix + token
                    return match.group(0)
                return replacer

            result = pattern.sub(make_replacer(field_name), result)

        # Pattern 2: DN components — "CN=Смирнов" inside DNs
        # These appear in dn: lines and as part of memberOf values
        dn_fields = {"cn", "ou"}
        for field_name in dn_fields:
            if field_name not in self._sensitive_fields:
                continue
            # Match CN=Value or OU=Value inside DN strings
            pattern = re.compile(
                rf'({re.escape(field_name.upper())}=)([^,=+\n]+)',
                re.IGNORECASE
            )

            def make_dn_replacer(fname):
                def replacer(match):
                    prefix = match.group(1)
                    raw_value = match.group(2).strip()
                    if raw_value:
                        token = self.mask_value(fname, raw_value)
                        return prefix + token
                    return match.group(0)
                return replacer

            result = pattern.sub(make_dn_replacer(field_name), result)

        return result

    # ──────────────────────────────────────────────────────────────
    #  Summary & AI context
    # ──────────────────────────────────────────────────────────────

    def get_mask_summary(self) -> Dict[str, Any]:
        """Get a summary of the masking state (for logging/debugging).

        Does NOT include the real values — only token counts.
        """
        return {
            "total_tokens": self._counter,
            "fields_masked": len(set(
                key.split("::")[0] for key in self._reverse_map
            )),
        }

    def get_ai_context_block(self) -> str:
        """Generate a short context block for the AI system prompt.

        Explains the masking system and how to use tokens.
        Much shorter than v1.0 (no range notation, no field names in tokens).

        Returns:
            A string to append to the system prompt.
        """
        return (
            "### DATA MASKING (PII Protection)\n"
            "You are seeing MASKED data. Real PII values are replaced with\n"
            "placeholder tokens like [P1], [P2], [P3], etc.\n"
            "JSON field names (cn, displayName, department, etc.) tell you\n"
            "what each token represents.\n"
            "\n"
            "RULES:\n"
            "1. Copy tokens EXACTLY as shown: [P1] not [P_1] or [P01]\n"
            "2. Never guess or invent values behind tokens\n"
            "3. Tokens will be auto-replaced with real values for the user\n"
        )


# ═══════════════════════════════════════════════════════════════════════
#  Module-level convenience functions
# ═══════════════════════════════════════════════════════════════════════


def create_masker_from_config() -> DataMasker:
    """Create a DataMasker instance configured from application settings.

    Reads the following settings:
    - AI_MASK_ENABLED: Whether masking is enabled (default: True)
    - AI_MASK_FIELDS: Comma-separated list of fields to mask
      (default: DEFAULT_PII_FIELDS)
    """
    from app.config import get_settings

    settings = get_settings()

    enabled = getattr(settings, "AI_MASK_ENABLED", True)
    if not enabled:
        # Return a no-op masker that doesn't mask anything
        return _NoOpMasker()

    # Parse custom fields if configured
    custom_fields_str = getattr(settings, "AI_MASK_FIELDS", "")
    if custom_fields_str:
        sensitive_fields = {
            f.strip() for f in custom_fields_str.split(",") if f.strip()
        }
    else:
        sensitive_fields = DEFAULT_PII_FIELDS

    return DataMasker(
        sensitive_fields=sensitive_fields,
    )


class _NoOpMasker(DataMasker):
    """A no-op masker that passes all data through unchanged.

    Used when masking is disabled via configuration.
    """

    def mask_value(self, field_name: str, value: Any) -> str:
        return "" if value is None else str(value)

    def unmask_text(self, text: str) -> str:
        return text

    def mask_dict(self, data: dict) -> dict:
        return data

    def mask_list_of_dicts(self, data: List[dict]) -> List[dict]:
        return data

    def mask_json_string(self, json_string: str) -> str:
        return json_string

    def get_ai_context_block(self) -> str:
        return ""
