"""
Unit tests for DataMasker — PII protection for AI agent (v2.0).

Tests cover:
    - Basic masking/unmasking of individual values (v2.0: [P1],[P2] format)
    - Dict masking with sensitive and non-sensitive fields
    - List of dicts masking
    - Deduplication of identical values
    - JSON string masking
    - Edge cases: empty values, None, nested structures
    - NoOp masker when masking is disabled
    - Longest-first unmasking ([P10] before [P1])
"""

import json
import sys
import os
import unittest

# Add the project root to path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.data_masker import DataMasker, DEFAULT_PII_FIELDS, _NoOpMasker


class TestBasicMasking(unittest.TestCase):
    """Test basic mask_value / unmask_text operations."""

    def setUp(self):
        self.masker = DataMasker()

    def test_mask_single_value(self):
        """A single value should get a unique token [P1]."""
        token = self.masker.mask_value("sAMAccountName", "ivanov")
        self.assertEqual(token, "[P1]")

    def test_mask_multiple_values(self):
        """Multiple values should get sequential tokens."""
        t1 = self.masker.mask_value("sAMAccountName", "ivanov")
        t2 = self.masker.mask_value("sAMAccountName", "petrov")
        t3 = self.masker.mask_value("displayName", "Иванов И.И.")
        self.assertEqual(t1, "[P1]")
        self.assertEqual(t2, "[P2]")
        self.assertEqual(t3, "[P3]")

    def test_unmask_single_token(self):
        """unmask_text should replace a single token with the real value."""
        self.masker.mask_value("sAMAccountName", "ivanov")
        result = self.masker.unmask_text("Логин: [P1]")
        self.assertEqual(result, "Логин: ivanov")

    def test_unmask_multiple_tokens(self):
        """unmask_text should replace multiple tokens correctly."""
        self.masker.mask_value("sAMAccountName", "ivanov")
        self.masker.mask_value("displayName", "Иванов Иван")
        result = self.masker.unmask_text(
            "Пользователь [P1] имеет имя [P2]"
        )
        self.assertEqual(result, "Пользователь ivanov имеет имя Иванов Иван")

    def test_unmask_no_tokens(self):
        """unmask_text should return unchanged text if no tokens present."""
        result = self.masker.unmask_text("Hello world")
        self.assertEqual(result, "Hello world")

    def test_unmask_empty_string(self):
        """unmask_text should handle empty strings."""
        self.assertEqual(self.masker.unmask_text(""), "")

    def test_mask_empty_value(self):
        """mask_value should return empty string for None/empty values."""
        self.assertEqual(self.masker.mask_value("field", ""), "")
        self.assertEqual(self.masker.mask_value("field", None), "")

    def test_unmask_longest_first(self):
        """Unmasking should replace [P10] before [P1] to prevent partial matches."""
        for i in range(1, 12):
            self.masker.mask_value("field", f"value{i}")
        # [P10] should not be partially matched by [P1]
        result = self.masker.unmask_text("[P1] [P10] [P11]")
        self.assertEqual(result, "value1 value10 value11")


class TestDeduplication(unittest.TestCase):
    """Test that identical values get the same token."""

    def setUp(self):
        self.masker = DataMasker()

    def test_dedup_same_field_same_value(self):
        """Same value in same field should return the same token."""
        t1 = self.masker.mask_value("sAMAccountName", "admin")
        t2 = self.masker.mask_value("sAMAccountName", "admin")
        self.assertEqual(t1, t2)
        self.assertEqual(t1, "[P1]")

    def test_different_fields_same_value(self):
        """Same value in different fields should get different tokens."""
        t1 = self.masker.mask_value("sAMAccountName", "admin")
        t2 = self.masker.mask_value("cn", "admin")
        self.assertNotEqual(t1, t2)


class TestDictMasking(unittest.TestCase):
    """Test mask_dict with sensitive/non-sensitive fields."""

    def setUp(self):
        self.masker = DataMasker()

    def test_mask_sensitive_fields_only(self):
        """Only fields in the sensitive set should be masked."""
        data = {
            "sAMAccountName": "ivanov",
            "displayName": "Иванов И.И.",
            "userAccountControl": 66048,  # Not sensitive
        }
        masked = self.masker.mask_dict(data)

        # Sensitive fields should be masked
        self.assertEqual(masked["sAMAccountName"], "[P1]")
        self.assertEqual(masked["displayName"], "[P2]")

        # Non-sensitive fields should pass through
        self.assertEqual(masked["userAccountControl"], 66048)

    def test_mask_list_values(self):
        """List values in sensitive fields should be masked element-wise."""
        data = {
            "memberOf": ["CN=Domain Admins,CN=Users,DC=kcrb,DC=local",
                         "CN=Print Operators,CN=Users,DC=kcrb,DC=local"],
        }
        masked = self.masker.mask_dict(data)
        self.assertEqual(masked["memberOf"][0], "[P1]")
        self.assertEqual(masked["memberOf"][1], "[P2]")

    def test_mask_dict_with_none(self):
        """None values in sensitive fields should stay None."""
        data = {"mail": None}
        masked = self.masker.mask_dict(data)
        self.assertIsNone(masked["mail"])

    def test_mask_empty_dict(self):
        """Empty dict should return empty dict."""
        self.assertEqual(self.masker.mask_dict({}), {})

    def test_custom_sensitive_fields(self):
        """Custom sensitive fields should override defaults."""
        masker = DataMasker(sensitive_fields={"customField"})
        data = {"customField": "secret", "sAMAccountName": "admin"}
        masked = masker.mask_dict(data)
        self.assertEqual(masked["customField"], "[P1]")
        self.assertEqual(masked["sAMAccountName"], "admin")  # Not masked!


class TestListOfDictsMasking(unittest.TestCase):
    """Test mask_list_of_dicts for batch masking."""

    def setUp(self):
        self.masker = DataMasker()

    def test_mask_multiple_users(self):
        """Multiple user records should all be masked."""
        users = [
            {"sAMAccountName": "ivanov", "displayName": "Иванов", "userAccountControl": 66048},
            {"sAMAccountName": "petrov", "displayName": "Петров", "userAccountControl": 512},
        ]
        masked = self.masker.mask_list_of_dicts(users)

        self.assertEqual(masked[0]["sAMAccountName"], "[P1]")
        self.assertEqual(masked[0]["displayName"], "[P2]")
        self.assertEqual(masked[0]["userAccountControl"], 66048)  # Not sensitive

        self.assertEqual(masked[1]["sAMAccountName"], "[P3]")
        self.assertEqual(masked[1]["displayName"], "[P4]")
        self.assertEqual(masked[1]["userAccountControl"], 512)  # Not sensitive


class TestJSONMasking(unittest.TestCase):
    """Test mask_json_string for tool result masking."""

    def setUp(self):
        self.masker = DataMasker()

    def test_mask_json_dict(self):
        """JSON dict should have sensitive fields masked."""
        json_str = json.dumps({
            "sAMAccountName": "admin",
            "displayName": "Administrator",
            "userAccountControl": 66048,
        }, ensure_ascii=False)
        masked = self.masker.mask_json_string(json_str)
        data = json.loads(masked)

        self.assertEqual(data["sAMAccountName"], "[P1]")
        self.assertEqual(data["displayName"], "[P2]")
        self.assertEqual(data["userAccountControl"], 66048)

    def test_mask_json_list(self):
        """JSON list of dicts should all be masked."""
        json_str = json.dumps([
            {"sAMAccountName": "ivanov", "mail": "ivan@test.local"},
            {"sAMAccountName": "petrov", "mail": "petr@test.local"},
        ], ensure_ascii=False)
        masked = self.masker.mask_json_string(json_str)
        data = json.loads(masked)

        self.assertEqual(data[0]["sAMAccountName"], "[P1]")
        self.assertEqual(data[0]["mail"], "[P2]")
        self.assertEqual(data[1]["sAMAccountName"], "[P3]")
        self.assertEqual(data[1]["mail"], "[P4]")

    def test_mask_invalid_json(self):
        """Invalid JSON should be returned as-is."""
        result = self.masker.mask_json_string("not json")
        self.assertEqual(result, "not json")

    def test_mask_empty_json(self):
        """Empty/whitespace JSON should be returned as-is."""
        self.assertEqual(self.masker.mask_json_string(""), "")
        self.assertEqual(self.masker.mask_json_string("   "), "   ")


class TestAIContextBlock(unittest.TestCase):
    """Test the AI context block generation."""

    def setUp(self):
        self.masker = DataMasker()

    def test_context_block_no_tokens(self):
        """Context block should explain the [P1] token format."""
        block = self.masker.get_ai_context_block()
        self.assertIn("MASKED data", block)
        self.assertIn("[P1]", block)

    def test_noop_masker_no_context(self):
        """NoOp masker should return empty context block."""
        masker = _NoOpMasker()
        self.assertEqual(masker.get_ai_context_block(), "")


class TestNoOpMasker(unittest.TestCase):
    """Test that _NoOpMasker passes all data through unchanged."""

    def setUp(self):
        self.masker = _NoOpMasker()

    def test_mask_value_passthrough(self):
        """mask_value should return the original value as string."""
        self.assertEqual(self.masker.mask_value("sAMAccountName", "admin"), "admin")

    def test_mask_dict_passthrough(self):
        """mask_dict should return the original dict unchanged."""
        data = {"sAMAccountName": "admin", "count": 5}
        self.assertEqual(self.masker.mask_dict(data), data)

    def test_unmask_text_passthrough(self):
        """unmask_text should return text unchanged."""
        self.assertEqual(self.masker.unmask_text("Hello"), "Hello")

    def test_mask_json_passthrough(self):
        """mask_json_string should return JSON unchanged."""
        json_str = '{"sAMAccountName": "admin"}'
        self.assertEqual(self.masker.mask_json_string(json_str), json_str)


class TestMaskSummary(unittest.TestCase):
    """Test get_mask_summary for debugging."""

    def test_summary_counts(self):
        """Summary should report correct token counts."""
        masker = DataMasker()
        masker.mask_value("sAMAccountName", "user1")
        masker.mask_value("sAMAccountName", "user2")
        masker.mask_value("displayName", "Name1")

        summary = masker.get_mask_summary()
        self.assertEqual(summary["total_tokens"], 3)
        self.assertEqual(summary["fields_masked"], 2)

    def test_summary_no_real_values(self):
        """Summary should NEVER contain real PII values."""
        masker = DataMasker()
        masker.mask_value("sAMAccountName", "super_secret_login")
        summary = masker.get_mask_summary()
        summary_str = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn("super_secret_login", summary_str)


class TestEndToEnd(unittest.TestCase):
    """End-to-end test: mask -> AI response -> unmask."""

    def test_full_pipeline(self):
        """Simulate a complete mask -> AI -> unmask cycle."""
        masker = DataMasker()

        # Step 1: LDAP returns real data
        ldap_result = {
            "sAMAccountName": "ivanov",
            "displayName": "Иванов Иван Иванович",
            "mail": "ivanov@kcrb.local",
            "userAccountControl": 66048,
            "memberOf": ["CN=Domain Admins,CN=Users,DC=kcrb,DC=local"],
        }

        # Step 2: Mask the data before sending to AI
        masked = masker.mask_dict(ldap_result)
        self.assertEqual(masked["sAMAccountName"], "[P1]")
        self.assertEqual(masked["displayName"], "[P2]")
        self.assertEqual(masked["mail"], "[P3]")
        self.assertEqual(masked["userAccountControl"], 66048)  # Not masked
        self.assertEqual(masked["memberOf"], ["[P4]"])

        # Step 3: AI processes and responds using tokens
        ai_response = (
            "Пользователь с логином [P1] имеет "
            "полное имя [P2] и почту [P3]. "
            "Он состоит в группе [P4]."
        )

        # Step 4: Unmask the AI response
        final = masker.unmask_text(ai_response)
        self.assertEqual(
            final,
            "Пользователь с логином ivanov имеет "
            "полное имя Иванов Иван Иванович и почту ivanov@kcrb.local. "
            "Он состоит в группе CN=Domain Admins,CN=Users,DC=kcrb,DC=local."
        )

    def test_pipeline_two_users_distinguishable(self):
        """Two different users should be distinguishable by token numbers."""
        masker = DataMasker()

        user1 = {"sAMAccountName": "ivanov", "displayName": "Иванов"}
        user2 = {"sAMAccountName": "petrov", "displayName": "Петров"}

        masked1 = masker.mask_dict(user1)
        masked2 = masker.mask_dict(user2)

        # AI can tell them apart because token numbers differ
        ai_response = (
            "Пользователь [P1] — это [P2], "
            "а пользователь [P3] — это [P4]."
        )

        final = masker.unmask_text(ai_response)
        self.assertEqual(
            final,
            "Пользователь ivanov — это Иванов, "
            "а пользователь petrov — это Петров."
        )

    def test_pipeline_token_format_robustness(self):
        """Test that [P1],[P2]... format is not corrupted by AI models.

        The old format [MASK_displayName_2] was corrupted by AI models
        into [MASK_displayName_isplayName_2]. The new [P1],[P2] format
        is immune to this corruption because there are no attribute names
        in the token that the model could duplicate.
        """
        masker = DataMasker()

        # Create tokens for various fields
        masker.mask_value("displayName", "Иванов")
        masker.mask_value("sAMAccountName", "ivanov")
        masker.mask_value("department", "IT")

        # AI uses the simple tokens — no corruption possible
        ai_response = "[P1] работает в отделе [P3], логин: [P2]"
        final = masker.unmask_text(ai_response)
        self.assertEqual(final, "Иванов работает в отделе IT, логин: ivanov")


if __name__ == "__main__":
    unittest.main()
