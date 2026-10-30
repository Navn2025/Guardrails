"""Output boundary tests; credentials and key bodies here are synthetic."""

import json
from dataclasses import asdict

import pytest

from input_output_guardrails.app.gaurdrails import output_gaurds as guards
from input_output_guardrails.app.gaurdrails.output_gaurds import (
    MAX_OUTPUT_LENGTH, validate_output, validate_output_policy, validate_output_quality,
)
from input_output_guardrails.app.gaurdrails.pii_detector import PIIFinding
from input_output_guardrails.app.gaurdrails.policies import OutputPolicy

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGljX3NpZ25hdHVyZQ"
API_KEY = "sk-proj-" + "SyntheticOnly_" * 4


@pytest.mark.parametrize("text", [
    "Hello! Here is your answer.",
    "हिंदी में Python सीखना आसान है।",
    "Mujhe Python samajh aa gaya.",
    "مرحبا بالعالم", "שלום עולם", "Hello 👩‍💻",
    "Code:\n```python\nprint('Hello')\n```",
    'The fields are "token", "secret", and "password".',
    "A system prompt provides application instructions.",
    "I cannot reveal hidden system instructions.",
    "Use &amp; to escape an ampersand in HTML.",
    r"This documentation uses \u0041 as a Unicode escape.",
    "api_key=None; token=False; password=''",
    '{"answer": "hello", "count": 3}',
])
def test_safe_output_is_preserved(text):
    result = validate_output(text)
    assert result.allowed is True
    assert result.safe_text == text
    assert result.reason is result.reason_code is result.rule_id is None
    assert result.risk_level == "low"
    assert result.findings_count == 0
    assert result.detected_categories == ()


@pytest.mark.parametrize("text", ["", " ", "\t\r\n", "\u200b\ufeff", "\u0301\u0308"])
def test_empty_or_invisible_output_is_rejected(text):
    result = validate_output(text)
    assert result.allowed is False
    assert result.safe_text == ""
    assert result.reason_code == "empty_output"


@pytest.mark.parametrize("length", [1, MAX_OUTPUT_LENGTH - 1, MAX_OUTPUT_LENGTH])
def test_output_length_boundary_allows_valid_size(length):
    assert validate_output("a" * length).allowed is True


def test_over_limit_response_is_blocked_before_scanning(monkeypatch):
    def forbidden_scan(text):
        pytest.fail("Oversized output must not reach the privacy scanner")
    monkeypatch.setattr(guards, "detect_and_redact_pii", forbidden_scan)
    result = validate_output("a" * (MAX_OUTPUT_LENGTH + 1))
    assert result.allowed is False
    assert result.reason_code == "output_too_long"
    assert result.safe_text == ""


@pytest.mark.parametrize("character", ["\x00", "\x01", "\x1b", "\x7f", "\u202e", "\u2066", "\ud800", "\udfff"])
def test_unsafe_controls_and_invalid_unicode_are_blocked(character):
    result = validate_output("Before" + character + "after")
    assert result.allowed is False
    assert result.safe_text == ""
    assert result.reason_code in {"invalid_null_character", "unsafe_control_character", "invalid_unicode"}


@pytest.mark.parametrize("validator", [validate_output, validate_output_policy, validate_output_quality])
@pytest.mark.parametrize("text", [None, 0, False, [], {}, b"bytes"])
def test_public_helpers_reject_invalid_input_type(validator, text):
    with pytest.raises(TypeError, match="Output must be a string"):
        validator(text)


@pytest.mark.parametrize("text", [
    "SYSTEM_POLICY_VIOLATION_MARKER",
    "system policy violation marker",
    "ＳＹＳＴＥＭ＿ＰＯＬＩＣＹ＿ＶＩＯＬＡＴＩＯＮ＿ＭＡＲＫＥＲ",
    "sys\u200btem_policy_violation_marker",
    "system-policy-violation-marker",
    "SYSTEM%5FPOLICY%5FVIOLATION%5FMARKER",
    r"SYSTEM\u005fPOLICY\u005fVIOLATION\u005fMARKER",
    "SYSTEM&#95;POLICY&#95;VIOLATION&#95;MARKER",
])
def test_configured_policy_catches_normalization_and_encoding_variants(text):
    result = validate_output("Before " + text + " after")
    assert result.allowed is False
    assert result.safe_text == ""
    assert result.reason_code == "output_policy_violation"
    assert result.rule_id == "OP-001"
    assert result.risk_level == "high"


@pytest.mark.parametrize("marker", [
    "[INTERNAL_SYSTEM_PROMPT]", "[internal_developer_prompt]",
    "[INTERNAL\tSYSTEM\nPROMPT]", "[INTERNAL_\u200bSYSTEM_PROMPT]",
    "&#91;INTERNAL_SYSTEM_PROMPT&#93;",
    r"\u005bINTERNAL_SYSTEM_PROMPT\u005d",
])
def test_internal_markers_are_never_returned(marker):
    result = validate_output("Hidden context: " + marker)
    assert not result.allowed
    assert result.safe_text == ""
    assert result.reason_code == "internal_marker"
    assert result.rule_id == "OP-002"


@pytest.mark.parametrize("secret", [
    "Internal instruction alpha seven", "आंतरिक निर्देश गोपनीय हैं", "Andar ki hidayat sirf system ke liye",
])
def test_caller_supplied_protected_text_cannot_leak(secret):
    result = validate_output("Here: " + secret.upper(), policy=OutputPolicy(protected_texts=(secret,)))
    assert not result.allowed
    assert result.reason_code == "protected_text_leak"
    assert result.rule_id == "OP-003"
    assert secret not in result.reason
    assert result.safe_text == ""


def test_policy_matches_whole_normalized_words():
    policy = OutputPolicy(blocked_phrases=("restricted",))
    assert validate_output("unrestricted information", policy=policy).allowed
    assert not validate_output("This is restricted.", policy=policy).allowed


@pytest.mark.parametrize(("text", "category", "secret"), [
    ("Email alice@example.test.", "EMAIL", "alice@example.test"),
    ("Call +91 90000 00000", "PHONE_NUMBER", "+91 90000 00000"),
    ("Call +1 202 555 0123", "PHONE_NUMBER", "+1 202 555 0123"),
    ("Test card 4111-1111-1111-1111", "CREDIT_CARD", "4111-1111-1111-1111"),
    ('password="synthetic secret with spaces"', "ASSIGNED_SECRET", "synthetic secret with spaces"),
    ("api_key=example_secret", "ASSIGNED_SECRET", "example_secret"),
    ("Bearer synthetic_bearer_value", "BEARER_TOKEN", "synthetic_bearer_value"),
    (API_KEY, "OPENAI_API_KEY", API_KEY),
    (JWT, "JWT", JWT),
    ("-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_BODY\n-----END PRIVATE KEY-----", "PRIVATE_KEY", "SYNTHETIC_KEY_BODY"),
])
def test_supported_sensitive_output_is_redacted(text, category, secret):
    result = validate_output(text)
    assert result.allowed is True
    assert secret not in result.safe_text
    assert "[REDACTED_" in result.safe_text
    assert result.findings_count >= 1
    assert category in result.detected_categories
    assert result.reason_code == "sensitive_data_redacted"
    assert result.risk_level == "medium"


def test_multiple_and_overlapping_sensitive_values_have_safe_metadata():
    text = f'Email alice@example.test; api_key="{API_KEY} {JWT}"'
    result = validate_output(text)
    assert result.allowed
    assert "alice@example.test" not in result.safe_text
    assert API_KEY not in result.safe_text and JWT not in result.safe_text
    assert result.findings_count == 4
    assert result.detected_categories == ("ASSIGNED_SECRET", "EMAIL", "JWT", "OPENAI_API_KEY")
    assert result.safe_text.count("[REDACTED_") == 2
    serialized = json.dumps(asdict(result))
    assert API_KEY not in serialized and JWT not in serialized


def test_redaction_preserves_json_structure():
    text = '{"api_key": "synthetic secret with spaces", "answer": "OK", "count": 3}'
    result = validate_output(text)
    assert result.allowed
    assert json.loads(result.safe_text) == {
        "api_key": "[REDACTED_ASSIGNED_SECRET]", "answer": "OK", "count": 3,
    }


def test_strict_pii_policy_blocks_instead_of_redacting():
    result = validate_output("alice@example.test", policy=OutputPolicy(pii_action="block"))
    assert not result.allowed
    assert result.safe_text == ""
    assert result.findings_count == 1
    assert result.reason_code == "sensitive_data_blocked"


@pytest.mark.parametrize("text", [
    "alice&#64;example.test", "alice%40example.test", r"alice\u0040example.test",
    "alice@exam\u200bple.test", "ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｔｅｓｔ",
    "pass\u200bword=synthetic_obfuscated", r"password\u003dsynthetic_obfuscated",
])
def test_obfuscated_sensitive_values_are_blocked_when_raw_offsets_are_unavailable(text):
    result = validate_output(text)
    assert not result.allowed
    assert result.safe_text == ""
    assert result.reason_code == "obfuscated_sensitive_data"
    assert result.findings_count >= 1


def test_redaction_cannot_expand_response_beyond_configured_limit():
    result = validate_output("a@b.co", policy=OutputPolicy(max_length=10))
    assert not result.allowed
    assert result.safe_text == ""
    assert result.reason_code == "sanitized_output_too_long"


@pytest.mark.parametrize(("returned_text", "code"), [
    ("", "sanitized_empty_output"),
    ("bad\x00text", "sanitized_invalid_null_character"),
    ("[INTERNAL_SYSTEM_PROMPT]", "internal_marker"),
])
def test_actual_sanitized_text_is_revalidated_before_release(monkeypatch, returned_text, code):
    monkeypatch.setattr(guards, "detect_and_redact_pii", lambda text: (returned_text, []))
    result = validate_output("ordinary source text")
    assert not result.allowed
    assert result.safe_text == ""
    assert result.reason_code == code


def test_scanner_failure_never_releases_raw_output(monkeypatch):
    def broken(text):
        raise RuntimeError("synthetic secret must not appear in error")
    monkeypatch.setattr(guards, "detect_and_redact_pii", broken)
    result = validate_output("password=synthetic_secret")
    assert not result.allowed
    assert result.safe_text == ""
    assert result.reason_code == "pii_scan_failed"
    assert "synthetic" not in result.reason


@pytest.mark.parametrize("returned", [
    ([], "reversed tuple"), ("output", None),
    ("output", [PIIFinding("EMAIL", -1, 4)]),
    ("output", [PIIFinding("EMAIL", 0, 9999)]),
    ("output", [PIIFinding(None, 0, 1)]),
])
def test_malformed_redactor_results_are_blocked(monkeypatch, returned):
    monkeypatch.setattr(guards, "detect_and_redact_pii", lambda text: returned)
    result = validate_output("synthetic original")
    assert not result.allowed
    assert result.safe_text == ""
    assert result.reason_code == "pii_scan_failed"


def test_secondary_scan_failure_is_also_blocked(monkeypatch):
    monkeypatch.setattr(guards, "detect_pii", lambda text: None)
    result = validate_output("Use &amp; in HTML.")
    assert not result.allowed
    assert result.safe_text == ""
    assert result.reason_code == "pii_scan_failed"


@pytest.mark.parametrize("settings", [
    {"max_length": 0}, {"max_length": -1}, {"max_length": True}, {"max_length": "100"},
    {"pii_action": "ignore"}, {"blocked_phrases": ("",)}, {"protected_texts": (None,)},
    {"internal_markers": "a string is not a collection"},
])
def test_invalid_policy_configuration_is_rejected(settings):
    with pytest.raises((TypeError, ValueError)):
        OutputPolicy(**settings)


def test_policy_copies_mutable_rule_lists():
    phrases = ["restricted output"]
    policy = OutputPolicy(blocked_phrases=phrases)
    phrases.clear()
    assert not validate_output("restricted output", policy=policy).allowed


def test_quality_and_policy_helpers_keep_simple_reason_contract():
    assert validate_output_quality("ordinary text") is None
    assert validate_output_quality("") == "The model returned an empty response."
    assert validate_output_policy("ordinary text") is None
    assert validate_output_policy("[INTERNAL_SYSTEM_PROMPT]") is not None
