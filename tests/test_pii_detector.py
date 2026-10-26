"""PII and redaction regressions using only fabricated values and test PANs.

Provider-shaped strings below are synthetic fixtures, not working credentials.
The card fixtures are standard test numbers, not cardholder data.
"""

import pytest

from app.gaurdrails.pii_detector import (
    detect_and_redact_pii,
    detect_pii,
    passes_luhn,
)

EMAIL = "alice+test@example.test"
PHONE = "+91 90000-00000"
TEST_CARD = "4111-1111-1111-1111"
SYNTHETIC_OPENAI_KEY = "sk-proj-" + "SyntheticOnly_" * 4
SYNTHETIC_GITHUB_TOKEN = "ghp_" + "SyntheticOnly" * 3
SYNTHETIC_GITHUB_PAT = "github_pat_" + "SyntheticOnly_" * 4
SYNTHETIC_AWS_ID = "AKIA" + "SYNTHETIC" + "A" * 7
SYNTHETIC_JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiJzeW50aGV0aWMifQ."
    "c3ludGhldGljX3NpZ25hdHVyZQ"
)
SYNTHETIC_PROVIDER_AND_JWT = SYNTHETIC_OPENAI_KEY + " " + SYNTHETIC_JWT


@pytest.mark.parametrize(
    ("sensitive", "entity_type"),
    [
        (EMAIL, "EMAIL"),
        (PHONE, "PHONE_NUMBER"),
        (TEST_CARD, "CREDIT_CARD"),
        ("api_key=example_secret", "ASSIGNED_SECRET"),
        ("Bearer synthetic_bearer_token", "BEARER_TOKEN"),
        ("password=synthetic_password", "ASSIGNED_SECRET"),
        (SYNTHETIC_JWT, "JWT"),
    ],
    ids=["email", "indian-mobile", "test-card", "api-assignment", "bearer", "password", "jwt"],
)
def test_detect_and_redact_sensitive_value(sensitive, entity_type):
    text = f"Before {sensitive} after."
    redacted, findings = detect_and_redact_pii(text)
    value = sensitive.split("=", 1)[-1] if entity_type == "ASSIGNED_SECRET" else sensitive
    if entity_type == "BEARER_TOKEN":
        value = sensitive.removeprefix("Bearer ")
    assert any(
        finding.entity_type == entity_type and text[finding.start:finding.end] == value
        for finding in findings
    )
    assert redacted == text.replace(value, f"[REDACTED_{entity_type}]")
    assert value not in redacted
    assert findings == detect_pii(text)


@pytest.mark.parametrize("phone", ["9000000000", "90000 00000", "90000.00000", "+91-90000-00000"])
def test_indian_mobile_formats(phone):
    redacted, findings = detect_and_redact_pii(f"Call {phone}.")
    assert {finding.entity_type for finding in findings} == {"PHONE_NUMBER"}
    assert redacted == "Call [REDACTED_PHONE_NUMBER]."


@pytest.mark.parametrize("number", ["4111111111111111", "4242 4242 4242 4242", "5555-5555-5555-4444"])
def test_luhn_valid_test_card_numbers(number):
    assert passes_luhn(number) is True
    redacted, findings = detect_and_redact_pii(f"Test card: {number}")
    assert {finding.entity_type for finding in findings} == {"CREDIT_CARD"}
    assert redacted == "Test card: [REDACTED_CREDIT_CARD]"


@pytest.mark.parametrize("number", ["4111111111111112", "4242 4242 4242 4243", "5555-5555-5555-4445"])
def test_number_failing_luhn_is_not_classified_as_a_card(number):
    assert passes_luhn(number) is False
    text = f"Reference: {number}"
    redacted, findings = detect_and_redact_pii(text)
    assert not any(finding.entity_type == "CREDIT_CARD" for finding in findings)
    assert redacted == text


@pytest.mark.parametrize(
    ("secret", "entity_type"),
    [
        ("sk-" + "SyntheticOnly" * 3, "OPENAI_API_KEY"),
        (SYNTHETIC_OPENAI_KEY, "OPENAI_API_KEY"),
        ("sk-proj-" + "SyntheticOnly" * 3 + "-", "OPENAI_API_KEY"),
        (SYNTHETIC_GITHUB_TOKEN, "GITHUB_TOKEN"),
        (SYNTHETIC_GITHUB_PAT, "GITHUB_TOKEN"),
        (SYNTHETIC_AWS_ID, "AWS_ACCESS_KEY"),
        ("ASIA" + "SYNTHETIC" + "A" * 7, "AWS_ACCESS_KEY"),
    ],
    ids=["openai-style", "project-style", "trailing-hyphen", "github-token", "github-pat", "aws-akia", "aws-asia"],
)
def test_supported_provider_specific_formats_are_fully_redacted(secret, entity_type):
    text = f"Before ({secret}) after."
    redacted, findings = detect_and_redact_pii(text)
    assert any(
        finding.entity_type == entity_type and text[finding.start:finding.end] == secret
        for finding in findings
    )
    assert redacted == f"Before ([REDACTED_{entity_type}]) after."


@pytest.mark.parametrize(
    ("assignment", "value"),
    [
        ("api_key=example_secret", "example_secret"),
        ("API-KEY: example_secret", "example_secret"),
        ('api_key="synthetic secret with spaces"', "synthetic secret with spaces"),
        ("api_key='synthetic,secret;with=punctuation'", "synthetic,secret;with=punctuation"),
        ('"api_key": "synthetic_json_secret"', "synthetic_json_secret"),
        ("'password': 'synthetic_dict_secret'", "synthetic_dict_secret"),
        ("OPENAI_API_KEY=example_secret", "example_secret"),
        ("MY_APP_CLIENT_SECRET=synthetic_client_secret", "synthetic_client_secret"),
        ('password="synthetic\\\"quoted\\\"secret"', 'synthetic\\\"quoted\\\"secret'),
        ("password='synthetic\\'quoted\\'secret'", "synthetic\\'quoted\\'secret"),
        ("token=synthetic_token", "synthetic_token"),
        ("secret: synthetic_secret", "synthetic_secret"),
        ('api_key="None"', "None"),
        ('api_key="null"', "null"),
    ],
)
def test_contextual_secret_assignments(assignment, value):
    text = f"Before {assignment}; after."
    redacted, findings = detect_and_redact_pii(text)
    assert any(
        finding.entity_type == "ASSIGNED_SECRET" and text[finding.start:finding.end] == value
        for finding in findings
    )
    assert redacted == text.replace(value, "[REDACTED_ASSIGNED_SECRET]")


@pytest.mark.parametrize(
    "text",
    [
        "Ordinary text with no sensitive values.",
        "Explain what token, password, secret, and API key mean.",
        "The token and password should be kept secret.",
        "api_key_count=3; token_count=4; password_length=12",
        "secretary=synthetic_name",
        "api_key=",
        "api_key =   ",
        'api_key=""',
        "password=''",
        'secret="   "',
        "api_key = None",
        "api_key=null",
        '"api_key": null',
        "access_token=undefined",
        "secret=False",
        "token=True",
        "api_key={} ; token=[]",
        "api_key=\nThis next line is public.",
        "password: \r\nThis next line is public.",
        "Bearer",
    ],
)
def test_empty_placeholder_or_harmless_text_is_unchanged(text):
    assert detect_pii(text) == []
    assert detect_and_redact_pii(text) == (text, [])


@pytest.mark.parametrize("assignment", ['api_key="synthetic_unterminated', "password='synthetic_unterminated"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_unterminated_quoted_assignment_redacts_to_line_end(assignment, newline):
    text = f"Before {assignment}{newline}Public next line."
    redacted, findings = detect_and_redact_pii(text)
    assert len(findings) == 1
    value = "synthetic_unterminated"
    assert text[findings[0].start:findings[0].end] == value
    assert redacted == text.replace(value, "[REDACTED_ASSIGNED_SECRET]")


def test_empty_assignment_does_not_hide_a_subsequent_secret():
    text = 'api_key="";password=synthetic_password'
    redacted, findings = detect_and_redact_pii(text)
    assert len(findings) == 1
    assert redacted == 'api_key="";password=[REDACTED_ASSIGNED_SECRET]'


def test_multiple_sensitive_values_are_all_redacted_with_original_offsets():
    text = (
        f"Email: {EMAIL}; phone={PHONE}; card={TEST_CARD}; "
        "api_key=example_secret; password=synthetic_password; "
        "Authorization: Bearer synthetic_bearer_token."
    )
    redacted, findings = detect_and_redact_pii(text)
    assert redacted == (
        "Email: [REDACTED_EMAIL]; phone=[REDACTED_PHONE_NUMBER]; card=[REDACTED_CREDIT_CARD]; "
        "api_key=[REDACTED_ASSIGNED_SECRET]; password=[REDACTED_ASSIGNED_SECRET]; "
        "Authorization: Bearer [REDACTED_BEARER_TOKEN]"
    )
    assert len(findings) == 6
    for finding in findings:
        assert 0 <= finding.start < finding.end <= len(text)
        assert text[finding.start:finding.end] not in redacted


@pytest.mark.parametrize("key_type", ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_private_key_redacts_complete_block_and_matching_footer(key_type, newline):
    block = newline.join([
        f"-----BEGIN {key_type}-----",
        "SYNTHETIC_PRIVATE_KEY_MATERIAL",
        "NOT_A_REAL_KEY",
        f"-----END {key_type}-----",
    ])
    text = f"Before\n{block}\nAfter"
    redacted, findings = detect_and_redact_pii(text)
    assert len(findings) == 1
    assert findings[0].entity_type == "PRIVATE_KEY"
    assert text[findings[0].start:findings[0].end] == block
    assert redacted == "Before\n[REDACTED_PRIVATE_KEY]\nAfter"


def test_private_key_does_not_stop_at_a_different_footer():
    block = (
        "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC_KEY_PART_ONE\n"
        "-----END EC PRIVATE KEY-----\nSYNTHETIC_KEY_PART_TWO\n"
        "-----END RSA PRIVATE KEY-----"
    )
    redacted, findings = detect_and_redact_pii(f"Before {block} after.")
    assert len(findings) == 1
    assert redacted == "Before [REDACTED_PRIVATE_KEY] after."


def test_two_private_keys_do_not_swallow_text_between_blocks():
    block = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_ONLY\n-----END PRIVATE KEY-----"
    redacted, findings = detect_and_redact_pii(f"{block}\nPublic text\n{block}")
    assert len(findings) == 2
    assert redacted == "[REDACTED_PRIVATE_KEY]\nPublic text\n[REDACTED_PRIVATE_KEY]"


def test_truncated_private_key_redacts_sensitive_remainder():
    block = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_ONLY_WITHOUT_FOOTER"
    redacted, findings = detect_and_redact_pii(f"Before\n{block}")
    assert len(findings) == 1
    assert redacted == "Before\n[REDACTED_PRIVATE_KEY]"


@pytest.mark.parametrize(
    ("sensitive", "expected"),
    [
        (f'api_key="{SYNTHETIC_OPENAI_KEY}"', 'api_key="[REDACTED_ASSIGNED_SECRET_OPENAI_API_KEY]"'),
        (f'api_key="{SYNTHETIC_PROVIDER_AND_JWT}"', 'api_key="[REDACTED_ASSIGNED_SECRET_JWT_OPENAI_API_KEY]"'),
        (f'access_token="Bearer {SYNTHETIC_JWT}"', 'access_token="[REDACTED_ASSIGNED_SECRET_BEARER_TOKEN_JWT]"'),
        (f"access_token=Bearer {SYNTHETIC_JWT}", "access_token=[REDACTED_ASSIGNED_SECRET] [REDACTED_BEARER_TOKEN_JWT]"),
        (f'api_key="Bearer {SYNTHETIC_PROVIDER_AND_JWT}"', 'api_key="[REDACTED_ASSIGNED_SECRET_BEARER_TOKEN_JWT_OPENAI_API_KEY]"'),
    ],
    ids=["assigned-provider", "assigned-provider-jwt", "quoted-bearer-jwt", "crossing-bearer-jwt", "all-secret-rules"],
)
def test_overlapping_secrets_are_redacted_once_without_leaking_fragments(sensitive, expected):
    redacted, findings = detect_and_redact_pii(f"Before {sensitive}; after.")
    assert len(findings) >= 2
    assert redacted == f"Before {expected}; after."
    assert redacted.count("[REDACTED_") == expected.count("[REDACTED_")
    assert "SyntheticOnly" not in redacted
    assert SYNTHETIC_JWT not in redacted


def test_private_key_overlapping_nested_secrets_is_fully_redacted():
    block = (
        f"-----BEGIN PRIVATE KEY-----\n{EMAIL}\napi_key={SYNTHETIC_PROVIDER_AND_JWT}\n"
        "-----END PRIVATE KEY-----"
    )
    redacted, findings = detect_and_redact_pii(f"Before\n{block}\nAfter")
    assert {finding.entity_type for finding in findings} == {
        "PRIVATE_KEY", "EMAIL", "ASSIGNED_SECRET", "OPENAI_API_KEY", "JWT",
    }
    assert redacted == "Before\n[REDACTED_ASSIGNED_SECRET_EMAIL_JWT_OPENAI_API_KEY_PRIVATE_KEY]\nAfter"


def test_separate_findings_preserve_separators():
    text = "alice@example.test,bob@example.test;api_key=synthetic_one;password=synthetic_two"
    redacted, _ = detect_and_redact_pii(text)
    assert redacted == "[REDACTED_EMAIL],[REDACTED_EMAIL];api_key=[REDACTED_ASSIGNED_SECRET];password=[REDACTED_ASSIGNED_SECRET]"


def test_empty_input_has_no_findings_and_is_unchanged():
    assert detect_pii("") == []
    assert detect_and_redact_pii("") == ("", [])


@pytest.mark.parametrize("detector", [detect_pii, detect_and_redact_pii])
@pytest.mark.parametrize("value", [None, 123, 1.5, False, [], {}, b"synthetic"])
def test_invalid_input_type_raises_type_error(detector, value):
    with pytest.raises(TypeError, match="Input must be a string"):
        detector(value)
