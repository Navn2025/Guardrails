

import html
import re
import unicodedata
from urllib.parse import unquote
from dataclasses import dataclass

from input_output_guardrails.app.gaurdrails.guardrail_result import RiskLevel
from input_output_guardrails.app.gaurdrails.input_gaurds import normalize_input
from input_output_guardrails.app.gaurdrails.pii_detector import PIIFinding, detect_and_redact_pii, detect_pii
from input_output_guardrails.app.gaurdrails.policies import (
    BLOCKED_PHRASES, INTERNAL_MARKERS, MAX_OUTPUT_LENGTH, OutputPolicy,
)


# ============================================================
# RESULT MODEL
# ============================================================

@dataclass(frozen=True)
class OutputGuardrailResult:
    allowed: bool
    safe_text: str
    reason: str | None = None
    risk_level: RiskLevel = "low"
    findings_count: int = 0
    detected_categories: tuple[str, ...] = ()
    reason_code: str | None = None
    rule_id: str | None = None


# ============================================================
# POLICY VALIDATION
# ============================================================

_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2}))")
_BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _require_text(text: object) -> None:
    if not isinstance(text, str):
        raise TypeError("Output must be a string.")


def _scan_view(text: str) -> str:
    """Decode up to three layers for scanning only; never rewrite display text."""
    def decode_escape(match: re.Match[str]) -> str:
        value = int(next(group for group in match.groups() if group is not None), 16)
        return chr(value) if value <= 0x10FFFF else match.group()

    for _ in range(3):
        decoded = unicodedata.normalize("NFKC", text)
        decoded = _ESCAPE.sub(decode_escape, unquote(html.unescape(decoded)))
        decoded = "".join(c for c in decoded if unicodedata.category(c) != "Cf")
        if decoded == text:
            break
        text = decoded
    return text


def _policy_issue(text: str, policy: OutputPolicy) -> tuple[str, str, str] | None:
    normalized = " " + normalize_input(_scan_view(text)) + " "
    for entries, code, message, rule_id in (
        (policy.blocked_phrases, "output_policy_violation",
         "The response violated a configured output policy.", "OP-001"),
        (policy.internal_markers, "internal_marker",
         "The response contains a configured internal marker.", "OP-002"),
        (policy.protected_texts, "protected_text_leak",
         "The response contains protected internal text.", "OP-003"),
    ):
        for phrase in entries:
            needle = normalize_input(_scan_view(phrase))
            if needle and " " + needle + " " in normalized:
                return code, message, rule_id
    return None


def validate_output_policy(text: str, *, policy: OutputPolicy | None = None) -> str | None:
    """Check explicit policy without banning ordinary discussion of prompts."""
    _require_text(text)
    issue = _policy_issue(text, policy or OutputPolicy())
    return issue[1] if issue else None


# ============================================================
# RESPONSE QUALITY CHECKS
# ============================================================

def _quality_issue(text: str, max_length: int) -> tuple[str, str] | None:
    if len(text) > max_length:
        return "output_too_long", "The model response exceeded the maximum allowed length."
    if "\x00" in text:
        return "invalid_null_character", "The response contains an invalid null character."
    for char in text:
        if unicodedata.category(char) == "Cs":
            return "invalid_unicode", "The response contains invalid Unicode."
        if char in _BIDI_CONTROLS or (unicodedata.category(char) == "Cc" and char not in "\t\r\n"):
            return "unsafe_control_character", "The response contains an unsafe control character."
    if not any(not c.isspace() and unicodedata.category(c) not in {"Cf", "Mn", "Me"} for c in text):
        return "empty_output", "The model returned an empty response."
    return None


def validate_output_quality(text: str, *, max_length: int = MAX_OUTPUT_LENGTH) -> str | None:
    """Check readable content, limits, Unicode, and controls, not factual accuracy."""
    _require_text(text)
    OutputPolicy(max_length=max_length)
    issue = _quality_issue(text, max_length)
    return issue[1] if issue else None


# ============================================================
# OUTPUT GUARDRAILS PIPELINE
# ============================================================

def validate_output(text: str, *, policy: OutputPolicy | None = None) -> OutputGuardrailResult:
    """
    Run output quality checks, policy checks, and PII redaction.

    Order:
      1. Validate the response type.
      2. Check response quality.
      3. Check configured output policies.
      4. Detect and redact PII and secrets.
      5. Return the safe response.
    """
    _require_text(text)
    policy = policy or OutputPolicy()

    # Step 1: Basic response quality checks.
    quality_error = _quality_issue(text, policy.max_length)

    if quality_error:
        return OutputGuardrailResult(
            allowed=False,
            safe_text="",
            reason=quality_error[1],
            reason_code=quality_error[0],
            risk_level="medium",
        )

    # Step 2: Policy checks.
    policy_error = _policy_issue(text, policy)

    if policy_error:
        return OutputGuardrailResult(
            allowed=False,
            safe_text="",
            reason=policy_error[1],
            reason_code=policy_error[0],
            rule_id=policy_error[2],
            risk_level="high",
        )

    # Step 3: Detect and redact PII and supported secrets.
    try:
        redacted_text, findings = detect_and_redact_pii(text)
        if not isinstance(redacted_text, str) or not isinstance(findings, list):
            raise ValueError("Invalid redactor result")
        if any(
            not isinstance(f, PIIFinding) or not isinstance(f.entity_type, str) or not f.entity_type
            or not 0 <= f.start < f.end <= len(text)
            for f in findings
        ):
            raise ValueError("Invalid finding offsets")
        # Encoded/obfuscated values cannot be safely mapped back to original
        # offsets here. Block instead of leaking them or corrupting formatting.
        view = _scan_view(redacted_text)
        remaining = detect_pii(view) if view != redacted_text else []
        if not isinstance(remaining, list) or any(
            not isinstance(f, PIIFinding) or not isinstance(f.entity_type, str) or not f.entity_type
            or not 0 <= f.start < f.end <= len(view)
            for f in remaining
        ):
            raise ValueError("Invalid secondary scan result")
    except Exception:
        return OutputGuardrailResult(
            allowed=False, safe_text="", risk_level="high",
            reason="Sensitive-data scanning failed.", reason_code="pii_scan_failed",
        )

    categories = tuple(sorted({
        finding.entity_type for finding in findings + remaining
    }))

    if remaining or (findings and policy.pii_action == "block"):
        return OutputGuardrailResult(
            allowed=False, safe_text="", risk_level="high",
            reason="The response contains sensitive information.",
            reason_code="obfuscated_sensitive_data" if remaining else "sensitive_data_blocked",
            findings_count=len(findings) + len(remaining), detected_categories=categories,
        )

    sanitized_error = _quality_issue(redacted_text, policy.max_length)
    if sanitized_error:
        return OutputGuardrailResult(
            allowed=False, safe_text="", risk_level="medium",
            reason="The sanitized response failed quality checks.",
            reason_code="sanitized_" + sanitized_error[0],
            findings_count=len(findings), detected_categories=categories,
        )

    final_policy_error = _policy_issue(redacted_text, policy)
    if final_policy_error:
        return OutputGuardrailResult(
            allowed=False, safe_text="", risk_level="high",
            reason_code=final_policy_error[0], reason=final_policy_error[1],
            rule_id=final_policy_error[2], findings_count=len(findings),
            detected_categories=categories,
        )

    # Step 4: Return the sanitized response.
    return OutputGuardrailResult(
        allowed=True,
        safe_text=redacted_text,
        reason=(
            "Sensitive information was redacted."
            if findings
            else None
        ),
        risk_level="medium" if findings else "low",
        findings_count=len(findings),
        detected_categories=categories,
        reason_code="sensitive_data_redacted" if findings else None,
    )


