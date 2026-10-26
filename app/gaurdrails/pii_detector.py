import re
from dataclasses import dataclass

import phonenumbers


# ============================================================
# DATA MODEL
# ============================================================

@dataclass(frozen=True)
class PIIFinding:
    entity_type: str
    start: int
    end: int


# ============================================================
# REGEX PATTERNS
# ============================================================

# Email addresses
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![\w-]|\.[A-Za-z0-9])"
)


# Credit card candidates.
# Luhn validation is applied separately.
CREDIT_CARD_PATTERN = re.compile(
    r"(?<!\d)"
    r"(?:\d[ -]?){12,18}\d"
    r"(?!\d)"
)


# Secrets assigned to recognizable names, for example:
# api_key=...
# access_token: ...
# password = ...
# client_secret=...
#
# Avoid matching empty values or ordinary placeholder strings.
ASSIGNED_SECRET_PATTERN = re.compile(
    r"""
    (?<![\w-])
    (?P<key_quote>["']?)
    (?P<key>
        (?:[a-z][a-z0-9]*[_-])*
        (?:
            api[_-]?key
            | access[_-]?token
            | refresh[_-]?token
            | auth[_-]?token
            | token
            | client[_-]?secret
            | client[_-]?password
            | password
            | passwd
            | secret
            | secret[_-]?key
            | private[_-]?key
        )
    )
    (?P=key_quote)
    (?![\w-])
    [ \t]*
    (?P<separator>[:=])
    [ \t]*
    (?P<value>
        "(?P<double>(?:\\[^\r\n]|[^"\\\r\n])*)"
        | '(?P<single>(?:\\[^\r\n]|[^'\\\r\n])*)'
        | "(?P<unclosed_double>(?:\\[^\r\n]|[^"\\\r\n])*)(?=\r?$)
        | '(?P<unclosed_single>(?:\\[^\r\n]|[^'\\\r\n])*)(?=\r?$)
        | (?P<bare>(?!["'])[^\s,;{}\[\]()]+)
    )
    """,
    flags=re.IGNORECASE | re.VERBOSE | re.MULTILINE,
)


# Common provider-specific key formats.
OPENAI_KEY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"
    r"(?![A-Za-z0-9_-])"
)

GITHUB_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:"
    r"github_pat_[A-Za-z0-9_]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r")"
    r"(?![A-Za-z0-9_])"
)

AWS_ACCESS_KEY_PATTERN = re.compile(
    r"(?<![A-Z0-9])"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"(?![A-Z0-9])"
)


# Bearer tokens in HTTP headers or text.
BEARER_TOKEN_PATTERN = re.compile(
    r"(?i)\bBearer\s+"
    r"([A-Za-z0-9._~+/=-]+)"
)


# JWT-like strings: header.payload.signature
JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{5,}"
    r"\."
    r"[A-Za-z0-9_-]{5,}"
    r"\."
    r"[A-Za-z0-9_-]{5,}"
    r"(?![A-Za-z0-9_-])"
)


# PEM private-key blocks.
# Matches from a recognized private-key header through its footer,
# or through the end of the text if the footer is missing.
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?P<key_type>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
    r".*?"
    r"(?:-----END (?P=key_type)-----|\Z)",
    re.DOTALL,
)


# ============================================================
# CREDIT CARD VALIDATION
# ============================================================

def passes_luhn(number: str) -> bool:
    """
    Return True if the digit sequence passes the Luhn checksum.

    This validates the checksum, not whether the card exists,
    is active, or belongs to a particular person.
    """
    digits = [int(char) for char in number if char.isdigit()]

    if not 13 <= len(digits) <= 19:
        return False

    checksum = 0

    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2

            if digit > 9:
                digit -= 9

        checksum += digit

    return checksum % 10 == 0


# ============================================================
# PHONE NUMBER DETECTION
# ============================================================

def detect_phone_numbers(
    text: str,
    default_region: str = "IN",
) -> list[PIIFinding]:
    """
    Detect valid phone numbers in free text using Google's
    libphonenumber data through the phonenumbers Python package.

    International numbers can include a country calling code,
    for example +1 or +91.

    Numbers without a country calling code are interpreted using
    default_region. The default is India ("IN").
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    findings: list[PIIFinding] = []

    for match in phonenumbers.PhoneNumberMatcher(
        text,
        default_region,
    ):
        if phonenumbers.is_valid_number(match.number):
            findings.append(
                PIIFinding(
                    entity_type="PHONE_NUMBER",
                    start=match.start,
                    end=match.end,
                )
            )

    return findings


# ============================================================
# GENERAL PII DETECTION
# ============================================================

def detect_pii(
    text: str,
    default_region: str = "IN",
) -> list[PIIFinding]:
    """
    Detect PII and common secrets in text.

    Returns findings containing entity type and character offsets.
    It does not return the matched sensitive values.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    findings: list[PIIFinding] = []

    def add_matches(
        pattern: re.Pattern,
        entity_type: str,
        group: int = 0,
    ) -> None:
        """Add regex matches as findings."""
        for match in pattern.finditer(text):
            start, end = match.span(group)

            if start < end:
                findings.append(
                    PIIFinding(
                        entity_type=entity_type,
                        start=start,
                        end=end,
                    )
                )

    # --------------------------------------------------------
    # 1. Email addresses
    # --------------------------------------------------------

    add_matches(EMAIL_PATTERN, "EMAIL")

    # --------------------------------------------------------
    # 2. Phone numbers
    # --------------------------------------------------------

    findings.extend(
        detect_phone_numbers(
            text,
            default_region=default_region,
        )
    )

    # --------------------------------------------------------
    # 3. Credit cards: require Luhn validation
    # --------------------------------------------------------

    for match in CREDIT_CARD_PATTERN.finditer(text):
        candidate = match.group()

        if passes_luhn(candidate):
            findings.append(
                PIIFinding(
                    entity_type="CREDIT_CARD",
                    start=match.start(),
                    end=match.end(),
                )
            )

    # --------------------------------------------------------
    # 4. Assigned secrets
    # --------------------------------------------------------

    for match in ASSIGNED_SECRET_PATTERN.finditer(text):
        group = next(
            name for name in ("double", "single", "unclosed_double", "unclosed_single", "bare")
            if match.group(name) is not None
        )
        value = match.group(group)

        # Do not flag empty values.
        if not value.strip():
            continue

        # Only bare language literals are placeholders. Quoted nonempty
        # strings and weak passwords such as "changeme" are still secrets.
        if group == "bare" and value.casefold() in {
            "none",
            "null",
            "undefined",
            "nil",
            "true",
            "false",
        }:
            continue

        findings.append(
            PIIFinding(
                entity_type="ASSIGNED_SECRET",
                start=match.start(group),
                end=match.end(group),
            )
        )

    # --------------------------------------------------------
    # 5. Provider-specific API keys
    # --------------------------------------------------------

    add_matches(OPENAI_KEY_PATTERN, "OPENAI_API_KEY")
    add_matches(GITHUB_TOKEN_PATTERN, "GITHUB_TOKEN")
    add_matches(AWS_ACCESS_KEY_PATTERN, "AWS_ACCESS_KEY")

    # --------------------------------------------------------
    # 6. Bearer tokens
    # --------------------------------------------------------

    # Capture only the token, not the word "Bearer".
    add_matches(
        BEARER_TOKEN_PATTERN,
        "BEARER_TOKEN",
        group=1,
    )

    # --------------------------------------------------------
    # 7. JWTs
    # --------------------------------------------------------

    add_matches(JWT_PATTERN, "JWT")

    # --------------------------------------------------------
    # 8. Private keys
    # --------------------------------------------------------

    add_matches(PRIVATE_KEY_PATTERN, "PRIVATE_KEY")

    # --------------------------------------------------------
    # 9. Deduplicate exact matches
    # --------------------------------------------------------

    unique_findings = {
        (finding.entity_type, finding.start, finding.end): finding
        for finding in findings
    }

    # Sort by starting offset, then longer matches first.
    return sorted(
        unique_findings.values(),
        key=lambda finding: (
            finding.start,
            -(finding.end - finding.start),
            finding.entity_type,
        ),
    )


# ============================================================
# REDACTION
# ============================================================

def detect_and_redact_pii(
    text: str,
    default_region: str = "IN",
) -> tuple[str, list[PIIFinding]]:
    """
    Detect sensitive values and redact their original spans.

    Overlapping findings are merged into one redacted span to
    prevent partial exposure of overlapping sensitive data.

    Returns:
        (redacted_text, findings)
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    findings = detect_pii(
        text,
        default_region=default_region,
    )

    if not findings:
        return text, []

    # Sort by start offset and then end offset.
    ordered = sorted(
        findings,
        key=lambda finding: (
            finding.start,
            finding.end,
        ),
    )

    # Merge overlapping spans.
    merged_spans: list[tuple[int, int, set[str]]] = []

    for finding in ordered:
        if not merged_spans:
            merged_spans.append(
                (
                    finding.start,
                    finding.end,
                    {finding.entity_type},
                )
            )
            continue

        previous_start, previous_end, previous_types = merged_spans[-1]

        if finding.start < previous_end:
            # Overlapping findings must be redacted together.
            merged_spans[-1] = (
                previous_start,
                max(previous_end, finding.end),
                previous_types | {finding.entity_type},
            )
        else:
            merged_spans.append(
                (
                    finding.start,
                    finding.end,
                    {finding.entity_type},
                )
            )

    # Replace from right to left so earlier offsets remain valid.
    redacted_text = text

    for start, end, entity_types in reversed(merged_spans):
        label = "_".join(sorted(entity_types))
        replacement = f"[REDACTED_{label}]"

        redacted_text = (
            redacted_text[:start]
            + replacement
            + redacted_text[end:]
        )

    return redacted_text, findings


# ============================================================
# MANUAL TEST
# ============================================================

if __name__ == "__main__":
    sample_text = """
    Contact: alice@example.com
    Indian mobile: +91 98765 43210
    US phone: +1 415 555 2671

    Card: 4532015112830366

    api_key=example_secret_value
    Authorization: Bearer example_token_123456
    AWS key: AKIAIOSFODNN7EXAMPLE

    JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456

    -----BEGIN PRIVATE KEY-----
    EXAMPLE_PRIVATE_KEY_DATA
    -----END PRIVATE KEY-----
    """

    findings = detect_pii(sample_text)

    print("Detected findings:")

    for finding in findings:
        # Do not print matched sensitive values.
        print(
            f"Type={finding.entity_type}, "
            f"Start={finding.start}, "
            f"End={finding.end}"
        )

    redacted_text, _ = detect_and_redact_pii(sample_text)

    print("\nRedacted text:")
    print(redacted_text)
