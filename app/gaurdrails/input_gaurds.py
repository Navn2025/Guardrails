import re
import unicodedata
from .guardrail_result import DetectionResult
from .guardrail_result import GuardrailResult as GuardrailResult
from .guardrail_result import RiskLevel as RiskLevel
from .rules import RULES


def _canonicalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).casefold()
    return "".join(char for char in text if unicodedata.category(char) != "Cf")


def normalize_input(text: str) -> str:
    """Normalize Unicode, invisible formatting, punctuation and whitespace."""
    text = "".join(
        " " if unicodedata.category(char).startswith("P") else char
        for char in _canonicalize(text)
    )
    return " ".join(text.split())

_QUOTED_TEXT = re.compile(r'''"[^"]*"|'[^']*'|“[^”]*”|‘[^’]*’|`[^`]*`''')
_DISCUSSION_PREFIX = re.compile(
    r"(?:please )?(?:"
    r"(?:explain|analyze|analyse|discuss|describe|classify|evaluate)"
    r"(?: (?:why|how))? (?:the|this|an?) (?:phrase|sentence|example|text)"
    r"|what does (?:the|this) (?:phrase|sentence|text)"
    r")"
)
_DISCUSSION_SUFFIX = re.compile(
    r"(?:mean|means|is (?:an? )?(?:prompt injection|attack|"
    r"example of (?:a )?prompt injection|dangerous|unsafe|malicious))?"
)

# Keep prefix/suffix pairs together: allowing an empty prefix must never make
# a bare quoted attack exempt from detection through the English empty suffix.
_DISCUSSION_FRAMES = (
    (_DISCUSSION_PREFIX, _DISCUSSION_SUFFIX),
    (
        re.compile(r"(?:कृपया )?(?:समझाओ|समझाइए|समझाइये|बताओ|बताइए) कि"),
        re.compile(r"(?:प्रॉम्प्ट इंजेक्शन|प्रॉम्पट इंजेक्शन|खतरनाक|असुरक्षित) क्यों है"),
    ),
    (
        re.compile(r""),
        re.compile(r"(?:वाक्य|वाक्यांश|कथन) का (?:अर्थ|मतलब) (?:समझाओ|समझाइए|बताओ|बताइए)"),
    ),
    (
        re.compile(r"(?:please |kripya )?(?:samjhao|samjhaiye|batao|bataiye) ki"),
        re.compile(r"(?:prompt injection|khatarnak|unsafe) (?:kyun|kyon) hai"),
    ),
    (
        re.compile(r""),
        re.compile(r"(?:vaakya|vakya|phrase|sentence) ka (?:matlab|arth) (?:samjhao|batao)"),
    ),
)


def _mask_discussed_quote(text: str) -> str:
    """Exclude one quoted example only in a complete educational question.

    Bare quotes, execution requests, and extra instructions retain their
    contents for detection. Both surrounding parts must match the restricted
    discussion grammar; an educational keyword alone grants no exception.
    """
    quotes = list(_QUOTED_TEXT.finditer(text))
    if len(quotes) != 1:
        return text
    quote = quotes[0]
    before, after = text[:quote.start()], text[quote.end():]
    normalized_before, normalized_after = normalize_input(before), normalize_input(after)
    if any(
        prefix.fullmatch(normalized_before) and suffix.fullmatch(normalized_after)
        for prefix, suffix in _DISCUSSION_FRAMES
    ):
        return before + " " + after
    return text


def detect_prompt_injection(text: str) -> DetectionResult:
    """
    Return the first enabled matching rule for English, Hindi or Hinglish.

    A restricted educational question may quote an attack for discussion.
    No match returns detected=False, no rule metadata, and low risk.
    This rule-based detector is not a comprehensive prompt-injection defense.
    """
    normalized_text = normalize_input(_mask_discussed_quote(_canonicalize(text)))
    for rule in RULES:
        if rule.enabled and rule.pattern.search(normalized_text) is not None:
            return DetectionResult(True, rule.rule_id, rule.category, rule.risk_level)
    return DetectionResult(False, None, None, "low")

MAX_INPUT_LENGTH = 10000

def validate_input(text: object) -> GuardrailResult:
    """
    Analyze user input and return a structured decision.

    Reject invalid types and empty input before checking the raw character
    limit, then check the normalized text for known injection phrases.
    """
    if not isinstance(text, str):
        return GuardrailResult(
            allowed=False,
            reason="invalid_input_type",
            risk_level="low"
        )
    if not text.strip():
        return GuardrailResult(
            allowed=False,
            reason="empty_input",
            risk_level="low"
        )
    if len(text) > MAX_INPUT_LENGTH:
        return GuardrailResult(
            allowed=False,
            reason="input_too_long",
            risk_level="medium"
        )
    detection = detect_prompt_injection(text)
    if detection.detected:
        return GuardrailResult(
            allowed=False,
            reason="prompt_injection",
            risk_level=detection.risk_level,
            rule_id=detection.rule_id,
            category=detection.category
        )
    return GuardrailResult(
        allowed=True,
        reason=None,
        risk_level="low"
    )

