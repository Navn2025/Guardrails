"""Explicit output policy settings; these are not a semantic safety classifier."""

from dataclasses import dataclass
from typing import Literal

MAX_OUTPUT_LENGTH = 20000
BLOCKED_PHRASES = ("SYSTEM_POLICY_VIOLATION_MARKER",)
INTERNAL_MARKERS = ("[INTERNAL_SYSTEM_PROMPT]", "[INTERNAL_DEVELOPER_PROMPT]")


@dataclass(frozen=True)
class OutputPolicy:
    max_length: int = MAX_OUTPUT_LENGTH
    pii_action: Literal["redact", "block"] = "redact"
    blocked_phrases: tuple[str, ...] = BLOCKED_PHRASES
    internal_markers: tuple[str, ...] = INTERNAL_MARKERS
    protected_texts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.max_length, bool) or not isinstance(self.max_length, int):
            raise TypeError("max_length must be an integer.")
        if self.max_length < 1:
            raise ValueError("max_length must be positive.")
        if self.pii_action not in {"redact", "block"}:
            raise ValueError("pii_action must be 'redact' or 'block'.")
        for name in ("blocked_phrases", "internal_markers", "protected_texts"):
            values = getattr(self, name)
            if not isinstance(values, (tuple, list)):
                raise TypeError(f"{name} must be a sequence of strings.")
            if any(not isinstance(value, str) or not any(c.isalnum() for c in value) for value in values):
                raise ValueError(f"{name} must contain nonempty text entries.")
            object.__setattr__(self, name, tuple(values))
