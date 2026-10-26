"""Structured decisions shared by guardrail detectors and validators."""

from dataclasses import dataclass
from typing import Literal

RiskLevel = Literal["low", "medium", "high"]


@dataclass
class DetectionResult:
    detected: bool
    rule_id: str | None
    category: str | None
    risk_level: RiskLevel


@dataclass
class GuardrailResult:
    allowed: bool
    reason: str | None
    risk_level: RiskLevel
    rule_id: str | None = None
    category: str | None = None
