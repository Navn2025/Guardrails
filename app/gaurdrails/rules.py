"""Central injection registry. IDs are local, stable implementation identifiers.

Patterns expect normalize_input() output. Registry order breaks ties when more
than one enabled rule matches. Hindi rules use whitespace boundaries because
Python's word boundaries can split Devanagari combining marks.
"""

import re
import unicodedata
from dataclasses import dataclass

from .guardrail_result import RiskLevel


@dataclass(frozen=True)
class GuardrailRule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    risk_level: RiskLevel = "high"
    enabled: bool = True


_ENGLISH_OVERRIDE = (
    r"\b(?:ignore|disregard|forget|override|bypass)\s+"
    r"(?:(?:all|any|the|your)\s+)*"
    r"(?:(?:previous|prior|earlier|system|original|initial|hidden)\s+)+"
    r"(?:instructions?|directions?|rules?|prompts?)\b"
)
_ENGLISH_EXTRACTION = (
    r"\b(?:reveal|disclose|show|print|expose|repeat|output|share)\s+"
    r"(?:me\s+)?(?:(?:all|the|your|full|entire|original|initial)\s+)*"
    r"(?:system|hidden|internal|developer)\s+(?:prompts?|instructions?|rules?)\b"
)

_HINDI_INSTRUCTION = (
    r"(?:निर्देश(?:ों)?|हिदायत(?:ें|ों)?|नियम(?:ों)?|प्रॉम्प्ट|प्रॉम्पट|प्रोम्प्ट|"
    r"instructions?|directions?|rules?|prompts?)"
)
_HINDI_SECRET_CONTEXT = (
    r"(?:सिस्टम|डेवलपर|गुप्त|छिपे|छिपी|छिपा|आंतरिक|असली|मूल|"
    r"system|developer|hidden|internal)"
)
_HINDI_OVERRIDE_CONTEXT = (
    r"(?:पुराने|पुरानी|पुराना|पिछले|पिछली|पिछला|पूर्व|पहले|शुरुआती|प्रारंभिक|"
    r"अपने|अपनी|अपना|तुम्हारे|आपके|previous|prior|earlier|your|"
    + _HINDI_SECRET_CONTEXT + r")"
)
_HINDI_CONTEXT_GAP = (
    r"(?:\s+(?:के|की|का|में|लिखे|लिखी|हुए|हुई|सभी|सारे|सारी|all|the|your)){0,5}\s+"
)
_HINDI_ACTION_GAP = (
    r"(?:\s+(?:को|मुझे|हमें|उन्हें|उन्हे|दिए|दिये|गए|गये|हैं|है|बिल्कुल|वैसे|ही|"
    r"पूरा|पूरे|पूरी|तरह|से|अब|यहाँ|भी)){0,12}\s+"
)
_HINDI_DO = r"(?:करो|करें|करिए|करिये|कीजिए|कीजिये|कर|करके)"
_HINDI_OVERRIDE_ACTION = (
    rf"(?:(?:अनदेखा|नज़रअंदाज़|नजरअंदाज|नज़रअंदाज|नजरअंदाज़|दरकिनार)\s+{_HINDI_DO}"
    r"|भूल\s+(?:जाओ|जाइए|जाइये|जाएं|जाएँ)"
    rf"|(?:ignore|disregard|forget|override|bypass)(?:\s+{_HINDI_DO})?)"
)
_HINDI_EXTRACTION_ACTION = (
    r"(?:बताओ|बताएं|बताएँ|बताइए|बताइये|दिखाओ|दिखाएं|दिखाएँ|दिखाइए|दिखाइये|"
    r"दोहराओ|दोहराएं|दोहराएँ|दोहराइए|दोहराइये|"
    r"बता\s+(?:दो|दें|दीजिए)|"
    rf"(?:उजागर|प्रकट|प्रिंट|साझा|लीक)\s+{_HINDI_DO}|"
    rf"छिपाना\s+बंद\s+{_HINDI_DO}|"
    rf"(?:reveal|disclose|show|print|repeat|share)(?:\s+{_HINDI_DO})?)"
)
_HINDI_SECRET_TARGET = _HINDI_SECRET_CONTEXT + _HINDI_CONTEXT_GAP + _HINDI_INSTRUCTION
_HINDI_OVERRIDE_TARGET = _HINDI_OVERRIDE_CONTEXT + _HINDI_CONTEXT_GAP + _HINDI_INSTRUCTION
_HINDI_LEADING_GAP = r"(?:\s+(?:अपने|अपनी|अपना|तुम्हारे|आपके|मुझे|the|your|me)){0,3}\s+"

_HINGLISH_INSTRUCTION = (
    r"(?:nirdesh(?:on)?|hidayat(?:ein|en|on)?|niyam(?:on)?|instructions?|directions?|rules?|prompts?)"
)
_HINGLISH_SECRET_CONTEXT = (
    r"(?:system|developer|hidden|internal|secret|gupt|chhipe|chhipa|chhipi|chhupe|chhupa|asli|mool)"
)
_HINGLISH_OVERRIDE_CONTEXT = (
    r"(?:pichle|pichhle|pichli|pichhli|purane|purani|purana|pehle|pahle|shuruati|shuruaati|"
    r"apne|apni|apna|tumhare|aapke|previous|prior|earlier|your|"
    + _HINGLISH_SECRET_CONTEXT + r")"
)
_HINGLISH_CONTEXT_GAP = (
    r"(?:\s+(?:ke|ki|ka|mein|me|likhe|likhi|hue|hui|sab|sabhi|saare|sare|saari|sari|"
    r"all|the|your)){0,5}\s+"
)
_HINGLISH_ACTION_GAP = (
    r"(?:\s+(?:ko|mujhe|humein|hamein|unhe|unhein|diye|gaye|hain|hai|bilkul|waise|hi|"
    r"poora|pura|poore|pure|poori|puri|tarah|se|ab|yahan|bhi)){0,12}\s+"
)
_HINGLISH_DO = r"(?:karo|karein|karen|kariye|kijiye|kar|karke)"
_HINGLISH_OVERRIDE_ACTION = (
    rf"(?:(?:andekha|nazarandaz|nazarandaaz|darkinar)\s+{_HINGLISH_DO}"
    r"|(?:bhool|bhul)\s+(?:jao|jaiye|jayein|jaayein)"
    rf"|(?:ignore|disregard|forget|override|bypass)(?:\s+{_HINGLISH_DO})?)"
)
_HINGLISH_EXTRACTION_ACTION = (
    r"(?:batao|bataiye|batayein|bataein|dikhao|dikhaiye|dikhayein|dohrao|dohraao|"
    r"bata\s+(?:do|dein|dijiye)|"
    rf"(?:ujagar|prakat|saajha|sajha|leak)\s+{_HINGLISH_DO}|"
    rf"(?:reveal|disclose|show|print|repeat|share)(?:\s+{_HINGLISH_DO})?)"
)
_HINGLISH_SECRET_TARGET = (
    _HINGLISH_SECRET_CONTEXT + _HINGLISH_CONTEXT_GAP + _HINGLISH_INSTRUCTION
)
_HINGLISH_OVERRIDE_TARGET = (
    _HINGLISH_OVERRIDE_CONTEXT + _HINGLISH_CONTEXT_GAP + _HINGLISH_INSTRUCTION
)
_HINGLISH_LEADING_GAP = r"(?:\s+(?:apne|apni|apna|tumhare|aapke|mujhe|the|your|me)){0,3}\s+"


def _target_action_pattern(
    target: str, action: str, action_gap: str, leading_gap: str
) -> re.Pattern[str]:
    body = f"(?:{target}{action_gap}{action}|{action}{leading_gap}{target})"
    return re.compile(unicodedata.normalize("NFKC", rf"(?<!\S){body}(?!\S)"))


RULES = (
    GuardrailRule("PI-001", "instruction_override", re.compile(_ENGLISH_OVERRIDE)),
    GuardrailRule("PI-002", "system_prompt_extraction", re.compile(_ENGLISH_EXTRACTION)),
    GuardrailRule(
        "PI-003", "instruction_override",
        _target_action_pattern(
            _HINDI_OVERRIDE_TARGET, _HINDI_OVERRIDE_ACTION, _HINDI_ACTION_GAP, _HINDI_LEADING_GAP
        ),
    ),
    GuardrailRule(
        "PI-004", "system_prompt_extraction",
        _target_action_pattern(
            _HINDI_SECRET_TARGET, _HINDI_EXTRACTION_ACTION, _HINDI_ACTION_GAP, _HINDI_LEADING_GAP
        ),
    ),
    GuardrailRule(
        "PI-005", "instruction_override",
        _target_action_pattern(
            _HINGLISH_OVERRIDE_TARGET, _HINGLISH_OVERRIDE_ACTION,
            _HINGLISH_ACTION_GAP, _HINGLISH_LEADING_GAP,
        ),
    ),
    GuardrailRule(
        "PI-006", "system_prompt_extraction",
        _target_action_pattern(
            _HINGLISH_SECRET_TARGET, _HINGLISH_EXTRACTION_ACTION,
            _HINGLISH_ACTION_GAP, _HINGLISH_LEADING_GAP,
        ),
    ),
)
