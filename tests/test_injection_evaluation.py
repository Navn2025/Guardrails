import json

import pytest

from input_output_guardrails.app.gaurdrails import evaluation
from input_output_guardrails.app.gaurdrails.guardrail_result import DetectionResult
from input_output_guardrails.app.gaurdrails.input_gaurds import detect_prompt_injection, validate_input

CASES = evaluation.load_cases(evaluation.DEFAULT_DATASET)


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_labeled_case_through_detector_and_validator(case):
    detection = detect_prompt_injection(case["text"])
    assert detection.detected is case["expected_detection"]
    result = validate_input(case["text"])
    assert result.allowed is not case["expected_detection"]
    if detection.detected:
        assert detection.category == case["category"]
        assert result.reason == "prompt_injection"
        assert result.rule_id == detection.rule_id
        assert result.category == detection.category
        assert result.risk_level == detection.risk_level == "high"
    else:
        assert detection.rule_id is result.rule_id is None
        assert detection.category is result.category is None
        assert detection.risk_level == result.risk_level == "low"


def test_starter_dataset_has_unique_ids_and_language_coverage():
    assert len({case["id"] for case in CASES}) == len(CASES)
    assert {"en", "hi", "hinglish", "mixed"} <= {case["language"] for case in CASES}
    for language in {case["language"] for case in CASES}:
        assert {True, False} == {
            case["expected_detection"] for case in CASES if case["language"] == language
        }


def _synthetic_cases():
    return [
        {"text": text, "expected_detection": expected, "category": category}
        for text, expected, category in [
            ("attack-caught", True, "instruction_override"),
            ("attack-missed", True, "instruction_override"),
            ("safe-blocked", False, "harmless_question"),
            ("safe-allowed", False, "harmless_question"),
        ]
    ]


def _detection(detected):
    return (
        DetectionResult(True, "PI-001", "instruction_override", "high")
        if detected else DetectionResult(False, None, None, "low")
    )


def test_confusion_matrix_and_metrics_include_misses_and_false_positives(monkeypatch):
    monkeypatch.setattr(
        evaluation, "detect_prompt_injection",
        lambda text: _detection(text in {"attack-caught", "safe-blocked"}),
    )
    report = evaluation.evaluate_cases(_synthetic_cases())
    assert report["total"] == 4
    for count in ("true_positives", "true_negatives", "false_positives", "false_negatives"):
        assert report[count] == 1
    for metric in ("precision", "recall", "false_positive_rate", "accuracy", "f1"):
        assert report[metric] == 0.5
    assert report["per_rule"]["PI-001"]["true_positives"] == 1
    assert report["per_rule"]["PI-001"]["false_positives"] == 1
    assert report["per_language"]["unspecified"]["total"] == 4
    assert {error["text"] for error in report["errors"]} == {"attack-missed", "safe-blocked"}


def test_block_everything_has_perfect_recall_but_poor_precision(monkeypatch):
    monkeypatch.setattr(evaluation, "detect_prompt_injection", lambda text: _detection(True))
    report = evaluation.evaluate_cases(_synthetic_cases())
    assert report["recall"] == 1.0
    assert report["precision"] == 0.5
    assert report["false_positive_rate"] == 1.0
    assert report["accuracy"] == 0.5
    assert report["f1"] == pytest.approx(2 / 3)


def test_allow_everything_reports_false_negatives_and_undefined_precision(monkeypatch):
    monkeypatch.setattr(evaluation, "detect_prompt_injection", lambda text: _detection(False))
    report = evaluation.evaluate_cases(_synthetic_cases())
    assert report["false_negatives"] == 2
    assert report["true_negatives"] == 2
    assert report["precision"] is None
    assert report["recall"] == report["false_positive_rate"] == report["f1"] == 0.0
    assert report["accuracy"] == 0.5


def test_category_mismatch_is_reported_even_if_attack_is_detected(monkeypatch):
    monkeypatch.setattr(evaluation, "detect_prompt_injection", lambda text: _detection(True))
    cases = [{"text": "extraction", "expected_detection": True, "category": "system_prompt_extraction"}]
    report = evaluation.evaluate_cases(cases)
    assert report["true_positives"] == 1
    assert report["category_mismatches"] == 1
    assert report["errors"][0]["expected_category"] == "system_prompt_extraction"


def test_empty_dataset_has_undefined_metrics_instead_of_claiming_perfect_quality():
    report = evaluation.evaluate_cases([])
    assert report["total"] == 0
    for metric in ("precision", "recall", "false_positive_rate", "accuracy", "f1"):
        assert report[metric] is None


@pytest.mark.parametrize(
    "case",
    [
        None,
        {},
        {"text": "test", "expected_detection": "false", "category": "harmless_question"},
        {"text": 123, "expected_detection": False, "category": "harmless_question"},
        {"text": "test", "expected_detection": False, "category": ""},
        {"text": "test", "expected_detection": False, "category": "harmless_question", "language": 1},
    ],
)
def test_invalid_dataset_labels_are_rejected(case):
    with pytest.raises(ValueError, match="Case 1"):
        evaluation.evaluate_cases([case])


def test_loader_rejects_json_object_instead_of_dataset_array(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"text": "test"}), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON array"):
        evaluation.load_cases(path)
