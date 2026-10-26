"""Evaluate a labeled JSON dataset with detection and rule-attribution metrics.

Run: uv run python -m app.gaurdrails.evaluation [dataset.json] [--output report.json]
"""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .input_gaurds import detect_prompt_injection
from .rules import RULES

DEFAULT_DATASET = Path(__file__).resolve().parents[2] / "tests/data/injection_cases.json"
_COUNT_NAMES = ("true_positives", "false_positives", "false_negatives", "true_negatives")


def _new_counts() -> dict[str, int]:
    return dict.fromkeys(_COUNT_NAMES, 0)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _metrics(counts: dict[str, int]) -> dict:
    tp, fp, fn, tn = (counts[name] for name in _COUNT_NAMES)
    total = tp + fp + fn + tn
    return {
        "total": total,
        **counts,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
        "accuracy": _ratio(tp + tn, total),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
    }


def load_cases(path: Path) -> list[dict]:
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list):
        raise ValueError("The evaluation dataset must be a JSON array.")
    return cases


def evaluate_cases(cases: list[dict]) -> dict:
    counts = _new_counts()
    per_language = {}
    per_rule = {
        rule.rule_id: {
            "category": rule.category,
            "enabled": rule.enabled,
            "true_positives": 0,
            "false_positives": 0,
        }
        for rule in RULES
    }
    errors = []
    category_mismatches = 0
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"Case {index} must be a JSON object.")
        text = case.get("text")
        expected = case.get("expected_detection")
        category = case.get("category")
        language = case.get("language", "unspecified")
        case_id = case.get("id", f"case-{index}")
        if (
            not isinstance(text, str)
            or not isinstance(expected, bool)
            or not isinstance(category, str) or not category
            or not isinstance(language, str) or not language
            or not isinstance(case_id, str) or not case_id
        ):
            raise ValueError(
                f"Case {index} needs string text/category, boolean expected_detection, "
                "and nonempty strings for any supplied id/language."
            )
        result = detect_prompt_injection(text)
        if expected:
            outcome = "true_positives" if result.detected else "false_negatives"
        else:
            outcome = "false_positives" if result.detected else "true_negatives"
        counts[outcome] += 1
        per_language.setdefault(language, _new_counts())[outcome] += 1
        if result.detected:
            per_rule[result.rule_id][outcome] += 1

        wrong_category = expected and result.detected and result.category != category
        category_mismatches += int(wrong_category)
        if result.detected != expected or wrong_category:
            errors.append({
                "id": case_id,
                "text": text,
                "language": language,
                "expected_detection": expected,
                "expected_category": category,
                "actual": asdict(result),
            })
    return {
        **_metrics(counts),
        "category_mismatches": category_mismatches,
        "per_rule": per_rule,
        "per_language": {name: _metrics(values) for name, values in per_language.items()},
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, help="Also save the JSON report to this path.")
    args = parser.parse_args()
    try:
        report = evaluate_cases(load_cases(args.dataset))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
