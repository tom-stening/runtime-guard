#!/usr/bin/env python3
"""Evaluate workshop certification outcomes for TRAINING_CURRICULUM.md."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_attendees(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise ValueError("attendees JSON must be a list")
    out: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"attendees[{idx}] must be a JSON object")
        out.append(dict(item))
    return out


def _strict_non_negative_int(value: Any) -> tuple[int, bool]:
    if isinstance(value, bool):
        return 0, False
    if isinstance(value, int) and value >= 0:
        return value, True
    return 0, False


def _strict_bool(value: Any) -> tuple[bool, bool]:
    if isinstance(value, bool):
        return value, True
    return False, False


def _strict_number(value: Any) -> tuple[float, bool]:
    if isinstance(value, bool):
        return 0.0, False
    if isinstance(value, (int, float)):
        return float(value), True
    return 0.0, False


def _attendee_name(record: dict[str, Any], index: int) -> tuple[str, bool]:
    fallback = f"attendee-{index}"

    raw_name = record.get("name")
    if raw_name is not None:
        if isinstance(raw_name, str) and raw_name.strip():
            return raw_name.strip(), True
        return fallback, False

    raw_id = record.get("id")
    if raw_id is not None:
        if isinstance(raw_id, str) and raw_id.strip():
            return raw_id.strip(), True
        return fallback, False

    return fallback, True


def _evaluate_attendee(
    record: dict[str, Any],
    *,
    required_labs: int,
    min_score: float,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []

    labs_completed, labs_ok = _strict_non_negative_int(record.get("labs_completed", 0))
    if not labs_ok:
        errors.append("labs_completed must be a non-negative integer")

    capstone_submitted, capstone_ok = _strict_bool(record.get("capstone_submitted", False))
    if not capstone_ok:
        errors.append("capstone_submitted must be boolean")

    framework_demo, framework_ok = _strict_bool(record.get("framework_demo", False))
    if not framework_ok:
        errors.append("framework_demo must be boolean")

    automation_demo, automation_ok = _strict_bool(record.get("automation_demo", False))
    if not automation_ok:
        errors.append("automation_demo must be boolean")

    score, score_ok = _strict_number(record.get("assessment_score", 0.0))
    if not score_ok:
        errors.append("assessment_score must be numeric")

    passed = (
        labs_completed >= required_labs
        and capstone_submitted
        and framework_demo
        and automation_demo
        and score >= min_score
        and not errors
    )

    return {
        "passed": passed,
        "labs_completed": labs_completed,
        "assessment_score": score,
        "capstone_submitted": capstone_submitted,
        "framework_demo": framework_demo,
        "automation_demo": automation_demo,
    }, errors


def _passed(record: dict[str, Any], *, required_labs: int, min_score: float) -> bool:
    evaluated, _errors = _evaluate_attendee(
        record,
        required_labs=required_labs,
        min_score=min_score,
    )
    passed_value, passed_ok = _strict_bool(evaluated.get("passed", False))
    return passed_value if passed_ok else False


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    attendees = getattr(args, "attendees", "")
    if not isinstance(attendees, str) or not attendees.strip():
        errors.append("--attendees must be a non-empty string path")

    required_labs = getattr(args, "required_labs", 0)
    if not isinstance(required_labs, int) or isinstance(required_labs, bool):
        errors.append("--required-labs must be an integer >= 1")

    min_score = getattr(args, "min_score", 0)
    if isinstance(min_score, bool) or not isinstance(min_score, (int, float)):
        errors.append("--min-score must be a number between 0 and 100")

    output = getattr(args, "output", None)
    if output is not None and not isinstance(output, str):
        errors.append("--output must be a string path")

    fail_on_gaps = getattr(args, "fail_on_gaps", False)
    if not isinstance(fail_on_gaps, bool):
        errors.append("--fail-on-gaps flag must be boolean")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Build training certification readiness report")
    parser.add_argument(
        "--attendees",
        required=True,
        help="Path to JSON array of attendee certification records",
    )
    parser.add_argument(
        "--required-labs",
        type=int,
        default=5,
        help="Required number of completed labs (default: 5)",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=80.0,
        help="Minimum assessment score required for certification (default: 80)",
    )
    parser.add_argument("--output", help="Optional path to write report JSON")
    parser.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help="Exit 1 when any attendee fails certification criteria",
    )
    args = parser.parse_args()

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    if args.required_labs < 1:
        print("error: --required-labs must be >= 1", file=sys.stderr)
        return 2
    if args.min_score < 0 or args.min_score > 100:
        print("error: --min-score must be between 0 and 100", file=sys.stderr)
        return 2

    try:
        attendees = _load_attendees(Path(args.attendees))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, Any]] = []
    for idx, attendee in enumerate(attendees, start=1):
        name, name_ok = _attendee_name(attendee, idx)
        evaluated, validation_errors = _evaluate_attendee(
            attendee,
            required_labs=args.required_labs,
            min_score=args.min_score,
        )
        if not name_ok:
            validation_errors = list(validation_errors) + [
                "name/id must be a non-empty string when provided"
            ]
        passed_value, passed_ok = _strict_bool(evaluated.get("passed", False))
        if not passed_ok:
            validation_errors = list(validation_errors) + ["passed must be boolean"]
        final_passed = passed_value if passed_ok else False
        if not name_ok:
            final_passed = False
        results.append(
            {
                "name": name,
                "passed": final_passed,
                "labs_completed": evaluated.get("labs_completed", 0),
                "assessment_score": evaluated.get("assessment_score", 0.0),
                "capstone_submitted": evaluated.get("capstone_submitted", False),
                "framework_demo": evaluated.get("framework_demo", False),
                "automation_demo": evaluated.get("automation_demo", False),
                "validation_errors": validation_errors,
            }
        )

    passed_attendees = [r for r in results if r["passed"]]
    failed_attendees = [r for r in results if not r["passed"]]

    report = {
        "total_attendees": len(results),
        "passed_attendees": len(passed_attendees),
        "failed_attendees": len(failed_attendees),
        "pass_rate": (len(passed_attendees) / len(results)) if results else 0.0,
        "required_labs": args.required_labs,
        "min_score": args.min_score,
        "all_certified": len(failed_attendees) == 0,
        "attendees": results,
    }

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on_gaps and not report["all_certified"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
