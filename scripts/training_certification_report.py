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
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
    return out


def _passed(record: dict[str, Any], *, required_labs: int, min_score: float) -> bool:
    labs_completed = int(record.get("labs_completed", 0) or 0)
    capstone_submitted = bool(record.get("capstone_submitted", False))
    framework_demo = bool(record.get("framework_demo", False))
    automation_demo = bool(record.get("automation_demo", False))
    score = float(record.get("assessment_score", 0.0) or 0.0)

    return (
        labs_completed >= required_labs
        and capstone_submitted
        and framework_demo
        and automation_demo
        and score >= min_score
    )


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
        name = str(attendee.get("name") or attendee.get("id") or f"attendee-{idx}").strip()
        passed = _passed(attendee, required_labs=args.required_labs, min_score=args.min_score)
        results.append(
            {
                "name": name,
                "passed": passed,
                "labs_completed": int(attendee.get("labs_completed", 0) or 0),
                "assessment_score": float(attendee.get("assessment_score", 0.0) or 0.0),
                "capstone_submitted": bool(attendee.get("capstone_submitted", False)),
                "framework_demo": bool(attendee.get("framework_demo", False)),
                "automation_demo": bool(attendee.get("automation_demo", False)),
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
