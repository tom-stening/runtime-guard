#!/usr/bin/env python3
"""Aggregate runtime-guard worker reports from a JSONL transport file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from runtime_guard import aggregate_worker_reports_jsonl


def _strict_non_negative_int(value: object) -> tuple[int, bool]:
    if isinstance(value, bool):
        return 0, False
    if isinstance(value, int) and value >= 0:
        return value, True
    return 0, False


def _strict_bool(value: object) -> tuple[bool, bool]:
    if isinstance(value, bool):
        return value, True
    return False, False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate runtime-guard worker reports from a JSONL file"
    )
    parser.add_argument("--input", required=True, help="Path to worker report JSONL file")
    parser.add_argument("--output", help="Optional path to write aggregate JSON")
    parser.add_argument(
        "--fail-on-pressure",
        action="store_true",
        help="Return exit code 1 when any worker pressure is detected",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Return exit code 1 when any worker is critical",
    )
    args = parser.parse_args()

    summary = aggregate_worker_reports_jsonl(args.input)
    if not isinstance(summary, dict):
        print("error: aggregated summary payload must be a JSON object", file=sys.stderr)
        return 2
    rendered = json.dumps(summary, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on_critical:
        critical_workers, critical_ok = _strict_non_negative_int(
            summary.get("critical_workers", 0)
        )
        if not critical_ok:
            print(
                "error: summary.critical_workers must be a non-negative integer",
                file=sys.stderr,
            )
            return 2
        if critical_workers > 0:
            return 1

    if args.fail_on_pressure:
        any_pressure, pressure_ok = _strict_bool(summary.get("any_pressure", False))
        if not pressure_ok:
            print("error: summary.any_pressure must be boolean", file=sys.stderr)
            return 2
        if any_pressure:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
