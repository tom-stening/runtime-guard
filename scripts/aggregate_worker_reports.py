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


def _validate_summary_gate_fields(summary: dict[str, object]) -> list[str]:
    errors: list[str] = []

    any_pressure, pressure_ok = _strict_bool(summary.get("any_pressure", False))
    if not pressure_ok:
        errors.append("summary.any_pressure must be boolean")

    pressured_workers, pressured_ok = _strict_non_negative_int(
        summary.get("pressured_workers", 0)
    )
    if not pressured_ok:
        errors.append("summary.pressured_workers must be a non-negative integer")

    critical_workers, critical_ok = _strict_non_negative_int(summary.get("critical_workers", 0))
    if not critical_ok:
        errors.append("summary.critical_workers must be a non-negative integer")

    total_workers, total_ok = _strict_non_negative_int(summary.get("total_workers", 0))
    if not total_ok:
        errors.append("summary.total_workers must be a non-negative integer")

    if pressure_ok and pressured_ok:
        if any_pressure and pressured_workers == 0:
            errors.append("summary.any_pressure=true requires pressured_workers > 0")
        if (not any_pressure) and pressured_workers > 0:
            errors.append("summary.any_pressure=false requires pressured_workers == 0")

    if pressured_ok and total_ok and pressured_workers > total_workers:
        errors.append("summary.pressured_workers cannot exceed total_workers")

    if critical_ok and total_ok and critical_workers > total_workers:
        errors.append("summary.critical_workers cannot exceed total_workers")

    if critical_ok and pressured_ok and critical_workers > pressured_workers:
        errors.append("summary.critical_workers cannot exceed pressured_workers")

    return errors


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    input_path = getattr(args, "input", "")
    if not isinstance(input_path, str) or not input_path.strip():
        errors.append("--input must be a non-empty string path")

    output_path = getattr(args, "output", None)
    if output_path is not None:
        if not isinstance(output_path, str) or not output_path.strip():
            errors.append("--output must be a non-empty string path")

    for field in ["fail_on_pressure", "fail_on_critical"]:
        value = getattr(args, field, False)
        if not isinstance(value, bool):
            errors.append(f"--{field.replace('_', '-')} flag must be boolean")

    return errors


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

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    input_path = Path(args.input).expanduser()
    if not input_path.exists():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    summary = aggregate_worker_reports_jsonl(str(input_path))
    if not isinstance(summary, dict):
        print("error: aggregated summary payload must be a JSON object", file=sys.stderr)
        return 2
    rendered = json.dumps(summary, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on_pressure or args.fail_on_critical:
        summary_errors = _validate_summary_gate_fields(summary)
        if summary_errors:
            for row in summary_errors:
                print(f"error: {row}", file=sys.stderr)
            return 2

    if args.fail_on_critical:
        critical_workers, _ = _strict_non_negative_int(summary.get("critical_workers", 0))
        if critical_workers > 0:
            return 1

    if args.fail_on_pressure:
        any_pressure, _ = _strict_bool(summary.get("any_pressure", False))
        if any_pressure:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
