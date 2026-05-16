#!/usr/bin/env python3
"""Parent-side worker aggregation CLI for process pool orchestration.

Workers write pressure reports via ``append_worker_report_jsonl()``.  This
script reads those reports from a JSONL file, aggregates them, and prints a
JSON summary.  Exit code is non-zero when pressure thresholds are exceeded,
making it suitable for CI/ops gating.

Usage
-----
    python scripts/aggregate_workers.py --input /tmp/workers.jsonl
    python scripts/aggregate_workers.py --input /tmp/workers.jsonl --fail-on-pressure
    python scripts/aggregate_workers.py --input /tmp/workers.jsonl --fail-on-critical

Exit codes
----------
0  No pressure detected (or threshold not exceeded).
1  Pressure detected when ``--fail-on-pressure`` or ``--fail-on-critical`` is active.
2  Input file not found or unreadable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def _find_package() -> None:
    """Add the repo src/ to sys.path so the script works from the repo root."""
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(here, "..", "src")
    if src not in sys.path:
        sys.path.insert(0, src)


_find_package()

from runtime_guard import aggregate_worker_reports_jsonl  # noqa: E402


def _strict_bool(value: object) -> tuple[bool, bool]:
    if isinstance(value, bool):
        return value, True
    return False, False


def _strict_non_negative_int(value: object) -> tuple[int, bool]:
    if isinstance(value, bool):
        return 0, False
    if isinstance(value, int) and value >= 0:
        return value, True
    return 0, False


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

    for field in ["fail_on_pressure", "fail_on_critical", "pretty"]:
        value = getattr(args, field, False)
        if not isinstance(value, bool):
            errors.append(f"--{field.replace('_', '-')} flag must be boolean")

    return errors


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aggregate_workers",
        description="Aggregate worker pressure reports from a JSONL file.",
    )
    p.add_argument(
        "--input",
        "-i",
        required=True,
        metavar="PATH",
        help="Path to the JSONL worker-reports file produced by append_worker_report_jsonl().",
    )
    p.add_argument(
        "--fail-on-pressure",
        action="store_true",
        help="Exit 1 if any worker reported pressure (warning or critical).",
    )
    p.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit 1 if any worker reported critical pressure (default gate).",
    )
    p.add_argument(
        "--output",
        "-o",
        metavar="PATH",
        help="Write JSON summary to this file instead of stdout.",
    )
    p.add_argument(
        "--pretty",
        action="store_true",
        default=False,
        help="Pretty-print JSON output (default: compact).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    path = os.path.expanduser(args.input)
    if not os.path.exists(path):
        print(f"error: input file not found: {path}", file=sys.stderr)
        return 2

    try:
        summary = aggregate_worker_reports_jsonl(path)
    except OSError as exc:
        print(f"error: could not read {path}: {exc}", file=sys.stderr)
        return 2

    if not isinstance(summary, dict):
        print("error: aggregated summary payload must be a JSON object", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    output_text = json.dumps(summary, indent=indent, separators=(None if indent else (",", ":")))

    if args.output:
        out_path = os.path.expanduser(args.output)
        parent = os.path.dirname(out_path)
        if parent:
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as exc:
                print(f"error: could not create output directory {parent}: {exc}", file=sys.stderr)
                return 2
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(output_text + "\n")
        except OSError as exc:
            print(f"error: could not write {out_path}: {exc}", file=sys.stderr)
            return 2
        print(f"Summary written to {out_path}", file=sys.stderr)
    else:
        print(output_text)

    # Gating logic
    if args.fail_on_pressure or args.fail_on_critical:
        summary_errors = _validate_summary_gate_fields(summary)
        if summary_errors:
            for row in summary_errors:
                print(f"error: {row}", file=sys.stderr)
            return 2

    if args.fail_on_pressure:
        any_pressure, _ = _strict_bool(summary.get("any_pressure", False))
        pressured_workers, _ = _strict_non_negative_int(summary.get("pressured_workers", 0))
        total_workers, _ = _strict_non_negative_int(summary.get("total_workers", 0))

        if any_pressure:
            print(
                f"FAIL: {pressured_workers} of {total_workers} "
                "worker(s) reported pressure.",
                file=sys.stderr,
            )
            return 1

    if args.fail_on_critical:
        critical_workers, _ = _strict_non_negative_int(summary.get("critical_workers", 0))
        total_workers, _ = _strict_non_negative_int(summary.get("total_workers", 0))

        if critical_workers > 0:
            print(
                f"FAIL: {critical_workers} of {total_workers} "
                "worker(s) reported critical pressure.",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
