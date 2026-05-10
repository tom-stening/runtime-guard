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

    path = os.path.expanduser(args.input)
    if not os.path.exists(path):
        print(f"error: input file not found: {path}", file=sys.stderr)
        return 2

    try:
        summary = aggregate_worker_reports_jsonl(path)
    except OSError as exc:
        print(f"error: could not read {path}: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    output_text = json.dumps(summary, indent=indent, separators=(None if indent else (",", ":")))

    if args.output:
        out_path = os.path.expanduser(args.output)
        parent = os.path.dirname(out_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(output_text + "\n")
        print(f"Summary written to {out_path}", file=sys.stderr)
    else:
        print(output_text)

    # Gating logic
    if args.fail_on_pressure and summary.get("any_pressure"):
        print(
            f"FAIL: {summary['pressured_workers']} of {summary['total_workers']} "
            "worker(s) reported pressure.",
            file=sys.stderr,
        )
        return 1

    if args.fail_on_critical and summary.get("critical_workers", 0) > 0:
        print(
            f"FAIL: {summary['critical_workers']} of {summary['total_workers']} "
            "worker(s) reported critical pressure.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
