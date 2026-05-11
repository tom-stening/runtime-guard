#!/usr/bin/env python3
"""Aggregate runtime-guard worker reports from a JSONL transport file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from runtime_guard import aggregate_worker_reports_jsonl


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
    rendered = json.dumps(summary, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on_critical and int(summary.get("critical_workers", 0)) > 0:
        return 1
    if args.fail_on_pressure and bool(summary.get("any_pressure", False)):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
