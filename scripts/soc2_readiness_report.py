#!/usr/bin/env python3
"""Generate SOC2 readiness output from control/evidence JSON inputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from runtime_guard import soc2_readiness_report


def _load_json(path: Path, *, expected: str) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"{expected} JSON must be an object")
    return dict(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build runtime-guard SOC2 readiness report")
    parser.add_argument("--controls", required=True, help="Path to JSON object of control statuses")
    parser.add_argument(
        "--required-controls",
        help="Optional path to JSON object of required controls (id -> description)",
    )
    parser.add_argument(
        "--evidence",
        required=True,
        help="Path to JSON object mapping control IDs to evidence artifact lists",
    )
    parser.add_argument("--output", help="Optional path to write readiness JSON")
    parser.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help="Exit 1 when report status is not ready",
    )
    args = parser.parse_args()

    try:
        controls = _load_json(Path(args.controls), expected="controls")
        evidence = _load_json(Path(args.evidence), expected="evidence")
        required_controls = (
            _load_json(Path(args.required_controls), expected="required-controls")
            if args.required_controls
            else None
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = soc2_readiness_report(
        controls,
        evidence_state=evidence,
        required_controls=required_controls,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on_gaps and str(report.get("status", "")).strip().lower() != "ready":
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
