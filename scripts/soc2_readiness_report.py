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
        "--evidence",
        required=True,
        help="Path to JSON object mapping control IDs to evidence artifact lists",
    )
    parser.add_argument("--output", help="Optional path to write readiness JSON")
    args = parser.parse_args()

    try:
        controls = _load_json(Path(args.controls), expected="controls")
        evidence = _load_json(Path(args.evidence), expected="evidence")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = soc2_readiness_report(controls, evidence_state=evidence)
    rendered = json.dumps(report, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
