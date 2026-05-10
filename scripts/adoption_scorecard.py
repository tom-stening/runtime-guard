#!/usr/bin/env python3
"""Generate an adoption scorecard from team rollout JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from runtime_guard import build_adoption_scorecard


def _load_records(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise ValueError("Input JSON must be a list of team records")
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Build runtime-guard adoption scorecard")
    parser.add_argument("--input", required=True, help="Path to JSON array of team records")
    parser.add_argument("--output", help="Optional path to write scorecard JSON")
    parser.add_argument(
        "--success-stage",
        default="production",
        help="Stage counted as adopted (default: production)",
    )
    args = parser.parse_args()

    records = _load_records(Path(args.input))
    scorecard = build_adoption_scorecard(records, success_stage=args.success_stage)
    rendered = json.dumps(scorecard, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
