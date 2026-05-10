#!/usr/bin/env python3
"""Generate an adoption scorecard from team rollout JSON."""

from __future__ import annotations

import argparse
import json
import sys
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


def _normalize_records(
    rows: list[dict[str, Any]],
    *,
    strict: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    normalized: list[dict[str, Any]] = []
    warnings: list[str] = []

    for idx, row in enumerate(rows, start=1):
        out = dict(row)

        team_name = str(out.get("team") or out.get("name") or "").strip()
        if team_name == "":
            msg = f"record[{idx}] missing team/name"
            if strict:
                raise ValueError(msg)
            warnings.append(msg)
            team_name = f"unknown-team-{idx}"
        out["team"] = team_name

        stage = str(out.get("stage") or "discover").strip().lower()
        if stage == "":
            stage = "discover"
        out["stage"] = stage

        evidence_raw = out.get("evidence", [])
        if evidence_raw is None:
            evidence_raw = []
        if not isinstance(evidence_raw, list):
            if strict:
                raise ValueError(f"record[{idx}] evidence must be a list when provided")
            warnings.append(f"record[{idx}] evidence was not a list; coerced to []")
            evidence_raw = []
        out["evidence"] = [str(item).strip() for item in evidence_raw if str(item).strip() != ""]

        normalized.append(out)

    return normalized, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Build runtime-guard adoption scorecard")
    parser.add_argument("--input", required=True, help="Path to JSON array of team records")
    parser.add_argument("--output", help="Optional path to write scorecard JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on malformed records (missing team/name or invalid evidence type)",
    )
    parser.add_argument(
        "--success-stage",
        default="production",
        help="Stage counted as adopted (default: production)",
    )
    args = parser.parse_args()

    try:
        records = _load_records(Path(args.input))
        records, warnings = _normalize_records(records, strict=bool(args.strict))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if warnings:
        for msg in warnings:
            print(f"warning: {msg}", file=sys.stderr)

    scorecard = build_adoption_scorecard(records, success_stage=args.success_stage)
    scorecard["input_records"] = len(records)
    scorecard["validation_warnings"] = list(warnings)
    rendered = json.dumps(scorecard, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
