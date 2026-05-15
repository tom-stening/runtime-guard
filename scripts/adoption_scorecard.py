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
    stage_aliases = {
        "discovery": "discover",
        "prod": "production",
    }
    normalized: list[dict[str, Any]] = []
    warnings: list[str] = []

    for idx, row in enumerate(rows, start=1):
        out = dict(row)

        team_raw = out.get("team") if out.get("team") is not None else out.get("name")
        if team_raw is None:
            team_name = ""
        elif isinstance(team_raw, str):
            team_name = team_raw.strip()
        else:
            msg = f"record[{idx}] team/name must be a string"
            if strict:
                raise ValueError(msg)
            warnings.append(msg)
            team_name = ""
        if team_name == "":
            msg = f"record[{idx}] missing team/name"
            if strict:
                raise ValueError(msg)
            warnings.append(msg)
            team_name = f"unknown-team-{idx}"
        out["team"] = team_name

        stage_raw = out.get("stage", "discover")
        if stage_raw is None:
            stage = "discover"
        elif isinstance(stage_raw, str):
            stage = stage_raw.strip().lower() or "discover"
        else:
            msg = f"record[{idx}] stage must be a string"
            if strict:
                raise ValueError(msg)
            warnings.append(msg)
            stage = "unknown"
        stage = stage_aliases.get(stage, stage)
        out["stage"] = stage

        evidence_raw = out.get("evidence", [])
        if evidence_raw is None:
            evidence_raw = []
        if not isinstance(evidence_raw, list):
            if strict:
                raise ValueError(f"record[{idx}] evidence must be a list when provided")
            warnings.append(f"record[{idx}] evidence was not a list; coerced to []")
            evidence_raw = []

        evidence_items: list[str] = []
        invalid_evidence_item = False
        for item in evidence_raw:
            if not isinstance(item, str):
                invalid_evidence_item = True
                continue
            text = item.strip()
            if text:
                evidence_items.append(text)

        if invalid_evidence_item:
            msg = f"record[{idx}] evidence items must be strings"
            if strict:
                raise ValueError(msg)
            warnings.append(msg)

        out["evidence"] = evidence_items

        normalized.append(out)

    return normalized, warnings


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    input_path = getattr(args, "input", "")
    if not isinstance(input_path, str) or not input_path.strip():
        errors.append("--input must be a non-empty string path")

    output_path = getattr(args, "output", None)
    if output_path is not None and not isinstance(output_path, str):
        errors.append("--output must be a string path")

    strict = getattr(args, "strict", False)
    if not isinstance(strict, bool):
        errors.append("--strict flag must be boolean")

    success_stage = getattr(args, "success_stage", "")
    if not isinstance(success_stage, str) or not success_stage.strip():
        errors.append("--success-stage must be a non-empty string")

    return errors


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

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    try:
        records = _load_records(Path(args.input))
        records, warnings = _normalize_records(records, strict=args.strict)
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
