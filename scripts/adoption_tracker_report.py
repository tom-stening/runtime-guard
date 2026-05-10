#!/usr/bin/env python3
"""Validate ADOPTION_TRACKER.md against M2-I02 success criteria."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from runtime_guard import build_adoption_scorecard

_SUCCESS_STAGES = {"pilot", "production", "expanded"}


def _parse_tracking_table(markdown: str) -> list[dict[str, str]]:
    lines = markdown.splitlines()
    header_idx = -1
    for idx, line in enumerate(lines):
        if line.strip().startswith("| Team ID | Organization | Industry | Stage |"):
            header_idx = idx
            break
    if header_idx < 0:
        return []

    rows: list[dict[str, str]] = []
    col_names = [c.strip() for c in lines[header_idx].strip().strip("|").split("|")]
    for line in lines[header_idx + 2 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            break
        cols = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cols) != len(col_names):
            continue
        item = {name: value for name, value in zip(col_names, cols)}
        if item.get("Team ID", "").strip() == "":
            continue
        rows.append(item)
    return rows


def _count_case_studies_with_before_after(markdown: str) -> int:
    pattern = re.compile(r"^\|\s*Metric\s*\|\s*Before\s*\|\s*After\s*\|\s*$", re.MULTILINE)
    return len(pattern.findall(markdown))


def _build_records(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        stage = str(row.get("Stage", "discover")).strip().lower()
        team = str(row.get("Team ID", "")).strip() or str(row.get("Organization", "")).strip()
        evidence: list[str] = []
        for key in ("Primary Use Case", "Integration Mode", "Outcome Metric"):
            value = str(row.get(key, "")).strip()
            if value:
                evidence.append(value)
        out.append({"team": team, "stage": stage, "evidence": evidence})
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate adoption tracker readiness for M2-I02")
    parser.add_argument(
        "--tracker",
        default="ADOPTION_TRACKER.md",
        help="Path to adoption tracker markdown (default: ADOPTION_TRACKER.md)",
    )
    parser.add_argument("--output", help="Optional path to write JSON report")
    parser.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help="Exit 1 when any M2-I02 success criterion is not met",
    )
    args = parser.parse_args()

    tracker_path = Path(args.tracker)
    text = tracker_path.read_text(encoding="utf-8")

    rows = _parse_tracking_table(text)
    records = _build_records(rows)
    scorecard = build_adoption_scorecard(records, success_stage="pilot")

    reached_success = [
        r for r in records if str(r.get("stage", "")).strip().lower() in _SUCCESS_STAGES
    ]
    missing_fields_teams = [
        r.get("team", "")
        for r in records
        if not r.get("evidence") or len(r.get("evidence", [])) < 3
    ]

    case_studies_with_before_after = _count_case_studies_with_before_after(text)

    criteria = {
        "five_teams_reached_pilot_or_production": len(reached_success) >= 5,
        "all_teams_have_use_case_mode_metric": len(missing_fields_teams) == 0,
        "at_least_two_case_studies_with_before_after": case_studies_with_before_after >= 2,
    }

    report = {
        "tracker_path": str(tracker_path),
        "total_teams": len(records),
        "teams_reached_pilot_or_production": len(reached_success),
        "successful_team_ids": [str(r.get("team", "")) for r in reached_success],
        "missing_fields_teams": [str(t) for t in missing_fields_teams if str(t).strip()],
        "case_studies_with_before_after": case_studies_with_before_after,
        "criteria": criteria,
        "all_criteria_met": all(criteria.values()),
        "scorecard": scorecard,
    }

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on_gaps and not report["all_criteria_met"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
