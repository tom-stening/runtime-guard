from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "adoption_tracker_report.py"


def test_tracker_report_detects_gap_when_fewer_than_five_success_teams(tmp_path: Path):
    tracker = tmp_path / "ADOPTION_TRACKER.md"
    tracker.write_text(
        "\n".join(
            [
                "# Enterprise Adoption Tracker",
                "",
                "## Tracking Fields",
                "",
                "| Team ID | Organization | Industry | Stage | Primary Use Case | Integration Mode | Start Date | Last Update | Outcome Metric | Next Action |",
                "|---|---|---|---|---|---|---|---|---|---|",
                "| T01 | Org1 | Fin | Pilot | Use case A | Library | 2026-01-01 | 2026-01-02 | Metric A | Next |",
                "| T02 | Org2 | Fin | Production | Use case B | CLI | 2026-01-01 | 2026-01-02 | Metric B | Next |",
                "| T03 | Org3 | Fin | Pilot | Use case C | Background | 2026-01-01 | 2026-01-02 | Metric C | Next |",
                "| T04 | Org4 | Fin | Discover | Use case D | Pytest | 2026-01-01 | 2026-01-02 | Metric D | Next |",
                "| T05 | Org5 | Fin | Pilot | Use case E | Audit | 2026-01-01 | 2026-01-02 | Metric E | Next |",
                "",
                "## Case Studies",
                "",
                "### T01",
                "| Metric | Before | After |",
                "|---|---|---|",
                "| m | 1 | 2 |",
                "",
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--tracker",
            str(tracker),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["criteria"]["five_teams_reached_pilot_or_production"] is False
    assert payload["all_criteria_met"] is False


def test_tracker_report_passes_when_all_criteria_met(tmp_path: Path):
    tracker = tmp_path / "ADOPTION_TRACKER.md"
    tracker.write_text(
        "\n".join(
            [
                "# Enterprise Adoption Tracker",
                "",
                "## Tracking Fields",
                "",
                "| Team ID | Organization | Industry | Stage | Primary Use Case | Integration Mode | Start Date | Last Update | Outcome Metric | Next Action |",
                "|---|---|---|---|---|---|---|---|---|---|",
                "| T01 | Org1 | Fin | Pilot | Use case A | Library | 2026-01-01 | 2026-01-02 | Metric A | Next |",
                "| T02 | Org2 | Fin | Production | Use case B | CLI | 2026-01-01 | 2026-01-02 | Metric B | Next |",
                "| T03 | Org3 | Fin | Pilot | Use case C | Background | 2026-01-01 | 2026-01-02 | Metric C | Next |",
                "| T04 | Org4 | Fin | Expanded | Use case D | Pytest | 2026-01-01 | 2026-01-02 | Metric D | Next |",
                "| T05 | Org5 | Fin | Pilot | Use case E | Audit | 2026-01-01 | 2026-01-02 | Metric E | Next |",
                "",
                "## Case Studies",
                "",
                "### T01",
                "| Metric | Before | After |",
                "|---|---|---|",
                "| m | 1 | 2 |",
                "",
                "### T02",
                "| Metric | Before | After |",
                "|---|---|---|",
                "| m | 3 | 4 |",
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--tracker",
            str(tracker),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["criteria"]["five_teams_reached_pilot_or_production"] is True
    assert payload["criteria"]["all_teams_have_use_case_mode_metric"] is True
    assert payload["criteria"]["at_least_two_case_studies_with_before_after"] is True
    assert payload["all_criteria_met"] is True
