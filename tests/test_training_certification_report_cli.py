from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "training_certification_report.py"


def test_training_report_fail_on_gaps_exits_1(tmp_path: Path):
    attendees = tmp_path / "attendees.json"
    attendees.write_text(
        json.dumps(
            [
                {
                    "name": "alice",
                    "labs_completed": 5,
                    "capstone_submitted": True,
                    "framework_demo": True,
                    "automation_demo": True,
                    "assessment_score": 85,
                },
                {
                    "name": "bob",
                    "labs_completed": 4,
                    "capstone_submitted": True,
                    "framework_demo": True,
                    "automation_demo": True,
                    "assessment_score": 90,
                },
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--attendees",
            str(attendees),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["all_certified"] is False
    assert payload["failed_attendees"] == 1


def test_training_report_passes_when_all_certified(tmp_path: Path):
    attendees = tmp_path / "attendees.json"
    attendees.write_text(
        json.dumps(
            [
                {
                    "name": "alice",
                    "labs_completed": 5,
                    "capstone_submitted": True,
                    "framework_demo": True,
                    "automation_demo": True,
                    "assessment_score": 85,
                },
                {
                    "name": "bob",
                    "labs_completed": 5,
                    "capstone_submitted": True,
                    "framework_demo": True,
                    "automation_demo": True,
                    "assessment_score": 90,
                },
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--attendees",
            str(attendees),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["all_certified"] is True
    assert payload["pass_rate"] == 1.0
