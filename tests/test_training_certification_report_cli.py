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


def test_training_report_fails_closed_on_malformed_attendee_field_types(tmp_path: Path):
    attendees = tmp_path / "attendees.json"
    attendees.write_text(
        json.dumps(
            [
                {
                    "name": "alice",
                    "labs_completed": 5,
                    "capstone_submitted": "false",
                    "framework_demo": "true",
                    "automation_demo": "true",
                    "assessment_score": "95",
                }
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
    row = payload["attendees"][0]
    assert row["passed"] is False
    assert any("must be boolean" in err or "must be numeric" in err for err in row["validation_errors"])


def test_training_report_rejects_non_object_attendee_rows(tmp_path: Path):
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
                "not-an-object",
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

    assert proc.returncode == 2
    assert "attendees[1] must be a JSON object" in proc.stderr


def test_training_report_fails_closed_on_non_string_attendee_identity(tmp_path: Path):
    attendees = tmp_path / "attendees.json"
    attendees.write_text(
        json.dumps(
            [
                {
                    "name": {"display": "alice"},
                    "labs_completed": 5,
                    "capstone_submitted": True,
                    "framework_demo": True,
                    "automation_demo": True,
                    "assessment_score": 90,
                }
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
    row = payload["attendees"][0]
    assert row["name"] == "attendee-1"
    assert row["passed"] is False
    assert any("name/id must be a non-empty string" in err for err in row["validation_errors"])
