from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "adoption_scorecard.py"


def test_cli_warns_and_coerces_non_strict(tmp_path: Path):
    input_path = tmp_path / "records.json"
    input_path.write_text(
        json.dumps(
            [
                {"stage": "production", "evidence": "bad-type"},
                {"team": "alpha", "stage": "pilot", "evidence": ["ok"]},
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--input", str(input_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    assert "warning:" in proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["input_records"] == 2
    assert len(payload["validation_warnings"]) >= 1


def test_cli_fails_in_strict_mode_on_missing_team(tmp_path: Path):
    input_path = tmp_path / "records.json"
    input_path.write_text(
        json.dumps(
            [
                {"stage": "production", "evidence": ["ok"]},
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--input", str(input_path), "--strict"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 2
    assert "missing team/name" in proc.stderr
