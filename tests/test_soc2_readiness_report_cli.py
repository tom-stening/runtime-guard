from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "soc2_readiness_report.py"


def test_soc2_cli_fail_on_gaps_exits_1(tmp_path: Path):
    controls = tmp_path / "controls.json"
    evidence = tmp_path / "evidence.json"

    controls.write_text(
        json.dumps({"CC6.1": True, "CC7.1": False, "CC8.1": True}),
        encoding="utf-8",
    )
    evidence.write_text(
        json.dumps({"CC6.1": ["access-review-log"], "CC8.1": ["change-approval-record"]}),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--controls",
            str(controls),
            "--evidence",
            str(evidence),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["status"] in {"gaps-found", "evidence-missing"}


def test_soc2_cli_ready_with_required_controls_scope_exits_0(tmp_path: Path):
    controls = tmp_path / "controls.json"
    evidence = tmp_path / "evidence.json"
    required = tmp_path / "required_controls.json"

    controls.write_text(
        json.dumps({"CC6.1": True}),
        encoding="utf-8",
    )
    evidence.write_text(
        json.dumps({"CC6.1": ["access-review-log", "privileged-action-audit-trail"]}),
        encoding="utf-8",
    )
    required.write_text(
        json.dumps({"CC6.1": "Logical access controls and role-bound privileged actions."}),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--controls",
            str(controls),
            "--evidence",
            str(evidence),
            "--required-controls",
            str(required),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ready"
    assert payload["missing_required_controls"] == []
