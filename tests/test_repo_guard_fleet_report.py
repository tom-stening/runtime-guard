from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run_script(tmp_path: Path, enforcement_payload: dict[str, object], *args: str) -> subprocess.CompletedProcess[str]:
    script = Path("scripts/repo_guard_fleet_report.py").resolve()
    enforcement_path = tmp_path / "enforcement.json"
    output_path = tmp_path / "runtime.json"
    enforcement_path.write_text(json.dumps(enforcement_payload), encoding="utf-8")

    return subprocess.run(
        [
            sys.executable,
            str(script),
            "--enforcement-report",
            str(enforcement_path),
            "--output",
            str(output_path),
            *args,
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def test_builds_runtime_summary_from_enforcement_report(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
            {"repo_path": "/tmp/repo-b", "repo_name": "repo-b", "status": "watcher_only_candidate"},
        ]
    }

    result = _run_script(tmp_path, payload, "--no-proc-scan")
    assert result.returncode == 0, result.stderr

    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime["summary"]["total_repos"] == 2
    assert runtime["summary"]["enforced_repos"] == 1
    assert runtime["summary"]["unenforced_repos"] == 1
    assert runtime["summary"]["fully_enforced"] is False
    assert runtime["summary"]["active_repos"] == 0


def test_marks_all_repos_enforced_when_statuses_are_enforced(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
            {"repo_path": "/tmp/repo-b", "repo_name": "repo-b", "status": "enforced"},
        ]
    }

    result = _run_script(tmp_path, payload, "--no-proc-scan")
    assert result.returncode == 0, result.stderr

    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime["summary"]["fully_enforced"] is True
    assert runtime["summary"]["unenforced_repos"] == 0


def test_includes_wsl_diagnosis_when_requested(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }

    result = _run_script(tmp_path, payload, "--no-proc-scan", "--include-wsl-diagnosis")
    assert result.returncode == 0, result.stderr

    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert "wsl_diagnosis" in runtime
    assert "risk_level" in runtime["wsl_diagnosis"]
    assert "wsl_risk_level" in runtime["summary"]
    assert "wsl_running_distro_count" in runtime["summary"]
