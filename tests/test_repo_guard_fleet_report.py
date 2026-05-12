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
    assert runtime["summary"]["recommendation_count"] >= 1
    assert any(
        "enforce_runtime_guard_all_repos.py" in row
        for row in runtime["recommendations"]
    )


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
    assert isinstance(runtime["recommendations"], list)
    assert runtime["summary"]["recommendation_count"] == len(runtime["recommendations"])
    assert "overall_runtime_healthy" in runtime["summary"]


def test_recommendations_are_deduplicated(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }

    result = _run_script(tmp_path, payload, "--no-proc-scan", "--include-wsl-diagnosis")
    assert result.returncode == 0, result.stderr

    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    recs = runtime.get("recommendations", [])
    assert len(recs) == len({(" ".join(str(r).lower().strip().rstrip(".").split())) for r in recs})
    docker_rows = [r for r in recs if "docker-desktop" in str(r).lower()]
    assert len(docker_rows) <= 1


def test_fail_on_unenforced_exits_nonzero(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "watcher_only_candidate"},
        ]
    }

    result = _run_script(tmp_path, payload, "--no-proc-scan", "--fail-on-unenforced")
    assert result.returncode == 1
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime["summary"]["failed_gate_count"] >= 1
    matched = [
        row for row in runtime.get("failed_gates", [])
        if isinstance(row, dict) and row.get("gate") == "fail-on-unenforced"
    ]
    assert matched
    assert matched[0].get("run_id") == runtime["summary"].get("run_id")
    assert matched[0].get("gate_id") == "fail-on-unenforced"
    assert str(matched[0].get("evaluated_at_utc", "")).endswith("Z")


def test_fail_on_integration_unhealthy_exits_nonzero(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }
    integration_path = tmp_path / "integration.json"
    integration_path.write_text(
        json.dumps(
            {
                "summary": {
                    "overall_healthy": False,
                    "components_total": 3,
                    "components_healthy": 2,
                    "risk_level": "high",
                },
                "execution_mode": "live",
                "pressure_fallback": {"enabled": False, "pressure_detected": False},
            }
        ),
        encoding="utf-8",
    )

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--integration-report",
        str(integration_path),
        "--fail-on-integration-unhealthy",
    )
    assert result.returncode == 1


def test_fail_on_wsl_risk_requires_threshold_exits_nonzero(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--include-wsl-diagnosis",
        "--fail-on-wsl-risk",
        "moderate",
    )
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    level = str(runtime["summary"].get("wsl_risk_level", "low"))
    if level in {"moderate", "high", "critical"}:
        assert result.returncode == 1
    else:
        assert result.returncode == 0


def test_fail_on_extension_rss_invalid_spec_exits_2(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--include-wsl-diagnosis",
        "--fail-on-extension-rss",
        "broken-spec",
    )
    assert result.returncode == 2
    assert "expected EXTENSION=MB" in result.stderr


def test_fail_on_extension_total_rss_records_failed_gate(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--include-wsl-diagnosis",
        "--fail-on-extension-total-rss-mb",
        "1",
    )
    assert result.returncode == 1
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime["summary"]["failed_gate_count"] >= 1
    matched = [
        row
        for row in runtime.get("failed_gates", [])
        if isinstance(row, dict) and row.get("gate") == "fail-on-extension-total-rss-mb"
    ]
    assert matched
    assert matched[0].get("run_id") == runtime["summary"].get("run_id")
    assert matched[0].get("gate_id") == "fail-on-extension-total-rss-mb"
    assert str(matched[0].get("evaluated_at_utc", "")).endswith("Z")


def test_failed_gates_share_single_run_id(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "watcher_only_candidate"},
        ]
    }
    integration_path = tmp_path / "integration.json"
    integration_path.write_text(
        json.dumps(
            {
                "summary": {
                    "overall_healthy": False,
                    "components_total": 1,
                    "components_healthy": 0,
                    "risk_level": "high",
                },
                "execution_mode": "live",
                "pressure_fallback": {"enabled": False, "pressure_detected": False},
            }
        ),
        encoding="utf-8",
    )

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--integration-report",
        str(integration_path),
        "--fail-on-unenforced",
        "--fail-on-integration-unhealthy",
    )
    assert result.returncode == 1
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    run_id = runtime["summary"].get("run_id")
    assert isinstance(run_id, str)
    assert run_id == runtime.get("run_id")
    failed_gates = [row for row in runtime.get("failed_gates", []) if isinstance(row, dict)]
    assert len(failed_gates) >= 2
    assert all(row.get("run_id") == run_id for row in failed_gates)


def test_run_id_override_is_propagated_to_output_and_failed_gates(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "watcher_only_candidate"},
        ]
    }

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--fail-on-unenforced",
        "--run-id",
        "ci-run-12345",
    )
    assert result.returncode == 1
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime.get("run_id") == "ci-run-12345"
    assert runtime.get("summary", {}).get("run_id") == "ci-run-12345"
    failed_gates = [row for row in runtime.get("failed_gates", []) if isinstance(row, dict)]
    assert failed_gates
    assert all(row.get("run_id") == "ci-run-12345" for row in failed_gates)


def test_source_run_ids_and_consistency_are_included_when_matching(tmp_path: Path) -> None:
    payload = {
        "run_id": "ci-sync-1",
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ],
    }
    integration_path = tmp_path / "integration.json"
    integration_path.write_text(
        json.dumps(
            {
                "run_id": "ci-sync-1",
                "summary": {
                    "overall_healthy": True,
                    "components_total": 1,
                    "components_healthy": 1,
                    "risk_level": "low",
                },
            }
        ),
        encoding="utf-8",
    )

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--integration-report",
        str(integration_path),
        "--run-id",
        "ci-sync-1",
    )
    assert result.returncode == 0, result.stderr
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime.get("run_id_consistent") is True
    assert runtime.get("source_run_ids", {}).get("repo_guard_enforcement") == "ci-sync-1"
    assert runtime.get("source_run_ids", {}).get("integration_fleet_status") == "ci-sync-1"
    assert runtime.get("source_run_ids", {}).get("repo_guard_runtime_status") == "ci-sync-1"
    provenance = runtime.get("provenance", {})
    assert provenance.get("tool") == "repo_guard_fleet_report"
    assert provenance.get("run_id") == "ci-sync-1"
    assert str(provenance.get("generated_at_utc", "")).endswith("Z")
    assert provenance.get("artifact_sha256")
    src_hashes = provenance.get("inputs", {}).get("source_artifact_hashes", {})
    assert src_hashes.get("repo_guard_enforcement")
    assert src_hashes.get("integration_fleet_status")


def test_fail_on_run_id_mismatch_exits_nonzero(tmp_path: Path) -> None:
    payload = {
        "run_id": "ci-a",
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ],
    }
    integration_path = tmp_path / "integration.json"
    integration_path.write_text(
        json.dumps(
            {
                "run_id": "ci-b",
                "summary": {
                    "overall_healthy": True,
                    "components_total": 1,
                    "components_healthy": 1,
                    "risk_level": "low",
                },
            }
        ),
        encoding="utf-8",
    )

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--integration-report",
        str(integration_path),
        "--run-id",
        "ci-a",
        "--fail-on-run-id-mismatch",
    )
    assert result.returncode == 1
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime.get("run_id_consistent") is False
    failed = [
        row
        for row in runtime.get("failed_gates", [])
        if isinstance(row, dict) and row.get("gate") == "fail-on-run-id-mismatch"
    ]
    assert failed
