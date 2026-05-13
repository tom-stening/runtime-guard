from __future__ import annotations

import importlib.util
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


def _run_script_with_paths(enforcement_path: Path, output_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    script = Path("scripts/repo_guard_fleet_report.py").resolve()
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


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "repo_guard_fleet_report.py"
    spec = importlib.util.spec_from_file_location("repo_guard_fleet_report", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


def test_integration_report_invalid_types_fail_closed_with_parse_warnings(tmp_path: Path) -> None:
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
                    "overall_healthy": "false",
                    "components_total": "many",
                    "components_healthy": -1,
                    "risk_level": 7,
                },
                "execution_mode": ["live"],
                "pressure_fallback": {"enabled": "true", "pressure_detected": 1},
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

    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    summary = runtime.get("summary", {})
    assert summary.get("integration_overall_healthy") is False
    warnings = summary.get("parse_warnings", [])
    assert isinstance(warnings, list)
    assert any("integration.summary.overall_healthy must be boolean" in row for row in warnings)
    assert any("integration.summary.components_total must be a non-negative integer" in row for row in warnings)
    assert any("integration.execution_mode must be non-empty string" in row for row in warnings)


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
    signature = provenance.get("signature", {})
    assert signature.get("mode") in {"unsigned", "detached"}
    assert signature.get("signed_field") == "artifact_sha256"
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


def test_non_string_run_id_generates_uuid_in_runtime_payload(tmp_path: Path, monkeypatch) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps({
            "run_id": "ci-sync-1",
            "repos": [
                {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
            ],
        }),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    module = _load_module()

    class _Args:
        enforcement_report = str(enforcement_path)
        output = str(output_path)
        no_proc_scan = True
        integration_report = str(tmp_path / "missing-integration.json")
        include_wsl_diagnosis = False
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss: list[str] = []
        run_id = 123
        fail_on_run_id_mismatch = False

    monkeypatch.setattr(module, "_parse_args", lambda: _Args())

    result_code = module.main()
    assert result_code == 0

    runtime = json.loads(output_path.read_text(encoding="utf-8"))
    run_id = runtime.get("run_id")
    assert isinstance(run_id, str)
    assert run_id
    assert run_id != "123"
    assert runtime.get("summary", {}).get("run_id") == run_id
    assert runtime.get("provenance", {}).get("run_id") == run_id


def test_malformed_extension_rss_rows_fail_safe_with_warning(tmp_path: Path, monkeypatch) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "run_id": "ci-sync-1",
                "repos": [
                    {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
                ],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    module = _load_module()

    class _Args:
        enforcement_report = str(enforcement_path)
        output = str(output_path)
        no_proc_scan = True
        integration_report = str(tmp_path / "missing-integration.json")
        include_wsl_diagnosis = True
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss = ["ms-python.python=1"]
        run_id = "ci-sync-1"
        fail_on_run_id_mismatch = False

    monkeypatch.setattr(module, "_parse_args", lambda: _Args())
    monkeypatch.setattr(
        module,
        "diagnose_wsl_crash",
        lambda: {
            "risk_level": "low",
            "risk_score": 0,
            "guest_vscode_extension_rss": [
                {"extension": "ms-python.python", "rss_mb": "broken"},
            ],
        },
    )

    result_code = module.main()
    assert result_code == 0

    runtime = json.loads(output_path.read_text(encoding="utf-8"))
    warnings = runtime.get("summary", {}).get("parse_warnings", [])
    assert isinstance(warnings, list)
    assert any("guest_vscode_extension_rss[ms-python.python].rss_mb" in row for row in warnings)


def test_malformed_activity_scan_count_fails_safe_with_warning(tmp_path: Path, monkeypatch) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "run_id": "ci-sync-1",
                "repos": [
                    {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
                ],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    module = _load_module()

    class _Args:
        enforcement_report = str(enforcement_path)
        output = str(output_path)
        no_proc_scan = False
        integration_report = str(tmp_path / "missing-integration.json")
        include_wsl_diagnosis = False
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss: list[str] = []
        run_id = "ci-sync-1"
        fail_on_run_id_mismatch = False

    monkeypatch.setattr(module, "_parse_args", lambda: _Args())
    monkeypatch.setattr(
        module,
        "_scan_repo_activity",
        lambda _paths: {"/tmp/repo-a": "bad-count"},
    )

    result_code = module.main()
    assert result_code == 0

    runtime = json.loads(output_path.read_text(encoding="utf-8"))
    repo = runtime.get("repos", [])[0]
    assert repo.get("active_pid_count") == 0
    warnings = runtime.get("summary", {}).get("parse_warnings", [])
    assert isinstance(warnings, list)
    assert any("activity_scan[/tmp/repo-a].active_pid_count" in row for row in warnings)


def test_fail_on_unenforced_returns_2_for_non_integer_summary_value(tmp_path: Path, monkeypatch) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "run_id": "ci-sync-1",
                "repos": [
                    {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
                ],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    module = _load_module()

    class _Args:
        enforcement_report = str(enforcement_path)
        output = str(output_path)
        no_proc_scan = True
        integration_report = str(tmp_path / "missing-integration.json")
        include_wsl_diagnosis = False
        fail_on_unenforced = True
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss: list[str] = []
        run_id = "ci-sync-1"
        fail_on_run_id_mismatch = False

    monkeypatch.setattr(module, "_parse_args", lambda: _Args())

    original_build_payload = module._build_payload

    def _bad_payload(*args, **kwargs):
        payload = original_build_payload(*args, **kwargs)
        payload["summary"]["unenforced_repos"] = "bad-count"
        return payload

    monkeypatch.setattr(module, "_build_payload", _bad_payload)

    result_code = module.main()
    assert result_code == 2


def test_fail_on_extension_total_rss_returns_2_for_non_integer_summary_value(
    tmp_path: Path, monkeypatch
) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "run_id": "ci-sync-1",
                "repos": [
                    {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
                ],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    module = _load_module()

    class _Args:
        enforcement_report = str(enforcement_path)
        output = str(output_path)
        no_proc_scan = True
        integration_report = str(tmp_path / "missing-integration.json")
        include_wsl_diagnosis = False
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 1
        fail_on_extension_rss: list[str] = []
        run_id = "ci-sync-1"
        fail_on_run_id_mismatch = False

    monkeypatch.setattr(module, "_parse_args", lambda: _Args())

    original_build_payload = module._build_payload

    def _bad_payload(*args, **kwargs):
        payload = original_build_payload(*args, **kwargs)
        payload["summary"]["wsl_vscode_extension_total_rss_mb"] = "bad-total"
        return payload

    monkeypatch.setattr(module, "_build_payload", _bad_payload)

    result_code = module.main()
    assert result_code == 2


def test_non_string_source_run_ids_are_not_coerced(tmp_path: Path) -> None:
    payload = {
        "run_id": 101,
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ],
    }
    integration_path = tmp_path / "integration.json"
    integration_path.write_text(
        json.dumps(
            {
                "run_id": "101",
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
        "101",
        "--fail-on-run-id-mismatch",
    )
    assert result.returncode == 1
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime.get("run_id_consistent") is False
    source_ids = runtime.get("source_run_ids", {})
    assert source_ids.get("repo_guard_enforcement") == ""
    assert source_ids.get("integration_fleet_status") == "101"


def test_invalid_enforcement_report_exits_with_config_error(tmp_path: Path) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text("{not json", encoding="utf-8")
    output_path = tmp_path / "runtime.json"

    result = _run_script_with_paths(enforcement_path, output_path, "--no-proc-scan")

    assert result.returncode == 2
    assert "unable to read enforcement report" in result.stderr


def test_enforcement_report_with_non_list_repos_exits_with_config_error(tmp_path: Path) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(json.dumps({"repos": {"repo": "bad"}}), encoding="utf-8")
    output_path = tmp_path / "runtime.json"

    result = _run_script_with_paths(enforcement_path, output_path, "--no-proc-scan")

    assert result.returncode == 2
    assert "invalid enforcement report" in result.stderr
    assert "field 'repos' must be a list" in result.stderr


def test_enforcement_report_with_non_object_repo_row_exits_with_config_error(tmp_path: Path) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(json.dumps({"repos": ["bad-row"]}), encoding="utf-8")
    output_path = tmp_path / "runtime.json"

    result = _run_script_with_paths(enforcement_path, output_path, "--no-proc-scan")

    assert result.returncode == 2
    assert "invalid enforcement report" in result.stderr
    assert "field 'repos[0]' must be an object" in result.stderr


def test_enforcement_report_with_missing_repo_path_exits_with_config_error(tmp_path: Path) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "repos": [
                    {"repo_name": "repo-a", "status": "already_enforced"},
                ]
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    result = _run_script_with_paths(enforcement_path, output_path, "--no-proc-scan")

    assert result.returncode == 2
    assert "invalid enforcement report" in result.stderr
    assert "field 'repos[0].repo_path' must be a non-empty string" in result.stderr


def test_enforcement_report_with_non_string_status_exits_with_config_error(tmp_path: Path) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "repos": [
                    {
                        "repo_path": "/tmp/repo-a",
                        "repo_name": "repo-a",
                        "status": 101,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    result = _run_script_with_paths(enforcement_path, output_path, "--no-proc-scan")

    assert result.returncode == 2
    assert "invalid enforcement report" in result.stderr
    assert "field 'repos[0].status' must be a non-empty string" in result.stderr


def test_enforcement_report_with_unknown_status_exits_with_config_error(tmp_path: Path) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "repos": [
                    {
                        "repo_path": "/tmp/repo-a",
                        "repo_name": "repo-a",
                        "status": "mystery_status",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    result = _run_script_with_paths(enforcement_path, output_path, "--no-proc-scan")

    assert result.returncode == 2
    assert "invalid enforcement report" in result.stderr
    assert "field 'repos[0].status' must be one of:" in result.stderr


def test_enforcement_report_with_duplicate_repo_path_exits_with_config_error(tmp_path: Path) -> None:
    enforcement_path = tmp_path / "enforcement.json"
    enforcement_path.write_text(
        json.dumps(
            {
                "repos": [
                    {
                        "repo_path": "/tmp/repo-a",
                        "repo_name": "repo-a",
                        "status": "enforced",
                    },
                    {
                        "repo_path": "/tmp/repo-a",
                        "repo_name": "repo-a-duplicate",
                        "status": "already_enforced",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "runtime.json"

    result = _run_script_with_paths(enforcement_path, output_path, "--no-proc-scan")

    assert result.returncode == 2
    assert "invalid enforcement report" in result.stderr
    assert "field 'repos[1].repo_path' duplicates an earlier row" in result.stderr


def test_invalid_integration_report_is_ignored_with_parse_warning(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }
    integration_path = tmp_path / "integration.json"
    integration_path.write_text("{not json", encoding="utf-8")

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--integration-report",
        str(integration_path),
    )

    assert result.returncode == 0, result.stderr
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    warnings = runtime.get("summary", {}).get("parse_warnings", [])
    assert isinstance(warnings, list)
    assert any("unable to read integration report" in row for row in warnings)


def test_invalid_integration_report_triggers_fail_on_integration_unhealthy(tmp_path: Path) -> None:
    payload = {
        "repos": [
            {"repo_path": "/tmp/repo-a", "repo_name": "repo-a", "status": "already_enforced"},
        ]
    }
    integration_path = tmp_path / "integration.json"
    integration_path.write_text("{not json", encoding="utf-8")

    result = _run_script(
        tmp_path,
        payload,
        "--no-proc-scan",
        "--integration-report",
        str(integration_path),
        "--fail-on-integration-unhealthy",
    )

    assert result.returncode == 1
    runtime = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert runtime.get("summary", {}).get("integration_overall_healthy") is False
    failed = [
        row
        for row in runtime.get("failed_gates", [])
        if isinstance(row, dict) and row.get("gate") == "fail-on-integration-unhealthy"
    ]
    assert failed
