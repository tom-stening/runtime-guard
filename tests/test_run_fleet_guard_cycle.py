from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "run_fleet_guard_cycle.py"
    spec = importlib.util.spec_from_file_location("run_fleet_guard_cycle", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_step_commands_includes_flags(tmp_path: Path):
    module = _load_module()

    class _Args:
        root = "/tmp/workspace"
        reports_dir = str(tmp_path / "reports")
        include_wsl_diagnosis = True
        integration_fallback_on_pressure = True
        integration_fallback_report_dir = "reports"
        fail_on_unenforced = True
        fail_on_integration_unhealthy = True
        fail_on_wsl_risk = "high"
        fail_on_extension_total_rss_mb = 2500
        fail_on_extension_rss = ["ms-python.vscode-pylance=800"]
        run_id = "ci-run-12345"

    enforce_cmd, integration_cmd, runtime_cmd, enforcement_report, integration_report, runtime_report = module._build_step_commands(
        _Args(), Path("/repo")
    )

    assert "enforce_runtime_guard_all_repos.py" in " ".join(enforce_cmd)
    assert "--enforce-all-repos" in enforce_cmd
    assert "--force-runtime-guard-sitecustomize" in enforce_cmd
    assert "--run-id" in enforce_cmd
    assert "ci-run-12345" in enforce_cmd
    assert str(enforcement_report).endswith("repo_guard_enforcement.json")

    assert "validate_integration_fleet.py" in " ".join(integration_cmd)
    assert "--fallback-on-pressure" in integration_cmd
    assert "--run-id" in integration_cmd
    assert "ci-run-12345" in integration_cmd
    assert str(integration_report).endswith("integration_fleet_status.json")

    assert "repo_guard_fleet_report.py" in " ".join(runtime_cmd)
    assert "--include-wsl-diagnosis" in runtime_cmd
    assert "--fail-on-unenforced" in runtime_cmd
    assert "--fail-on-integration-unhealthy" in runtime_cmd
    assert "--fail-on-wsl-risk" in runtime_cmd
    assert "--fail-on-extension-total-rss-mb" in runtime_cmd
    assert "--fail-on-extension-rss" in runtime_cmd
    assert "--fail-on-run-id-mismatch" in runtime_cmd
    assert "--run-id" in runtime_cmd
    assert "ci-run-12345" in runtime_cmd
    assert str(runtime_report).endswith("repo_guard_runtime_status.json")


def test_build_step_commands_generates_and_propagates_run_id_when_missing(tmp_path: Path):
    module = _load_module()

    class _Args:
        root = "/tmp/workspace"
        reports_dir = str(tmp_path / "reports")
        include_wsl_diagnosis = False
        integration_fallback_on_pressure = False
        integration_fallback_report_dir = "reports"
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss = []
        run_id = ""

    enforce_cmd, integration_cmd, runtime_cmd, _, _, _ = module._build_step_commands(_Args(), Path("/repo"))

    assert "--run-id" in enforce_cmd
    assert "--run-id" in integration_cmd
    assert "--run-id" in runtime_cmd

    enforce_run_id = enforce_cmd[enforce_cmd.index("--run-id") + 1]
    integration_run_id = integration_cmd[integration_cmd.index("--run-id") + 1]
    runtime_run_id = runtime_cmd[runtime_cmd.index("--run-id") + 1]

    assert enforce_run_id
    assert enforce_run_id == integration_run_id == runtime_run_id


def test_validate_run_id_consistency_returns_true_for_matching_reports(tmp_path: Path):
    module = _load_module()

    enforcement = tmp_path / "repo_guard_enforcement.json"
    integration = tmp_path / "integration_fleet_status.json"
    runtime = tmp_path / "repo_guard_runtime_status.json"

    for path in (enforcement, integration, runtime):
        path.write_text(json.dumps({"run_id": "ci-sync-1"}), encoding="utf-8")

    ok, run_ids = module._validate_run_id_consistency(enforcement, integration, runtime)
    assert ok is True
    assert set(run_ids.values()) == {"ci-sync-1"}


def test_validate_run_id_consistency_returns_false_for_mismatched_reports(tmp_path: Path):
    module = _load_module()

    enforcement = tmp_path / "repo_guard_enforcement.json"
    integration = tmp_path / "integration_fleet_status.json"
    runtime = tmp_path / "repo_guard_runtime_status.json"

    enforcement.write_text(json.dumps({"run_id": "ci-a"}), encoding="utf-8")
    integration.write_text(json.dumps({"run_id": "ci-b"}), encoding="utf-8")
    runtime.write_text(json.dumps({"run_id": "ci-a"}), encoding="utf-8")

    ok, run_ids = module._validate_run_id_consistency(enforcement, integration, runtime)
    assert ok is False
    assert run_ids["repo_guard_enforcement"] == "ci-a"
    assert run_ids["integration_fleet_status"] == "ci-b"
    assert run_ids["repo_guard_runtime_status"] == "ci-a"


def test_summarize_runtime_report(tmp_path: Path):
    module = _load_module()
    path = tmp_path / "runtime.json"
    path.write_text(
        json.dumps(
            {
                "summary": {
                    "overall_runtime_healthy": True,
                    "fully_enforced": True,
                    "integration_overall_healthy": True,
                    "wsl_risk_level": "low",
                    "recommendation_count": 2,
                }
            }
        ),
        encoding="utf-8",
    )

    out = module._summarize_runtime_report(path)
    assert out["overall_runtime_healthy"] is True
    assert out["fully_enforced"] is True
    assert out["integration_overall_healthy"] is True
    assert out["wsl_risk_level"] == "low"
    assert out["recommendation_count"] == 2


def test_build_lineage_verify_command_contains_expected_paths(tmp_path: Path):
    module = _load_module()
    repo_root = Path("/repo")
    enforcement = tmp_path / "repo_guard_enforcement.json"
    integration = tmp_path / "integration_fleet_status.json"
    runtime = tmp_path / "repo_guard_runtime_status.json"

    cmd = module._build_lineage_verify_command(repo_root, enforcement, integration, runtime)
    rendered = " ".join(cmd)

    assert "verify_fleet_artifact_lineage.py" in rendered
    assert "--json" in cmd
    assert "--strict" in cmd
    assert "--enforcement-report" in cmd
    assert str(enforcement) in cmd
    assert "--integration-report" in cmd
    assert str(integration) in cmd
    assert "--runtime-report" in cmd
    assert str(runtime) in cmd
