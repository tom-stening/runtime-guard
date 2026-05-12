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
    assert str(enforcement_report).endswith("repo_guard_enforcement.json")

    assert "validate_integration_fleet.py" in " ".join(integration_cmd)
    assert "--fallback-on-pressure" in integration_cmd
    assert str(integration_report).endswith("integration_fleet_status.json")

    assert "repo_guard_fleet_report.py" in " ".join(runtime_cmd)
    assert "--include-wsl-diagnosis" in runtime_cmd
    assert "--fail-on-unenforced" in runtime_cmd
    assert "--fail-on-integration-unhealthy" in runtime_cmd
    assert "--fail-on-wsl-risk" in runtime_cmd
    assert "--fail-on-extension-total-rss-mb" in runtime_cmd
    assert "--fail-on-extension-rss" in runtime_cmd
    assert "--run-id" in runtime_cmd
    assert "ci-run-12345" in runtime_cmd
    assert str(runtime_report).endswith("repo_guard_runtime_status.json")


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
