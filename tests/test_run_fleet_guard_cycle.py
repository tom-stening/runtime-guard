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
        integration_max_fallback_report_age_hours = 24
        integration_require_signed_report_inputs = True
        integration_verify_report_input_signatures = True
        integration_report_signature_public_key = "/tmp/report-public.pem"
        integration_report_allowed_key_id = ["report-key-a", "report-key-b"]
        integration_max_report_signature_age_hours = 12
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
    assert "--max-fallback-report-age-hours" in integration_cmd
    assert "24" in integration_cmd
    assert "--require-signed-report-inputs" in integration_cmd
    assert "--verify-report-input-signatures" in integration_cmd
    assert "--report-signature-public-key" in integration_cmd
    assert "/tmp/report-public.pem" in integration_cmd
    assert integration_cmd.count("--report-allowed-key-id") == 2
    assert "report-key-a" in integration_cmd
    assert "report-key-b" in integration_cmd
    assert "--max-report-signature-age-hours" in integration_cmd
    assert "12" in integration_cmd
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


def test_validate_cli_configuration_requires_integration_report_signature_key():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = True
        integration_require_signed_report_inputs = True
        integration_report_signature_public_key = ""
        verify_signed_artifacts = False
        signature_public_key = ""

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--integration-report-signature-public-key" in errors[0]


def test_validate_cli_configuration_requires_lineage_signature_key_when_verifying():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_report_signature_public_key = ""
        verify_signed_artifacts = True
        signature_public_key = ""

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--signature-public-key" in errors[0]


def test_validate_cli_configuration_requires_integration_require_signed_when_verifying():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = True
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = "/tmp/report-public.pem"
        verify_signed_artifacts = False
        signature_public_key = ""

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--integration-require-signed-report-inputs" in errors[0]


def test_validate_cli_configuration_requires_integration_verification_when_key_ids_are_constrained():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = True
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id = ["report-key-a"]
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--integration-verify-report-input-signatures" in errors[0]
    assert "--integration-report-allowed-key-id" in errors[0]


def test_validate_cli_configuration_requires_integration_verification_when_signature_age_policy_enabled():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = True
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_report_signature_age_hours = 8
        verify_signed_artifacts = False
        signature_public_key = ""

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--integration-verify-report-input-signatures" in errors[0]
    assert "--integration-max-report-signature-age-hours" in errors[0]


def test_validate_cli_configuration_requires_lineage_verification_when_key_ids_are_constrained():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        allowed_key_id = ["lineage-key-a"]
        max_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--verify-signed-artifacts" in errors[0]
    assert "--allowed-key-id" in errors[0]


def test_validate_cli_configuration_requires_lineage_verification_when_signature_age_policy_enabled():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = 8

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--verify-signed-artifacts" in errors[0]
    assert "--max-signature-age-hours" in errors[0]


def test_validate_cli_configuration_rejects_negative_age_policies():
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = True
        integration_require_signed_report_inputs = True
        integration_report_signature_public_key = "/tmp/report-public.pem"
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = -1
        integration_max_report_signature_age_hours = -2
        verify_signed_artifacts = False
        signature_public_key = ""
        max_signature_age_hours = -3

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 3
    assert any("--integration-max-fallback-report-age-hours" in row for row in errors)
    assert any("--integration-max-report-signature-age-hours" in row for row in errors)
    assert any("--max-signature-age-hours" in row for row in errors)


def test_validate_cli_configuration_rejects_non_boolean_policy_flags() -> None:
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = "true"  # type: ignore[assignment]
        integration_require_signed_report_inputs = 1  # type: ignore[assignment]
        integration_report_signature_public_key = "/tmp/report-public.pem"
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = "false"  # type: ignore[assignment]
        signature_public_key = ""
        max_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert any(
        "--integration-verify-report-input-signatures flag must be boolean" in row
        for row in errors
    )
    assert any(
        "--integration-require-signed-report-inputs flag must be boolean" in row
        for row in errors
    )
    assert any("--verify-signed-artifacts flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_non_boolean_orchestration_flags() -> None:
    module = _load_module()

    class _Args:
        integration_fallback_on_pressure = "yes"  # type: ignore[assignment]
        include_wsl_diagnosis = 1  # type: ignore[assignment]
        fail_on_unenforced = "true"  # type: ignore[assignment]
        fail_on_integration_unhealthy = 0  # type: ignore[assignment]
        dry_run = "false"  # type: ignore[assignment]
        skip_lineage_verify = "no"  # type: ignore[assignment]
        require_signed_artifacts = 1  # type: ignore[assignment]

        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        max_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert any("--integration-fallback-on-pressure flag must be boolean" in row for row in errors)
    assert any("--include-wsl-diagnosis flag must be boolean" in row for row in errors)
    assert any("--fail-on-unenforced flag must be boolean" in row for row in errors)
    assert any("--fail-on-integration-unhealthy flag must be boolean" in row for row in errors)
    assert any("--dry-run flag must be boolean" in row for row in errors)
    assert any("--skip-lineage-verify flag must be boolean" in row for row in errors)
    assert any("--require-signed-artifacts flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_non_integer_age_policy_types() -> None:
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 2.5  # type: ignore[assignment]
        integration_max_report_signature_age_hours = "8"  # type: ignore[assignment]
        verify_signed_artifacts = False
        signature_public_key = ""
        max_signature_age_hours = "3"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any(
        "--integration-max-fallback-report-age-hours must be a non-negative integer" in row
        for row in errors
    )
    assert any(
        "--integration-max-report-signature-age-hours must be a non-negative integer" in row
        for row in errors
    )
    assert any("--max-signature-age-hours must be a non-negative integer" in row for row in errors)


def test_validate_cli_configuration_rejects_non_integer_extension_total_rss_type() -> None:
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        max_signature_age_hours = 0
        fail_on_extension_total_rss_mb = "512"  # type: ignore[assignment]
        fail_on_extension_rss: list[str] = []

    errors = module._validate_cli_configuration(_Args())
    assert any("--fail-on-extension-total-rss-mb must be a non-negative integer" in row for row in errors)


def test_validate_cli_configuration_rejects_negative_extension_total_rss() -> None:
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        max_signature_age_hours = 0
        fail_on_extension_total_rss_mb = -1
        fail_on_extension_rss: list[str] = []

    errors = module._validate_cli_configuration(_Args())
    assert any("--fail-on-extension-total-rss-mb must be greater than or equal to 0" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_allowed_key_ids() -> None:
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = True
        integration_require_signed_report_inputs = True
        integration_report_signature_public_key = "/tmp/report-public.pem"
        integration_report_allowed_key_id = ["report-key-a", 42]  # type: ignore[list-item]
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        max_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert any(
        "--integration-report-allowed-key-id values must be strings" in row
        for row in errors
    )


def test_validate_cli_configuration_rejects_non_string_lineage_allowed_key_ids() -> None:
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        allowed_key_id = ["lineage-key-a", 42]  # type: ignore[list-item]
        max_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert any("--allowed-key-id values must be strings" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_extension_rss_specs() -> None:
    module = _load_module()

    class _Args:
        integration_verify_report_input_signatures = False
        integration_require_signed_report_inputs = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_fallback_report_age_hours = 0
        integration_max_report_signature_age_hours = 0
        verify_signed_artifacts = False
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = 0
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss = ["ms-python.python=800", 42]  # type: ignore[list-item]

    errors = module._validate_cli_configuration(_Args())
    assert any("--fail-on-extension-rss values must be non-empty strings" in row for row in errors)


def test_build_step_commands_generates_and_propagates_run_id_when_missing(tmp_path: Path):
    module = _load_module()

    class _Args:
        root = "/tmp/workspace"
        reports_dir = str(tmp_path / "reports")
        include_wsl_diagnosis = False
        integration_fallback_on_pressure = False
        integration_fallback_report_dir = "reports"
        integration_max_fallback_report_age_hours = 0
        integration_require_signed_report_inputs = False
        integration_verify_report_input_signatures = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_report_signature_age_hours = 0
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss: list[str] = []
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


def test_build_step_commands_rejects_non_string_run_id_and_generates_uuid(tmp_path: Path):
    module = _load_module()

    class _Args:
        root = "/tmp/workspace"
        reports_dir = str(tmp_path / "reports")
        include_wsl_diagnosis = False
        integration_fallback_on_pressure = False
        integration_fallback_report_dir = "reports"
        integration_max_fallback_report_age_hours = 0
        integration_require_signed_report_inputs = False
        integration_verify_report_input_signatures = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_report_signature_age_hours = 0
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss: list[str] = []
        run_id = 123

    enforce_cmd, integration_cmd, runtime_cmd, _, _, _ = module._build_step_commands(_Args(), Path("/repo"))

    enforce_run_id = enforce_cmd[enforce_cmd.index("--run-id") + 1]
    integration_run_id = integration_cmd[integration_cmd.index("--run-id") + 1]
    runtime_run_id = runtime_cmd[runtime_cmd.index("--run-id") + 1]

    assert enforce_run_id
    assert enforce_run_id != "123"
    assert enforce_run_id == integration_run_id == runtime_run_id


def test_build_step_commands_omits_fallback_age_flag_when_disabled(tmp_path: Path):
    module = _load_module()

    class _Args:
        root = "/tmp/workspace"
        reports_dir = str(tmp_path / "reports")
        include_wsl_diagnosis = False
        integration_fallback_on_pressure = True
        integration_fallback_report_dir = "reports"
        integration_max_fallback_report_age_hours = 0
        integration_require_signed_report_inputs = False
        integration_verify_report_input_signatures = False
        integration_report_signature_public_key = ""
        integration_report_allowed_key_id: list[str] = []
        integration_max_report_signature_age_hours = 0
        fail_on_unenforced = False
        fail_on_integration_unhealthy = False
        fail_on_wsl_risk = None
        fail_on_extension_total_rss_mb = 0
        fail_on_extension_rss: list[str] = []
        run_id = "ci-run-age-0"

    _, integration_cmd, _, _, _, _ = module._build_step_commands(_Args(), Path("/repo"))
    assert "--max-fallback-report-age-hours" not in integration_cmd


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


    def test_validate_run_id_consistency_handles_invalid_report_json(tmp_path: Path):
        module = _load_module()

        enforcement = tmp_path / "repo_guard_enforcement.json"
        integration = tmp_path / "integration_fleet_status.json"
        runtime = tmp_path / "repo_guard_runtime_status.json"

        enforcement.write_text(json.dumps({"run_id": "ci-a"}), encoding="utf-8")
        integration.write_text("{not json", encoding="utf-8")
        runtime.write_text(json.dumps({"run_id": "ci-a"}), encoding="utf-8")

        ok, run_ids = module._validate_run_id_consistency(enforcement, integration, runtime)
        assert ok is False
        assert run_ids["repo_guard_enforcement"] == "ci-a"
        assert run_ids["integration_fleet_status"] == ""
        assert run_ids["repo_guard_runtime_status"] == "ci-a"


    def test_validate_run_id_consistency_rejects_non_string_run_ids(tmp_path: Path):
        module = _load_module()

        enforcement = tmp_path / "repo_guard_enforcement.json"
        integration = tmp_path / "integration_fleet_status.json"
        runtime = tmp_path / "repo_guard_runtime_status.json"

        enforcement.write_text(json.dumps({"run_id": 123}), encoding="utf-8")
        integration.write_text(json.dumps({"summary": {"run_id": "ci-a"}}), encoding="utf-8")
        runtime.write_text(json.dumps({"run_id": "ci-a"}), encoding="utf-8")

        ok, run_ids = module._validate_run_id_consistency(enforcement, integration, runtime)
        assert ok is False
        assert run_ids["repo_guard_enforcement"] == ""
        assert run_ids["integration_fleet_status"] == "ci-a"
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


    def test_summarize_runtime_report_handles_invalid_json(tmp_path: Path):
        module = _load_module()
        path = tmp_path / "runtime.json"
        path.write_text("{not json", encoding="utf-8")

        summary = module._summarize_runtime_report(path)
        assert summary["run_id"] == ""
        assert summary["overall_runtime_healthy"] is False
        assert summary["fully_enforced"] is False
        assert summary["recommendation_count"] == 0
        assert "parse_error" in summary


    def test_summarize_runtime_report_handles_non_object_payload(tmp_path: Path):
        module = _load_module()
        path = tmp_path / "runtime.json"
        path.write_text(json.dumps([]), encoding="utf-8")

        summary = module._summarize_runtime_report(path)
        assert summary["run_id"] == ""
        assert summary["overall_runtime_healthy"] is False
        assert summary["fully_enforced"] is False
        assert summary["recommendation_count"] == 0
        assert "must be a JSON object" in summary["parse_error"]


    def test_summarize_runtime_report_rejects_malformed_summary_field_types(tmp_path: Path):
        module = _load_module()
        path = tmp_path / "runtime.json"
        path.write_text(
            json.dumps(
                {
                    "run_id": "ci-1",
                    "summary": {
                        "overall_runtime_healthy": "true",
                        "fully_enforced": "true",
                        "integration_overall_healthy": "false",
                        "wsl_risk_level": {"level": "high"},
                        "recommendation_count": "5",
                    },
                }
            ),
            encoding="utf-8",
        )

        summary = module._summarize_runtime_report(path)
        assert summary["run_id"] == "ci-1"
        assert summary["overall_runtime_healthy"] is False
        assert summary["fully_enforced"] is False
        assert summary["integration_overall_healthy"] is None
        assert summary["wsl_risk_level"] is None
        assert summary["recommendation_count"] == 0
        assert any("summary.overall_runtime_healthy must be boolean" in row for row in summary["parse_warnings"])
        assert any("summary.fully_enforced must be boolean" in row for row in summary["parse_warnings"])
        assert any("summary.integration_overall_healthy must be boolean or null" in row for row in summary["parse_warnings"])
        assert any("summary.wsl_risk_level must be string or null" in row for row in summary["parse_warnings"])
        assert any("summary.recommendation_count must be a non-negative integer" in row for row in summary["parse_warnings"])


    def test_summarize_runtime_report_rejects_non_string_run_id_fields(tmp_path: Path):
        module = _load_module()
        path = tmp_path / "runtime.json"
        path.write_text(
            json.dumps(
                {
                    "run_id": 321,
                    "summary": {
                        "run_id": ["ci-1"],
                        "overall_runtime_healthy": True,
                        "fully_enforced": True,
                        "integration_overall_healthy": True,
                        "wsl_risk_level": "low",
                        "recommendation_count": 1,
                    },
                }
            ),
            encoding="utf-8",
        )

        summary = module._summarize_runtime_report(path)
        assert summary["run_id"] == ""
        assert summary["overall_runtime_healthy"] is True
        assert summary["fully_enforced"] is True


def test_build_lineage_verify_command_contains_expected_paths(tmp_path: Path):
    module = _load_module()
    repo_root = Path("/repo")
    enforcement = tmp_path / "repo_guard_enforcement.json"
    integration = tmp_path / "integration_fleet_status.json"
    runtime = tmp_path / "repo_guard_runtime_status.json"

    cmd = module._build_lineage_verify_command(
        repo_root,
        enforcement,
        integration,
        runtime,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
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


def test_build_lineage_verify_command_includes_require_signed_flag(tmp_path: Path):
    module = _load_module()
    cmd = module._build_lineage_verify_command(
        Path("/repo"),
        tmp_path / "repo_guard_enforcement.json",
        tmp_path / "integration_fleet_status.json",
        tmp_path / "repo_guard_runtime_status.json",
        require_signed=True,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert "--require-signed" in cmd


def test_build_lineage_verify_command_includes_signature_verification_flags(tmp_path: Path):
    module = _load_module()
    cmd = module._build_lineage_verify_command(
        Path("/repo"),
        tmp_path / "repo_guard_enforcement.json",
        tmp_path / "integration_fleet_status.json",
        tmp_path / "repo_guard_runtime_status.json",
        require_signed=True,
        verify_signatures=True,
        signature_public_key="/tmp/public.pem",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert "--require-signed" in cmd
    assert "--verify-signatures" in cmd
    assert "--signature-public-key" in cmd
    assert "/tmp/public.pem" in cmd


def test_build_lineage_verify_command_includes_key_policy_flags(tmp_path: Path):
    module = _load_module()
    cmd = module._build_lineage_verify_command(
        Path("/repo"),
        tmp_path / "repo_guard_enforcement.json",
        tmp_path / "integration_fleet_status.json",
        tmp_path / "repo_guard_runtime_status.json",
        require_signed=True,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=["key-a", "key-b"],
        max_signature_age_hours=24,
        expected_require_signed_report_inputs=True,
        expected_verify_report_input_signatures=True,
        expected_report_allowed_key_ids=["report-key-a", "report-key-b"],
        expected_max_report_signature_age_hours=12,
    )
    assert cmd.count("--allowed-key-id") == 2
    assert "key-a" in cmd
    assert "key-b" in cmd
    assert "--max-signature-age-hours" in cmd
    assert "24" in cmd
    assert "--expected-require-signed-report-inputs" in cmd
    assert "--expected-verify-report-input-signatures" in cmd
    assert cmd.count("--expected-report-allowed-key-id") == 2
    assert "report-key-a" in cmd
    assert "report-key-b" in cmd
    assert "--expected-max-report-signature-age-hours" in cmd
    assert "12" in cmd


def test_build_lineage_verify_command_rejects_non_typed_policy_inputs(tmp_path: Path):
    module = _load_module()

    try:
        module._build_lineage_verify_command(
            Path("/repo"),
            tmp_path / "repo_guard_enforcement.json",
            tmp_path / "integration_fleet_status.json",
            tmp_path / "repo_guard_runtime_status.json",
            require_signed="true",  # type: ignore[arg-type]
            verify_signatures=False,
            signature_public_key=123,  # type: ignore[arg-type]
            allowed_key_ids=["fleet-key", 7],  # type: ignore[list-item]
            max_signature_age_hours="4",  # type: ignore[arg-type]
            expected_require_signed_report_inputs=False,
            expected_verify_report_input_signatures="false",  # type: ignore[arg-type]
            expected_report_allowed_key_ids=["report-key", object()],  # type: ignore[list-item]
            expected_max_report_signature_age_hours=0,
        )
    except ValueError as exc:
        text = str(exc)
        assert (
            "require_signed" in text
            or "signature_public_key" in text
            or "max_signature_age_hours" in text
            or "expected_verify_report_input_signatures" in text
            or "expected_report_allowed_key_ids" in text
        )
    else:
        raise AssertionError("expected ValueError for non-typed lineage policy input")
