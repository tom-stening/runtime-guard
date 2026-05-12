from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "validate_integration_fleet.py"
    spec = importlib.util.spec_from_file_location("validate_integration_fleet", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_extract_last_json_object_handles_prefixed_lines():
    module = _load_module()
    text = "warn one\nwarn two\n{\"ok\": true, \"value\": 3}\n"
    payload = module._extract_last_json_object(text)
    assert payload == {"ok": True, "value": 3}


def test_summarize_validator_stderr_filters_pressure_event_json_lines():
    module = _load_module()
    stderr = (
        "[RuntimeGuard] HIGH warning\n"
        '{"event":"runtime_guard.pressure","severity":"warning"}\n'
        "Dask not installed\n"
    )
    summarized = module._summarize_validator_stderr(stderr)
    assert "[RuntimeGuard] HIGH warning" in summarized
    assert "Dask not installed" in summarized
    assert '"event":"runtime_guard.pressure"' not in summarized


def test_summarize_validator_stderr_truncates_lines_and_text():
    module = _load_module()
    many_lines = "\n".join(f"line-{idx:03d}" for idx in range(80))
    summarized = module._summarize_validator_stderr(many_lines)
    assert "stderr lines truncated" in summarized

    oversized = "x" * 10000
    summarized_big = module._summarize_validator_stderr(oversized)
    assert "stderr text truncated" in summarized_big


def test_required_checks_for_each_component():
    module = _load_module()

    polars_ok, polars_errors = module._required_checks_for(
        "polars",
        {
            "scan_budget_api": {"available": True},
            "native_callback_api": {"available": True},
        },
    )
    assert polars_ok is True
    assert polars_errors == []

    dask_ok, dask_errors = module._required_checks_for(
        "dask",
        {
            "task_graph_guard_api": {"available": True},
            "scheduler_callback_api": {
                "available": True,
                "telemetry_counters_present": True,
            },
        },
    )
    assert dask_ok is True
    assert dask_errors == []

    ray_ok, ray_errors = module._required_checks_for(
        "ray",
        {
            "actor_monitoring_api": {
                "available": True,
                "hotspot_fields_present": True,
            }
        },
    )
    assert ray_ok is True
    assert ray_errors == []


def test_risk_level_rules():
    module = _load_module()

    low = module._risk_level(
        [
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
        ]
    )
    assert low == "low"

    high = module._risk_level(
        [
            {"healthy": False, "api_importable": False, "required_checks_ok": True},
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
        ]
    )
    assert high == "high"

    medium = module._risk_level(
        [
            {"healthy": False, "api_importable": True, "required_checks_ok": True},
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
        ]
    )
    assert medium == "medium"


def test_component_from_payload_marks_healthy_with_required_checks():
    module = _load_module()
    comp = module._component_from_payload(
        "dask",
        {
            "ok": True,
            "api_importable": True,
            "task_graph_guard_api": {"available": True},
            "scheduler_callback_api": {
                "available": True,
                "telemetry_counters_present": True,
            },
            "errors": ["runtime warning"],
        },
        source="report",
        command=None,
        exit_code=0,
        hard_errors=[],
        warnings=["stderr warning"],
    )
    assert comp["healthy"] is True
    assert comp["source"] == "report"
    assert comp["errors"] == []
    assert "stderr warning" in comp["warnings"]
    assert "runtime warning" in comp["warnings"]


def test_component_from_payload_hard_errors_force_unhealthy():
    module = _load_module()
    comp = module._component_from_payload(
        "ray",
        {
            "ok": True,
            "api_importable": True,
            "actor_monitoring_api": {
                "available": True,
                "hotspot_fields_present": True,
            },
        },
        source="report",
        command=None,
        exit_code=0,
        hard_errors=["identity mismatch"],
        warnings=[],
    )
    assert comp["healthy"] is False
    assert any("identity mismatch" in err for err in comp["errors"])


def test_component_from_report_invalid_file(tmp_path: Path):
    module = _load_module()
    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")

    comp = module._component_from_report("ray", bad)
    assert comp["healthy"] is False
    assert comp["source"] == "report"
    assert comp["exit_code"] == 1
    assert any("unable to read report" in err for err in comp["errors"])


def test_component_from_report_rejects_identity_mismatch(tmp_path: Path):
    module = _load_module()
    wrong = tmp_path / "wrong.json"
    wrong.write_text(
        '{"tool": "validate_ray_integration", "milestone": "M1-I03", "ok": true, '
        '"api_importable": true, "scan_budget_api": {"available": true}, '
        '"native_callback_api": {"available": true}}',
        encoding="utf-8",
    )

    comp = module._component_from_report("polars", wrong)
    assert comp["healthy"] is False
    assert any("report tool mismatch" in err for err in comp["errors"])
    assert any("report milestone mismatch" in err for err in comp["errors"])


def test_build_payload_uses_report_fallback_when_pressure_detected(
    tmp_path: Path,
    monkeypatch,
):
    module = _load_module()

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    (reports_dir / "polars_integration_status.json").write_text(
        '{"tool": "validate_polars_integration", "milestone": "M1-I01", '
        '"ok": true, "api_importable": true, "scan_budget_api": {"available": true}, '
        '"native_callback_api": {"available": true}}',
        encoding="utf-8",
    )
    (reports_dir / "dask_integration_status.json").write_text(
        '{"tool": "validate_dask_integration", "milestone": "M1-I02", '
        '"ok": true, "api_importable": true, '
        '"task_graph_guard_api": {"available": true}, '
        '"scheduler_callback_api": {"available": true, "telemetry_counters_present": true}}',
        encoding="utf-8",
    )
    (reports_dir / "ray_integration_status.json").write_text(
        '{"tool": "validate_ray_integration", "milestone": "M1-I03", '
        '"ok": true, "api_importable": true, '
        '"actor_monitoring_api": {"available": true, "hotspot_fields_present": true}}',
        encoding="utf-8",
    )

    def _fail_run(*_args, **_kwargs):
        raise AssertionError("live validator should not run in fallback offline mode")

    monkeypatch.setattr(module, "_run_validator", _fail_run)

    payload = module._build_payload(
        tmp_path,
        timeout_s=1,
        include_wsl_diagnosis=False,
        polars_report=None,
        dask_report=None,
        ray_report=None,
        fallback_on_pressure=True,
        fallback_report_dir="reports",
        pressure_detected_override=True,
    )

    assert payload["execution_mode"] == "offline"
    assert payload["pressure_fallback"]["enabled"] is True
    assert payload["pressure_fallback"]["pressure_detected"] is True
    assert payload["summary"]["overall_healthy"] is True
    assert [c["source"] for c in payload["components"]] == ["report", "report", "report"]


def test_build_payload_propagates_run_id(tmp_path: Path, monkeypatch):
    module = _load_module()

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)
    (reports_dir / "polars_integration_status.json").write_text(
        '{"tool": "validate_polars_integration", "milestone": "M1-I01", '
        '"ok": true, "api_importable": true, "scan_budget_api": {"available": true}, '
        '"native_callback_api": {"available": true}}',
        encoding="utf-8",
    )
    (reports_dir / "dask_integration_status.json").write_text(
        '{"tool": "validate_dask_integration", "milestone": "M1-I02", '
        '"ok": true, "api_importable": true, '
        '"task_graph_guard_api": {"available": true}, '
        '"scheduler_callback_api": {"available": true, "telemetry_counters_present": true}}',
        encoding="utf-8",
    )
    (reports_dir / "ray_integration_status.json").write_text(
        '{"tool": "validate_ray_integration", "milestone": "M1-I03", '
        '"ok": true, "api_importable": true, '
        '"actor_monitoring_api": {"available": true, "hotspot_fields_present": true}}',
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "_run_validator", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("unexpected live validator")))

    payload = module._build_payload(
        tmp_path,
        timeout_s=1,
        include_wsl_diagnosis=False,
        polars_report=None,
        dask_report=None,
        ray_report=None,
        fallback_on_pressure=True,
        fallback_report_dir="reports",
        run_id="ci-run-xyz",
        pressure_detected_override=True,
    )

    assert payload.get("run_id") == "ci-run-xyz"
    assert payload.get("summary", {}).get("run_id") == "ci-run-xyz"
    provenance = payload.get("provenance", {})
    assert provenance.get("tool") == "validate_integration_fleet"
    assert provenance.get("run_id") == "ci-run-xyz"
    assert str(provenance.get("generated_at_utc", "")).endswith("Z")
    assert provenance.get("artifact_sha256")
    signature = provenance.get("signature", {})
    assert signature.get("mode") in {"unsigned", "detached"}
    assert signature.get("signed_field") == "artifact_sha256"
    src_hashes = provenance.get("inputs", {}).get("source_artifact_hashes", {})
    assert src_hashes.get("polars")
    assert src_hashes.get("dask")
    assert src_hashes.get("ray")
    script_hashes = provenance.get("inputs", {}).get("validator_script_hashes", {})
    assert script_hashes.get("polars")
    assert script_hashes.get("dask")
    assert script_hashes.get("ray")


def test_run_validator_timeout_returns_unhealthy_component(tmp_path: Path, monkeypatch):
    module = _load_module()

    def _raise_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="validator", timeout=1)

    monkeypatch.setattr(module.subprocess, "run", _raise_timeout)

    component = module._run_validator(
        tmp_path,
        "polars",
        "validate_polars_integration.py",
        ["--check-budget-api", "--check-callback-api"],
        timeout_s=1,
    )

    assert component["tool"] == "polars"
    assert component["healthy"] is False
    assert component["exit_code"] == 124
    assert any("timed out" in row for row in component["errors"])
