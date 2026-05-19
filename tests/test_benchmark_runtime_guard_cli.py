from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "benchmark_runtime_guard.py"
    spec = importlib.util.spec_from_file_location("benchmark_runtime_guard", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_boolean_flags() -> None:
    module = _load_module()

    class _Args:
        json = "true"  # type: ignore[assignment]
        disable_top_procs = 1  # type: ignore[assignment]
        out = ""
        iterations = 100
        warmup = 10
        stage = "benchmark"
        fail_on_check_p99_ms = -1.0
        fail_on_snapshot_p99_ms = -1.0
        fail_on_peak_kib = -1

    errors = module._validate_cli_configuration(_Args())
    assert any("--json flag must be boolean" in row for row in errors)
    assert any("--disable-top-procs flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_invalid_numeric_bounds() -> None:
    module = _load_module()

    class _Args:
        json = False
        disable_top_procs = False
        out = ""
        iterations = 0
        warmup = 5
        stage = "benchmark"
        fail_on_check_p99_ms = -2.0
        fail_on_snapshot_p99_ms = "bad"  # type: ignore[assignment]
        fail_on_peak_kib = -2

    errors = module._validate_cli_configuration(_Args())
    assert any("--iterations must be a positive integer" in row for row in errors)
    assert any("--fail-on-check-p99-ms must be -1 or >= 0" in row for row in errors)
    assert any("--fail-on-snapshot-p99-ms must be a number" in row for row in errors)
    assert any("--fail-on-peak-kib must be -1 or >= 0" in row for row in errors)


def test_validate_cli_configuration_rejects_warmup_greater_or_equal_iterations() -> None:
    module = _load_module()

    class _Args:
        json = False
        disable_top_procs = False
        out = ""
        iterations = 100
        warmup = 100
        stage = "benchmark"
        fail_on_check_p99_ms = -1.0
        fail_on_snapshot_p99_ms = -1.0
        fail_on_peak_kib = -1

    errors = module._validate_cli_configuration(_Args())
    assert any("--warmup must be less than --iterations" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_inputs() -> None:
    module = _load_module()

    class _Args:
        json = True
        disable_top_procs = True
        out = "reports/perf.json"
        iterations = 500
        warmup = 20
        stage = "bench"
        fail_on_check_p99_ms = 2.5
        fail_on_snapshot_p99_ms = 2.5
        fail_on_peak_kib = 4096

    assert module._validate_cli_configuration(_Args()) == []


def test_percentile_handles_edges() -> None:
    module = _load_module()
    samples = [1.0, 2.0, 3.0, 4.0]
    assert module._percentile(samples, 0.0) == 1.0
    assert module._percentile(samples, 100.0) == 4.0


def test_build_failure_reasons_reports_threshold_breaches() -> None:
    module = _load_module()

    class _Args:
        fail_on_check_p99_ms = 0.5
        fail_on_snapshot_p99_ms = 0.5
        fail_on_peak_kib = 512

    payload = {
        "benchmarks": {
            "check": {"p99_ms": 1.0, "peak_traced_kib": 1024},
            "snapshot": {"p99_ms": 1.0},
        }
    }

    reasons = module._build_failure_reasons(payload, _Args())
    assert len(reasons) == 3


def test_main_rejects_non_boolean_flags_even_if_prevalidation_is_bypassed(
    monkeypatch, capsys
) -> None:
    module = _load_module()

    class _Args:
        json = "true"  # type: ignore[assignment]
        disable_top_procs = False
        out = ""
        iterations = 100
        warmup = 10
        stage = "benchmark"
        fail_on_check_p99_ms = -1.0
        fail_on_snapshot_p99_ms = -1.0
        fail_on_peak_kib = -1

    monkeypatch.setattr(
        module,
        "_build_parser",
        lambda: type("_P", (), {"parse_args": lambda self: _Args()})(),
    )
    monkeypatch.setattr(module, "_validate_cli_configuration", lambda _args: [])

    result_code = module.main()
    captured = capsys.readouterr()
    assert result_code == 2
    assert "--json flag must be boolean" in captured.err
