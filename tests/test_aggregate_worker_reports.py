from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "aggregate_worker_reports.py"
    spec = importlib.util.spec_from_file_location("aggregate_worker_reports", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fail_on_critical_returns_2_for_non_integer_summary_value(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {"critical_workers": "1", "any_pressure": False},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-critical"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.critical_workers must be a non-negative integer" in captured.err


def test_fail_on_pressure_returns_2_for_non_boolean_summary_value(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {"critical_workers": 0, "any_pressure": "false"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-pressure"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.any_pressure must be boolean" in captured.err


def test_fail_on_pressure_returns_1_for_true_boolean(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "critical_workers": 0,
            "any_pressure": True,
            "pressured_workers": 1,
            "total_workers": 1,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-pressure"],
    )

    assert module.main() == 1


def test_fail_on_pressure_returns_2_for_inconsistent_summary(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "critical_workers": 0,
            "any_pressure": True,
            "pressured_workers": 0,
            "total_workers": 1,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-pressure"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.any_pressure=true requires pressured_workers > 0" in captured.err


def test_fail_on_critical_returns_2_when_critical_exceeds_pressured(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "critical_workers": 2,
            "any_pressure": True,
            "pressured_workers": 1,
            "total_workers": 2,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-critical"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.critical_workers cannot exceed pressured_workers" in captured.err


def test_returns_2_for_non_object_summary_payload(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: ["not", "an", "object"],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "aggregated summary payload must be a JSON object" in captured.err


def test_validate_cli_configuration_rejects_non_boolean_flags() -> None:
    module = _load_module()

    class _Args:
        input = "dummy.jsonl"
        output = None
        fail_on_pressure = "true"  # type: ignore[assignment]
        fail_on_critical = 1  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--fail-on-pressure flag must be boolean" in row for row in errors)
    assert any("--fail-on-critical flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_paths() -> None:
    module = _load_module()

    class _Args:
        input = 101  # type: ignore[assignment]
        output = 202  # type: ignore[assignment]
        fail_on_pressure = False
        fail_on_critical = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--input must be a non-empty string path" in row for row in errors)
    assert any("--output must be a string path" in row for row in errors)
