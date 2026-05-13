from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "aggregate_workers.py"
    spec = importlib.util.spec_from_file_location("aggregate_workers", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_boolean_flags() -> None:
    module = _load_module()

    class _Args:
        input = "workers.jsonl"
        output = None
        fail_on_pressure = "true"  # type: ignore[assignment]
        fail_on_critical = 1  # type: ignore[assignment]
        pretty = "yes"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--fail-on-pressure flag must be boolean" in row for row in errors)
    assert any("--fail-on-critical flag must be boolean" in row for row in errors)
    assert any("--pretty flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_paths() -> None:
    module = _load_module()

    class _Args:
        input = 101  # type: ignore[assignment]
        output = 202  # type: ignore[assignment]
        fail_on_pressure = False
        fail_on_critical = False
        pretty = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--input must be a non-empty string path" in row for row in errors)
    assert any("--output must be a string path" in row for row in errors)


def test_main_returns_2_for_non_boolean_any_pressure(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": "false",
            "pressured_workers": 0,
            "critical_workers": 0,
            "total_workers": 1,
        },
    )

    code = module.main(["--input", str(input_path), "--fail-on-pressure"])
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.any_pressure must be boolean" in captured.err


def test_main_returns_2_for_non_integer_critical_workers(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": "1",
            "total_workers": 1,
        },
    )

    code = module.main(["--input", str(input_path), "--fail-on-critical"])
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.critical_workers must be a non-negative integer" in captured.err
