from __future__ import annotations

import importlib.util
import builtins
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
    assert any("--output must be a non-empty string path" in row for row in errors)


def test_validate_cli_configuration_rejects_empty_output_path() -> None:
    module = _load_module()

    class _Args:
        input = "workers.jsonl"
        output = "  "
        fail_on_pressure = False
        fail_on_critical = False
        pretty = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--output must be a non-empty string path" in row for row in errors)


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


def test_main_returns_2_for_non_finite_summary_values(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "total_workers": 0,
            "nan_field": float("nan"),
        },
    )

    code = module.main(["--input", str(input_path)])
    captured = capsys.readouterr()

    assert code == 2
    assert "error: aggregated summary is not strict-JSON renderable" in captured.err


def test_main_returns_2_for_non_serializable_summary_values(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "total_workers": 0,
            "bad": {"x"},
        },
    )

    code = module.main(["--input", str(input_path)])
    captured = capsys.readouterr()

    assert code == 2
    assert "error: aggregated summary is not strict-JSON renderable" in captured.err


def test_main_returns_2_for_inconsistent_pressure_summary(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": True,
            "pressured_workers": 0,
            "critical_workers": 0,
            "total_workers": 1,
        },
    )

    code = module.main(["--input", str(input_path), "--fail-on-pressure"])
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.any_pressure=true requires pressured_workers > 0" in captured.err


def test_main_returns_2_when_critical_exceeds_pressured(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": True,
            "pressured_workers": 1,
            "critical_workers": 2,
            "total_workers": 2,
        },
    )

    code = module.main(["--input", str(input_path), "--fail-on-critical"])
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.critical_workers cannot exceed pressured_workers" in captured.err


def test_main_returns_2_when_output_write_fails(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "total_workers": 0,
        },
    )
    monkeypatch.setattr(
        builtins,
        "open",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    code = module.main(
        [
            "--input",
            str(input_path),
            "--output",
            str(tmp_path / "summary.json"),
        ]
    )
    captured = capsys.readouterr()

    assert code == 2
    assert "error: could not write" in captured.err


def test_main_returns_2_when_output_directory_creation_fails(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "workers.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "total_workers": 0,
        },
    )
    monkeypatch.setattr(
        module.os,
        "makedirs",
        lambda path, exist_ok=False: (_ for _ in ()).throw(OSError("permission denied")),
    )

    code = module.main(
        [
            "--input",
            str(input_path),
            "--output",
            str(tmp_path / "nested" / "summary.json"),
        ]
    )
    captured = capsys.readouterr()

    assert code == 2
    assert "error: could not create output directory" in captured.err
