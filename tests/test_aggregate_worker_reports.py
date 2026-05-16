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
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {"critical_workers": "1", "any_pressure": False},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--fail-on-critical",
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.critical_workers must be a non-negative integer" in captured.err


def test_fail_on_pressure_returns_2_for_non_boolean_summary_value(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {"critical_workers": 0, "any_pressure": "false"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--fail-on-pressure",
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.any_pressure must be boolean" in captured.err


def test_fail_on_pressure_returns_1_for_true_boolean(monkeypatch, tmp_path) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
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
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--fail-on-pressure",
        ],
    )

    assert module.main() == 1


def test_fail_on_pressure_returns_2_for_inconsistent_summary(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
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
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--fail-on-pressure",
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.any_pressure=true requires pressured_workers > 0" in captured.err


def test_fail_on_critical_returns_2_when_critical_exceeds_pressured(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
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
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--fail-on-critical",
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.critical_workers cannot exceed pressured_workers" in captured.err


def test_fail_on_pressure_returns_2_when_typed_workers_exceed_total(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "typed_workers": 2,
            "total_workers": 1,
            "parse_warning_count": 0,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--fail-on-pressure",
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.typed_workers cannot exceed total_workers" in captured.err


def test_fail_on_pressure_returns_2_when_parse_warnings_below_malformed_count(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "typed_workers": 1,
            "total_workers": 3,
            "parse_warning_count": 1,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--fail-on-pressure",
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.parse_warning_count cannot be lower than malformed row count" in captured.err


def test_returns_2_for_non_object_summary_payload(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: ["not", "an", "object"],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", str(input_path)],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "aggregated summary payload must be a JSON object" in captured.err


def test_returns_2_for_non_finite_summary_values(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
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
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", str(input_path)],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: aggregated summary is not strict-JSON renderable" in captured.err


def test_returns_2_for_invalid_summary_fields_without_fail_flags(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "typed_workers": 2,
            "total_workers": 1,
            "parse_warning_count": 0,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", str(input_path)],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.typed_workers cannot exceed total_workers" in captured.err


def test_returns_2_without_writing_output_for_invalid_summary(
    monkeypatch, tmp_path, capsys
) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    output_path = tmp_path / "summary.json"
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {
            "any_pressure": False,
            "pressured_workers": 0,
            "critical_workers": 0,
            "typed_workers": 2,
            "total_workers": 1,
            "parse_warning_count": 0,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.typed_workers cannot exceed total_workers" in captured.err
    assert not output_path.exists()


def test_returns_2_for_non_serializable_summary_values(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
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
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", str(input_path)],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: aggregated summary is not strict-JSON renderable" in captured.err


def test_returns_2_when_input_file_missing(monkeypatch, capsys) -> None:
    module = _load_module()
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "does-not-exist.jsonl"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: input file not found:" in captured.err


def test_returns_2_when_input_file_unreadable(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: (_ for _ in ()).throw(OSError("permission denied")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", str(input_path)],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: could not read" in captured.err


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
    assert any("--output must be a non-empty string path" in row for row in errors)


def test_validate_cli_configuration_rejects_empty_output_path() -> None:
    module = _load_module()

    class _Args:
        input = "dummy.jsonl"
        output = "   "
        fail_on_pressure = False
        fail_on_critical = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--output must be a non-empty string path" in row for row in errors)


def test_writes_output_when_parent_directory_missing(monkeypatch, tmp_path) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
    input_path.write_text("{}\n", encoding="utf-8")
    output_path = tmp_path / "nested" / "summary.json"

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
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert module.main() == 0
    assert output_path.exists()


def test_returns_2_when_output_write_fails(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
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
        Path,
        "write_text",
        lambda self, data, encoding=None: (_ for _ in ()).throw(OSError("disk full")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--output",
            str(tmp_path / "summary.json"),
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: could not write" in captured.err


def test_returns_2_when_output_directory_creation_fails(monkeypatch, tmp_path, capsys) -> None:
    module = _load_module()
    input_path = tmp_path / "dummy.jsonl"
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
        Path,
        "mkdir",
        lambda self, parents=False, exist_ok=False: (_ for _ in ()).throw(
            OSError("permission denied")
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aggregate_worker_reports.py",
            "--input",
            str(input_path),
            "--output",
            str(tmp_path / "nested" / "summary.json"),
        ],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: could not create output directory" in captured.err
