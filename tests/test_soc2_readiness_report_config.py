from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "soc2_readiness_report.py"
    spec = importlib.util.spec_from_file_location("soc2_readiness_report", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_string_required_paths() -> None:
    module = _load_module()

    class _Args:
        controls = 101  # type: ignore[assignment]
        required_controls = None
        evidence = 202  # type: ignore[assignment]
        output = None
        fail_on_gaps = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--controls must be a non-empty string path" in row for row in errors)
    assert any("--evidence must be a non-empty string path" in row for row in errors)


def test_validate_cli_configuration_rejects_optional_type_mismatches() -> None:
    module = _load_module()

    class _Args:
        controls = "controls.json"
        required_controls = 303  # type: ignore[assignment]
        evidence = "evidence.json"
        output = 404  # type: ignore[assignment]
        fail_on_gaps = "true"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--required-controls must be a string path" in row for row in errors)
    assert any("--output must be a string path" in row for row in errors)
    assert any("--fail-on-gaps flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_values() -> None:
    module = _load_module()

    class _Args:
        controls = "controls.json"
        required_controls = "required_controls.json"
        evidence = "evidence.json"
        output = "report.json"
        fail_on_gaps = True

    assert module._validate_cli_configuration(_Args()) == []


def test_main_rejects_non_string_report_status_for_fail_on_gaps(tmp_path, monkeypatch, capsys) -> None:
    module = _load_module()

    controls = tmp_path / "controls.json"
    evidence = tmp_path / "evidence.json"
    controls.write_text("{}\n", encoding="utf-8")
    evidence.write_text("{}\n", encoding="utf-8")

    args = argparse.Namespace(
        controls=str(controls),
        required_controls=None,
        evidence=str(evidence),
        output=None,
        fail_on_gaps=True,
    )

    monkeypatch.setattr(module.argparse.ArgumentParser, "parse_args", lambda self: args)
    monkeypatch.setattr(module, "soc2_readiness_report", lambda *_args, **_kwargs: {"status": 7})

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: report status must be a string" in captured.err


def test_main_returns_one_when_status_not_ready(tmp_path, monkeypatch) -> None:
    module = _load_module()

    controls = tmp_path / "controls.json"
    evidence = tmp_path / "evidence.json"
    controls.write_text("{}\n", encoding="utf-8")
    evidence.write_text("{}\n", encoding="utf-8")

    args = argparse.Namespace(
        controls=str(controls),
        required_controls=None,
        evidence=str(evidence),
        output=None,
        fail_on_gaps=True,
    )

    monkeypatch.setattr(module.argparse.ArgumentParser, "parse_args", lambda self: args)
    monkeypatch.setattr(module, "soc2_readiness_report", lambda *_args, **_kwargs: {"status": "needs-work"})

    assert module.main() == 1
