from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "training_certification_report.py"
    spec = importlib.util.spec_from_file_location("training_certification_report", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_string_paths() -> None:
    module = _load_module()

    class _Args:
        attendees = 101  # type: ignore[assignment]
        required_labs = 5
        min_score = 80.0
        output = 202  # type: ignore[assignment]
        fail_on_gaps = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--attendees must be a non-empty string path" in row for row in errors)
    assert any("--output must be a string path" in row for row in errors)


def test_validate_cli_configuration_rejects_invalid_numeric_and_flag_types() -> None:
    module = _load_module()

    class _Args:
        attendees = "attendees.json"
        required_labs = "5"  # type: ignore[assignment]
        min_score = "80"  # type: ignore[assignment]
        output = None
        fail_on_gaps = "true"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--required-labs must be an integer >= 1" in row for row in errors)
    assert any("--min-score must be a number between 0 and 100" in row for row in errors)
    assert any("--fail-on-gaps flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_values() -> None:
    module = _load_module()

    class _Args:
        attendees = "attendees.json"
        required_labs = 5
        min_score = 80.0
        output = "report.json"
        fail_on_gaps = True

    assert module._validate_cli_configuration(_Args()) == []
