from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "adoption_scorecard.py"
    spec = importlib.util.spec_from_file_location("adoption_scorecard", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_string_paths() -> None:
    module = _load_module()

    class _Args:
        input = 101  # type: ignore[assignment]
        output = 202  # type: ignore[assignment]
        strict = False
        success_stage = "production"

    errors = module._validate_cli_configuration(_Args())
    assert any("--input must be a non-empty string path" in row for row in errors)
    assert any("--output must be a string path" in row for row in errors)


def test_validate_cli_configuration_rejects_non_boolean_strict_flag() -> None:
    module = _load_module()

    class _Args:
        input = "records.json"
        output = None
        strict = "true"  # type: ignore[assignment]
        success_stage = "production"

    errors = module._validate_cli_configuration(_Args())
    assert any("--strict flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_empty_success_stage() -> None:
    module = _load_module()

    class _Args:
        input = "records.json"
        output = None
        strict = False
        success_stage = ""

    errors = module._validate_cli_configuration(_Args())
    assert any("--success-stage must be a non-empty string" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_values() -> None:
    module = _load_module()

    class _Args:
        input = "records.json"
        output = "scorecard.json"
        strict = True
        success_stage = "production"

    assert module._validate_cli_configuration(_Args()) == []
