from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "seed_repo_autorun.py"
    spec = importlib.util.spec_from_file_location("seed_repo_autorun", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_string_fields() -> None:
    module = _load_module()

    class _Args:
        repo_path = 101  # type: ignore[assignment]
        stage = None  # type: ignore[assignment]
        interval_s = 30.0
        cooldown_s = 30.0
        env_prefix = "RUNTIME_GUARD"
        force = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--repo-path must be a non-empty string" in row for row in errors)
    assert any("--stage must be a non-empty string" in row for row in errors)


def test_validate_cli_configuration_rejects_invalid_numeric_and_flag_types() -> None:
    module = _load_module()

    class _Args:
        repo_path = "/tmp/repo"
        stage = "repo-autostart"
        interval_s = "30"  # type: ignore[assignment]
        cooldown_s = -1
        env_prefix = "RUNTIME_GUARD"
        force = "true"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--interval-s must be a non-negative number" in row for row in errors)
    assert any("--cooldown-s must be a non-negative number" in row for row in errors)
    assert any("--force flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_empty_env_prefix() -> None:
    module = _load_module()

    class _Args:
        repo_path = "/tmp/repo"
        stage = "repo-autostart"
        interval_s = 30.0
        cooldown_s = 30.0
        env_prefix = ""
        force = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--env-prefix must be a non-empty string" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_values() -> None:
    module = _load_module()

    class _Args:
        repo_path = "/tmp/repo"
        stage = "repo-autostart"
        interval_s = 30.0
        cooldown_s = 30.0
        env_prefix = "RUNTIME_GUARD"
        force = True

    assert module._validate_cli_configuration(_Args()) == []
