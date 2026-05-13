from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "runtime_guard_repo_watcher.py"
    spec = importlib.util.spec_from_file_location("runtime_guard_repo_watcher", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_string_paths_and_stage() -> None:
    module = _load_module()

    class _Args:
        repo_path = 101  # type: ignore[assignment]
        stage = None  # type: ignore[assignment]
        interval_active = 15.0
        interval_idle = 60.0
        cooldown_s = 30.0
        log_tag = ""
        once = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--repo-path must be a non-empty string" in row for row in errors)
    assert any("--stage must be a non-empty string" in row for row in errors)


def test_validate_cli_configuration_rejects_non_numeric_intervals() -> None:
    module = _load_module()

    class _Args:
        repo_path = "/tmp/repo"
        stage = "repo-background"
        interval_active = "15"  # type: ignore[assignment]
        interval_idle = -1
        cooldown_s = True  # type: ignore[assignment]
        log_tag = ""
        once = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--interval-active must be a non-negative number" in row for row in errors)
    assert any("--interval-idle must be a non-negative number" in row for row in errors)
    assert any("--cooldown-s must be a non-negative number" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_log_tag_and_once_flag() -> None:
    module = _load_module()

    class _Args:
        repo_path = "/tmp/repo"
        stage = "repo-background"
        interval_active = 15.0
        interval_idle = 60.0
        cooldown_s = 30.0
        log_tag = 123  # type: ignore[assignment]
        once = "true"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--log-tag must be a string" in row for row in errors)
    assert any("--once flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_values() -> None:
    module = _load_module()

    class _Args:
        repo_path = "/tmp/repo"
        stage = "repo-background"
        interval_active = 15.0
        interval_idle = 60.0
        cooldown_s = 30.0
        log_tag = "repo"
        once = True

    assert module._validate_cli_configuration(_Args()) == []
