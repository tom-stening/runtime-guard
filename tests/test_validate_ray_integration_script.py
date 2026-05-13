from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "validate_ray_integration.py"
    spec = importlib.util.spec_from_file_location("validate_ray_integration", script_path)
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
        require_hooks = 1  # type: ignore[assignment]
        check_actor_api = "false"  # type: ignore[assignment]
        stage = "ray-get"
        run_id = ""

    errors = module._validate_cli_configuration(_Args())
    assert any("--json flag must be boolean" in row for row in errors)
    assert any("--require-hooks flag must be boolean" in row for row in errors)
    assert any("--check-actor-api flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_or_empty_stage() -> None:
    module = _load_module()

    class _Args:
        json = False
        require_hooks = False
        check_actor_api = False
        stage = 123  # type: ignore[assignment]
        run_id = ""

    errors = module._validate_cli_configuration(_Args())
    assert any("--stage must be a non-empty string" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_run_id() -> None:
    module = _load_module()

    class _Args:
        json = False
        require_hooks = False
        check_actor_api = False
        stage = "ray-get"
        run_id = 123  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--run-id must be a string" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_inputs() -> None:
    module = _load_module()

    class _Args:
        json = True
        require_hooks = True
        check_actor_api = True
        stage = "ray-get"
        run_id = "ci-123"

    assert module._validate_cli_configuration(_Args()) == []
