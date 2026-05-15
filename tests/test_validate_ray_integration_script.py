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


def test_strict_bool_field_rejects_non_boolean_values() -> None:
    module = _load_module()
    value, ok = module._strict_bool_field({"available": "true"}, "available")
    assert value is False
    assert ok is False


def test_strict_bool_field_accepts_boolean_values() -> None:
    module = _load_module()
    value, ok = module._strict_bool_field({"available": True}, "available")
    assert value is True
    assert ok is True


def test_extract_signature_artifact_sha256_rejects_non_string() -> None:
    module = _load_module()
    value, ok = module._extract_signature_artifact_sha256({"artifact_sha256": 123})
    assert value == ""
    assert ok is False


def test_extract_signature_artifact_sha256_accepts_string() -> None:
    module = _load_module()
    value, ok = module._extract_signature_artifact_sha256({"artifact_sha256": "abc"})
    assert value == "abc"
    assert ok is True


def test_main_rejects_non_boolean_flags_even_if_prevalidation_is_bypassed(
    monkeypatch, capsys
) -> None:
    module = _load_module()

    class _Args:
        json = "true"  # type: ignore[assignment]
        require_hooks = False
        check_actor_api = False
        stage = "ray-get"
        run_id = ""

    monkeypatch.setattr(
        module,
        "_build_parser",
        lambda: type("_P", (), {"parse_args": lambda self: _Args()})(),
    )
    monkeypatch.setattr(module, "_validate_cli_configuration", lambda _args: [])

    result_code = module.main()
    captured = capsys.readouterr()
    assert result_code == 2
    assert "--json flag must be boolean" in captured.err
