from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "soc2_audit_kickoff_pack.py"
    spec = importlib.util.spec_from_file_location("soc2_audit_kickoff_pack", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_string_required_paths() -> None:
    module = _load_module()

    class _Args:
        readiness_report = 101  # type: ignore[assignment]
        contacts = 202  # type: ignore[assignment]
        output = 303  # type: ignore[assignment]
        audit_window_start = None
        audit_window_end = None
        fail_on_gaps = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--readiness-report must be a non-empty string path" in row for row in errors)
    assert any("--contacts must be a non-empty string path" in row for row in errors)
    assert any("--output must be a non-empty string path" in row for row in errors)


def test_validate_cli_configuration_rejects_optional_type_mismatches() -> None:
    module = _load_module()

    class _Args:
        readiness_report = "readiness.json"
        contacts = "contacts.json"
        output = "kickoff.json"
        audit_window_start = 123  # type: ignore[assignment]
        audit_window_end = 456  # type: ignore[assignment]
        fail_on_gaps = "true"  # type: ignore[assignment]
        fail_on_placeholder_contacts = "true"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--audit-window-start must be a string" in row for row in errors)
    assert any("--audit-window-end must be a string" in row for row in errors)
    assert any("--fail-on-gaps flag must be boolean" in row for row in errors)
    assert any("--fail-on-placeholder-contacts flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_values() -> None:
    module = _load_module()

    class _Args:
        readiness_report = "readiness.json"
        contacts = "contacts.json"
        output = "kickoff.json"
        audit_window_start = "2026-06-01T00:00:00Z"
        audit_window_end = "2026-06-30T23:59:59Z"
        fail_on_gaps = True
        fail_on_placeholder_contacts = False

    assert module._validate_cli_configuration(_Args()) == []


def test_main_rejects_non_string_status(tmp_path, monkeypatch, capsys) -> None:
    module = _load_module()

    readiness = tmp_path / "readiness.json"
    contacts = tmp_path / "contacts.json"
    output = tmp_path / "kickoff.json"
    readiness.write_text("{}\n", encoding="utf-8")
    contacts.write_text("{}\n", encoding="utf-8")

    args = argparse.Namespace(
        readiness_report=str(readiness),
        contacts=str(contacts),
        output=str(output),
        audit_window_start=None,
        audit_window_end=None,
        fail_on_gaps=True,
        fail_on_placeholder_contacts=False,
    )

    monkeypatch.setattr(module.argparse.ArgumentParser, "parse_args", lambda self: args)
    monkeypatch.setattr(
        module,
        "_build_kickoff_package",
        lambda *_args, **_kwargs: {
            "readiness_summary": {"status": 5},
        },
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "error: readiness status must be a string" in captured.err
