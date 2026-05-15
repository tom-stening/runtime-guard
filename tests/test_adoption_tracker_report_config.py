from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "adoption_tracker_report.py"
    spec = importlib.util.spec_from_file_location("adoption_tracker_report", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_cli_configuration_rejects_non_string_tracker_and_output() -> None:
    module = _load_module()

    class _Args:
        tracker = 101  # type: ignore[assignment]
        output = 202  # type: ignore[assignment]
        fail_on_gaps = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--tracker must be a non-empty string path" in row for row in errors)
    assert any("--output must be a string path" in row for row in errors)


def test_validate_cli_configuration_rejects_non_boolean_fail_on_gaps() -> None:
    module = _load_module()

    class _Args:
        tracker = "ADOPTION_TRACKER.md"
        output = None
        fail_on_gaps = "true"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--fail-on-gaps flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_accepts_valid_values() -> None:
    module = _load_module()

    class _Args:
        tracker = "ADOPTION_TRACKER.md"
        output = "tracker_report.json"
        fail_on_gaps = True

    assert module._validate_cli_configuration(_Args()) == []


def test_build_records_rejects_non_string_stage_and_evidence_fields() -> None:
    module = _load_module()

    records, invalid_stage_teams, invalid_evidence_teams = module._build_records(
        [
            {
                "Team ID": "T01",
                "Organization": "Org1",
                "Stage": 123,
                "Primary Use Case": "Use",
                "Integration Mode": ["not", "string"],
                "Outcome Metric": "Metric",
            }
        ]
    )

    assert records[0]["team"] == "T01"
    assert records[0]["stage"] == "unknown"
    assert invalid_stage_teams == ["T01"]
    assert invalid_evidence_teams == ["T01"]


def test_build_records_accepts_string_fields() -> None:
    module = _load_module()

    records, invalid_stage_teams, invalid_evidence_teams = module._build_records(
        [
            {
                "Team ID": "T01",
                "Organization": "Org1",
                "Stage": "Pilot",
                "Primary Use Case": "Use",
                "Integration Mode": "CLI",
                "Outcome Metric": "Metric",
            }
        ]
    )

    assert records[0]["team"] == "T01"
    assert records[0]["stage"] == "pilot"
    assert invalid_stage_teams == []
    assert invalid_evidence_teams == []
