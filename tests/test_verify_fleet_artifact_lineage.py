from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "verify_fleet_artifact_lineage.py"
    spec = importlib.util.spec_from_file_location("verify_fleet_artifact_lineage", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stamp_artifact_sha256(payload: dict) -> dict:
    prov = payload.get("provenance")
    assert isinstance(prov, dict)
    canonical_payload = json.loads(json.dumps(payload, sort_keys=True))
    canonical_prov = canonical_payload.get("provenance")
    if isinstance(canonical_prov, dict):
        canonical_prov.pop("artifact_sha256", None)
        canonical_prov.pop("signature", None)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    prov["artifact_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def _stamp_signature_envelope(payload: dict, *, detached: bool = False) -> dict:
    prov = payload.get("provenance")
    assert isinstance(prov, dict)
    artifact_sha = str(prov.get("artifact_sha256") or "")
    if detached:
        prov["signature"] = {
            "mode": "detached",
            "signed_field": "artifact_sha256",
            "signed_value": artifact_sha,
            "algorithm": "ed25519",
            "key_id": "test-key",
            "signature": "deadbeef",
        }
    else:
        prov["signature"] = {
            "mode": "unsigned",
            "signed_field": "artifact_sha256",
            "signed_value": artifact_sha,
            "algorithm": "",
            "key_id": "",
            "signature": "",
        }
    return payload


def test_validate_cli_configuration_requires_public_key_for_verification():
    module = _load_module()

    class _Args:
        verify_signatures = True
        require_signed = True
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = False
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--signature-public-key" in errors[0]


def test_validate_cli_configuration_requires_signed_mode_when_verifying():
    module = _load_module()

    class _Args:
        verify_signatures = True
        require_signed = False
        signature_public_key = "/tmp/public.pem"
        allowed_key_id: list[str] = []
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = False
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--require-signed" in errors[0]


def test_validate_cli_configuration_requires_verification_for_allowed_key_ids():
    module = _load_module()

    class _Args:
        verify_signatures = False
        require_signed = True
        signature_public_key = ""
        allowed_key_id = ["fleet-key-a"]
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = False
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--verify-signatures" in errors[0]
    assert "--allowed-key-id" in errors[0]


def test_validate_cli_configuration_requires_verification_for_signature_age_policy():
    module = _load_module()

    class _Args:
        verify_signatures = False
        require_signed = True
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = 4
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = False
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--verify-signatures" in errors[0]
    assert "--max-signature-age-hours" in errors[0]


def test_validate_cli_configuration_requires_expected_signed_inputs_when_expected_verification_enabled():
    module = _load_module()

    class _Args:
        verify_signatures = False
        require_signed = False
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = True
        expected_require_signed_report_inputs = False
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--expected-require-signed-report-inputs" in errors[0]


def test_validate_cli_configuration_requires_expected_verification_for_expected_allowed_key_ids():
    module = _load_module()

    class _Args:
        verify_signatures = False
        require_signed = False
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = True
        expected_report_allowed_key_id = ["report-key-a"]
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--expected-verify-report-input-signatures" in errors[0]
    assert "--expected-report-allowed-key-id" in errors[0]


def test_validate_cli_configuration_requires_expected_verification_for_expected_signature_age_policy():
    module = _load_module()

    class _Args:
        verify_signatures = False
        require_signed = False
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = True
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 7

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 1
    assert "--expected-verify-report-input-signatures" in errors[0]
    assert "--expected-max-report-signature-age-hours" in errors[0]


def test_validate_cli_configuration_rejects_negative_age_policies():
    module = _load_module()

    class _Args:
        verify_signatures = False
        require_signed = False
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = -1
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = False
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = -2

    errors = module._validate_cli_configuration(_Args())
    assert len(errors) == 2
    assert any("--max-signature-age-hours" in row for row in errors)
    assert any("--expected-max-report-signature-age-hours" in row for row in errors)


def test_validate_cli_configuration_rejects_non_boolean_policy_flags() -> None:
    module = _load_module()

    class _Args:
        verify_signatures = "true"  # type: ignore[assignment]
        require_signed = 1  # type: ignore[assignment]
        signature_public_key = "/tmp/public.pem"
        allowed_key_id: list[str] = []
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = "false"  # type: ignore[assignment]
        expected_require_signed_report_inputs = 0  # type: ignore[assignment]
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert any("--verify-signatures flag must be boolean" in row for row in errors)
    assert any("--require-signed flag must be boolean" in row for row in errors)
    assert any(
        "--expected-verify-report-input-signatures flag must be boolean" in row
        for row in errors
    )
    assert any(
        "--expected-require-signed-report-inputs flag must be boolean" in row
        for row in errors
    )


def test_validate_cli_configuration_rejects_non_integer_age_policy_types() -> None:
    module = _load_module()

    class _Args:
        verify_signatures = False
        require_signed = False
        signature_public_key = ""
        allowed_key_id: list[str] = []
        max_signature_age_hours = "4"  # type: ignore[assignment]
        expected_verify_report_input_signatures = False
        expected_require_signed_report_inputs = False
        expected_report_allowed_key_id: list[str] = []
        expected_max_report_signature_age_hours = 2.5  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--max-signature-age-hours must be a non-negative integer" in row for row in errors)
    assert any(
        "--expected-max-report-signature-age-hours must be a non-negative integer" in row
        for row in errors
    )


def test_validate_cli_configuration_rejects_non_string_key_id_values() -> None:
    module = _load_module()

    class _Args:
        verify_signatures = True
        require_signed = True
        signature_public_key = "/tmp/public.pem"
        allowed_key_id = ["fleet-key", 101]  # type: ignore[list-item]
        max_signature_age_hours = 0
        expected_verify_report_input_signatures = True
        expected_require_signed_report_inputs = True
        expected_report_allowed_key_id = ["report-key", object()]  # type: ignore[list-item]
        expected_max_report_signature_age_hours = 0

    errors = module._validate_cli_configuration(_Args())
    assert any("--allowed-key-id values must be strings" in row for row in errors)
    assert any("--expected-report-allowed-key-id values must be strings" in row for row in errors)


def test_validate_provenance_rejects_invalid_core_field_types():
    module = _load_module()
    errors = module._validate_provenance(
        "integration_fleet_status",
        {
            "provenance": {
                "schema_version": "1",
                "tool": "",
                "generated_at_utc": "2026-05-12T00:00:00",
                "run_id": "",
                "inputs": [],
                "artifact_sha256": 123,
                "git_commit": 123,
                "script": None,
            }
        },
        strict=True,
    )
    assert any("provenance.schema_version must be a positive integer" in row for row in errors)
    assert any("provenance.tool must be a non-empty string" in row for row in errors)
    assert any("provenance.generated_at_utc must be UTC Z format" in row for row in errors)
    assert any("provenance.run_id must be a non-empty string" in row for row in errors)
    assert any("provenance.inputs must be an object" in row for row in errors)
    assert any("provenance.artifact_sha256 must be a non-empty string" in row for row in errors)
    assert any("provenance.git_commit missing in strict mode" in row for row in errors)
    assert any("provenance.script missing in strict mode" in row for row in errors)


def test_extract_run_id_rejects_non_string_fields():
    module = _load_module()

    payload = {
        "run_id": 123,
        "summary": {
            "run_id": ["ci-1"],
        },
    }
    assert module._extract_run_id(payload) == ""

    summary_payload = {
        "summary": {
            "run_id": "  ci-2  ",
        }
    }
    assert module._extract_run_id(summary_payload) == "ci-2"


def test_validate_artifact_sha256_rejects_non_string_value() -> None:
    module = _load_module()
    errors = module._validate_artifact_sha256(
        "integration_fleet_status",
        {
            "provenance": {
                "artifact_sha256": 101,
            }
        },
    )
    assert errors == ["integration_fleet_status: missing provenance artifact_sha256"]


def test_validate_expected_tool_rejects_non_string_provenance_tool() -> None:
    module = _load_module()
    errors = module._validate_expected_tool(
        "integration_fleet_status",
        {
            "provenance": {
                "tool": 101,
            }
        },
        "validate_integration_fleet",
    )
    assert errors == ["integration_fleet_status: provenance.tool missing"]


def test_validate_expected_report_allowed_key_policy_rejects_non_string_expected_values() -> None:
    module = _load_module()
    errors = module._validate_expected_integration_report_signature_policy(
        {
            "provenance": {
                "inputs": {
                    "require_signed_report_inputs": False,
                    "verify_report_input_signatures": False,
                    "report_allowed_key_ids": [],
                    "max_report_signature_age_hours": 0,
                }
            }
        },
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=["", 101],
        expected_max_report_signature_age_hours=0,
    )
    assert any(
        "expected report_allowed_key_ids policy values must be strings" in row
        for row in errors
    )


def test_validate_expected_report_signature_policy_rejects_non_boolean_expected_flags() -> None:
    module = _load_module()
    errors = module._validate_expected_integration_report_signature_policy(
        {
            "provenance": {
                "inputs": {
                    "require_signed_report_inputs": False,
                    "verify_report_input_signatures": False,
                    "report_allowed_key_ids": [],
                    "max_report_signature_age_hours": 0,
                }
            }
        },
        expected_require_signed_report_inputs="false",  # type: ignore[arg-type]
        expected_verify_report_input_signatures=1,  # type: ignore[arg-type]
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert any(
        "expected require_signed_report_inputs policy must be boolean" in row
        for row in errors
    )
    assert any(
        "expected verify_report_input_signatures policy must be boolean" in row
        for row in errors
    )


def test_validate_expected_report_signature_policy_rejects_non_integer_expected_age() -> None:
    module = _load_module()
    errors = module._validate_expected_integration_report_signature_policy(
        {
            "provenance": {
                "inputs": {
                    "require_signed_report_inputs": False,
                    "verify_report_input_signatures": False,
                    "report_allowed_key_ids": [],
                    "max_report_signature_age_hours": 0,
                }
            }
        },
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours="0",  # type: ignore[arg-type]
    )
    assert any(
        "expected max_report_signature_age_hours policy must be a non-negative integer" in row
        for row in errors
    )


def test_build_result_passes_for_consistent_artifacts(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = {
        "run_id": "ci-1",
        "summary": {"run_id": "ci-1"},
        "provenance": {
            "schema_version": 1,
            "tool": "enforce_runtime_guard_all_repos",
            "generated_at_utc": "2026-05-12T00:00:00Z",
            "run_id": "ci-1",
            "git_commit": "abc123",
            "script": "/repo/scripts/enforce_runtime_guard_all_repos.py",
            "inputs": {},
        },
    }
    integration = {
        "run_id": "ci-1",
        "summary": {"run_id": "ci-1"},
        "provenance": {
            "schema_version": 1,
            "tool": "validate_integration_fleet",
            "generated_at_utc": "2026-05-12T00:00:01Z",
            "run_id": "ci-1",
            "git_commit": "abc123",
            "script": "/repo/scripts/validate_integration_fleet.py",
            "inputs": {
                "require_signed_report_inputs": False,
                "verify_report_input_signatures": False,
                "report_allowed_key_ids": [],
                "max_report_signature_age_hours": 0,
            },
        },
    }

    enforcement = _stamp_signature_envelope(_stamp_artifact_sha256(enforcement))
    integration = _stamp_signature_envelope(_stamp_artifact_sha256(integration))
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = {
        "run_id": "ci-1",
        "summary": {"run_id": "ci-1"},
        "provenance": {
            "schema_version": 1,
            "tool": "repo_guard_fleet_report",
            "generated_at_utc": "2026-05-12T00:00:02Z",
            "run_id": "ci-1",
            "git_commit": "abc123",
            "script": "/repo/scripts/repo_guard_fleet_report.py",
            "inputs": {
                "source_artifact_hashes": {
                    "repo_guard_enforcement": _sha(enforcement_path),
                    "integration_fleet_status": _sha(integration_path),
                }
            },
        },
    }
    runtime = _stamp_signature_envelope(_stamp_artifact_sha256(runtime))
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is True
    assert result["errors"] == []
    assert result["run_id"] == "ci-1"


def test_build_result_fails_on_hash_or_run_id_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-a",
            "provenance": {
                "schema_version": 1,
                "tool": "enforce_runtime_guard_all_repos",
                "generated_at_utc": "2026-05-12T00:00:00Z",
                "run_id": "ci-a",
                "inputs": {},
            },
        }
    ))
    integration = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-b",
            "provenance": {
                "schema_version": 1,
                "tool": "validate_integration_fleet",
                "generated_at_utc": "2026-05-12T00:00:01Z",
                "run_id": "ci-b",
                "inputs": {},
            },
        }
    ))
    runtime = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-a",
            "provenance": {
                "schema_version": 1,
                "tool": "repo_guard_fleet_report",
                "generated_at_utc": "2026-05-12T00:00:02Z",
                "run_id": "ci-a",
                "inputs": {
                    "source_artifact_hashes": {
                        "repo_guard_enforcement": "deadbeef",
                        "integration_fleet_status": "deadbeef",
                    }
                },
            },
        }
    ))
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("run_id values do not match" in row for row in result["errors"])
    assert any("source hash mismatch" in row for row in result["errors"])


def test_build_result_rejects_non_string_runtime_source_hash_values(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "provenance": {
                "schema_version": 1,
                "tool": "enforce_runtime_guard_all_repos",
                "generated_at_utc": "2026-05-12T00:00:00Z",
                "run_id": "ci-1",
                "inputs": {},
            },
        }
    ))
    integration = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "provenance": {
                "schema_version": 1,
                "tool": "validate_integration_fleet",
                "generated_at_utc": "2026-05-12T00:00:01Z",
                "run_id": "ci-1",
                "inputs": {},
            },
        }
    ))
    runtime = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "provenance": {
                "schema_version": 1,
                "tool": "repo_guard_fleet_report",
                "generated_at_utc": "2026-05-12T00:00:02Z",
                "run_id": "ci-1",
                "inputs": {
                    "source_artifact_hashes": {
                        "repo_guard_enforcement": 101,
                        "integration_fleet_status": "deadbeef",
                    }
                },
            },
        }
    ))

    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )

    assert ok is False
    assert any(
        "source hash for repo_guard_enforcement must be a non-empty string" in row
        for row in result["errors"]
    )


def test_build_result_fails_safely_on_invalid_artifact_json(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement_path.write_text("{not json", encoding="utf-8")
    integration_path.write_text("[]", encoding="utf-8")
    runtime_path.write_text("{}", encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("repo_guard_enforcement: unable to parse artifact JSON" in row for row in result["errors"])
    assert any("integration_fleet_status: unable to parse artifact JSON" in row for row in result["errors"])


def test_build_result_fails_on_artifact_digest_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "summary": {"run_id": "ci-1"},
            "provenance": {
                "schema_version": 1,
                "tool": "enforce_runtime_guard_all_repos",
                "generated_at_utc": "2026-05-12T00:00:00Z",
                "run_id": "ci-1",
                "inputs": {},
            },
        }
    ))
    integration = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "summary": {"run_id": "ci-1"},
            "provenance": {
                "schema_version": 1,
                "tool": "validate_integration_fleet",
                "generated_at_utc": "2026-05-12T00:00:01Z",
                "run_id": "ci-1",
                "inputs": {},
            },
        }
    ))
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "summary": {"run_id": "ci-1"},
            "provenance": {
                "schema_version": 1,
                "tool": "repo_guard_fleet_report",
                "generated_at_utc": "2026-05-12T00:00:02Z",
                "run_id": "ci-1",
                "inputs": {
                    "source_artifact_hashes": {
                        "repo_guard_enforcement": _sha(enforcement_path),
                        "integration_fleet_status": _sha(integration_path),
                    }
                },
            },
        }
    ))
    runtime["provenance"]["artifact_sha256"] = "badbadbad"
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("artifact_sha256 mismatch" in row for row in result["errors"])


def test_build_result_fails_on_artifact_tool_identity_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "summary": {"run_id": "ci-1"},
            "provenance": {
                "schema_version": 1,
                "tool": "validate_integration_fleet",
                "generated_at_utc": "2026-05-12T00:00:00Z",
                "run_id": "ci-1",
                "inputs": {},
            },
        }
    ))
    integration = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "summary": {"run_id": "ci-1"},
            "provenance": {
                "schema_version": 1,
                "tool": "validate_integration_fleet",
                "generated_at_utc": "2026-05-12T00:00:01Z",
                "run_id": "ci-1",
                "inputs": {},
            },
        }
    ))
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(_stamp_artifact_sha256(
        {
            "run_id": "ci-1",
            "summary": {"run_id": "ci-1"},
            "provenance": {
                "schema_version": 1,
                "tool": "repo_guard_fleet_report",
                "generated_at_utc": "2026-05-12T00:00:02Z",
                "run_id": "ci-1",
                "inputs": {
                    "source_artifact_hashes": {
                        "repo_guard_enforcement": _sha(enforcement_path),
                        "integration_fleet_status": _sha(integration_path),
                    }
                },
            },
        }
    ))
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("provenance.tool mismatch" in row for row in result["errors"])


def test_build_result_requires_detached_signature_when_requested(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/enforce_runtime_guard_all_repos.py",
                    "inputs": {},
                },
            }
        )
    )
    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/validate_integration_fleet.py",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/repo_guard_fleet_report.py",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=True,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("detached signature required" in row for row in result["errors"])


def test_build_result_verify_signatures_calls_crypto_backend(tmp_path: Path, monkeypatch):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/enforce_runtime_guard_all_repos.py",
                    "inputs": {},
                },
            }
        ),
        detached=True,
    )
    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/validate_integration_fleet.py",
                    "inputs": {
                        "require_signed_report_inputs": False,
                        "verify_report_input_signatures": False,
                        "report_allowed_key_ids": [],
                        "max_report_signature_age_hours": 0,
                    },
                },
            }
        ),
        detached=True,
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/repo_guard_fleet_report.py",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        ),
        detached=True,
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    monkeypatch.setattr(module, "_verify_detached_signature", lambda **_k: (True, "ok"))

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=True,
        verify_signatures=True,
        signature_public_key="/tmp/pubkey.pem",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is True
    assert result["errors"] == []


def test_build_result_rejects_non_string_signature_envelope_fields(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/enforce_runtime_guard_all_repos.py",
                    "inputs": {},
                },
            }
        )
    )
    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/validate_integration_fleet.py",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/repo_guard_fleet_report.py",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )

    enforcement["provenance"]["signature"] = {
        "mode": 123,
        "signed_field": True,
        "signed_value": False,
        "algorithm": 7,
        "key_id": [],
        "signature": {},
    }
    integration["provenance"]["signature"] = enforcement["provenance"]["signature"]
    runtime["provenance"]["signature"] = enforcement["provenance"]["signature"]

    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=True,
        verify_signatures=True,
        signature_public_key="/tmp/pubkey.pem",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("signature mode must be a non-empty string" in row for row in result["errors"])
    assert any("signature.signed_field must be a non-empty string" in row for row in result["errors"])
    assert any("signature.signed_value must be a non-empty string" in row for row in result["errors"])


def test_build_result_fails_on_disallowed_key_id(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/enforce_runtime_guard_all_repos.py",
                    "inputs": {},
                },
            }
        ),
        detached=True,
    )
    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/validate_integration_fleet.py",
                    "inputs": {},
                },
            }
        ),
        detached=True,
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/repo_guard_fleet_report.py",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        ),
        detached=True,
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=True,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=["another-key"],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("not in allowed-key-id policy" in row for row in result["errors"])


def test_build_result_fails_when_signature_age_exceeds_limit(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2020-01-01T00:00:00Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/enforce_runtime_guard_all_repos.py",
                    "inputs": {},
                },
            }
        ),
        detached=True,
    )
    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2020-01-01T00:00:00Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/validate_integration_fleet.py",
                    "inputs": {},
                },
            }
        ),
        detached=True,
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2020-01-01T00:00:00Z",
                    "run_id": "ci-1",
                    "git_commit": "abc123",
                    "script": "/repo/scripts/repo_guard_fleet_report.py",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        ),
        detached=True,
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=True,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=1,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("signature age" in row for row in result["errors"])


def test_build_result_fails_on_integration_fallback_policy_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "pressure_fallback": {
                    "enabled": True,
                    "pressure_detected": True,
                    "fallback_report_dir": "/repo/reports",
                    "max_report_age_hours": 12,
                    "note": None,
                },
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": True,
                        "fallback_report_dir": "/repo/reports",
                        "max_fallback_report_age_hours": 24,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("fallback age policy mismatch" in row for row in result["errors"])


def test_build_result_fails_on_integration_fallback_enabled_policy_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "pressure_fallback": {
                    "enabled": True,
                    "pressure_detected": True,
                    "fallback_report_dir": "/repo/reports",
                    "max_report_age_hours": 12,
                    "note": None,
                },
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": False,
                        "fallback_report_dir": "/repo/reports",
                        "max_fallback_report_age_hours": 12,
                        "require_signed_report_inputs": False,
                        "verify_report_input_signatures": False,
                        "report_allowed_key_ids": [],
                        "max_report_signature_age_hours": 0,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("fallback enabled policy mismatch" in row for row in result["errors"])


def test_build_result_fails_on_integration_fallback_directory_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "pressure_fallback": {
                    "enabled": True,
                    "pressure_detected": True,
                    "fallback_report_dir": "/repo/reports-a",
                    "max_report_age_hours": 12,
                    "note": None,
                },
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": True,
                        "fallback_report_dir": "/repo/reports-b",
                        "max_fallback_report_age_hours": 12,
                        "require_signed_report_inputs": False,
                        "verify_report_input_signatures": False,
                        "report_allowed_key_ids": [],
                        "max_report_signature_age_hours": 0,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("fallback report directory mismatch" in row for row in result["errors"])


def test_build_result_fails_on_integration_fallback_policy_type_errors(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "pressure_fallback": {
                    "enabled": "true",
                    "pressure_detected": True,
                    "fallback_report_dir": 123,
                    "max_report_age_hours": "12",
                    "note": None,
                },
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": "false",
                        "fallback_report_dir": 456,
                        "max_fallback_report_age_hours": -1,
                        "require_signed_report_inputs": False,
                        "verify_report_input_signatures": False,
                        "report_allowed_key_ids": [],
                        "max_report_signature_age_hours": 0,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("pressure_fallback.enabled must be a boolean" in row for row in result["errors"])
    assert any("pressure_fallback.fallback_report_dir must be a string" in row for row in result["errors"])
    assert any("pressure_fallback.max_report_age_hours must be a non-negative integer" in row for row in result["errors"])
    assert any("provenance.inputs.fallback_on_pressure must be a boolean" in row for row in result["errors"])
    assert any("provenance.inputs.fallback_report_dir must be a string" in row for row in result["errors"])
    assert any("provenance.inputs.max_fallback_report_age_hours must be a non-negative integer" in row for row in result["errors"])


def test_build_result_fails_on_report_signature_policy_type_errors(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": False,
                        "fallback_report_dir": "",
                        "max_fallback_report_age_hours": 0,
                        "require_signed_report_inputs": "false",
                        "verify_report_input_signatures": "false",
                        "report_allowed_key_ids": ["key-a", 42],
                        "max_report_signature_age_hours": "0",
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("provenance.inputs.require_signed_report_inputs must be a boolean" in row for row in result["errors"])
    assert any("provenance.inputs.verify_report_input_signatures must be a boolean" in row for row in result["errors"])
    assert any("provenance.inputs.report_allowed_key_ids entries must be strings" in row for row in result["errors"])
    assert any("provenance.inputs.max_report_signature_age_hours must be a non-negative integer" in row for row in result["errors"])


def test_build_result_fails_when_runtime_source_hashes_is_not_object(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": False,
                        "fallback_report_dir": "",
                        "max_fallback_report_age_hours": 0,
                        "require_signed_report_inputs": False,
                        "verify_report_input_signatures": False,
                        "report_allowed_key_ids": [],
                        "max_report_signature_age_hours": 0,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": ["not", "an", "object"],
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("source_artifact_hashes must be an object" in row for row in result["errors"])
    assert any("missing source hash" in row for row in result["errors"])


def test_build_result_fails_on_expected_integration_report_signature_policy_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "pressure_fallback": {
                    "enabled": True,
                    "pressure_detected": True,
                    "fallback_report_dir": "/repo/reports",
                    "max_report_age_hours": 12,
                    "note": None,
                },
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": True,
                        "fallback_report_dir": "/repo/reports",
                        "max_fallback_report_age_hours": 12,
                        "require_signed_report_inputs": False,
                        "verify_report_input_signatures": False,
                        "report_allowed_key_ids": [],
                        "max_report_signature_age_hours": 0,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=True,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("expected require_signed_report_inputs policy does not match" in row for row in result["errors"])


def test_build_result_fails_when_default_expected_report_signature_policy_does_not_match(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": False,
                        "fallback_report_dir": "",
                        "max_fallback_report_age_hours": 0,
                        "require_signed_report_inputs": True,
                        "verify_report_input_signatures": True,
                        "report_allowed_key_ids": ["report-key-a"],
                        "max_report_signature_age_hours": 4,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("expected require_signed_report_inputs policy does not match" in row for row in result["errors"])
    assert any("expected verify_report_input_signatures policy does not match" in row for row in result["errors"])
    assert any("expected report_allowed_key_ids policy does not match" in row for row in result["errors"])
    assert any("expected max_report_signature_age_hours policy does not match" in row for row in result["errors"])


def test_build_result_fails_when_report_signature_policy_keys_missing_from_provenance_inputs(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "enforce_runtime_guard_all_repos",
                    "generated_at_utc": "2026-05-12T00:00:00Z",
                    "run_id": "ci-1",
                    "inputs": {},
                },
            }
        )
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")

    integration = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "validate_integration_fleet",
                    "generated_at_utc": "2026-05-12T00:00:01Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {},
                        "validator_script_hashes": {},
                        "fallback_on_pressure": False,
                        "fallback_report_dir": "",
                        "max_fallback_report_age_hours": 0,
                    },
                },
            }
        )
    )
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_signature_envelope(
        _stamp_artifact_sha256(
            {
                "run_id": "ci-1",
                "summary": {"run_id": "ci-1"},
                "provenance": {
                    "schema_version": 1,
                    "tool": "repo_guard_fleet_report",
                    "generated_at_utc": "2026-05-12T00:00:02Z",
                    "run_id": "ci-1",
                    "inputs": {
                        "source_artifact_hashes": {
                            "repo_guard_enforcement": _sha(enforcement_path),
                            "integration_fleet_status": _sha(integration_path),
                        }
                    },
                },
            }
        )
    )
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
        require_signed=False,
        verify_signatures=False,
        signature_public_key="",
        allowed_key_ids=[],
        max_signature_age_hours=0,
        expected_require_signed_report_inputs=False,
        expected_verify_report_input_signatures=False,
        expected_report_allowed_key_ids=[],
        expected_max_report_signature_age_hours=0,
    )
    assert ok is False
    assert any("missing 'require_signed_report_inputs'" in row for row in result["errors"])
    assert any("missing 'verify_report_input_signatures'" in row for row in result["errors"])
    assert any("missing 'report_allowed_key_ids'" in row for row in result["errors"])
    assert any("missing 'max_report_signature_age_hours'" in row for row in result["errors"])
