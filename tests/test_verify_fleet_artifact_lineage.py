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
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    prov["artifact_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


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
            "inputs": {},
        },
    }

    enforcement = _stamp_artifact_sha256(enforcement)
    integration = _stamp_artifact_sha256(integration)
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
    runtime = _stamp_artifact_sha256(runtime)
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=True,
    )
    assert ok is True
    assert result["errors"] == []
    assert result["run_id"] == "ci-1"


def test_build_result_fails_on_hash_or_run_id_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_artifact_sha256(
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
    )
    integration = _stamp_artifact_sha256(
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
    )
    runtime = _stamp_artifact_sha256(
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
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
    )
    assert ok is False
    assert any("run_id values do not match" in row for row in result["errors"])
    assert any("source hash mismatch" in row for row in result["errors"])


def test_build_result_fails_on_artifact_digest_mismatch(tmp_path: Path):
    module = _load_module()

    enforcement_path = tmp_path / "repo_guard_enforcement.json"
    integration_path = tmp_path / "integration_fleet_status.json"
    runtime_path = tmp_path / "repo_guard_runtime_status.json"

    enforcement = _stamp_artifact_sha256(
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
    integration = _stamp_artifact_sha256(
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
    )
    enforcement_path.write_text(json.dumps(enforcement), encoding="utf-8")
    integration_path.write_text(json.dumps(integration), encoding="utf-8")

    runtime = _stamp_artifact_sha256(
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
    runtime["provenance"]["artifact_sha256"] = "badbadbad"
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    ok, result = module._build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=False,
    )
    assert ok is False
    assert any("artifact_sha256 mismatch" in row for row in result["errors"])
