#!/usr/bin/env python3
"""Verify RuntimeGuard fleet artifact lineage and correlation integrity.

Checks:
- Required artifacts exist and are valid JSON objects.
- run_id is present and consistent across enforcement/integration/runtime artifacts.
- provenance block exists with required fields.
- runtime provenance source artifact hashes match current enforcement/integration files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify fleet artifact lineage integrity")
    parser.add_argument(
        "--enforcement-report",
        default="reports/repo_guard_enforcement.json",
        help="Path to enforcement artifact JSON",
    )
    parser.add_argument(
        "--integration-report",
        default="reports/integration_fleet_status.json",
        help="Path to integration artifact JSON",
    )
    parser.add_argument(
        "--runtime-report",
        default="reports/repo_guard_runtime_status.json",
        help="Path to runtime artifact JSON",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output (default: compact text)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when optional provenance metadata (git_commit/script) is missing",
    )
    return parser


def _load_json(path: Path) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"artifact must be JSON object: {path}")
    return parsed


def _extract_run_id(payload: dict[str, Any]) -> str:
    root = str(payload.get("run_id") or "").strip()
    if root:
        return root
    summary = payload.get("summary")
    if isinstance(summary, dict):
        nested = str(summary.get("run_id") or "").strip()
        if nested:
            return nested
    return ""


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_provenance(name: str, payload: dict[str, Any], strict: bool) -> list[str]:
    errors: list[str] = []
    prov = payload.get("provenance")
    if not isinstance(prov, dict):
        return [f"{name}: missing provenance block"]

    required = ["schema_version", "tool", "generated_at_utc", "run_id", "inputs"]
    for key in required:
        if key not in prov:
            errors.append(f"{name}: provenance missing '{key}'")

    generated = str(prov.get("generated_at_utc") or "")
    if generated and not generated.endswith("Z"):
        errors.append(f"{name}: provenance.generated_at_utc must be UTC Z format")

    if strict:
        if not str(prov.get("git_commit") or "").strip():
            errors.append(f"{name}: provenance.git_commit missing in strict mode")
        if not str(prov.get("script") or "").strip():
            errors.append(f"{name}: provenance.script missing in strict mode")

    return errors


def _build_result(
    enforcement_path: Path,
    integration_path: Path,
    runtime_path: Path,
    strict: bool,
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []

    for path in [enforcement_path, integration_path, runtime_path]:
        if not path.exists():
            errors.append(f"missing artifact: {path}")
    if errors:
        return False, {"ok": False, "errors": errors}

    enforcement = _load_json(enforcement_path)
    integration = _load_json(integration_path)
    runtime = _load_json(runtime_path)

    run_ids = {
        "repo_guard_enforcement": _extract_run_id(enforcement),
        "integration_fleet_status": _extract_run_id(integration),
        "repo_guard_runtime_status": _extract_run_id(runtime),
    }
    if any(not value for value in run_ids.values()):
        errors.append("one or more artifacts have missing run_id")
    if len(set(run_ids.values())) != 1:
        errors.append("artifact run_id values do not match")

    errors.extend(_validate_provenance("repo_guard_enforcement", enforcement, strict))
    errors.extend(_validate_provenance("integration_fleet_status", integration, strict))
    errors.extend(_validate_provenance("repo_guard_runtime_status", runtime, strict))

    runtime_prov = runtime.get("provenance", {})
    runtime_inputs = runtime_prov.get("inputs", {}) if isinstance(runtime_prov, dict) else {}
    runtime_source_hashes = (
        runtime_inputs.get("source_artifact_hashes", {})
        if isinstance(runtime_inputs, dict)
        else {}
    )

    expected_source_hashes = {
        "repo_guard_enforcement": _sha256_file(enforcement_path),
        "integration_fleet_status": _sha256_file(integration_path),
    }
    for key, expected in expected_source_hashes.items():
        actual = str(runtime_source_hashes.get(key) or "").strip()
        if not actual:
            errors.append(f"repo_guard_runtime_status: missing source hash for {key}")
            continue
        if actual != expected:
            errors.append(
                f"repo_guard_runtime_status: source hash mismatch for {key}"
            )

    result = {
        "ok": len(errors) == 0,
        "errors": errors,
        "run_id": next(iter(set(run_ids.values()))) if len(set(run_ids.values())) == 1 else "",
        "run_ids": run_ids,
        "artifacts": {
            "repo_guard_enforcement": str(enforcement_path),
            "integration_fleet_status": str(integration_path),
            "repo_guard_runtime_status": str(runtime_path),
        },
        "runtime_expected_source_hashes": expected_source_hashes,
    }
    return result["ok"], result


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(__file__).resolve().parent.parent

    enforcement_path = Path(args.enforcement_report)
    if not enforcement_path.is_absolute():
        enforcement_path = repo_root / enforcement_path

    integration_path = Path(args.integration_report)
    if not integration_path.is_absolute():
        integration_path = repo_root / integration_path

    runtime_path = Path(args.runtime_report)
    if not runtime_path.is_absolute():
        runtime_path = repo_root / runtime_path

    ok, result = _build_result(
        enforcement_path,
        integration_path,
        runtime_path,
        strict=bool(args.strict),
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("PASS" if ok else "FAIL")
        if result.get("run_id"):
            print(f"run_id: {result['run_id']}")
        for row in result.get("errors", []):
            print(f"- {row}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
