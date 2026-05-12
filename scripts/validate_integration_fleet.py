#!/usr/bin/env python3
"""Unified integration health validator for RuntimeGuard (M1 integration stream).

Runs Polars, Dask, and Ray integration validators and emits a single machine-
verifiable payload that can be used as a CI gate for integration readiness.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Polars/Dask/Ray integration validators and aggregate one health verdict"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON payload (recommended for CI)",
    )
    parser.add_argument(
        "--output",
        help="Optional output path to write the aggregated JSON payload",
    )
    parser.add_argument(
        "--require-healthy",
        action="store_true",
        help="Exit 1 if any component validator is unhealthy",
    )
    parser.add_argument(
        "--include-wsl-diagnosis",
        action="store_true",
        help="Include diagnose_wsl_crash() summary in the aggregated payload",
    )
    parser.add_argument(
        "--timeout-s",
        type=int,
        default=120,
        help="Per-validator timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--polars-report",
        help="Use an existing JSON report from validate_polars_integration.py instead of running it",
    )
    parser.add_argument(
        "--dask-report",
        help="Use an existing JSON report from validate_dask_integration.py instead of running it",
    )
    parser.add_argument(
        "--ray-report",
        help="Use an existing JSON report from validate_ray_integration.py instead of running it",
    )
    parser.add_argument(
        "--fallback-on-pressure",
        action="store_true",
        help=(
            "When runtime pressure is detected, use per-component reports from "
            "--fallback-report-dir if available"
        ),
    )
    parser.add_argument(
        "--fallback-report-dir",
        default="reports",
        help=(
            "Directory used with --fallback-on-pressure to discover component "
            "reports (default: reports)"
        ),
    )
    parser.add_argument(
        "--run-id",
        default="",
        help="Optional external run identifier for cross-artifact correlation.",
    )
    return parser


def _extract_last_json_object(text: str) -> dict[str, Any] | None:
    """Extract the last JSON object from mixed stdout text.

    Validators may emit warning lines before their JSON payload. This parser scans
    backwards for candidate JSON object starts and returns the first valid decode.
    """
    starts = [idx for idx, ch in enumerate(text) if ch == "{"]
    for idx in reversed(starts):
        candidate = text[idx:].strip()
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _required_checks_for(tool_name: str, payload: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if tool_name == "polars":
        budget_check = payload.get("scan_budget_api", {})
        callback_check = payload.get("native_callback_api", {})
        if not isinstance(budget_check, dict) or not bool(budget_check.get("available", False)):
            errors.append("scan_budget_api check failed")
        if not isinstance(callback_check, dict) or not bool(callback_check.get("available", False)):
            errors.append("native_callback_api check failed")
    elif tool_name == "dask":
        guard_check = payload.get("task_graph_guard_api", {})
        scheduler_check = payload.get("scheduler_callback_api", {})
        if not isinstance(guard_check, dict) or not bool(guard_check.get("available", False)):
            errors.append("task_graph_guard_api check failed")
        if not isinstance(scheduler_check, dict) or not bool(scheduler_check.get("available", False)):
            errors.append("scheduler_callback_api check failed")
    elif tool_name == "ray":
        actor_check = payload.get("actor_monitoring_api", {})
        if not isinstance(actor_check, dict) or not bool(actor_check.get("available", False)):
            errors.append("actor_monitoring_api check failed")

    return len(errors) == 0, errors


def _component_from_payload(
    tool_name: str,
    payload: dict[str, Any],
    *,
    source: str,
    command: list[str] | None = None,
    exit_code: int | None = None,
    hard_errors: list[str] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    errors = list(hard_errors or [])
    warning_rows = list(warnings or [])

    validator_ok = bool(payload.get("ok", False))
    api_importable = bool(payload.get("api_importable", False))
    checks_ok, check_errors = _required_checks_for(tool_name, payload)
    errors.extend(check_errors)

    payload_errors = payload.get("errors", [])
    if isinstance(payload_errors, list):
        warning_rows.extend(str(item) for item in payload_errors if str(item).strip())

    effective_exit_code = 0 if exit_code is None else int(exit_code)
    if effective_exit_code != 0:
        errors.append(f"validator exited non-zero: {effective_exit_code}")

    healthy = validator_ok and api_importable and checks_ok and effective_exit_code == 0

    return {
        "tool": tool_name,
        "source": source,
        "command": command,
        "healthy": healthy,
        "validator_ok": validator_ok,
        "api_importable": api_importable,
        "required_checks_ok": checks_ok,
        "required_check_errors": check_errors,
        "exit_code": effective_exit_code,
        "errors": errors,
        "warnings": warning_rows,
        "report": payload,
    }


def _load_report_payload(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)

    if not isinstance(parsed, dict):
        return None, "report payload must be a JSON object"

    return parsed, None


def _default_component_report_name(tool_name: str) -> str:
    return f"{tool_name}_integration_status.json"


def _safe_git_commit(repo_root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    commit = proc.stdout.strip()
    return commit or "unknown"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stamp_artifact_sha256(payload: dict[str, Any]) -> None:
    prov = payload.get("provenance")
    if not isinstance(prov, dict):
        return
    canonical_payload = json.loads(json.dumps(payload, sort_keys=True))
    canonical_prov = canonical_payload.get("provenance")
    if isinstance(canonical_prov, dict):
        canonical_prov.pop("artifact_sha256", None)
        canonical_prov.pop("signature", None)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    prov["artifact_sha256"] = _sha256_text(canonical)


def _build_signature_envelope(artifact_sha256: str) -> dict[str, str]:
    key_id = str(os.getenv("RUNTIME_GUARD_ARTIFACT_KEY_ID", "")).strip()
    algorithm = str(os.getenv("RUNTIME_GUARD_ARTIFACT_SIGNATURE_ALGORITHM", "")).strip()
    signature = str(os.getenv("RUNTIME_GUARD_ARTIFACT_SIGNATURE", "")).strip()
    mode = "detached" if signature else "unsigned"
    return {
        "mode": mode,
        "signed_field": "artifact_sha256",
        "signed_value": artifact_sha256,
        "algorithm": algorithm,
        "key_id": key_id,
        "signature": signature,
    }


def _resolve_validator_script_path(repo_root: Path, script_name: str) -> Path | None:
    candidate = repo_root / "scripts" / script_name
    if candidate.exists():
        return candidate
    fallback = Path(__file__).resolve().parent / script_name
    if fallback.exists():
        return fallback
    return None


def _detect_runtime_pressure() -> tuple[bool, str | None]:
    """Return whether RuntimeGuard currently detects memory pressure."""
    try:
        from runtime_guard import RuntimeGuard

        guard = RuntimeGuard()
        report = guard.check(stage="integration-fleet:auto-fallback")
        if report is None:
            return False, None
        return True, str(getattr(report, "cause", "runtime pressure detected"))
    except Exception as exc:
        return False, f"pressure probe unavailable: {exc}"


def _run_validator(repo_root: Path, tool_name: str, script_name: str, extra_args: list[str], timeout_s: int) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / script_name),
        "--json",
        *extra_args,
    ]

    proc = subprocess.run(
        cmd,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )

    payload = _extract_last_json_object(proc.stdout)
    errors: list[str] = []
    warnings: list[str] = []
    if payload is None:
        errors.append("validator JSON payload was not parseable")
        payload = {}

    if proc.stderr.strip():
        warnings.append(proc.stderr.strip())

    return _component_from_payload(
        tool_name,
        payload,
        source="live",
        command=cmd,
        exit_code=proc.returncode,
        hard_errors=errors,
        warnings=warnings,
    )


def _component_from_report(tool_name: str, report_path: Path) -> dict[str, Any]:
    payload, load_error = _load_report_payload(report_path)
    if load_error is not None:
        return _component_from_payload(
            tool_name,
            {},
            source="report",
            command=None,
            exit_code=1,
            hard_errors=[f"unable to read report {report_path}: {load_error}"],
            warnings=[],
        )

    return _component_from_payload(
        tool_name,
        payload or {},
        source="report",
        command=None,
        exit_code=0,
        hard_errors=[],
        warnings=[],
    )


def _risk_level(components: list[dict[str, Any]]) -> str:
    if all(bool(c.get("healthy", False)) for c in components):
        return "low"

    # High if API surface or required capability checks fail.
    if any(not bool(c.get("api_importable", False)) for c in components):
        return "high"
    if any(not bool(c.get("required_checks_ok", False)) for c in components):
        return "high"

    # Otherwise unhealthy due to execution/reporting issues.
    return "medium"


def _build_payload(
    repo_root: Path,
    timeout_s: int,
    include_wsl_diagnosis: bool,
    *,
    polars_report: str | None,
    dask_report: str | None,
    ray_report: str | None,
    fallback_on_pressure: bool,
    fallback_report_dir: str,
    run_id: str = "",
    pressure_detected_override: bool | None = None,
) -> dict[str, Any]:
    effective_run_id = str(run_id or "").strip()
    if not effective_run_id:
        effective_run_id = str(uuid.uuid4())

    pressure_detected = False
    pressure_probe_note: str | None = None
    if fallback_on_pressure:
        if pressure_detected_override is None:
            pressure_detected, pressure_probe_note = _detect_runtime_pressure()
        else:
            pressure_detected = bool(pressure_detected_override)

    fallback_dir = Path(fallback_report_dir)
    if not fallback_dir.is_absolute():
        fallback_dir = repo_root / fallback_dir

    component_specs = [
        (
            "polars",
            "validate_polars_integration.py",
            ["--check-budget-api", "--check-callback-api"],
            polars_report,
        ),
        (
            "dask",
            "validate_dask_integration.py",
            ["--check-guard-api", "--check-scheduler-api"],
            dask_report,
        ),
        (
            "ray",
            "validate_ray_integration.py",
            ["--check-actor-api"],
            ray_report,
        ),
    ]

    components: list[dict[str, Any]] = []
    source_hashes: dict[str, str] = {}
    validator_script_hashes: dict[str, str] = {}
    fleet_warnings: list[str] = []
    for tool, script_name, extra_args, report_path in component_specs:
        script_path = _resolve_validator_script_path(repo_root, script_name)
        if script_path is not None:
            validator_script_hashes[tool] = _sha256_file(script_path)

        effective_report_path = report_path
        if (
            not effective_report_path
            and fallback_on_pressure
            and pressure_detected
        ):
            discovered = fallback_dir / _default_component_report_name(tool)
            if discovered.exists():
                effective_report_path = str(discovered)
            else:
                fleet_warnings.append(
                    f"pressure fallback enabled but report missing for {tool}: {discovered}"
                )

        if effective_report_path:
            path = Path(effective_report_path)
            if not path.is_absolute():
                path = repo_root / path
            if path.exists():
                source_hashes[tool] = _sha256_file(path)
            components.append(_component_from_report(tool, path))
            continue
        components.append(_run_validator(repo_root, tool, script_name, extra_args, timeout_s))

    summary = {
        "components_total": len(components),
        "components_healthy": sum(1 for c in components if bool(c.get("healthy", False))),
        "components_unhealthy": sum(1 for c in components if not bool(c.get("healthy", False))),
    }
    summary["overall_healthy"] = summary["components_unhealthy"] == 0
    summary["risk_level"] = _risk_level(components)

    payload: dict[str, Any] = {
        "tool": "validate_integration_fleet",
        "milestone": "M1-integration",
        "run_id": effective_run_id,
        "execution_mode": (
            "offline"
            if all(c.get("source") == "report" for c in components)
            else "hybrid"
            if any(c.get("source") == "report" for c in components)
            else "live"
        ),
        "pressure_fallback": {
            "enabled": bool(fallback_on_pressure),
            "pressure_detected": bool(pressure_detected),
            "fallback_report_dir": str(fallback_dir),
            "note": pressure_probe_note,
        },
        "warnings": fleet_warnings,
        "summary": summary,
        "components": components,
        "provenance": {
            "schema_version": 1,
            "tool": "validate_integration_fleet",
            "script": str(Path(__file__).resolve()),
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "run_id": effective_run_id,
            "git_commit": _safe_git_commit(repo_root),
            "inputs": {
                "source_artifact_hashes": source_hashes,
                "validator_script_hashes": validator_script_hashes,
                "fallback_on_pressure": bool(fallback_on_pressure),
                "fallback_report_dir": str(fallback_dir),
            },
        },
    }
    summary["run_id"] = effective_run_id

    if include_wsl_diagnosis:
        try:
            from runtime_guard import diagnose_wsl_crash

            payload["wsl_diagnosis"] = diagnose_wsl_crash()
        except Exception as exc:
            payload["wsl_diagnosis_error"] = str(exc)

    _stamp_artifact_sha256(payload)
    prov = payload.get("provenance")
    if isinstance(prov, dict):
        prov["signature"] = _build_signature_envelope(str(prov.get("artifact_sha256") or ""))

    return payload


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(__file__).resolve().parent.parent

    payload = _build_payload(
        repo_root,
        timeout_s=int(args.timeout_s),
        include_wsl_diagnosis=bool(args.include_wsl_diagnosis),
        polars_report=args.polars_report,
        dask_report=args.dask_report,
        ray_report=args.ray_report,
        fallback_on_pressure=bool(args.fallback_on_pressure),
        fallback_report_dir=str(args.fallback_report_dir),
        run_id=str(args.run_id),
    )

    rendered = json.dumps(payload, indent=2, sort_keys=True)

    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = repo_root / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")

    if args.json:
        print(rendered)
    else:
        summary = payload.get("summary", {})
        status = "PASS" if summary.get("overall_healthy") else "FAIL"
        healthy = summary.get("components_healthy", 0)
        total = summary.get("components_total", 0)
        risk = summary.get("risk_level", "unknown")
        print(f"[{status}] integration health {healthy}/{total} healthy (risk={risk})")
        for comp in payload.get("components", []):
            comp_name = str(comp.get("tool", "unknown"))
            comp_state = "ok" if comp.get("healthy") else "FAIL"
            print(f"  {comp_name}: {comp_state}")

    if args.require_healthy and not payload.get("summary", {}).get("overall_healthy", False):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
