#!/usr/bin/env python3
"""Unified integration health validator for RuntimeGuard (M1 integration stream).

Runs Polars, Dask, and Ray integration validators and emits a single machine-
verifiable payload that can be used as a CI gate for integration readiness.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import subprocess
import tempfile
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
    parser.add_argument(
        "--max-fallback-report-age-hours",
        type=int,
        default=0,
        help=(
            "Maximum age allowed for fallback/explicit report inputs in hours "
            "(0 disables staleness enforcement)"
        ),
    )
    parser.add_argument(
        "--require-signed-report-inputs",
        action="store_true",
        help="Fail when explicit/fallback report inputs are not detached-signed",
    )
    parser.add_argument(
        "--verify-report-input-signatures",
        action="store_true",
        help="Cryptographically verify detached signatures for explicit/fallback report inputs",
    )
    parser.add_argument(
        "--report-signature-public-key",
        default="",
        help="Path to public key PEM used when --verify-report-input-signatures is enabled",
    )
    parser.add_argument(
        "--report-allowed-key-id",
        action="append",
        default=[],
        help="Allowed signature key ID for explicit/fallback report inputs (repeatable)",
    )
    parser.add_argument(
        "--max-report-signature-age-hours",
        type=int,
        default=0,
        help="Maximum age allowed for explicit/fallback report signatures in hours (0 disables)",
    )
    return parser


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []
    verify_signatures = bool(getattr(args, "verify_report_input_signatures", False))
    require_signed = bool(getattr(args, "require_signed_report_inputs", False))
    public_key = str(getattr(args, "report_signature_public_key", "") or "").strip()
    allowed_key_ids = [
        str(key_id).strip()
        for key_id in list(getattr(args, "report_allowed_key_id", []) or [])
        if str(key_id).strip()
    ]
    max_signature_age_hours = int(getattr(args, "max_report_signature_age_hours", 0) or 0)
    max_fallback_report_age_hours = int(getattr(args, "max_fallback_report_age_hours", 0) or 0)

    if max_fallback_report_age_hours < 0:
        errors.append("--max-fallback-report-age-hours must be greater than or equal to 0")
    if max_signature_age_hours < 0:
        errors.append("--max-report-signature-age-hours must be greater than or equal to 0")

    if verify_signatures and not require_signed:
        errors.append(
            "--require-signed-report-inputs must be set when --verify-report-input-signatures is enabled"
        )
    if verify_signatures and not public_key:
        errors.append(
            "--report-signature-public-key is required when --verify-report-input-signatures is set"
        )
    if allowed_key_ids and not verify_signatures:
        errors.append(
            "--verify-report-input-signatures must be set when --report-allowed-key-id is used"
        )
    if max_signature_age_hours > 0 and not verify_signatures:
        errors.append(
            "--verify-report-input-signatures must be set when --max-report-signature-age-hours is greater than 0"
        )
    return errors


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


def _summarize_validator_stderr(text: str) -> str:
    """Summarize validator stderr into a compact, actionable warning string."""
    raw_lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not raw_lines:
        return ""

    # RuntimeGuard JSON event rows can be very noisy in aggregate reports.
    filtered_lines = [
        line for line in raw_lines if not line.lstrip().startswith('{"event":"runtime_guard.pressure"')
    ]
    lines = filtered_lines or raw_lines

    max_lines = 40
    if len(lines) > max_lines:
        kept = lines[:max_lines]
        kept.append(f"... ({len(lines) - max_lines} stderr lines truncated)")
        lines = kept

    rendered = "\n".join(lines)
    max_chars = 4000
    if len(rendered) > max_chars:
        rendered = rendered[:max_chars].rstrip() + "\n... (stderr text truncated)"
    return rendered


def _is_true_boolean(value: Any) -> bool:
    return isinstance(value, bool) and value


def _required_checks_for(tool_name: str, payload: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if tool_name == "polars":
        budget_check = payload.get("scan_budget_api", {})
        callback_check = payload.get("native_callback_api", {})
        if not isinstance(budget_check, dict) or not _is_true_boolean(budget_check.get("available", False)):
            errors.append("scan_budget_api check failed")
        if not isinstance(callback_check, dict) or not _is_true_boolean(callback_check.get("available", False)):
            errors.append("native_callback_api check failed")
    elif tool_name == "dask":
        guard_check = payload.get("task_graph_guard_api", {})
        scheduler_check = payload.get("scheduler_callback_api", {})
        if not isinstance(guard_check, dict) or not _is_true_boolean(guard_check.get("available", False)):
            errors.append("task_graph_guard_api check failed")
        if not isinstance(scheduler_check, dict) or not _is_true_boolean(scheduler_check.get("available", False)):
            errors.append("scheduler_callback_api check failed")
        if not isinstance(scheduler_check, dict) or not _is_true_boolean(
            scheduler_check.get("telemetry_counters_present", False)
        ):
            errors.append("scheduler_callback_api telemetry counter check failed")
    elif tool_name == "ray":
        actor_check = payload.get("actor_monitoring_api", {})
        if not isinstance(actor_check, dict) or not _is_true_boolean(actor_check.get("available", False)):
            errors.append("actor_monitoring_api check failed")
        if not isinstance(actor_check, dict) or not _is_true_boolean(
            actor_check.get("hotspot_fields_present", False)
        ):
            errors.append("actor_monitoring_api hotspot field check failed")

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

    raw_validator_ok = payload.get("ok", False)
    raw_api_importable = payload.get("api_importable", False)
    validator_ok = _is_true_boolean(raw_validator_ok)
    api_importable = _is_true_boolean(raw_api_importable)
    if not isinstance(raw_validator_ok, bool):
        errors.append("validator 'ok' field must be boolean")
    if not isinstance(raw_api_importable, bool):
        errors.append("validator 'api_importable' field must be boolean")
    checks_ok, check_errors = _required_checks_for(tool_name, payload)
    errors.extend(check_errors)

    payload_errors = payload.get("errors", [])
    if isinstance(payload_errors, list):
        warning_rows.extend(str(item) for item in payload_errors if str(item).strip())

    effective_exit_code = 0 if exit_code is None else int(exit_code)
    if effective_exit_code != 0:
        errors.append(f"validator exited non-zero: {effective_exit_code}")

    healthy = (
        validator_ok
        and api_importable
        and checks_ok
        and effective_exit_code == 0
        and len(errors) == 0
    )

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


def _parse_utc_timestamp(value: str) -> dt.datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


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


def _expected_artifact_sha256(payload: dict[str, Any]) -> str:
    canonical_payload = json.loads(json.dumps(payload, sort_keys=True))
    canonical_prov = canonical_payload.get("provenance")
    if isinstance(canonical_prov, dict):
        canonical_prov.pop("artifact_sha256", None)
        canonical_prov.pop("signature", None)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return _sha256_text(canonical)


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


def _decode_signature_bytes(signature_text: str) -> bytes:
    sig = signature_text.strip()
    if not sig:
        raise ValueError("empty signature")

    try:
        return bytes.fromhex(sig)
    except ValueError:
        pass

    try:
        return base64.b64decode(sig, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature must be hex or base64") from exc


def _verify_signature_with_openssl(
    *,
    signed_value: str,
    signature_bytes: bytes,
    public_key_path: Path,
) -> tuple[bool, str]:
    if not public_key_path.exists():
        return False, f"public key not found: {public_key_path}"

    try:
        with tempfile.TemporaryDirectory(prefix="rg-report-sign-verify-") as tmp:
            tmp_dir = Path(tmp)
            data_path = tmp_dir / "signed_value.txt"
            sig_path = tmp_dir / "signature.bin"
            data_path.write_text(signed_value, encoding="utf-8")
            sig_path.write_bytes(signature_bytes)

            cmd = [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-sigfile",
                str(sig_path),
                "-rawin",
                "-in",
                str(data_path),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return False, "openssl binary not found"
    except Exception as exc:
        return False, str(exc)

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        return False, stderr or "openssl verification returned non-zero"
    return True, "ok"


def _verify_detached_signature(
    *,
    algorithm: str,
    signed_value: str,
    signature_text: str,
    public_key_path: Path,
) -> tuple[bool, str]:
    algo = algorithm.strip().lower()
    if algo != "ed25519":
        return False, f"unsupported signature algorithm: {algorithm}"

    try:
        signature_bytes = _decode_signature_bytes(signature_text)
    except ValueError as exc:
        return False, str(exc)

    return _verify_signature_with_openssl(
        signed_value=signed_value,
        signature_bytes=signature_bytes,
        public_key_path=public_key_path,
    )


def _validate_report_signature(
    *,
    tool_name: str,
    provenance: dict[str, Any],
    require_signed: bool,
    verify_signatures: bool,
    signature_public_key: str,
    allowed_key_ids: set[str],
    max_signature_age_hours: int,
) -> list[str]:
    signature = provenance.get("signature")
    if not isinstance(signature, dict):
        return [f"report signature envelope missing for {tool_name}"]

    errors: list[str] = []
    mode = str(signature.get("mode") or "").strip()
    if mode not in {"unsigned", "detached"}:
        errors.append(f"report signature mode invalid for {tool_name}: {mode or 'missing'}")

    if str(signature.get("signed_field") or "").strip() != "artifact_sha256":
        errors.append(f"report signature.signed_field invalid for {tool_name}")

    artifact_sha = str(provenance.get("artifact_sha256") or "").strip()
    if str(signature.get("signed_value") or "").strip() != artifact_sha:
        errors.append(f"report signature.signed_value mismatch for {tool_name}")

    if require_signed:
        if mode != "detached":
            errors.append(f"report detached signature required for {tool_name}")
        if not str(signature.get("signature") or "").strip():
            errors.append(f"report detached signature payload missing for {tool_name}")
        if not str(signature.get("key_id") or "").strip():
            errors.append(f"report detached signature key_id missing for {tool_name}")
        if not str(signature.get("algorithm") or "").strip():
            errors.append(f"report detached signature algorithm missing for {tool_name}")

    key_id = str(signature.get("key_id") or "").strip()
    if allowed_key_ids:
        if not key_id:
            errors.append(f"report signature key_id is required by policy for {tool_name}")
        elif key_id not in allowed_key_ids:
            errors.append(f"report signature key_id '{key_id}' not allowed for {tool_name}")

    if int(max_signature_age_hours or 0) > 0:
        issued = _parse_utc_timestamp(str(provenance.get("generated_at_utc") or "").strip())
        if issued is None:
            errors.append(f"report generated_at_utc missing/invalid for {tool_name} signature age policy")
        else:
            age_h = (dt.datetime.now(dt.timezone.utc) - issued).total_seconds() / 3600.0
            if age_h > float(max_signature_age_hours):
                errors.append(
                    f"report signature age {age_h:.2f}h exceeds max {int(max_signature_age_hours)}h for {tool_name}"
                )

    if verify_signatures:
        if mode != "detached":
            errors.append(f"report detached signature required for cryptographic verification of {tool_name}")
            return errors
        key_path = str(signature_public_key or "").strip()
        if not key_path:
            errors.append("--report-signature-public-key is required when --verify-report-input-signatures is set")
            return errors
        ok, reason = _verify_detached_signature(
            algorithm=str(signature.get("algorithm") or ""),
            signed_value=str(signature.get("signed_value") or ""),
            signature_text=str(signature.get("signature") or ""),
            public_key_path=Path(key_path),
        )
        if not ok:
            errors.append(f"report signature verification failed for {tool_name}: {reason}")

    return errors


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
        from runtime_guard import RuntimeGuard  # type: ignore[import-untyped]

        guard = RuntimeGuard()
        report = guard.check(stage="integration-fleet:auto-fallback")
        if report is None:
            return False, None
        return True, str(getattr(report, "cause", "runtime pressure detected"))
    except Exception as exc:
        return False, f"pressure probe unavailable: {exc}"


def _run_validator(
    repo_root: Path,
    tool_name: str,
    script_name: str,
    extra_args: list[str],
    timeout_s: int,
    run_id: str = "",
) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / script_name),
        "--json",
        *extra_args,
    ]
    effective_run_id = str(run_id or "").strip()
    if effective_run_id:
        cmd.extend(["--run-id", effective_run_id])
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _component_from_payload(
            tool_name,
            {},
            source="live",
            command=cmd,
            exit_code=124,
            hard_errors=[f"validator timed out after {int(timeout_s)}s"],
            warnings=[],
        )

    payload = _extract_last_json_object(proc.stdout)
    errors: list[str] = []
    warnings: list[str] = []
    if payload is None:
        errors.append("validator JSON payload was not parseable")
        payload = {}

    if proc.stderr.strip():
        summarized = _summarize_validator_stderr(proc.stderr)
        if summarized:
            warnings.append(summarized)

    return _component_from_payload(
        tool_name,
        payload,
        source="live",
        command=cmd,
        exit_code=proc.returncode,
        hard_errors=errors,
        warnings=warnings,
    )


def _component_from_report(
    tool_name: str,
    report_path: Path,
    *,
    max_report_age_hours: int = 0,
    expected_run_id: str = "",
    require_signed: bool = False,
    verify_signatures: bool = False,
    signature_public_key: str = "",
    allowed_key_ids: set[str] | None = None,
    max_signature_age_hours: int = 0,
    now_utc: dt.datetime | None = None,
) -> dict[str, Any]:
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

    report_payload = payload or {}
    expected_tool = {
        "polars": "validate_polars_integration",
        "dask": "validate_dask_integration",
        "ray": "validate_ray_integration",
    }.get(tool_name, "")
    expected_milestone = {
        "polars": "M1-I01",
        "dask": "M1-I02",
        "ray": "M1-I03",
    }.get(tool_name, "")

    identity_errors: list[str] = []
    if expected_tool and str(report_payload.get("tool", "")).strip() != expected_tool:
        identity_errors.append(
            f"report tool mismatch for {tool_name}: expected {expected_tool}"
        )
    if expected_milestone and str(report_payload.get("milestone", "")).strip() != expected_milestone:
        identity_errors.append(
            f"report milestone mismatch for {tool_name}: expected {expected_milestone}"
        )

    provenance = report_payload.get("provenance")
    if not isinstance(provenance, dict):
        identity_errors.append(f"report provenance missing for {tool_name}")
    else:
        artifact_sha = str(provenance.get("artifact_sha256") or "").strip()
        if not artifact_sha:
            identity_errors.append(f"report artifact_sha256 missing for {tool_name}")
        elif artifact_sha != _expected_artifact_sha256(report_payload):
            identity_errors.append(f"report artifact_sha256 mismatch for {tool_name}")

        identity_errors.extend(
            _validate_report_signature(
                tool_name=tool_name,
                provenance=provenance,
                require_signed=bool(require_signed),
                verify_signatures=bool(verify_signatures),
                signature_public_key=str(signature_public_key),
                allowed_key_ids=set(allowed_key_ids or set()),
                max_signature_age_hours=int(max_signature_age_hours or 0),
            )
        )

    expected_run = str(expected_run_id or "").strip()
    if expected_run:
        report_run_id = ""
        raw_root_run_id = report_payload.get("run_id")
        if isinstance(raw_root_run_id, str) and raw_root_run_id.strip():
            report_run_id = raw_root_run_id.strip()
        else:
            summary = report_payload.get("summary")
            if isinstance(summary, dict):
                raw_summary_run_id = summary.get("run_id")
                if isinstance(raw_summary_run_id, str) and raw_summary_run_id.strip():
                    report_run_id = raw_summary_run_id.strip()
        if report_run_id != expected_run:
            identity_errors.append(
                f"report run_id mismatch for {tool_name}: expected {expected_run}"
            )

    if int(max_report_age_hours or 0) > 0:
        generated_at_text = ""
        if isinstance(provenance, dict):
            generated_at_text = str(provenance.get("generated_at_utc") or "").strip()
        issued = _parse_utc_timestamp(generated_at_text)
        if issued is None:
            identity_errors.append(
                f"report generated_at_utc missing/invalid for {tool_name} staleness policy"
            )
        else:
            reference = now_utc or dt.datetime.now(dt.timezone.utc)
            age_h = (reference - issued).total_seconds() / 3600.0
            if age_h > float(max_report_age_hours):
                identity_errors.append(
                    f"report too old for {tool_name}: {age_h:.2f}h > {int(max_report_age_hours)}h"
                )

    return _component_from_payload(
        tool_name,
        report_payload,
        source="report",
        command=None,
        exit_code=0,
        hard_errors=identity_errors,
        warnings=[],
    )


def _risk_level(components: list[dict[str, Any]]) -> str:
    if all(bool(c.get("healthy", False)) for c in components):
        return "low"

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
    max_fallback_report_age_hours: int = 0,
    require_signed_report_inputs: bool = False,
    verify_report_input_signatures: bool = False,
    report_signature_public_key: str = "",
    report_allowed_key_ids: list[str] | None = None,
    max_report_signature_age_hours: int = 0,
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
    report_age_reference_utc = dt.datetime.now(dt.timezone.utc)
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
            components.append(
                _component_from_report(
                    tool,
                    path,
                    max_report_age_hours=int(max_fallback_report_age_hours or 0),
                    expected_run_id=effective_run_id,
                    require_signed=bool(require_signed_report_inputs),
                    verify_signatures=bool(verify_report_input_signatures),
                    signature_public_key=str(report_signature_public_key),
                    allowed_key_ids={k for k in list(report_allowed_key_ids or []) if str(k).strip()},
                    max_signature_age_hours=int(max_report_signature_age_hours or 0),
                    now_utc=report_age_reference_utc,
                )
            )
            continue
        components.append(
            _run_validator(
                repo_root,
                tool,
                script_name,
                extra_args,
                timeout_s,
                run_id=effective_run_id,
            )
        )

    summary: dict[str, Any] = {
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
            "max_report_age_hours": int(max_fallback_report_age_hours or 0),
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
                "max_fallback_report_age_hours": int(max_fallback_report_age_hours or 0),
                "require_signed_report_inputs": bool(require_signed_report_inputs),
                "verify_report_input_signatures": bool(verify_report_input_signatures),
                "report_allowed_key_ids": [k for k in list(report_allowed_key_ids or []) if str(k).strip()],
                "max_report_signature_age_hours": int(max_report_signature_age_hours or 0),
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

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        if args.json:
            print(json.dumps({"ok": False, "errors": config_errors}, indent=2, sort_keys=True))
        else:
            for err in config_errors:
                print(f"[config-error] {err}", file=sys.stderr)
        return 2

    payload = _build_payload(
        repo_root,
        timeout_s=int(args.timeout_s),
        include_wsl_diagnosis=bool(args.include_wsl_diagnosis),
        polars_report=args.polars_report,
        dask_report=args.dask_report,
        ray_report=args.ray_report,
        fallback_on_pressure=bool(args.fallback_on_pressure),
        fallback_report_dir=str(args.fallback_report_dir),
        max_fallback_report_age_hours=int(args.max_fallback_report_age_hours),
        require_signed_report_inputs=bool(args.require_signed_report_inputs),
        verify_report_input_signatures=bool(args.verify_report_input_signatures),
        report_signature_public_key=str(args.report_signature_public_key),
        report_allowed_key_ids=list(args.report_allowed_key_id or []),
        max_report_signature_age_hours=int(args.max_report_signature_age_hours),
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
