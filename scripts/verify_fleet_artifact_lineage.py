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
import base64
import binascii
import datetime as dt
import hashlib
import json
import subprocess
import tempfile
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
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="Fail when artifacts are not detached-signed in provenance.signature",
    )
    parser.add_argument(
        "--verify-signatures",
        action="store_true",
        help="Cryptographically verify detached signatures against artifact_sha256",
    )
    parser.add_argument(
        "--signature-public-key",
        default="",
        help="Path to public key PEM used for detached signature verification",
    )
    parser.add_argument(
        "--allowed-key-id",
        action="append",
        default=[],
        help="Allowed signature key ID (repeatable). When set, artifacts signed by other keys fail.",
    )
    parser.add_argument(
        "--max-signature-age-hours",
        type=int,
        default=0,
        help="Maximum allowed artifact signature age in hours (0 disables age check).",
    )
    parser.add_argument(
        "--expected-require-signed-report-inputs",
        action="store_true",
        help="Fail if integration provenance does not record require_signed_report_inputs=true",
    )
    parser.add_argument(
        "--expected-verify-report-input-signatures",
        action="store_true",
        help="Fail if integration provenance does not record verify_report_input_signatures=true",
    )
    parser.add_argument(
        "--expected-report-allowed-key-id",
        action="append",
        default=[],
        help="Expected integration report-input allowed key ID (repeatable)",
    )
    parser.add_argument(
        "--expected-max-report-signature-age-hours",
        type=int,
        default=0,
        help="Expected integration max_report_signature_age_hours value (0 disables check)",
    )
    return parser


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    verify_signatures = bool(getattr(args, "verify_signatures", False))
    require_signed = bool(getattr(args, "require_signed", False))
    signature_public_key = str(getattr(args, "signature_public_key", "") or "").strip()
    allowed_key_ids = [
        str(key_id).strip()
        for key_id in list(getattr(args, "allowed_key_id", []) or [])
        if str(key_id).strip()
    ]
    max_signature_age_hours = int(getattr(args, "max_signature_age_hours", 0) or 0)

    expected_verify = bool(getattr(args, "expected_verify_report_input_signatures", False))
    expected_require_signed = bool(getattr(args, "expected_require_signed_report_inputs", False))
    expected_allowed_key_ids = [
        str(key_id).strip()
        for key_id in list(getattr(args, "expected_report_allowed_key_id", []) or [])
        if str(key_id).strip()
    ]
    expected_max_age = int(getattr(args, "expected_max_report_signature_age_hours", 0) or 0)

    if max_signature_age_hours < 0:
        errors.append("--max-signature-age-hours must be greater than or equal to 0")
    if expected_max_age < 0:
        errors.append(
            "--expected-max-report-signature-age-hours must be greater than or equal to 0"
        )

    if verify_signatures and not require_signed:
        errors.append("--require-signed must be set when --verify-signatures is enabled")
    if verify_signatures and not signature_public_key:
        errors.append("--signature-public-key is required when --verify-signatures is set")
    if allowed_key_ids and not verify_signatures:
        errors.append("--verify-signatures must be set when --allowed-key-id is used")
    if max_signature_age_hours > 0 and not verify_signatures:
        errors.append(
            "--verify-signatures must be set when --max-signature-age-hours is greater than 0"
        )

    if expected_verify and not expected_require_signed:
        errors.append(
            "--expected-require-signed-report-inputs must be set when --expected-verify-report-input-signatures is enabled"
        )
    if expected_allowed_key_ids and not expected_verify:
        errors.append(
            "--expected-verify-report-input-signatures must be set when --expected-report-allowed-key-id is used"
        )
    if expected_max_age > 0 and not expected_verify:
        errors.append(
            "--expected-verify-report-input-signatures must be set when --expected-max-report-signature-age-hours is greater than 0"
        )

    return errors


def _load_json(path: Path) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"artifact must be JSON object: {path}")
    return parsed


def _strict_string(value: Any) -> tuple[str, bool]:
    if isinstance(value, str) and value.strip():
        return value.strip(), True
    return "", False


def _extract_run_id(payload: dict[str, Any]) -> str:
    root = payload.get("run_id")
    if isinstance(root, str) and root.strip():
        return root.strip()
    summary = payload.get("summary")
    if isinstance(summary, dict):
        nested = summary.get("run_id")
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return ""


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _expected_artifact_sha256(payload: dict[str, Any]) -> str:
    canonical_payload = json.loads(json.dumps(payload, sort_keys=True))
    prov = canonical_payload.get("provenance")
    if isinstance(prov, dict):
        prov.pop("artifact_sha256", None)
        prov.pop("signature", None)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return _sha256_text(canonical)


def _validate_provenance(name: str, payload: dict[str, Any], strict: bool) -> list[str]:
    errors: list[str] = []
    prov = payload.get("provenance")
    if not isinstance(prov, dict):
        return [f"{name}: missing provenance block"]

    required = ["schema_version", "tool", "generated_at_utc", "run_id", "inputs", "artifact_sha256"]
    for key in required:
        if key not in prov:
            errors.append(f"{name}: provenance missing '{key}'")

    if "schema_version" in prov:
        schema_version = prov.get("schema_version")
        if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version <= 0:
            errors.append(f"{name}: provenance.schema_version must be a positive integer")

    if "tool" in prov:
        tool = prov.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            errors.append(f"{name}: provenance.tool must be a non-empty string")

    if "run_id" in prov:
        run_id = prov.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            errors.append(f"{name}: provenance.run_id must be a non-empty string")

    if "inputs" in prov and not isinstance(prov.get("inputs"), dict):
        errors.append(f"{name}: provenance.inputs must be an object")

    if "artifact_sha256" in prov:
        artifact_sha = prov.get("artifact_sha256")
        if not isinstance(artifact_sha, str) or not artifact_sha.strip():
            errors.append(f"{name}: provenance.artifact_sha256 must be a non-empty string")

    if "generated_at_utc" in prov:
        generated_raw = prov.get("generated_at_utc")
        if not isinstance(generated_raw, str) or not generated_raw.strip():
            errors.append(f"{name}: provenance.generated_at_utc must be a non-empty string")
        else:
            generated = generated_raw.strip()
            if not generated.endswith("Z"):
                errors.append(f"{name}: provenance.generated_at_utc must be UTC Z format")
            elif _parse_utc_timestamp(generated) is None:
                errors.append(f"{name}: provenance.generated_at_utc must be an ISO-8601 UTC timestamp")

    if strict:
        git_commit = prov.get("git_commit")
        if not isinstance(git_commit, str) or not git_commit.strip():
            errors.append(f"{name}: provenance.git_commit missing in strict mode")
        script = prov.get("script")
        if not isinstance(script, str) or not script.strip():
            errors.append(f"{name}: provenance.script missing in strict mode")

    return errors


def _validate_artifact_sha256(name: str, payload: dict[str, Any]) -> list[str]:
    prov = payload.get("provenance")
    if not isinstance(prov, dict):
        return [f"{name}: missing provenance block"]
    actual = str(prov.get("artifact_sha256") or "").strip()
    if not actual:
        return [f"{name}: missing provenance artifact_sha256"]
    expected = _expected_artifact_sha256(payload)
    if actual != expected:
        return [f"{name}: artifact_sha256 mismatch"]
    return []


def _validate_integration_fallback_policy_consistency(payload: dict[str, Any]) -> list[str]:
    """Validate integration fallback-age policy consistency across payload/provenance.

    If either side includes the fallback age policy, both must be present and match.
    """
    errors: list[str] = []
    pressure_fallback = payload.get("pressure_fallback")
    provenance = payload.get("provenance")
    inputs = provenance.get("inputs") if isinstance(provenance, dict) else None

    fallback_enabled_payload: str | None = None
    fallback_dir_payload: str | None = None
    fallback_age_payload: str | None = None
    if isinstance(pressure_fallback, dict) and "max_report_age_hours" in pressure_fallback:
        raw_age = pressure_fallback.get("max_report_age_hours")
        if not isinstance(raw_age, int) or isinstance(raw_age, bool) or raw_age < 0:
            errors.append(
                "integration_fleet_status: pressure_fallback.max_report_age_hours must be a non-negative integer"
            )
        else:
            fallback_age_payload = str(raw_age).strip()
    if isinstance(pressure_fallback, dict) and "enabled" in pressure_fallback:
        raw_enabled = pressure_fallback.get("enabled")
        if not isinstance(raw_enabled, bool):
            errors.append(
                "integration_fleet_status: pressure_fallback.enabled must be a boolean"
            )
        else:
            fallback_enabled_payload = str(raw_enabled).strip()
    if isinstance(pressure_fallback, dict) and "fallback_report_dir" in pressure_fallback:
        raw_dir = pressure_fallback.get("fallback_report_dir")
        if not isinstance(raw_dir, str):
            errors.append(
                "integration_fleet_status: pressure_fallback.fallback_report_dir must be a string"
            )
        else:
            fallback_dir_payload = raw_dir.strip()

    fallback_enabled_provenance: str | None = None
    fallback_dir_provenance: str | None = None
    fallback_age_provenance: str | None = None
    if isinstance(inputs, dict) and "max_fallback_report_age_hours" in inputs:
        raw_age = inputs.get("max_fallback_report_age_hours")
        if not isinstance(raw_age, int) or isinstance(raw_age, bool) or raw_age < 0:
            errors.append(
                "integration_fleet_status: provenance.inputs.max_fallback_report_age_hours must be a non-negative integer"
            )
        else:
            fallback_age_provenance = str(raw_age).strip()
    if isinstance(inputs, dict) and "fallback_on_pressure" in inputs:
        raw_enabled = inputs.get("fallback_on_pressure")
        if not isinstance(raw_enabled, bool):
            errors.append(
                "integration_fleet_status: provenance.inputs.fallback_on_pressure must be a boolean"
            )
        else:
            fallback_enabled_provenance = str(raw_enabled).strip()
    if isinstance(inputs, dict) and "fallback_report_dir" in inputs:
        raw_dir = inputs.get("fallback_report_dir")
        if not isinstance(raw_dir, str):
            errors.append(
                "integration_fleet_status: provenance.inputs.fallback_report_dir must be a string"
            )
        else:
            fallback_dir_provenance = raw_dir.strip()

    if fallback_enabled_payload is None and fallback_enabled_provenance is not None:
        errors.append(
            "integration_fleet_status: pressure_fallback.enabled missing while provenance.inputs.fallback_on_pressure is present"
        )
    elif fallback_enabled_payload is not None and fallback_enabled_provenance is None:
        errors.append(
            "integration_fleet_status: provenance.inputs.fallback_on_pressure missing while pressure_fallback.enabled is present"
        )
    elif (
        fallback_enabled_payload is not None
        and fallback_enabled_provenance is not None
        and fallback_enabled_payload != fallback_enabled_provenance
    ):
        errors.append(
            "integration_fleet_status: fallback enabled policy mismatch between pressure_fallback.enabled and provenance.inputs.fallback_on_pressure"
        )

    if fallback_dir_payload is None and fallback_dir_provenance is not None:
        errors.append(
            "integration_fleet_status: pressure_fallback.fallback_report_dir missing while provenance.inputs.fallback_report_dir is present"
        )
    elif fallback_dir_payload is not None and fallback_dir_provenance is None:
        errors.append(
            "integration_fleet_status: provenance.inputs.fallback_report_dir missing while pressure_fallback.fallback_report_dir is present"
        )
    elif (
        fallback_dir_payload is not None
        and fallback_dir_provenance is not None
        and fallback_dir_payload != fallback_dir_provenance
    ):
        errors.append(
            "integration_fleet_status: fallback report directory mismatch between pressure_fallback.fallback_report_dir and provenance.inputs.fallback_report_dir"
        )

    if fallback_age_payload is None and fallback_age_provenance is None:
        return errors

    if fallback_age_payload is None:
        errors.append(
            "integration_fleet_status: pressure_fallback.max_report_age_hours missing while provenance fallback age is present"
        )
        return errors
    if fallback_age_provenance is None:
        errors.append(
            "integration_fleet_status: provenance.inputs.max_fallback_report_age_hours missing while pressure_fallback fallback age is present"
        )
        return errors

    if fallback_age_payload != fallback_age_provenance:
        errors.append(
            "integration_fleet_status: fallback age policy mismatch between pressure_fallback.max_report_age_hours and provenance.inputs.max_fallback_report_age_hours"
        )
    return errors


def _validate_expected_tool(name: str, payload: dict[str, Any], expected_tool: str) -> list[str]:
    prov = payload.get("provenance")
    if not isinstance(prov, dict):
        return [f"{name}: missing provenance block"]

    actual_tool = str(prov.get("tool") or "").strip()
    if not actual_tool:
        return [f"{name}: provenance.tool missing"]
    if actual_tool != expected_tool:
        return [
            f"{name}: provenance.tool mismatch (expected {expected_tool}, got {actual_tool})"
        ]
    return []


def _validate_expected_integration_report_signature_policy(
    payload: dict[str, Any],
    *,
    expected_require_signed_report_inputs: bool,
    expected_verify_report_input_signatures: bool,
    expected_report_allowed_key_ids: list[str],
    expected_max_report_signature_age_hours: int,
) -> list[str]:
    errors: list[str] = []
    provenance = payload.get("provenance")
    inputs = provenance.get("inputs") if isinstance(provenance, dict) else None
    if not isinstance(inputs, dict):
        return ["integration_fleet_status: provenance.inputs missing for report-signature policy check"]

    required_policy_keys = [
        "require_signed_report_inputs",
        "verify_report_input_signatures",
        "report_allowed_key_ids",
        "max_report_signature_age_hours",
    ]
    for key in required_policy_keys:
        if key not in inputs:
            errors.append(
                f"integration_fleet_status: provenance.inputs missing '{key}' for report-signature policy check"
            )
    if errors:
        return errors

    raw_require_signed = inputs.get("require_signed_report_inputs")
    if not isinstance(raw_require_signed, bool):
        errors.append(
            "integration_fleet_status: provenance.inputs.require_signed_report_inputs must be a boolean"
        )
    elif raw_require_signed != bool(expected_require_signed_report_inputs):
        errors.append(
            "integration_fleet_status: expected require_signed_report_inputs policy does not match provenance.inputs"
        )

    raw_verify = inputs.get("verify_report_input_signatures")
    if not isinstance(raw_verify, bool):
        errors.append(
            "integration_fleet_status: provenance.inputs.verify_report_input_signatures must be a boolean"
        )
    elif raw_verify != bool(expected_verify_report_input_signatures):
        errors.append(
            "integration_fleet_status: expected verify_report_input_signatures policy does not match provenance.inputs"
        )

    expected_allowed = sorted({str(k).strip() for k in list(expected_report_allowed_key_ids or []) if str(k).strip()})
    actual_allowed_raw = inputs.get("report_allowed_key_ids", [])
    actual_allowed: list[str] = []
    if not isinstance(actual_allowed_raw, list):
        errors.append(
            "integration_fleet_status: provenance.inputs.report_allowed_key_ids must be a list"
        )
    else:
        invalid_keys = [k for k in actual_allowed_raw if not isinstance(k, str)]
        if invalid_keys:
            errors.append(
                "integration_fleet_status: provenance.inputs.report_allowed_key_ids entries must be strings"
            )
        actual_allowed = sorted({k.strip() for k in actual_allowed_raw if isinstance(k, str) and k.strip()})
    if isinstance(actual_allowed_raw, list) and actual_allowed != expected_allowed:
        errors.append(
            "integration_fleet_status: expected report_allowed_key_ids policy does not match provenance.inputs"
        )

    expected_age = int(expected_max_report_signature_age_hours or 0)
    raw_age = inputs.get("max_report_signature_age_hours")
    if not isinstance(raw_age, int) or isinstance(raw_age, bool) or raw_age < 0:
        errors.append(
            "integration_fleet_status: provenance.inputs.max_report_signature_age_hours must be a non-negative integer"
        )
    elif raw_age != expected_age:
        errors.append(
            "integration_fleet_status: expected max_report_signature_age_hours policy does not match provenance.inputs"
        )

    return errors


def _validate_signature_envelope(
    name: str,
    payload: dict[str, Any],
    *,
    require_signed: bool,
    verify_signatures: bool,
    signature_public_key: str,
    allowed_key_ids: set[str],
    max_signature_age_hours: int,
) -> list[str]:
    prov = payload.get("provenance")
    if not isinstance(prov, dict):
        return [f"{name}: missing provenance block"]
    sig = prov.get("signature")
    if not isinstance(sig, dict):
        return [f"{name}: missing provenance.signature envelope"]

    required = ["mode", "signed_field", "signed_value", "algorithm", "key_id", "signature"]
    errors: list[str] = []
    for key in required:
        if key not in sig:
            errors.append(f"{name}: signature missing '{key}'")

    mode, mode_ok = _strict_string(sig.get("mode"))
    if not mode_ok:
        errors.append(f"{name}: signature mode must be a non-empty string")
    if mode not in {"unsigned", "detached"}:
        errors.append(f"{name}: signature mode must be 'unsigned' or 'detached'")

    signed_field, signed_field_ok = _strict_string(sig.get("signed_field"))
    if not signed_field_ok:
        errors.append(f"{name}: signature.signed_field must be a non-empty string")
    if signed_field != "artifact_sha256":
        errors.append(f"{name}: signature.signed_field must be artifact_sha256")

    artifact_sha, artifact_sha_ok = _strict_string(prov.get("artifact_sha256"))
    if not artifact_sha_ok:
        errors.append(f"{name}: provenance.artifact_sha256 must be a non-empty string")
    signed_value, signed_value_ok = _strict_string(sig.get("signed_value"))
    if not signed_value_ok:
        errors.append(f"{name}: signature.signed_value must be a non-empty string")
    if artifact_sha and signed_value != artifact_sha:
        errors.append(f"{name}: signature.signed_value must match provenance.artifact_sha256")

    if require_signed:
        if mode != "detached":
            errors.append(f"{name}: detached signature required")
        signature_text, signature_ok = _strict_string(sig.get("signature"))
        if not signature_ok:
            errors.append(f"{name}: detached signature payload missing")
        key_id, key_id_ok = _strict_string(sig.get("key_id"))
        if not key_id_ok:
            errors.append(f"{name}: detached signature key_id missing")
        algorithm, algorithm_ok = _strict_string(sig.get("algorithm"))
        if not algorithm_ok:
            errors.append(f"{name}: detached signature algorithm missing")
    else:
        signature_text, _ = _strict_string(sig.get("signature"))
        key_id, _ = _strict_string(sig.get("key_id"))
        algorithm, _ = _strict_string(sig.get("algorithm"))

    if allowed_key_ids:
        if not key_id:
            errors.append(f"{name}: signature key_id is required by allowed-key-id policy")
        elif key_id not in allowed_key_ids:
            errors.append(f"{name}: signature key_id '{key_id}' not in allowed-key-id policy")

    if int(max_signature_age_hours or 0) > 0:
        generated_at = ""
        if isinstance(prov, dict):
            generated_at, generated_ok = _strict_string(prov.get("generated_at_utc"))
            if not generated_ok:
                errors.append(f"{name}: provenance.generated_at_utc must be a non-empty string")
        issued = _parse_utc_timestamp(generated_at)
        if issued is None:
            errors.append(f"{name}: invalid generated_at_utc for signature age policy")
        else:
            now = dt.datetime.now(dt.timezone.utc)
            age_h = (now - issued).total_seconds() / 3600.0
            if age_h > float(max_signature_age_hours):
                errors.append(
                    f"{name}: signature age {age_h:.2f}h exceeds max {int(max_signature_age_hours)}h"
                )

    if verify_signatures:
        if mode != "detached":
            errors.append(f"{name}: detached signature required for cryptographic verification")
            return errors
        key_path = str(signature_public_key or "").strip()
        if not key_path:
            errors.append(f"{name}: --signature-public-key is required when --verify-signatures is set")
            return errors

        ok, reason = _verify_detached_signature(
            algorithm=algorithm,
            signed_value=signed_value,
            signature_text=signature_text,
            public_key_path=Path(key_path),
        )
        if not ok:
            errors.append(f"{name}: signature verification failed: {reason}")

    return errors


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


def _decode_signature_bytes(signature_text: str) -> bytes:
    sig = signature_text.strip()
    if not sig:
        raise ValueError("empty signature")

    # Prefer hex for deterministic shell workflows, fallback to base64.
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
        with tempfile.TemporaryDirectory(prefix="rg-sign-verify-") as tmp:
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


def _build_result(
    enforcement_path: Path,
    integration_path: Path,
    runtime_path: Path,
    strict: bool,
    require_signed: bool,
    verify_signatures: bool,
    signature_public_key: str,
    allowed_key_ids: list[str],
    max_signature_age_hours: int,
    expected_require_signed_report_inputs: bool,
    expected_verify_report_input_signatures: bool,
    expected_report_allowed_key_ids: list[str],
    expected_max_report_signature_age_hours: int,
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    artifacts = {
        "repo_guard_enforcement": str(enforcement_path),
        "integration_fleet_status": str(integration_path),
        "repo_guard_runtime_status": str(runtime_path),
    }

    for path in [enforcement_path, integration_path, runtime_path]:
        if not path.exists():
            errors.append(f"missing artifact: {path}")
    if errors:
        return False, {"ok": False, "errors": errors, "artifacts": artifacts}

    parsed_payloads: dict[str, dict[str, Any]] = {}
    for name, path in [
        ("repo_guard_enforcement", enforcement_path),
        ("integration_fleet_status", integration_path),
        ("repo_guard_runtime_status", runtime_path),
    ]:
        try:
            parsed_payloads[name] = _load_json(path)
        except Exception as exc:
            errors.append(f"{name}: unable to parse artifact JSON: {exc}")

    if errors:
        return False, {"ok": False, "errors": errors, "artifacts": artifacts}

    enforcement = parsed_payloads["repo_guard_enforcement"]
    integration = parsed_payloads["integration_fleet_status"]
    runtime = parsed_payloads["repo_guard_runtime_status"]

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
    errors.extend(
        _validate_expected_tool(
            "repo_guard_enforcement",
            enforcement,
            "enforce_runtime_guard_all_repos",
        )
    )
    errors.extend(
        _validate_expected_tool(
            "integration_fleet_status",
            integration,
            "validate_integration_fleet",
        )
    )
    errors.extend(
        _validate_expected_tool(
            "repo_guard_runtime_status",
            runtime,
            "repo_guard_fleet_report",
        )
    )
    errors.extend(_validate_artifact_sha256("repo_guard_enforcement", enforcement))
    errors.extend(_validate_artifact_sha256("integration_fleet_status", integration))
    errors.extend(_validate_artifact_sha256("repo_guard_runtime_status", runtime))
    errors.extend(_validate_integration_fallback_policy_consistency(integration))
    errors.extend(
        _validate_expected_integration_report_signature_policy(
            integration,
            expected_require_signed_report_inputs=bool(expected_require_signed_report_inputs),
            expected_verify_report_input_signatures=bool(expected_verify_report_input_signatures),
            expected_report_allowed_key_ids=list(expected_report_allowed_key_ids or []),
            expected_max_report_signature_age_hours=int(expected_max_report_signature_age_hours or 0),
        )
    )
    errors.extend(
        _validate_signature_envelope(
            "repo_guard_enforcement",
            enforcement,
            require_signed=require_signed,
            verify_signatures=verify_signatures,
            signature_public_key=signature_public_key,
            allowed_key_ids={k for k in allowed_key_ids if str(k).strip()},
            max_signature_age_hours=int(max_signature_age_hours or 0),
        )
    )
    errors.extend(
        _validate_signature_envelope(
            "integration_fleet_status",
            integration,
            require_signed=require_signed,
            verify_signatures=verify_signatures,
            signature_public_key=signature_public_key,
            allowed_key_ids={k for k in allowed_key_ids if str(k).strip()},
            max_signature_age_hours=int(max_signature_age_hours or 0),
        )
    )
    errors.extend(
        _validate_signature_envelope(
            "repo_guard_runtime_status",
            runtime,
            require_signed=require_signed,
            verify_signatures=verify_signatures,
            signature_public_key=signature_public_key,
            allowed_key_ids={k for k in allowed_key_ids if str(k).strip()},
            max_signature_age_hours=int(max_signature_age_hours or 0),
        )
    )

    runtime_prov = runtime.get("provenance", {})
    runtime_inputs = runtime_prov.get("inputs", {}) if isinstance(runtime_prov, dict) else {}
    runtime_source_hashes: dict[str, Any] = {}
    if isinstance(runtime_inputs, dict):
        raw_runtime_source_hashes = runtime_inputs.get("source_artifact_hashes", {})
        if isinstance(raw_runtime_source_hashes, dict):
            runtime_source_hashes = raw_runtime_source_hashes
        else:
            errors.append("repo_guard_runtime_status: source_artifact_hashes must be an object")

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

    ok = len(errors) == 0
    result = {
        "ok": ok,
        "errors": errors,
        "run_id": next(iter(set(run_ids.values()))) if len(set(run_ids.values())) == 1 else "",
        "run_ids": run_ids,
        "artifacts": artifacts,
        "runtime_expected_source_hashes": expected_source_hashes,
    }
    return ok, result


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(__file__).resolve().parent.parent

    configuration_errors = _validate_cli_configuration(args)
    if configuration_errors:
        result = {
            "ok": False,
            "errors": configuration_errors,
            "run_id": "",
            "run_ids": {},
            "artifacts": {},
            "runtime_expected_source_hashes": {},
        }
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("FAIL")
            for row in configuration_errors:
                print(f"- {row}")
        return 1

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
        require_signed=bool(args.require_signed),
        verify_signatures=bool(args.verify_signatures),
        signature_public_key=str(args.signature_public_key),
        allowed_key_ids=list(args.allowed_key_id or []),
        max_signature_age_hours=int(args.max_signature_age_hours or 0),
        expected_require_signed_report_inputs=bool(args.expected_require_signed_report_inputs),
        expected_verify_report_input_signatures=bool(args.expected_verify_report_input_signatures),
        expected_report_allowed_key_ids=list(args.expected_report_allowed_key_id or []),
        expected_max_report_signature_age_hours=int(args.expected_max_report_signature_age_hours or 0),
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("PASS" if ok else "FAIL")
        if result.get("run_id"):
            print(f"run_id: {result['run_id']}")
        rows = result.get("errors", [])
        if isinstance(rows, list):
            for row in rows:
                print(f"- {row}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
