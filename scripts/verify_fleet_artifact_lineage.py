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

    generated = str(prov.get("generated_at_utc") or "")
    if generated and not generated.endswith("Z"):
        errors.append(f"{name}: provenance.generated_at_utc must be UTC Z format")

    if strict:
        if not str(prov.get("git_commit") or "").strip():
            errors.append(f"{name}: provenance.git_commit missing in strict mode")
        if not str(prov.get("script") or "").strip():
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


def _validate_signature_envelope(
    name: str,
    payload: dict[str, Any],
    *,
    require_signed: bool,
    verify_signatures: bool,
    signature_public_key: str,
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

    mode = str(sig.get("mode") or "")
    if mode not in {"unsigned", "detached"}:
        errors.append(f"{name}: signature mode must be 'unsigned' or 'detached'")

    signed_field = str(sig.get("signed_field") or "")
    if signed_field != "artifact_sha256":
        errors.append(f"{name}: signature.signed_field must be artifact_sha256")

    artifact_sha = str(prov.get("artifact_sha256") or "")
    signed_value = str(sig.get("signed_value") or "")
    if artifact_sha and signed_value != artifact_sha:
        errors.append(f"{name}: signature.signed_value must match provenance.artifact_sha256")

    if require_signed:
        if mode != "detached":
            errors.append(f"{name}: detached signature required")
        if not str(sig.get("signature") or "").strip():
            errors.append(f"{name}: detached signature payload missing")
        if not str(sig.get("key_id") or "").strip():
            errors.append(f"{name}: detached signature key_id missing")
        if not str(sig.get("algorithm") or "").strip():
            errors.append(f"{name}: detached signature algorithm missing")

    if verify_signatures:
        if mode != "detached":
            errors.append(f"{name}: detached signature required for cryptographic verification")
            return errors
        key_path = str(signature_public_key or "").strip()
        if not key_path:
            errors.append(f"{name}: --signature-public-key is required when --verify-signatures is set")
            return errors

        ok, reason = _verify_detached_signature(
            algorithm=str(sig.get("algorithm") or ""),
            signed_value=str(sig.get("signed_value") or ""),
            signature_text=str(sig.get("signature") or ""),
            public_key_path=Path(key_path),
        )
        if not ok:
            errors.append(f"{name}: signature verification failed: {reason}")

    return errors


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
    errors.extend(_validate_artifact_sha256("repo_guard_enforcement", enforcement))
    errors.extend(_validate_artifact_sha256("integration_fleet_status", integration))
    errors.extend(_validate_artifact_sha256("repo_guard_runtime_status", runtime))
    errors.extend(
        _validate_signature_envelope(
            "repo_guard_enforcement",
            enforcement,
            require_signed=require_signed,
            verify_signatures=verify_signatures,
            signature_public_key=signature_public_key,
        )
    )
    errors.extend(
        _validate_signature_envelope(
            "integration_fleet_status",
            integration,
            require_signed=require_signed,
            verify_signatures=verify_signatures,
            signature_public_key=signature_public_key,
        )
    )
    errors.extend(
        _validate_signature_envelope(
            "repo_guard_runtime_status",
            runtime,
            require_signed=require_signed,
            verify_signatures=verify_signatures,
            signature_public_key=signature_public_key,
        )
    )

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
        require_signed=bool(args.require_signed),
        verify_signatures=bool(args.verify_signatures),
        signature_public_key=str(args.signature_public_key),
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
