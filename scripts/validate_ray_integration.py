#!/usr/bin/env python3
"""Machine-verifiable Ray integration validation CLI (M1-I03).

Validates that runtime-guard's Ray hooks are correctly installed and emits
structured evidence suitable for adoption tracking and CI gating.

Usage::

    # Basic validation (checks Ray availability + hook status)
    python scripts/validate_ray_integration.py

    # JSON evidence output for ADOPTION_TRACKER.md audit
    python scripts/validate_ray_integration.py --json

    # Fail with exit code 1 if hooks are not installed
    python scripts/validate_ray_integration.py --require-hooks

    # Also verify the actor monitoring API is callable
    python scripts/validate_ray_integration.py --check-actor-api

    # Full CI gate: all checks, JSON output
    python scripts/validate_ray_integration.py --json --require-hooks --check-actor-api
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Validate runtime-guard Ray integration for M1-I03 adoption evidence"
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON evidence report instead of plain text",
    )
    p.add_argument(
        "--require-hooks",
        action="store_true",
        help="Exit 1 if Ray hooks are not currently installed (useful in CI)",
    )
    p.add_argument(
        "--check-actor-api",
        action="store_true",
        help="Verify that enable_ray_actor_memory_monitoring() is importable and callable",
    )
    p.add_argument(
        "--stage",
        default="ray-get",
        help="Stage label to pass to attach_ray_guard (default: ray-get)",
    )
    p.add_argument(
        "--run-id",
        default="",
        help="Optional external run identifier for cross-artifact correlation.",
    )
    return p


def _normalize_run_id(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return ""


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    for field in ["json", "require_hooks", "check_actor_api"]:
        value = getattr(args, field, False)
        if not isinstance(value, bool):
            errors.append(f"--{field.replace('_', '-')} flag must be boolean")

    stage = getattr(args, "stage", "")
    if not isinstance(stage, str) or not stage.strip():
        errors.append("--stage must be a non-empty string")

    run_id = getattr(args, "run_id", "")
    if not isinstance(run_id, str):
        errors.append("--run-id must be a string")

    return errors


def _strict_bool_field(
    payload: dict[str, Any],
    key: str,
    *,
    default: bool = False,
) -> tuple[bool, bool]:
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value, True
    return default, False


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


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stamp_artifact_sha256(payload: dict[str, Any]) -> None:
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        return
    canonical_payload = json.loads(json.dumps(payload, sort_keys=True))
    canonical_provenance = canonical_payload.get("provenance")
    if isinstance(canonical_provenance, dict):
        canonical_provenance.pop("artifact_sha256", None)
        canonical_provenance.pop("signature", None)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    provenance["artifact_sha256"] = _sha256_text(canonical)


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


def _check_actor_api() -> dict[str, Any]:
    """Verify the actor memory monitoring API surface is present and callable."""
    result: dict[str, Any] = {
        "available": False,
        "hotspot_fields_present": False,
        "errors": [],
    }
    try:
        from runtime_guard import enable_ray_actor_memory_monitoring

        if not callable(enable_ray_actor_memory_monitoring):
            result["errors"].append("enable_ray_actor_memory_monitoring is not callable")
            return result

        import runtime_guard as rg

        guard = rg.RuntimeGuard()
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=False)

        required_keys = {
            "method_decorator",
            "remote_wrapper",
            "get_actor_report",
            "reset_actor_report",
            "node_report",
            "reset_node_reports",
            "get_all_node_reports",
            "cluster_summary",
        }
        missing = required_keys - set(config.keys())
        if missing:
            result["errors"].append(f"Actor monitoring config missing keys: {sorted(missing)}")
            return result

        # Smoke-test the remote_wrapper with a trivial function.
        def _noop_fn(*args, **kwargs):
            return "ok"

        wrapped = config["remote_wrapper"](_noop_fn)
        ret = wrapped()
        if ret != "ok":
            result["errors"].append(f"remote_wrapper smoke-test returned unexpected value: {ret!r}")
            return result

        summary = config["cluster_summary"]()
        if not isinstance(summary, dict):
            result["errors"].append("cluster_summary did not return a dict")
            return result
        hotspot_fields = {
            "busiest_node",
            "busiest_node_events",
            "busiest_actor",
            "busiest_actor_events",
        }
        missing_summary_fields = sorted(hotspot_fields - set(summary.keys()))
        if missing_summary_fields:
            result["errors"].append(
                "cluster_summary missing hotspot fields: "
                + ", ".join(missing_summary_fields)
            )
            return result
        result["hotspot_fields_present"] = True

        result["available"] = True
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def main() -> int:
    args = _build_parser().parse_args()

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parent.parent

    report: dict[str, Any] = {
        "tool": "validate_ray_integration",
        "milestone": "M1-I03",
        "errors": [],
    }

    # ---- 1. Import runtime_guard ----------------------------------------
    try:
        import runtime_guard as rg
        from runtime_guard import (
            attach_ray_guard,
            collect_ray_integration_evidence,
            validate_ray_integration,
        )

        report["runtime_guard_version"] = getattr(rg, "__version__", "unknown")
        report["api_importable"] = True
    except ImportError as exc:
        report["api_importable"] = False
        report["errors"].append(f"runtime_guard import failed: {exc}")
        if args.json:
            print(json.dumps(report, sort_keys=True))
        else:
            print(f"[FAIL] runtime_guard not importable: {exc}", file=sys.stderr)
        return 1

    # ---- 2. Check Ray availability ----------------------------------------
    try:
        import ray as _ray

        report["ray_version"] = str(getattr(_ray, "__version__", "unknown"))
        report["ray_available"] = True
        ray_mod = _ray
    except ImportError:
        report["ray_available"] = False
        report["ray_version"] = "not-installed"
        ray_mod = None  # structural validation only

    # ---- 3. Structural validation (works without real Ray) ----------------
    guard = rg.RuntimeGuard()
    validation = validate_ray_integration(guard, stage=args.stage, module=ray_mod)
    report["validation"] = validation

    # ---- 4. Evidence collection -------------------------------------------
    evidence = collect_ray_integration_evidence(guard, stage=args.stage, module=ray_mod)
    report["evidence_items"] = evidence.get("evidence_items", [])

    # ---- 5. Hook installation check (optional live attach) ----------------
    hooks_installed = False
    if ray_mod is not None:
        try:
            restore = attach_ray_guard(guard, stage=args.stage, module=ray_mod)
            re_validation = validate_ray_integration(guard, stage=args.stage, module=ray_mod)
            hooks_installed, hooks_ok = _strict_bool_field(re_validation, "methods_wrapped")
            if not hooks_ok:
                report["errors"].append(
                    "hook validation returned non-boolean methods_wrapped field"
                )
            report["hooks_installed"] = hooks_installed
            restore()
        except Exception as exc:
            report["errors"].append(f"hook installation failed: {exc}")
            report["hooks_installed"] = False
    else:
        report["hooks_installed"] = False
        report["errors"].append(
            "Ray not installed — hook live-attach skipped; "
            "structural validation only"
        )

    # ---- 6. Actor monitoring API check (optional) -------------------------
    actor_check_ok = True
    if args.check_actor_api:
        actor_check = _check_actor_api()
        report["actor_monitoring_api"] = actor_check
        if actor_check.get("errors"):
            report["errors"].extend(actor_check["errors"])
        actor_check_ok, actor_ok = _strict_bool_field(actor_check, "available")
        if not actor_ok:
            report["errors"].append(
                "actor monitoring API probe returned non-boolean available field"
            )

    # ---- 7. Determine pass/fail -------------------------------------------
    ok, api_ok = _strict_bool_field(report, "api_importable")
    if not api_ok:
        report["errors"].append("invalid report field: api_importable must be boolean")
    if args.require_hooks:
        ok = ok and hooks_installed
    if args.check_actor_api:
        ok = ok and actor_check_ok

    report["ok"] = ok
    run_id = _normalize_run_id(args.run_id)
    report["run_id"] = run_id
    report["provenance"] = {
        "schema_version": 1,
        "tool": "validate_ray_integration",
        "script": str(Path(__file__).resolve()),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
        "git_commit": _safe_git_commit(repo_root),
        "inputs": {
            "check_actor_api": bool(args.check_actor_api),
            "require_hooks": bool(args.require_hooks),
            "stage": str(args.stage),
        },
    }
    _stamp_artifact_sha256(report)
    provenance = report.get("provenance")
    if isinstance(provenance, dict):
        provenance["signature"] = _build_signature_envelope(str(provenance.get("artifact_sha256") or ""))

    # ---- 8. Emit output ---------------------------------------------------
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        status = "PASS" if ok else "FAIL"
        ray_ver = report.get("ray_version", "unknown")
        rg_ver = report.get("runtime_guard_version", "unknown")
        hooks_str = "installed" if hooks_installed else "not-installed"
        get_present = "yes" if validation.get("get_present") else "no"
        wait_present = "yes" if validation.get("wait_present") else "no"
        put_present = "yes" if validation.get("put_present") else "no"
        print(f"[{status}] runtime-guard={rg_ver} ray={ray_ver}")
        print(f"  hooks: {hooks_str}")
        print(f"  ray.get: {get_present}  ray.wait: {wait_present}  ray.put: {put_present}")
        if report.get("actor_monitoring_api"):
            actor_ok = report["actor_monitoring_api"].get("available", False)
            print(f"  actor_monitoring_api: {'ok' if actor_ok else 'FAIL'}")
        if report["errors"]:
            for err in report["errors"]:
                print(f"  WARN: {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
