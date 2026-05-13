#!/usr/bin/env python3
"""Machine-verifiable Polars integration validation CLI (M1-I01).

Validates that runtime-guard's Polars hooks are correctly installed and emits
structured evidence suitable for adoption tracking and CI gating.

Usage::

    # Basic validation (checks Polars availability + hook status)
    python scripts/validate_polars_integration.py

    # JSON evidence output for ADOPTION_TRACKER.md audit
    python scripts/validate_polars_integration.py --json

    # Fail with exit code 1 if hooks are not installed
    python scripts/validate_polars_integration.py --require-hooks

    # Also check scan budget API is callable
    python scripts/validate_polars_integration.py --check-budget-api

    # Also check native callback bridging API/behavior
    python scripts/validate_polars_integration.py --check-callback-api

    # Full CI gate: all checks, JSON output
    python scripts/validate_polars_integration.py --json --require-hooks --check-budget-api --check-callback-api
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
        description="Validate runtime-guard Polars integration for M1-I01 adoption evidence"
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON evidence report instead of plain text",
    )
    p.add_argument(
        "--require-hooks",
        action="store_true",
        help="Exit 1 if Polars hooks are not currently installed (useful in CI)",
    )
    p.add_argument(
        "--check-budget-api",
        action="store_true",
        help="Verify that install_polars_scan_budget() is importable and callable",
    )
    p.add_argument(
        "--check-callback-api",
        action="store_true",
        help=(
            "Verify native callback bridging behavior in attach_polars_guard() for "
            "kwarg and positional callback signatures"
        ),
    )
    p.add_argument(
        "--stage",
        default="polars-collect",
        help="Stage label to pass to attach_polars_guard (default: polars-collect)",
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

    for field in ["json", "require_hooks", "check_budget_api", "check_callback_api"]:
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


def _extract_signature_artifact_sha256(provenance: dict[str, Any]) -> tuple[str, bool]:
    artifact_sha256 = provenance.get("artifact_sha256")
    if not isinstance(artifact_sha256, str):
        return "", False
    return artifact_sha256, True


def _check_budget_api() -> dict[str, Any]:
    """Verify the scan budget API surface is present and callable."""
    result: dict[str, Any] = {"available": False, "errors": []}
    try:
        from runtime_guard import install_polars_scan_budget

        if not callable(install_polars_scan_budget):
            result["errors"].append("install_polars_scan_budget is not callable")
            return result

        # Smoke-test with a minimal mock module (no Polars required).
        class _MockFrame:
            schema = {"col_a": "Int64", "col_b": "Utf8"}

            def explain(self) -> str:
                return "SCAN parquet a\nFILTER\nSCAN parquet b"

            def collect(self) -> list[int]:
                return [1, 2]

        class _MockPolars:
            LazyFrame = _MockFrame

        import runtime_guard as rg

        guard = rg.RuntimeGuard()
        restore = install_polars_scan_budget(
            guard,
            module=_MockPolars,
            warn_columns=1,
            warn_scans=1,
            max_columns=50,
        )
        # Invoking collect() on a frame with 2 columns should warn (>1) but not raise.
        try:
            _MockPolars.LazyFrame().collect()
        finally:
            restore()

        result["available"] = True
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def _check_callback_api() -> dict[str, Any]:
    """Verify native callback bridging behavior is available and functional."""
    result: dict[str, Any] = {"available": False, "errors": []}
    try:
        from runtime_guard import attach_polars_guard, validate_polars_integration

        class _MockFrame:
            def collect(
                self,
                multiplier: int = 1,
                optimization_callback: Any | None = None,
            ) -> int:
                if callable(optimization_callback):
                    optimization_callback("plan")
                return 21 * multiplier

        class _MockPolars:
            LazyFrame = _MockFrame

        import runtime_guard as rg

        guard = rg.RuntimeGuard()
        calls: list[str] = []
        setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_polars_guard(guard, stage="callback-check", module=_MockPolars)
        try:
            kw_calls: list[str] = []
            out_kw = _MockPolars.LazyFrame().collect(
                multiplier=2,
                optimization_callback=lambda plan: kw_calls.append(str(plan)),
            )
            if out_kw != 42:
                result["errors"].append("callback kwarg bridging produced unexpected collect result")
                return result
            if kw_calls != ["plan"]:
                result["errors"].append("callback kwarg bridging did not chain user callback")
                return result

            pos_calls: list[str] = []
            out_pos = _MockPolars.LazyFrame().collect(2, lambda plan: pos_calls.append(str(plan)))
            if out_pos != 42:
                result["errors"].append("callback positional bridging produced unexpected collect result")
                return result
            if pos_calls != ["plan"]:
                result["errors"].append("callback positional bridging did not chain user callback")
                return result

            validation = validate_polars_integration(guard, module=_MockPolars)
            if not validation.get("native_callback_supported"):
                result["errors"].append("native_callback_supported marker not set")
                return result
            if not validation.get("native_callback_wrapped"):
                result["errors"].append("native_callback_wrapped marker not set")
                return result
            if "optimization_callback" not in validation.get("native_callback_kwargs", []):
                result["errors"].append("native callback kwarg metadata missing optimization_callback")
                return result
        finally:
            restore()

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
        "tool": "validate_polars_integration",
        "milestone": "M1-I01",
        "errors": [],
    }

    # ---- 1. Import runtime_guard ----------------------------------------
    try:
        import runtime_guard as rg
        from runtime_guard import (
            attach_polars_guard,
            collect_polars_integration_evidence,
            validate_polars_integration,
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

    # ---- 2. Check Polars availability --------------------------------------
    try:
        import polars as _pl

        report["polars_version"] = str(getattr(_pl, "__version__", "unknown"))
        report["polars_available"] = True
        polars_mod = _pl
    except ImportError:
        report["polars_available"] = False
        report["polars_version"] = "not-installed"
        polars_mod = None  # will use mock for structural validation

    # ---- 3. Structural validation (works without real Polars) --------------
    guard = rg.RuntimeGuard()
    validation = validate_polars_integration(guard, stage=args.stage, module=polars_mod)
    report["validation"] = validation

    # ---- 4. Evidence collection -------------------------------------------
    evidence = collect_polars_integration_evidence(guard, stage=args.stage, module=polars_mod)
    report["evidence_items"] = evidence.get("evidence_items", [])

    # ---- 5. Hook installation check (optional live attach) ----------------
    hooks_installed = False
    if polars_mod is not None:
        try:
            restore = attach_polars_guard(guard, stage=args.stage, module=polars_mod)
            re_validation = validate_polars_integration(guard, stage=args.stage, module=polars_mod)
            hooks_installed, hooks_ok = _strict_bool_field(re_validation, "methods_wrapped")
            if not hooks_ok:
                report["errors"].append(
                    "hook validation returned non-boolean methods_wrapped field"
                )
            report["hooks_installed"] = hooks_installed
            report["wrapped_methods"] = re_validation.get("wrapped_methods", [])
            restore()
        except Exception as exc:
            report["errors"].append(f"hook installation failed: {exc}")
            report["hooks_installed"] = False
    else:
        report["hooks_installed"] = False
        report["wrapped_methods"] = []
        report["errors"].append(
            "Polars not installed — hook live-attach skipped; "
            "structural validation only"
        )

    # ---- 6. Budget API check (optional) -----------------------------------
    budget_check_ok = True
    callback_check_ok = True

    if args.check_budget_api:
        budget_check = _check_budget_api()
        report["scan_budget_api"] = budget_check
        if budget_check.get("errors"):
            report["errors"].extend(budget_check["errors"])
        budget_check_ok, budget_ok = _strict_bool_field(budget_check, "available")
        if not budget_ok:
            report["errors"].append(
                "scan budget API probe returned non-boolean available field"
            )

    if args.check_callback_api:
        callback_check = _check_callback_api()
        report["native_callback_api"] = callback_check
        if callback_check.get("errors"):
            report["errors"].extend(callback_check["errors"])
        callback_check_ok, callback_ok = _strict_bool_field(callback_check, "available")
        if not callback_ok:
            report["errors"].append(
                "native callback API probe returned non-boolean available field"
            )

    # ---- 7. Determine pass/fail -------------------------------------------
    ok, api_ok = _strict_bool_field(report, "api_importable")
    if not api_ok:
        report["errors"].append("invalid report field: api_importable must be boolean")
    if args.require_hooks:
        ok = ok and hooks_installed
    if args.check_budget_api:
        ok = ok and budget_check_ok
    if args.check_callback_api:
        ok = ok and callback_check_ok

    report["ok"] = ok
    run_id = _normalize_run_id(args.run_id)
    report["run_id"] = run_id
    report["provenance"] = {
        "schema_version": 1,
        "tool": "validate_polars_integration",
        "script": str(Path(__file__).resolve()),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
        "git_commit": _safe_git_commit(repo_root),
        "inputs": {
            "check_budget_api": bool(args.check_budget_api),
            "check_callback_api": bool(args.check_callback_api),
            "require_hooks": bool(args.require_hooks),
            "stage": str(args.stage),
        },
    }
    _stamp_artifact_sha256(report)
    provenance = report.get("provenance")
    if isinstance(provenance, dict):
        artifact_sha256, artifact_sha256_ok = _extract_signature_artifact_sha256(provenance)
        if not artifact_sha256_ok:
            print("error: provenance.artifact_sha256 must be a string", file=sys.stderr)
            return 2
        provenance["signature"] = _build_signature_envelope(artifact_sha256)

    # ---- 8. Emit output ---------------------------------------------------
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        status = "PASS" if ok else "FAIL"
        polars_ver = report.get("polars_version", "unknown")
        rg_ver = report.get("runtime_guard_version", "unknown")
        hooks_str = "installed" if hooks_installed else "not-installed"
        wrapped = ", ".join(report.get("wrapped_methods", []))
        print(f"[{status}] runtime-guard={rg_ver} polars={polars_ver}")
        print(f"  hooks: {hooks_str}")
        if wrapped:
            print(f"  wrapped methods: {wrapped}")
        if report.get("scan_budget_api"):
            budget_ok = report["scan_budget_api"].get("available", False)
            print(f"  scan_budget_api: {'ok' if budget_ok else 'FAIL'}")
        if report.get("native_callback_api"):
            callback_ok = report["native_callback_api"].get("available", False)
            print(f"  native_callback_api: {'ok' if callback_ok else 'FAIL'}")
        if report["errors"]:
            for err in report["errors"]:
                print(f"  WARN: {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
