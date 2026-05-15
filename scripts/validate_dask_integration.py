#!/usr/bin/env python3
"""Machine-verifiable Dask integration validation CLI (M1-I02).

Validates that runtime-guard's Dask hooks are correctly installed and emits
structured evidence suitable for adoption tracking and CI gating.

Usage::

    # Basic validation (checks Dask availability + hook status)
    python scripts/validate_dask_integration.py

    # JSON evidence output for ADOPTION_TRACKER.md audit
    python scripts/validate_dask_integration.py --json

    # Fail with exit code 1 if hooks are not installed
    python scripts/validate_dask_integration.py --require-hooks

    # Also verify the task-graph guard API is callable
    python scripts/validate_dask_integration.py --check-guard-api

    # Also verify scheduler callback integration API/behavior is callable
    python scripts/validate_dask_integration.py --check-scheduler-api

    # Full CI gate: all checks, JSON output
    python scripts/validate_dask_integration.py --json --require-hooks --check-guard-api --check-scheduler-api
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
        description="Validate runtime-guard Dask integration for M1-I02 adoption evidence"
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON evidence report instead of plain text",
    )
    p.add_argument(
        "--require-hooks",
        action="store_true",
        help="Exit 1 if Dask hooks are not currently installed (useful in CI)",
    )
    p.add_argument(
        "--check-guard-api",
        action="store_true",
        help="Verify that install_dask_task_graph_guard() is importable and callable",
    )
    p.add_argument(
        "--check-scheduler-api",
        action="store_true",
        help=(
            "Verify that install_dask_scheduler_callbacks() and "
            "attach_dask_guard(..., enable_scheduler_callbacks=True) are callable"
        ),
    )
    p.add_argument(
        "--stage",
        default="dask-compute",
        help="Stage label to pass to attach_dask_guard (default: dask-compute)",
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

    for field in ["json", "require_hooks", "check_guard_api", "check_scheduler_api"]:
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


def _check_guard_api() -> dict[str, Any]:
    """Verify the task-graph guard API surface is present and callable."""
    result: dict[str, Any] = {"available": False, "errors": []}
    try:
        from runtime_guard import install_dask_task_graph_guard

        if not callable(install_dask_task_graph_guard):
            result["errors"].append("install_dask_task_graph_guard is not callable")
            return result

        # Smoke-test with a minimal mock module (no Dask required).
        class _MockGraph:
            def __dask_graph__(self):
                return {"task-1": 1, "task-2": 2}

        class _MockDaskBase:
            @staticmethod
            def compute(*args, **kwargs):
                return args

        class _MockDask:
            base = _MockDaskBase

            @staticmethod
            def compute(*args, **kwargs):
                return args

        import runtime_guard as rg

        guard = rg.RuntimeGuard()
        restore = install_dask_task_graph_guard(
            guard,
            module=_MockDask,
            warn_tasks=1,
            max_tasks=50,
        )
        # compute() with a 2-task graph should warn (>1) but not raise
        try:
            _MockDask.compute(_MockGraph())
        finally:
            restore()

        result["available"] = True
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def _check_scheduler_api() -> dict[str, Any]:
    """Verify scheduler callback integration API surface and behavior."""
    result: dict[str, Any] = {
        "available": False,
        "telemetry_counters_present": False,
        "errors": [],
    }
    try:
        from runtime_guard import attach_dask_guard, install_dask_scheduler_callbacks, validate_dask_integration

        if not callable(install_dask_scheduler_callbacks):
            result["errors"].append("install_dask_scheduler_callbacks is not callable")
            return result

        class _MockDaskBase:
            @staticmethod
            def compute(*args, **kwargs):
                return args

            @staticmethod
            def persist(*args, **kwargs):
                return args

        class _MockCallback:
            pass

        class _MockDask:
            base = _MockDaskBase

            class callbacks:
                Callback = _MockCallback

            @staticmethod
            def compute(*args, **kwargs):
                return args

            @staticmethod
            def persist(*args, **kwargs):
                return args

        import runtime_guard as rg

        guard = rg.RuntimeGuard()

        # Callback metadata API should be callable and expose context helpers.
        callback_report = install_dask_scheduler_callbacks(
            guard,
            stage_prefix="sched-check",
            module=_MockDask,
        )
        callback_summary = callback_report()
        if not isinstance(callback_summary, dict):
            result["errors"].append("scheduler callback reporter did not return dict")
            return result
        required_counter_fields = {
            "total_tasks",
            "total_healthy_events",
            "total_pressure_events",
        }
        missing_counter_fields = sorted(required_counter_fields - set(callback_summary.keys()))
        if missing_counter_fields:
            result["errors"].append(
                "scheduler callback report missing telemetry counters: "
                + ", ".join(missing_counter_fields)
            )
            return result
        result["telemetry_counters_present"] = True

        create_ctx = getattr(callback_report, "create_callback_context", None)
        if not callable(create_ctx):
            result["errors"].append("create_callback_context metadata missing")
            return result
        _ctx = create_ctx()

        # Full attach path should mark scheduler callback wrapping as enabled.
        restore = attach_dask_guard(
            guard,
            stage="sched-check",
            enable_scheduler_callbacks=True,
            module=_MockDask,
        )
        try:
            validation = validate_dask_integration(guard, module=_MockDask)
            if not validation.get("scheduler_callbacks_wrapped"):
                result["errors"].append("scheduler_callbacks_wrapped flag not set")
                return result
            if not validation.get("scheduler_callback_context_available"):
                result["errors"].append("scheduler_callback_context_available flag not set")
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

    if not isinstance(args.json, bool):
        print("error: --json flag must be boolean", file=sys.stderr)
        return 2
    if not isinstance(args.require_hooks, bool):
        print("error: --require-hooks flag must be boolean", file=sys.stderr)
        return 2
    if not isinstance(args.check_guard_api, bool):
        print("error: --check-guard-api flag must be boolean", file=sys.stderr)
        return 2
    if not isinstance(args.check_scheduler_api, bool):
        print("error: --check-scheduler-api flag must be boolean", file=sys.stderr)
        return 2
    if not isinstance(args.stage, str):
        print("error: --stage must be a non-empty string", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parent.parent

    report: dict[str, Any] = {
        "tool": "validate_dask_integration",
        "milestone": "M1-I02",
        "errors": [],
    }

    # ---- 1. Import runtime_guard ----------------------------------------
    try:
        import runtime_guard as rg
        from runtime_guard import (
            attach_dask_guard,
            collect_dask_integration_evidence,
            validate_dask_integration,
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

    # ---- 2. Check Dask availability ---------------------------------------
    try:
        import dask as _dask

        report["dask_version"] = str(getattr(_dask, "__version__", "unknown"))
        report["dask_available"] = True
        dask_mod = _dask
    except ImportError:
        report["dask_available"] = False
        report["dask_version"] = "not-installed"
        dask_mod = None  # structural validation only

    # ---- 3. Structural validation (works without real Dask) ---------------
    guard = rg.RuntimeGuard()
    validation = validate_dask_integration(guard, stage=args.stage, module=dask_mod)
    report["validation"] = validation

    # ---- 4. Evidence collection -------------------------------------------
    evidence = collect_dask_integration_evidence(guard, stage=args.stage, module=dask_mod)
    report["evidence_items"] = evidence.get("evidence_items", [])

    # ---- 5. Hook installation check (optional live attach) ----------------
    hooks_installed = False
    if dask_mod is not None:
        try:
            restore = attach_dask_guard(guard, stage=args.stage, module=dask_mod)
            re_validation = validate_dask_integration(guard, stage=args.stage, module=dask_mod)
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
            "Dask not installed — hook live-attach skipped; "
            "structural validation only"
        )

    # ---- 6. Task-graph guard API check (optional) -------------------------
    guard_check_ok = True
    scheduler_check_ok = True

    if args.check_guard_api:
        guard_check = _check_guard_api()
        report["task_graph_guard_api"] = guard_check
        if guard_check.get("errors"):
            report["errors"].extend(guard_check["errors"])
        guard_check_ok, guard_ok = _strict_bool_field(guard_check, "available")
        if not guard_ok:
            report["errors"].append(
                "task graph guard API probe returned non-boolean available field"
            )

    if args.check_scheduler_api:
        scheduler_check = _check_scheduler_api()
        report["scheduler_callback_api"] = scheduler_check
        if scheduler_check.get("errors"):
            report["errors"].extend(scheduler_check["errors"])
        scheduler_check_ok, scheduler_ok = _strict_bool_field(scheduler_check, "available")
        if not scheduler_ok:
            report["errors"].append(
                "scheduler callback API probe returned non-boolean available field"
            )

    # ---- 7. Determine pass/fail -------------------------------------------
    ok, api_ok = _strict_bool_field(report, "api_importable")
    if not api_ok:
        report["errors"].append("invalid report field: api_importable must be boolean")
    if args.require_hooks:
        ok = ok and hooks_installed
    if args.check_guard_api:
        ok = ok and guard_check_ok
    if args.check_scheduler_api:
        ok = ok and scheduler_check_ok

    report["ok"] = ok
    run_id = _normalize_run_id(args.run_id)
    report["run_id"] = run_id
    report["provenance"] = {
        "schema_version": 1,
        "tool": "validate_dask_integration",
        "script": str(Path(__file__).resolve()),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
        "git_commit": _safe_git_commit(repo_root),
        "inputs": {
            "check_guard_api": args.check_guard_api,
            "check_scheduler_api": args.check_scheduler_api,
            "require_hooks": args.require_hooks,
            "stage": args.stage,
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
        dask_ver = report.get("dask_version", "unknown")
        rg_ver = report.get("runtime_guard_version", "unknown")
        hooks_str = "installed" if hooks_installed else "not-installed"
        cb_api = "yes" if validation.get("scheduler_callback_api_present") else "no"
        print(f"[{status}] runtime-guard={rg_ver} dask={dask_ver}")
        print(f"  hooks: {hooks_str}")
        print(f"  scheduler_callback_api: {cb_api}")
        if report.get("task_graph_guard_api"):
            guard_ok = report["task_graph_guard_api"].get("available", False)
            print(f"  task_graph_guard_api: {'ok' if guard_ok else 'FAIL'}")
        if report.get("scheduler_callback_api"):
            sched_ok = report["scheduler_callback_api"].get("available", False)
            print(f"  scheduler_callback_api_check: {'ok' if sched_ok else 'FAIL'}")
        if report["errors"]:
            for err in report["errors"]:
                print(f"  WARN: {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
