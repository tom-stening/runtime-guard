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
import json
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
    return p


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
    result: dict[str, Any] = {"available": False, "errors": []}
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
            hooks_installed = bool(re_validation.get("methods_wrapped"))
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
    if args.check_guard_api:
        guard_check = _check_guard_api()
        report["task_graph_guard_api"] = guard_check
        if guard_check.get("errors"):
            report["errors"].extend(guard_check["errors"])

    if args.check_scheduler_api:
        scheduler_check = _check_scheduler_api()
        report["scheduler_callback_api"] = scheduler_check
        if scheduler_check.get("errors"):
            report["errors"].extend(scheduler_check["errors"])

    # ---- 7. Determine pass/fail -------------------------------------------
    ok = report.get("api_importable", False)
    if args.require_hooks:
        ok = ok and hooks_installed

    report["ok"] = ok

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
