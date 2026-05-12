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
import json
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
    return p


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
            hooks_installed = bool(re_validation.get("methods_wrapped"))
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
        actor_check_ok = bool(actor_check.get("available", False))

    # ---- 7. Determine pass/fail -------------------------------------------
    ok = report.get("api_importable", False)
    if args.require_hooks:
        ok = ok and hooks_installed
    if args.check_actor_api:
        ok = ok and actor_check_ok

    report["ok"] = ok

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
