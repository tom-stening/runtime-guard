#!/usr/bin/env python3
"""Run a full RuntimeGuard fleet governance cycle in one command.

This orchestrator executes:
1. enforce_runtime_guard_all_repos.py
2. validate_integration_fleet.py
3. repo_guard_fleet_report.py

It is intended for CI/cron automation where we need consistent ordering and
repeatable fail-fast gates across enforcement, integration health, and WSL risk.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run RuntimeGuard fleet governance cycle")
    p.add_argument("--root", required=True, help="Root directory containing repositories")
    p.add_argument(
        "--reports-dir",
        default="reports",
        help="Directory for generated report artifacts (default: reports)",
    )
    p.add_argument(
        "--include-wsl-diagnosis",
        action="store_true",
        help="Include WSL diagnosis in final runtime status report",
    )
    p.add_argument(
        "--integration-fallback-on-pressure",
        action="store_true",
        help="Enable pressure-triggered fallback for integration validator",
    )
    p.add_argument(
        "--integration-fallback-report-dir",
        default="reports",
        help="Fallback report directory for integration validator",
    )
    p.add_argument(
        "--fail-on-unenforced",
        action="store_true",
        help="Fail when any repos are unenforced",
    )
    p.add_argument(
        "--fail-on-integration-unhealthy",
        action="store_true",
        help="Fail when aggregated integration health is unhealthy",
    )
    p.add_argument(
        "--fail-on-wsl-risk",
        choices=["moderate", "high", "critical"],
        help="Fail when WSL risk reaches the selected threshold",
    )
    p.add_argument(
        "--fail-on-extension-total-rss-mb",
        type=int,
        default=0,
        help="Fail when summed VS Code extension RSS meets/exceeds MB threshold",
    )
    p.add_argument(
        "--fail-on-extension-rss",
        action="append",
        default=[],
        metavar="EXTENSION=MB",
        help="Fail when named VS Code extension RSS meets/exceeds MB threshold (repeatable)",
    )
    p.add_argument(
        "--run-id",
        default="",
        help="Optional external run identifier passed through to fleet report generation",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the step commands without executing",
    )
    return p


def _build_step_commands(args: argparse.Namespace, repo_root: Path) -> tuple[list[str], list[str], list[str], Path, Path, Path]:
    reports_dir = Path(args.reports_dir)
    if not reports_dir.is_absolute():
        reports_dir = repo_root / reports_dir

    enforcement_report = reports_dir / "repo_guard_enforcement.json"
    integration_report = reports_dir / "integration_fleet_status.json"
    runtime_report = reports_dir / "repo_guard_runtime_status.json"

    enforce_cmd = [
        sys.executable,
        str(repo_root / "scripts" / "enforce_runtime_guard_all_repos.py"),
        "--root",
        str(Path(args.root).expanduser()),
        "--enforce-all-repos",
        "--force-runtime-guard-sitecustomize",
        "--report-path",
        str(enforcement_report),
    ]

    integration_cmd = [
        sys.executable,
        str(repo_root / "scripts" / "validate_integration_fleet.py"),
        "--json",
        "--output",
        str(integration_report),
    ]
    if bool(args.integration_fallback_on_pressure):
        integration_cmd.extend(["--fallback-on-pressure", "--fallback-report-dir", str(args.integration_fallback_report_dir)])
    run_id = str(args.run_id or "").strip()
    if run_id:
        integration_cmd.extend(["--run-id", run_id])

    runtime_cmd = [
        sys.executable,
        str(repo_root / "scripts" / "repo_guard_fleet_report.py"),
        "--enforcement-report",
        str(enforcement_report),
        "--integration-report",
        str(integration_report),
        "--output",
        str(runtime_report),
    ]
    if bool(args.include_wsl_diagnosis):
        runtime_cmd.append("--include-wsl-diagnosis")
    if bool(args.fail_on_unenforced):
        runtime_cmd.append("--fail-on-unenforced")
    if bool(args.fail_on_integration_unhealthy):
        runtime_cmd.append("--fail-on-integration-unhealthy")
    if args.fail_on_wsl_risk:
        runtime_cmd.extend(["--fail-on-wsl-risk", str(args.fail_on_wsl_risk)])
    if int(args.fail_on_extension_total_rss_mb or 0) > 0:
        runtime_cmd.extend(
            ["--fail-on-extension-total-rss-mb", str(int(args.fail_on_extension_total_rss_mb))]
        )
    for spec in list(args.fail_on_extension_rss or []):
        runtime_cmd.extend(["--fail-on-extension-rss", str(spec)])
    run_id = str(args.run_id or "").strip()
    if run_id:
        runtime_cmd.extend(["--run-id", run_id])

    return enforce_cmd, integration_cmd, runtime_cmd, enforcement_report, integration_report, runtime_report


def _run_step(cmd: list[str], cwd: Path) -> int:
    proc = subprocess.run(cmd, cwd=str(cwd), check=False)
    return int(proc.returncode)


def _summarize_runtime_report(runtime_report_path: Path) -> dict[str, Any]:
    payload = json.loads(runtime_report_path.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    return {
        "overall_runtime_healthy": bool(summary.get("overall_runtime_healthy", False)),
        "fully_enforced": bool(summary.get("fully_enforced", False)),
        "integration_overall_healthy": summary.get("integration_overall_healthy"),
        "wsl_risk_level": summary.get("wsl_risk_level"),
        "recommendation_count": int(summary.get("recommendation_count", 0) or 0),
        "runtime_report": str(runtime_report_path),
    }


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(__file__).resolve().parent.parent

    enforce_cmd, integration_cmd, runtime_cmd, _, _, runtime_report = _build_step_commands(args, repo_root)

    if bool(args.dry_run):
        print("[dry-run] enforce:", " ".join(enforce_cmd))
        print("[dry-run] integration:", " ".join(integration_cmd))
        print("[dry-run] runtime:", " ".join(runtime_cmd))
        return 0

    step1 = _run_step(enforce_cmd, repo_root)
    if step1 != 0:
        return step1

    step2 = _run_step(integration_cmd, repo_root)
    if step2 != 0:
        return step2

    step3 = _run_step(runtime_cmd, repo_root)
    if step3 != 0:
        return step3

    summary = _summarize_runtime_report(runtime_report)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
