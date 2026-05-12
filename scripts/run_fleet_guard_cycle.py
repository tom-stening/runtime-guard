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
import uuid
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
        "--integration-max-fallback-report-age-hours",
        type=int,
        default=0,
        help=(
            "Maximum age (hours) allowed for integration fallback reports "
            "(0 disables staleness enforcement)"
        ),
    )
    p.add_argument(
        "--integration-require-signed-report-inputs",
        action="store_true",
        help="Require detached signatures for integration explicit/fallback report inputs",
    )
    p.add_argument(
        "--integration-verify-report-input-signatures",
        action="store_true",
        help="Cryptographically verify detached signatures for integration explicit/fallback report inputs",
    )
    p.add_argument(
        "--integration-report-signature-public-key",
        default="",
        help="Public key PEM path used for integration report-input signature verification",
    )
    p.add_argument(
        "--integration-report-allowed-key-id",
        action="append",
        default=[],
        help="Allowed key ID for integration report-input signatures (repeatable)",
    )
    p.add_argument(
        "--integration-max-report-signature-age-hours",
        type=int,
        default=0,
        help="Maximum allowed age in hours for integration report-input signatures (0 disables)",
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
    p.add_argument(
        "--skip-lineage-verify",
        action="store_true",
        help="Skip final verify_fleet_artifact_lineage.py integrity check",
    )
    p.add_argument(
        "--require-signed-artifacts",
        action="store_true",
        help="Require detached signatures during lineage verification",
    )
    p.add_argument(
        "--verify-signed-artifacts",
        action="store_true",
        help="Cryptographically verify detached signatures during lineage verification",
    )
    p.add_argument(
        "--signature-public-key",
        default="",
        help="Public key PEM path used when --verify-signed-artifacts is enabled",
    )
    p.add_argument(
        "--allowed-key-id",
        action="append",
        default=[],
        help="Allowed signature key ID for lineage verification (repeatable)",
    )
    p.add_argument(
        "--max-signature-age-hours",
        type=int,
        default=0,
        help="Maximum allowed signature age in hours for lineage verification (0 disables)",
    )
    return p


def _build_step_commands(args: argparse.Namespace, repo_root: Path) -> tuple[list[str], list[str], list[str], Path, Path, Path]:
    reports_dir = Path(args.reports_dir)
    if not reports_dir.is_absolute():
        reports_dir = repo_root / reports_dir

    enforcement_report = reports_dir / "repo_guard_enforcement.json"
    integration_report = reports_dir / "integration_fleet_status.json"
    runtime_report = reports_dir / "repo_guard_runtime_status.json"
    run_id = str(args.run_id or "").strip()
    if not run_id:
        run_id = str(uuid.uuid4())

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
    if run_id:
        enforce_cmd.extend(["--run-id", run_id])

    integration_cmd = [
        sys.executable,
        str(repo_root / "scripts" / "validate_integration_fleet.py"),
        "--json",
        "--output",
        str(integration_report),
    ]
    if bool(args.integration_fallback_on_pressure):
        integration_cmd.extend(["--fallback-on-pressure", "--fallback-report-dir", str(args.integration_fallback_report_dir)])
    if int(args.integration_max_fallback_report_age_hours or 0) > 0:
        integration_cmd.extend(
            [
                "--max-fallback-report-age-hours",
                str(int(args.integration_max_fallback_report_age_hours)),
            ]
        )
    if bool(args.integration_require_signed_report_inputs):
        integration_cmd.append("--require-signed-report-inputs")
    if bool(args.integration_verify_report_input_signatures):
        integration_cmd.append("--verify-report-input-signatures")
        key_path = str(args.integration_report_signature_public_key or "").strip()
        if key_path:
            integration_cmd.extend(["--report-signature-public-key", key_path])
    for key_id in list(args.integration_report_allowed_key_id or []):
        key = str(key_id or "").strip()
        if key:
            integration_cmd.extend(["--report-allowed-key-id", key])
    if int(args.integration_max_report_signature_age_hours or 0) > 0:
        integration_cmd.extend(
            [
                "--max-report-signature-age-hours",
                str(int(args.integration_max_report_signature_age_hours)),
            ]
        )
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
        "--fail-on-run-id-mismatch",
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
    if run_id:
        runtime_cmd.extend(["--run-id", run_id])

    return enforce_cmd, integration_cmd, runtime_cmd, enforcement_report, integration_report, runtime_report


def _run_step(cmd: list[str], cwd: Path) -> int:
    proc = subprocess.run(cmd, cwd=str(cwd), check=False)
    return int(proc.returncode)


def _build_lineage_verify_command(
    repo_root: Path,
    enforcement_report: Path,
    integration_report: Path,
    runtime_report: Path,
    *,
    require_signed: bool,
    verify_signatures: bool,
    signature_public_key: str,
    allowed_key_ids: list[str],
    max_signature_age_hours: int,
    expected_require_signed_report_inputs: bool,
    expected_verify_report_input_signatures: bool,
    expected_report_allowed_key_ids: list[str],
    expected_max_report_signature_age_hours: int,
) -> list[str]:
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / "verify_fleet_artifact_lineage.py"),
        "--json",
        "--strict",
        "--enforcement-report",
        str(enforcement_report),
        "--integration-report",
        str(integration_report),
        "--runtime-report",
        str(runtime_report),
    ]
    if require_signed:
        cmd.append("--require-signed")
    if verify_signatures:
        cmd.append("--verify-signatures")
        key_path = str(signature_public_key or "").strip()
        if key_path:
            cmd.extend(["--signature-public-key", key_path])
    for key_id in list(allowed_key_ids or []):
        key = str(key_id or "").strip()
        if key:
            cmd.extend(["--allowed-key-id", key])
    if int(max_signature_age_hours or 0) > 0:
        cmd.extend(["--max-signature-age-hours", str(int(max_signature_age_hours))])
    if bool(expected_require_signed_report_inputs):
        cmd.append("--expected-require-signed-report-inputs")
    if bool(expected_verify_report_input_signatures):
        cmd.append("--expected-verify-report-input-signatures")
    for key_id in list(expected_report_allowed_key_ids or []):
        key = str(key_id or "").strip()
        if key:
            cmd.extend(["--expected-report-allowed-key-id", key])
    if int(expected_max_report_signature_age_hours or 0) > 0:
        cmd.extend(
            [
                "--expected-max-report-signature-age-hours",
                str(int(expected_max_report_signature_age_hours)),
            ]
        )
    return cmd


def _summarize_runtime_report(runtime_report_path: Path) -> dict[str, Any]:
    payload = json.loads(runtime_report_path.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    return {
        "run_id": payload.get("run_id") or summary.get("run_id"),
        "overall_runtime_healthy": bool(summary.get("overall_runtime_healthy", False)),
        "fully_enforced": bool(summary.get("fully_enforced", False)),
        "integration_overall_healthy": summary.get("integration_overall_healthy"),
        "wsl_risk_level": summary.get("wsl_risk_level"),
        "recommendation_count": int(summary.get("recommendation_count", 0) or 0),
        "runtime_report": str(runtime_report_path),
    }


def _read_run_id_from_report(report_path: Path) -> str:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    root_run_id = str(payload.get("run_id") or "").strip()
    if root_run_id:
        return root_run_id
    summary = payload.get("summary")
    if isinstance(summary, dict):
        summary_run_id = str(summary.get("run_id") or "").strip()
        if summary_run_id:
            return summary_run_id
    return ""


def _validate_run_id_consistency(
    enforcement_report: Path,
    integration_report: Path,
    runtime_report: Path,
) -> tuple[bool, dict[str, str]]:
    run_ids = {
        "repo_guard_enforcement": _read_run_id_from_report(enforcement_report),
        "integration_fleet_status": _read_run_id_from_report(integration_report),
        "repo_guard_runtime_status": _read_run_id_from_report(runtime_report),
    }
    unique_run_ids = {value for value in run_ids.values() if value}
    if len(unique_run_ids) != 1 or any(not value for value in run_ids.values()):
        return False, run_ids
    return True, run_ids


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(__file__).resolve().parent.parent

    enforce_cmd, integration_cmd, runtime_cmd, enforcement_report, integration_report, runtime_report = _build_step_commands(args, repo_root)
    lineage_verify_cmd = _build_lineage_verify_command(
        repo_root,
        enforcement_report,
        integration_report,
        runtime_report,
        require_signed=bool(args.require_signed_artifacts),
        verify_signatures=bool(args.verify_signed_artifacts),
        signature_public_key=str(args.signature_public_key),
        allowed_key_ids=list(args.allowed_key_id or []),
        max_signature_age_hours=int(args.max_signature_age_hours or 0),
        expected_require_signed_report_inputs=bool(args.integration_require_signed_report_inputs),
        expected_verify_report_input_signatures=bool(args.integration_verify_report_input_signatures),
        expected_report_allowed_key_ids=list(args.integration_report_allowed_key_id or []),
        expected_max_report_signature_age_hours=int(args.integration_max_report_signature_age_hours or 0),
    )

    if bool(args.dry_run):
        print("[dry-run] enforce:", " ".join(enforce_cmd))
        print("[dry-run] integration:", " ".join(integration_cmd))
        print("[dry-run] runtime:", " ".join(runtime_cmd))
        if not bool(args.skip_lineage_verify):
            print("[dry-run] lineage:", " ".join(lineage_verify_cmd))
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

    if not bool(args.skip_lineage_verify):
        step4 = _run_step(lineage_verify_cmd, repo_root)
        if step4 != 0:
            return step4

    run_id_consistent, run_id_map = _validate_run_id_consistency(
        enforcement_report,
        integration_report,
        runtime_report,
    )
    if not run_id_consistent:
        print(
            json.dumps(
                {
                    "error": "run_id mismatch across fleet artifacts",
                    "run_ids": run_id_map,
                    "artifacts": {
                        "enforcement_report": str(enforcement_report),
                        "integration_report": str(integration_report),
                        "runtime_report": str(runtime_report),
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1

    summary = _summarize_runtime_report(runtime_report)
    summary["run_id_consistent"] = True
    summary["run_ids"] = run_id_map
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
