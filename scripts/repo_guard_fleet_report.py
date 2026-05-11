#!/usr/bin/env python3
"""Generate a fleet runtime report for RuntimeGuard coverage across repos.

This script reads the JSON output from enforce_runtime_guard_all_repos.py and
adds runtime visibility signals:
- whether each repo is currently active in /proc (cwd-based)
- aggregate enforcement and activity summary
- optional integration summary from validate_integration_fleet.py
- optional WSL crash diagnosis snapshot
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from runtime_guard import diagnose_wsl_crash


_ENFORCED_STATES = {"enforced", "already_enforced"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build fleet runtime report for RuntimeGuard.")
    parser.add_argument(
        "--enforcement-report",
        default="reports/repo_guard_enforcement.json",
        help="Path to enforcement JSON report produced by enforce_runtime_guard_all_repos.py",
    )
    parser.add_argument(
        "--output",
        default="reports/repo_guard_runtime_status.json",
        help="Path for generated runtime status JSON",
    )
    parser.add_argument(
        "--no-proc-scan",
        action="store_true",
        help="Skip /proc activity scan (useful for deterministic tests).",
    )
    parser.add_argument(
        "--integration-report",
        default="reports/integration_fleet_status.json",
        help=(
            "Optional path to integration fleet report from "
            "validate_integration_fleet.py"
        ),
    )
    parser.add_argument(
        "--include-wsl-diagnosis",
        action="store_true",
        help="Include diagnose_wsl_crash() payload in report.",
    )
    return parser.parse_args()


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _cwd_in_repo(cwd: str, repo_path: str) -> bool:
    try:
        common = os.path.commonpath([cwd, repo_path])
    except ValueError:
        return False
    return common == repo_path


def _scan_repo_activity(repo_paths: list[str]) -> dict[str, int]:
    counts = {p: 0 for p in repo_paths}
    if not sys_platform_linux_proc_available():
        return counts

    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        cwd_link = os.path.join(entry.path, "cwd")
        try:
            cwd = os.readlink(cwd_link)
        except OSError:
            continue
        for repo_path in repo_paths:
            if _cwd_in_repo(cwd, repo_path):
                counts[repo_path] += 1
    return counts


def sys_platform_linux_proc_available() -> bool:
    return os.name == "posix" and os.path.isdir("/proc")


def _build_recommendations(
    summary: dict[str, Any],
    *,
    include_wsl_diagnosis: bool,
    wsl_diag: dict[str, Any] | None,
) -> list[str]:
    recommendations: list[str] = []

    if not bool(summary.get("fully_enforced", False)):
        recommendations.append(
            "Run enforce_runtime_guard_all_repos.py with --enforce-all-repos to close guard coverage gaps."
        )

    integration_healthy = summary.get("integration_overall_healthy")
    if integration_healthy is False:
        recommendations.append(
            "Run validate_integration_fleet.py --json --require-healthy and fix unhealthy component checks."
        )

    if include_wsl_diagnosis and isinstance(wsl_diag, dict):
        wsl_risk = str(summary.get("wsl_risk_level", "unknown"))
        if wsl_risk in {"moderate", "high", "critical"}:
            recommendations.append(
                "WSL risk is elevated; reduce concurrent heavy processes and rerun runtime-guard --diagnose-wsl-crash --json."
            )

        if bool(summary.get("wsl_docker_desktop_running", False)):
            recommendations.append(
                "Stop docker-desktop when not needed during heavy WSL IDE/test/training sessions."
            )

        top_cmd = str(summary.get("wsl_top_process_command", "")).lower()
        if "vscode-server" in top_cmd or "extensionhost" in top_cmd:
            recommendations.append(
                "Close idle VS Code windows/workspaces to reduce extension host memory pressure."
            )
        if "pylance" in top_cmd:
            recommendations.append(
                "Reduce Pylance indexing scope (exclude large directories) during heavy workload windows."
            )
        if "python" in top_cmd:
            recommendations.append(
                "Pause non-essential long-running Python jobs while memory pressure is elevated."
            )

        for action in wsl_diag.get("prevention_actions", [])[:3]:
            text = str(action).strip()
            if text:
                recommendations.append(text)

    deduped: list[str] = []
    seen: set[str] = set()
    for row in recommendations:
        if row in seen:
            continue
        seen.add(row)
        deduped.append(row)

    if not deduped:
        deduped.append("Fleet status is healthy; keep periodic enforcement and runtime reporting enabled.")

    return deduped


def _build_payload(
    enforcement: dict[str, Any],
    *,
    include_proc_scan: bool,
    include_wsl_diagnosis: bool,
    integration_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    repos = list(enforcement.get("repos", []))
    repo_paths = [str(r.get("repo_path", "")) for r in repos]

    activity_counts = _scan_repo_activity(repo_paths) if include_proc_scan else {p: 0 for p in repo_paths}

    runtime_repos: list[dict[str, Any]] = []
    for repo in repos:
        repo_path = str(repo.get("repo_path", ""))
        status = str(repo.get("status", ""))
        pid_count = int(activity_counts.get(repo_path, 0))
        runtime_repos.append(
            {
                **repo,
                "is_enforced": status in _ENFORCED_STATES,
                "active_pid_count": pid_count,
                "is_active": pid_count > 0,
            }
        )

    enforced_count = sum(1 for r in runtime_repos if r["is_enforced"])
    active_count = sum(1 for r in runtime_repos if r["is_active"])

    summary = {
        "total_repos": len(runtime_repos),
        "enforced_repos": enforced_count,
        "unenforced_repos": len(runtime_repos) - enforced_count,
        "active_repos": active_count,
        "fully_enforced": enforced_count == len(runtime_repos),
        "proc_scan_enabled": include_proc_scan,
    }

    if isinstance(integration_report, dict):
        integ_summary = integration_report.get("summary", {})
        if isinstance(integ_summary, dict):
            summary["integration_overall_healthy"] = bool(
                integ_summary.get("overall_healthy", False)
            )
            summary["integration_risk_level"] = str(
                integ_summary.get("risk_level", "unknown")
            )
            summary["integration_components_total"] = int(
                integ_summary.get("components_total", 0)
            )
            summary["integration_components_healthy"] = int(
                integ_summary.get("components_healthy", 0)
            )
        summary["integration_execution_mode"] = str(
            integration_report.get("execution_mode", "unknown")
        )
        pressure_meta = integration_report.get("pressure_fallback", {})
        if isinstance(pressure_meta, dict):
            summary["integration_pressure_fallback_enabled"] = bool(
                pressure_meta.get("enabled", False)
            )
            summary["integration_pressure_detected"] = bool(
                pressure_meta.get("pressure_detected", False)
            )

    wsl_diag: dict[str, Any] | None = None

    payload: dict[str, Any] = {
        "source_enforcement_report": enforcement,
        "summary": summary,
        "repos": runtime_repos,
    }

    if include_wsl_diagnosis:
        wsl_diag = diagnose_wsl_crash()
        payload["wsl_diagnosis"] = wsl_diag
        summary["wsl_risk_level"] = str(wsl_diag.get("risk_level", "unknown"))
        summary["wsl_risk_score"] = int(wsl_diag.get("risk_score", 0) or 0)
        summary["wsl_running_distro_count"] = int(wsl_diag.get("wsl_running_distro_count", 0) or 0)
        summary["wsl_docker_desktop_running"] = bool(wsl_diag.get("docker_desktop_running", False))
        top_rows = wsl_diag.get("guest_top_memory_processes", [])
        if isinstance(top_rows, list) and top_rows:
            first = top_rows[0]
            if isinstance(first, dict):
                summary["wsl_top_process_pid"] = int(first.get("pid", 0) or 0)
                summary["wsl_top_process_rss_mb"] = int(first.get("rss_mb", 0) or 0)
                summary["wsl_top_process_command"] = str(first.get("command", ""))

    payload["recommendations"] = _build_recommendations(
        summary,
        include_wsl_diagnosis=include_wsl_diagnosis,
        wsl_diag=wsl_diag,
    )
    summary["recommendation_count"] = len(payload["recommendations"])

    if isinstance(integration_report, dict):
        payload["integration_status"] = integration_report

    return payload


def main() -> int:
    args = _parse_args()

    enforcement_path = Path(args.enforcement_report)
    if not enforcement_path.is_absolute():
        enforcement_path = Path.cwd() / enforcement_path
    if not enforcement_path.exists():
        raise SystemExit(f"error: enforcement report not found: {enforcement_path}")

    enforcement = _load_json(enforcement_path)

    integration_payload: dict[str, Any] | None = None
    integration_path = Path(args.integration_report)
    if not integration_path.is_absolute():
        integration_path = Path.cwd() / integration_path
    if integration_path.exists():
        loaded = _load_json(integration_path)
        if isinstance(loaded, dict):
            integration_payload = loaded

    payload = _build_payload(
        enforcement,
        include_proc_scan=not args.no_proc_scan,
        include_wsl_diagnosis=bool(args.include_wsl_diagnosis),
        integration_report=integration_payload,
    )

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = Path.cwd() / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps(payload["summary"], indent=2, sort_keys=True))
    print(f"report: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
