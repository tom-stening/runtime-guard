#!/usr/bin/env python3
"""Generate a fleet runtime report for RuntimeGuard coverage across repos.

This script reads the JSON output from enforce_runtime_guard_all_repos.py and
adds runtime visibility signals:
- whether each repo is currently active in /proc (cwd-based)
- aggregate enforcement and activity summary
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


def _build_payload(
    enforcement: dict[str, Any],
    *,
    include_proc_scan: bool,
    include_wsl_diagnosis: bool,
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

    payload: dict[str, Any] = {
        "source_enforcement_report": enforcement,
        "summary": summary,
        "repos": runtime_repos,
    }

    if include_wsl_diagnosis:
        payload["wsl_diagnosis"] = diagnose_wsl_crash()

    return payload


def main() -> int:
    args = _parse_args()

    enforcement_path = Path(args.enforcement_report)
    if not enforcement_path.is_absolute():
        enforcement_path = Path.cwd() / enforcement_path
    if not enforcement_path.exists():
        raise SystemExit(f"error: enforcement report not found: {enforcement_path}")

    enforcement = _load_json(enforcement_path)
    payload = _build_payload(
        enforcement,
        include_proc_scan=not args.no_proc_scan,
        include_wsl_diagnosis=bool(args.include_wsl_diagnosis),
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
