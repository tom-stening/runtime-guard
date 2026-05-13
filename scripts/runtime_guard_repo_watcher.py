#!/usr/bin/env python3
"""Auto-run runtime-guard checks while a repository has active processes.

This watcher is intended for Linux user-level service managers (for example
systemd --user). It scans /proc for processes whose current working directory
is within the target repository path, and only performs memory checks while
activity is present.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path

from runtime_guard import RuntimeGuard


_STOP = False


def _on_stop(_signum: int, _frame: object) -> None:
    global _STOP
    _STOP = True


def _is_linux_proc_available() -> bool:
    return sys.platform.startswith("linux") and os.path.isdir("/proc")


def _cwd_in_repo(cwd: str, repo_path: str) -> bool:
    try:
        common = os.path.commonpath([cwd, repo_path])
    except ValueError:
        return False
    return common == repo_path


def repo_has_activity(repo_path: str) -> bool:
    """Return True when any process cwd is inside *repo_path*."""
    if not _is_linux_proc_available():
        return False

    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        cwd_link = os.path.join(entry.path, "cwd")
        try:
            cwd = os.readlink(cwd_link)
        except OSError:
            continue
        if _cwd_in_repo(cwd, repo_path):
            return True
    return False


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run runtime-guard checks only while repository processes are active."
    )
    parser.add_argument("--repo-path", required=True, help="Absolute path to repository root")
    parser.add_argument("--stage", default="repo-background", help="Stage label for checks")
    parser.add_argument("--interval-active", type=float, default=15.0)
    parser.add_argument("--interval-idle", type=float, default=60.0)
    parser.add_argument("--cooldown-s", type=float, default=30.0)
    parser.add_argument(
        "--log-tag",
        default="",
        help="Optional RuntimeGuard log tag (defaults to repo directory name)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one iteration and exit (useful for smoke tests).",
    )
    return parser.parse_args()


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    repo_path = getattr(args, "repo_path", "")
    if not isinstance(repo_path, str) or not repo_path.strip():
        errors.append("--repo-path must be a non-empty string")

    stage = getattr(args, "stage", "")
    if not isinstance(stage, str) or not stage.strip():
        errors.append("--stage must be a non-empty string")

    for field in ["interval_active", "interval_idle", "cooldown_s"]:
        value = getattr(args, field, 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"--{field.replace('_', '-')} must be a non-negative number")
            continue
        if value < 0:
            errors.append(f"--{field.replace('_', '-')} must be a non-negative number")

    log_tag = getattr(args, "log_tag", "")
    if not isinstance(log_tag, str):
        errors.append("--log-tag must be a string")

    once = getattr(args, "once", False)
    if not isinstance(once, bool):
        errors.append("--once flag must be boolean")

    return errors


def main() -> int:
    args = _parse_args()

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    repo = str(Path(args.repo_path).expanduser().resolve())

    if not os.path.isdir(repo):
        print(f"error: repo path does not exist: {repo}", file=sys.stderr)
        return 2

    if not _is_linux_proc_available():
        print(
            "error: this watcher currently supports Linux /proc environments only", file=sys.stderr
        )
        return 2

    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)

    tag = args.log_tag.strip() or os.path.basename(repo)
    guard = RuntimeGuard(log_tag=tag, cooldown_s=args.cooldown_s)

    while not _STOP:
        active = repo_has_activity(repo)
        if active:
            guard.check_and_log(stage=args.stage)
            if args.once:
                return 0
            time.sleep(max(1.0, args.interval_active))
            continue

        if args.once:
            return 0
        time.sleep(max(1.0, args.interval_idle))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
