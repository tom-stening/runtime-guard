#!/usr/bin/env python3
"""Seed a repository with RuntimeGuard Python autostart bootstrap.

Writes a sitecustomize.py file into the target repository so Python processes
started from that repo automatically start RuntimeGuard background checks.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from runtime_guard import make_sitecustomize_content


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed repo-level RuntimeGuard autostart via sitecustomize.py"
    )
    parser.add_argument("--repo-path", required=True, help="Absolute path to target repository")
    parser.add_argument("--stage", default="repo-autostart")
    parser.add_argument("--interval-s", type=float, default=30.0)
    parser.add_argument("--cooldown-s", type=float, default=30.0)
    parser.add_argument("--env-prefix", default="RUNTIME_GUARD")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing sitecustomize.py if present.",
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

    for field in ["interval_s", "cooldown_s"]:
        value = getattr(args, field, 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"--{field.replace('_', '-')} must be a non-negative number")
            continue
        if value < 0:
            errors.append(f"--{field.replace('_', '-')} must be a non-negative number")

    env_prefix = getattr(args, "env_prefix", "")
    if not isinstance(env_prefix, str) or not env_prefix.strip():
        errors.append("--env-prefix must be a non-empty string")

    force = getattr(args, "force", False)
    if not isinstance(force, bool):
        errors.append("--force flag must be boolean")

    return errors


def main() -> int:
    args = _parse_args()

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    repo_path = Path(args.repo_path).expanduser().resolve()
    if not repo_path.is_dir():
        raise SystemExit(f"error: repo path does not exist: {repo_path}")

    out_path = repo_path / "sitecustomize.py"
    if out_path.exists() and not args.force:
        raise SystemExit(f"error: {out_path} already exists (use --force to overwrite)")

    content = make_sitecustomize_content(
        repo_name=repo_path.name,
        stage=args.stage,
        interval_s=args.interval_s,
        cooldown_s=args.cooldown_s,
        env_prefix=args.env_prefix,
    )
    out_path.write_text(content, encoding="utf-8")

    print(f"wrote: {out_path}")
    print("next steps:")
    print(f"  1) cd {repo_path}")
    print("  2) ensure runtime_guard is installed in the active environment")
    print(f"  3) optional disable toggle: export {args.env_prefix}_AUTOSTART=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
