#!/usr/bin/env python3
"""WSL-safe preflight gate for memory-heavy subprocess launches.

Use this script before launching memory-hungry tools (browsers, JVM, large
worker pools) to avoid avoidable OOM pressure in WSL sessions.

Quick crash-prevention checklist (run once after WSL reinstall):
  1. Set memory=16GB in %USERPROFILE%\\.wslconfig  (not 20GB / unlimited)
  2. Add autoMemoryReclaim=gradual under [experimental] in .wslconfig
  3. Restart WSL: wsl --shutdown && wsl
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
from typing import Any

from runtime_guard import RuntimeGuard


def _check_wslconfig_cap() -> tuple[bool, str]:
    """Return (capped, warning_message).

    Returns True if a memory cap smaller than total RAM is detected in the
    Windows .wslconfig, reducing OOM crash risk.  Returns False with a
    remediation hint if the config is absent or sets memory=<total>.
    """
    # Heuristic: look for .wslconfig in common Windows user profile paths
    candidate_dirs = []
    # /proc/sys/fs/binfmt_misc or WSLENV sometimes carries the Windows username
    win_user = os.environ.get("WINUSER") or os.environ.get("WSLENV", "")
    for d in pathlib.Path("/mnt/c/Users").iterdir() if pathlib.Path("/mnt/c/Users").is_dir() else []:
        candidate_dirs.append(d)

    for profile in candidate_dirs:
        cfg = profile / ".wslconfig"
        if not cfg.is_file():
            continue
        text = cfg.read_text(errors="replace").lower()
        if "memory=" not in text:
            return False, (
                f"[wslconfig] {cfg} has no memory= cap — WSL can consume all host RAM. "
                "Add memory=16GB under [wsl2] and run 'wsl --shutdown' to apply."
            )
        # Extract the value and warn if it equals total RAM (risky)
        import re
        m = re.search(r"memory=(\d+)(gb|mb)?", text)
        if m:
            val_gb = int(m.group(1)) * (1 if (m.group(2) or "gb") == "gb" else 0.001)
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            total_kb = int(line.split()[1])
                            total_gb = total_kb / 1e6
                            break
            except OSError:
                total_gb = 0
            if total_gb and val_gb >= total_gb * 0.95:
                return False, (
                    f"[wslconfig] memory={m.group(1)}{m.group(2) or 'GB'} equals total RAM "
                    f"({total_gb:.0f} GB) — no Windows headroom. "
                    "Reduce to memory=16GB and run 'wsl --shutdown' to apply."
                )
        return True, ""

    return False, (
        "[wslconfig] No .wslconfig found under /mnt/c/Users/*/. "
        "Create %USERPROFILE%\\.wslconfig with memory=16GB under [wsl2]."
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check WSL memory safety before launching a heavy subprocess"
    )
    parser.add_argument(
        "--label",
        default="subprocess",
        help="Human-readable process label (e.g. Chrome, JVM, workers)",
    )
    parser.add_argument(
        "--min-mb",
        type=int,
        default=500,
        help="Minimum MemAvailable required before launch (default: 500)",
    )
    parser.add_argument(
        "--env-prefix",
        default="RUNTIME_GUARD",
        help="Environment prefix for RuntimeGuard thresholds",
    )
    parser.add_argument(
        "--stage",
        default="",
        help="Optional stage label for pressure attribution",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output instead of plain text",
    )
    parser.add_argument(
        "--check-memory-before-start",
        action="store_true",
        help=(
            "Only check .wslconfig cap and current memory; do not gate a specific "
            "subprocess. Useful as a VS Code task or extension host startup hook. "
            "Exits 0 if healthy, 1 if .wslconfig cap is missing/unsafe."
        ),
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    guard = RuntimeGuard(env_prefix=args.env_prefix)

    cap_ok, cap_warning = _check_wslconfig_cap()
    available_mb, total_mb, swap_used_pct = guard.memory_snapshot_mb()

    if args.check_memory_before_start:
        # Startup-only check: report .wslconfig cap + current memory, no subprocess gate
        payload: dict[str, Any] = {
            "wslconfig_cap_ok": cap_ok,
            "wslconfig_cap_warning": cap_warning,
            "mem_available_mb": available_mb,
            "mem_total_mb": total_mb,
            "swap_used_pct": swap_used_pct,
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            cap_status = "OK" if cap_ok else "WARN"
            print(
                f"[{cap_status}] wslconfig cap | "
                f"MemAvailable={available_mb}MB SwapUsed={swap_used_pct}%"
            )
            if not cap_ok:
                print(f"  {cap_warning}")
        return 0 if cap_ok else 1

    safe, reason = guard.subprocess_safe(
        args.label,
        min_mb=args.min_mb,
        stage=args.stage,
    )

    payload = {
        "safe": safe,
        "label": args.label,
        "reason": reason,
        "mem_available_mb": available_mb,
        "mem_total_mb": total_mb,
        "swap_used_pct": swap_used_pct,
        "min_required_mb": args.min_mb,
        "env_prefix": args.env_prefix,
    }

    cap_ok, cap_warning = _check_wslconfig_cap()

    if args.json:
        payload["wslconfig_cap_ok"] = cap_ok
        payload["wslconfig_cap_warning"] = cap_warning
        print(json.dumps(payload, sort_keys=True))
    else:
        status = "SAFE" if safe else "BLOCK"
        print(
            f"[{status}] {args.label}: MemAvailable={available_mb}MB "
            f"SwapUsed={swap_used_pct}% Required={args.min_mb}MB"
        )
        if reason:
            print(reason)
        if not cap_ok:
            print(f"[WARN] {cap_warning}")

    return 0 if safe else 2


if __name__ == "__main__":
    raise SystemExit(main())
