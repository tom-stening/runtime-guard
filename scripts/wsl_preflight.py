#!/usr/bin/env python3
"""WSL-safe preflight gate for memory-heavy subprocess launches.

Use this script before launching memory-hungry tools (browsers, JVM, large
worker pools) to avoid avoidable OOM pressure in WSL sessions.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from runtime_guard import RuntimeGuard


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
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    guard = RuntimeGuard(env_prefix=args.env_prefix)

    safe, reason = guard.subprocess_safe(
        args.label,
        min_mb=args.min_mb,
        stage=args.stage,
    )
    available_mb, total_mb, swap_used_pct = guard.memory_snapshot_mb()

    payload: dict[str, Any] = {
        "safe": safe,
        "label": args.label,
        "reason": reason,
        "mem_available_mb": available_mb,
        "mem_total_mb": total_mb,
        "swap_used_pct": swap_used_pct,
        "min_required_mb": args.min_mb,
        "env_prefix": args.env_prefix,
    }

    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        status = "SAFE" if safe else "BLOCK"
        print(
            f"[{status}] {args.label}: MemAvailable={available_mb}MB "
            f"SwapUsed={swap_used_pct}% Required={args.min_mb}MB"
        )
        if reason:
            print(reason)

    return 0 if safe else 2


if __name__ == "__main__":
    raise SystemExit(main())
