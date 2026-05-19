#!/usr/bin/env python3
"""Benchmark runtime-guard latency and memory overhead (P2-A).

This script provides machine-verifiable performance evidence for pilot and
release-readiness workflows.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
from pathlib import Path
import statistics
import sys
import tracemalloc
from typing import Any, Callable


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Benchmark runtime-guard check() and snapshot read performance"
    )
    p.add_argument("--json", action="store_true", help="Emit JSON output")
    p.add_argument(
        "--out",
        default="",
        help="Optional path to write JSON benchmark artifact",
    )
    p.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Measured iterations per benchmark (default: 1000)",
    )
    p.add_argument(
        "--warmup",
        type=int,
        default=50,
        help="Warmup iterations per benchmark (default: 50)",
    )
    p.add_argument(
        "--stage",
        default="benchmark",
        help="Stage label for RuntimeGuard.check(stage=...) (default: benchmark)",
    )
    p.add_argument(
        "--disable-top-procs",
        action="store_true",
        help="Disable top process collection for low-noise latency measurement",
    )
    p.add_argument(
        "--fail-on-check-p99-ms",
        type=float,
        default=-1.0,
        help="Exit 1 when check() p99 exceeds this threshold (disabled when < 0)",
    )
    p.add_argument(
        "--fail-on-snapshot-p99-ms",
        type=float,
        default=-1.0,
        help="Exit 1 when _read_snapshot() p99 exceeds this threshold (disabled when < 0)",
    )
    p.add_argument(
        "--fail-on-peak-kib",
        type=int,
        default=-1,
        help="Exit 1 when check() peak traced memory exceeds this KiB threshold (disabled when < 0)",
    )
    return p


def _normalize_run_timestamp() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    for field in ["json", "disable_top_procs"]:
        value = getattr(args, field, False)
        if not isinstance(value, bool):
            errors.append(f"--{field.replace('_', '-')} flag must be boolean")

    out = getattr(args, "out", "")
    if not isinstance(out, str):
        errors.append("--out must be a string")

    stage = getattr(args, "stage", "")
    if not isinstance(stage, str) or not stage.strip():
        errors.append("--stage must be a non-empty string")

    iterations = getattr(args, "iterations", 0)
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations <= 0:
        errors.append("--iterations must be a positive integer")

    warmup = getattr(args, "warmup", 0)
    if isinstance(warmup, bool) or not isinstance(warmup, int) or warmup < 0:
        errors.append("--warmup must be a non-negative integer")

    if (
        isinstance(iterations, int)
        and not isinstance(iterations, bool)
        and iterations > 0
        and isinstance(warmup, int)
        and not isinstance(warmup, bool)
        and warmup >= 0
        and warmup >= iterations
    ):
        errors.append("--warmup must be less than --iterations")

    for field in ["fail_on_check_p99_ms", "fail_on_snapshot_p99_ms"]:
        value = getattr(args, field, -1.0)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"--{field.replace('_', '-')} must be a number")
            continue
        if float(value) < 0.0 and float(value) != -1.0:
            errors.append(f"--{field.replace('_', '-')} must be -1 or >= 0")

    peak_kib = getattr(args, "fail_on_peak_kib", -1)
    if isinstance(peak_kib, bool) or not isinstance(peak_kib, int):
        errors.append("--fail-on-peak-kib must be an integer")
    elif peak_kib < -1:
        errors.append("--fail-on-peak-kib must be -1 or >= 0")

    return errors


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    if pct <= 0:
        return float(min(samples))
    if pct >= 100:
        return float(max(samples))
    sorted_samples = sorted(samples)
    k = (len(sorted_samples) - 1) * (pct / 100.0)
    low = int(k)
    high = min(low + 1, len(sorted_samples) - 1)
    if low == high:
        return float(sorted_samples[low])
    frac = k - low
    return float(sorted_samples[low] * (1.0 - frac) + sorted_samples[high] * frac)


def _benchmark_callable(
    fn: Callable[[], Any],
    *,
    iterations: int,
    warmup: int,
    perf_counter: Callable[[], float],
) -> list[float]:
    for _ in range(warmup):
        fn()

    samples_ms: list[float] = []
    for _ in range(iterations):
        start = perf_counter()
        fn()
        elapsed_ms = (perf_counter() - start) * 1000.0
        samples_ms.append(elapsed_ms)
    return samples_ms


def _summarize_samples(samples_ms: list[float]) -> dict[str, float]:
    if not samples_ms:
        return {
            "mean_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
        }
    return {
        "mean_ms": float(statistics.fmean(samples_ms)),
        "p50_ms": _percentile(samples_ms, 50.0),
        "p95_ms": _percentile(samples_ms, 95.0),
        "p99_ms": _percentile(samples_ms, 99.0),
        "min_ms": float(min(samples_ms)),
        "max_ms": float(max(samples_ms)),
    }


def _build_failure_reasons(payload: dict[str, Any], args: argparse.Namespace) -> list[str]:
    reasons: list[str] = []

    check_p99 = payload["benchmarks"]["check"]["p99_ms"]
    snapshot_p99 = payload["benchmarks"]["snapshot"]["p99_ms"]
    check_peak_kib = payload["benchmarks"]["check"]["peak_traced_kib"]

    check_limit = float(args.fail_on_check_p99_ms)
    if check_limit >= 0.0 and check_p99 > check_limit:
        reasons.append(
            f"check() p99 exceeded threshold: observed={check_p99:.4f} ms limit={check_limit:.4f} ms"
        )

    snapshot_limit = float(args.fail_on_snapshot_p99_ms)
    if snapshot_limit >= 0.0 and snapshot_p99 > snapshot_limit:
        reasons.append(
            f"_read_snapshot() p99 exceeded threshold: observed={snapshot_p99:.4f} ms limit={snapshot_limit:.4f} ms"
        )

    peak_limit = int(args.fail_on_peak_kib)
    if peak_limit >= 0 and check_peak_kib > peak_limit:
        reasons.append(
            "check() peak traced memory exceeded threshold: "
            f"observed={check_peak_kib} KiB limit={peak_limit} KiB"
        )

    return reasons


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    import time

    import runtime_guard as rg

    guard = rg.RuntimeGuard(show_top_procs=not args.disable_top_procs)

    check_samples = _benchmark_callable(
        lambda: guard.check(stage=args.stage),
        iterations=int(args.iterations),
        warmup=int(args.warmup),
        perf_counter=time.perf_counter,
    )

    snapshot_reader = getattr(rg, "_read_snapshot", None)
    if not callable(snapshot_reader):
        raise RuntimeError("runtime_guard._read_snapshot is unavailable or not callable")

    snapshot_samples = _benchmark_callable(
        snapshot_reader,
        iterations=int(args.iterations),
        warmup=int(args.warmup),
        perf_counter=time.perf_counter,
    )

    # Use traced allocations around check() loop as a portable memory-overhead proxy.
    tracemalloc.start()
    _ = _benchmark_callable(
        lambda: guard.check(stage=args.stage),
        iterations=int(args.iterations),
        warmup=0,
        perf_counter=time.perf_counter,
    )
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    payload: dict[str, Any] = {
        "tool": "scripts/benchmark_runtime_guard.py",
        "generated_at_utc": _normalize_run_timestamp(),
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "config": {
            "iterations": int(args.iterations),
            "warmup": int(args.warmup),
            "stage": str(args.stage),
            "disable_top_procs": bool(args.disable_top_procs),
        },
        "benchmarks": {
            "check": {
                **_summarize_samples(check_samples),
                "peak_traced_kib": int(peak_bytes // 1024),
                "current_traced_kib": int(current_bytes // 1024),
            },
            "snapshot": _summarize_samples(snapshot_samples),
        },
    }

    return payload


def _emit_output(payload: dict[str, Any], args: argparse.Namespace) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    check = payload["benchmarks"]["check"]
    snapshot = payload["benchmarks"]["snapshot"]
    print("runtime-guard benchmark summary")
    print(f"  check() p50/p99: {check['p50_ms']:.4f} / {check['p99_ms']:.4f} ms")
    print(
        "  check() peak traced memory: "
        f"{check['peak_traced_kib']} KiB (current {check['current_traced_kib']} KiB)"
    )
    print(
        f"  _read_snapshot() p50/p99: {snapshot['p50_ms']:.4f} / {snapshot['p99_ms']:.4f} ms"
    )


def _write_artifact(payload: dict[str, Any], path_text: str) -> None:
    target = Path(path_text).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = _build_parser().parse_args()

    errors = _validate_cli_configuration(args)
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 2

    # Defense in depth for parser-bypass usage.
    if not isinstance(args.json, bool):
        print("--json flag must be boolean", file=sys.stderr)
        return 2
    if not isinstance(args.disable_top_procs, bool):
        print("--disable-top-procs flag must be boolean", file=sys.stderr)
        return 2

    try:
        payload = run_benchmark(args)
    except Exception as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        return 2

    failure_reasons = _build_failure_reasons(payload, args)
    payload["gates"] = {
        "healthy": not failure_reasons,
        "failure_count": len(failure_reasons),
        "failure_reasons": failure_reasons,
    }

    if isinstance(args.out, str) and args.out.strip():
        _write_artifact(payload, args.out)

    _emit_output(payload, args)

    if failure_reasons:
        for reason in failure_reasons:
            print(reason, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
