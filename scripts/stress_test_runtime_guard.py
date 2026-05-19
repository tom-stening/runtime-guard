#!/usr/bin/env python3
"""Stress test runtime-guard under concurrent load (P2-B).

Validates latency percentiles and memory overhead when check() is called
from multiple threads simultaneously, simulating real ML/data pipeline load.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import platform
import statistics
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable

import runtime_guard as rg


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Stress-test runtime-guard under concurrent check() load"
    )
    p.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent worker threads (default: 4)",
    )
    p.add_argument(
        "--duration-s",
        type=float,
        default=10.0,
        help="Duration of stress test in seconds (default: 10)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output",
    )
    p.add_argument(
        "--out",
        default="",
        help="Optional path to write JSON stress artifact",
    )
    p.add_argument(
        "--stage",
        default="stress",
        help="Stage label for RuntimeGuard.check(stage=...) (default: stress)",
    )
    p.add_argument(
        "--fail-on-p99-ms",
        type=float,
        default=-1.0,
        help="Exit 1 when check() p99 exceeds this threshold (disabled when < 0)",
    )
    p.add_argument(
        "--fail-on-peak-kib",
        type=int,
        default=-1,
        help="Exit 1 when peak traced memory exceeds this KiB (disabled when < 0)",
    )
    return p


def _normalize_run_timestamp() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    workers = getattr(args, "workers", 0)
    if isinstance(workers, bool) or not isinstance(workers, int) or workers <= 0:
        errors.append("--workers must be a positive integer")

    duration = getattr(args, "duration_s", 0.0)
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        errors.append("--duration-s must be a positive number")
    elif float(duration) <= 0.0:
        errors.append("--duration-s must be > 0")

    stage = getattr(args, "stage", "")
    if not isinstance(stage, str) or not stage.strip():
        errors.append("--stage must be a non-empty string")

    for field in ["json"]:
        value = getattr(args, field, False)
        if not isinstance(value, bool):
            errors.append(f"--{field.replace('_', '-')} flag must be boolean")

    out = getattr(args, "out", "")
    if not isinstance(out, str):
        errors.append("--out must be a string")

    for field in ["fail_on_p99_ms"]:
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


def _worker_thread(
    guard: rg.RuntimeGuard,
    duration_s: float,
    stage: str,
    perf_counter: Callable[[], float],
) -> list[float]:
    """Run check() calls for duration_s, return latency samples in milliseconds."""
    samples_ms: list[float] = []
    end_time = perf_counter() + duration_s

    while perf_counter() < end_time:
        start = perf_counter()
        guard.check(stage=stage)
        elapsed_ms = (perf_counter() - start) * 1000.0
        samples_ms.append(elapsed_ms)

    return samples_ms


def _build_failure_reasons(payload: dict[str, Any], args: argparse.Namespace) -> list[str]:
    reasons: list[str] = []

    check_p99 = payload["benchmarks"]["check"]["p99_ms"]
    check_peak_kib = payload["benchmarks"]["check"]["peak_traced_kib"]

    check_limit = float(args.fail_on_p99_ms)
    if check_limit >= 0.0 and check_p99 > check_limit:
        reasons.append(
            f"check() p99 exceeded threshold: observed={check_p99:.4f} ms limit={check_limit:.4f} ms"
        )

    peak_limit = int(args.fail_on_peak_kib)
    if peak_limit >= 0 and check_peak_kib > peak_limit:
        reasons.append(
            "check() peak traced memory exceeded threshold: "
            f"observed={check_peak_kib} KiB limit={peak_limit} KiB"
        )

    return reasons


def run_stress_test(args: argparse.Namespace) -> dict[str, Any]:
    """Run concurrent stress test and collect latency/memory metrics."""
    guard = rg.RuntimeGuard(show_top_procs=False)

    # Trace memory during concurrent phase
    tracemalloc.start()

    # Launch worker threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.workers)) as executor:
        futures = [
            executor.submit(
                _worker_thread,
                guard,
                float(args.duration_s),
                str(args.stage),
                time.perf_counter,
            )
            for _ in range(int(args.workers))
        ]
        # Collect all results
        all_samples: list[float] = []
        for future in concurrent.futures.as_completed(futures):
            all_samples.extend(future.result())

    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    payload: dict[str, Any] = {
        "tool": "scripts/stress_test_runtime_guard.py",
        "generated_at_utc": _normalize_run_timestamp(),
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "config": {
            "workers": int(args.workers),
            "duration_s": float(args.duration_s),
            "stage": str(args.stage),
            "total_check_calls": len(all_samples),
        },
        "benchmarks": {
            "check": {
                **_summarize_samples(all_samples),
                "peak_traced_kib": int(peak_bytes // 1024),
                "current_traced_kib": int(current_bytes // 1024),
                "call_count": len(all_samples),
            }
        },
    }

    return payload


def _emit_output(payload: dict[str, Any], args: argparse.Namespace) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    check = payload["benchmarks"]["check"]
    config = payload["config"]
    print("runtime-guard stress test summary")
    print(f"  workers: {config['workers']}, duration: {config['duration_s']}s")
    print(f"  total check() calls: {check['call_count']}")
    print(f"  check() p50/p99: {check['p50_ms']:.4f} / {check['p99_ms']:.4f} ms")
    print(
        f"  peak traced memory: {check['peak_traced_kib']} KiB (current {check['current_traced_kib']} KiB)"
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

    try:
        payload = run_stress_test(args)
    except Exception as exc:
        print(f"stress test failed: {exc}", file=sys.stderr)
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
