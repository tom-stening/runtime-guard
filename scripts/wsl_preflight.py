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
import subprocess
import sys
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
    host = _read_host_snapshot_from_wsl()
    host_total_mb_raw = host.get("host_mem_total_mb", 0)
    host_total_mb = host_total_mb_raw if isinstance(host_total_mb_raw, int) else 0
    host_total_gb = host_total_mb / 1024.0
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
        # Extract configured cap and validate against host RAM when available.
        import re
        m = re.search(r"memory=(\d+)(gb|mb)?", text)
        if m:
            val_gb = int(m.group(1)) * (1 if (m.group(2) or "gb") == "gb" else 0.001)
            if host_total_gb and val_gb >= host_total_gb * 0.95:
                recommended_gb = max(8, int(host_total_gb * 0.6))
                return False, (
                    f"[wslconfig] memory={m.group(1)}{m.group(2) or 'GB'} is near host total RAM "
                    f"({host_total_gb:.0f} GB) — little Windows headroom. "
                    f"Reduce to memory={recommended_gb}GB and run 'wsl --shutdown' to apply."
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
    parser.add_argument(
        "--diagnose-crash",
        action="store_true",
        help=(
            "Collect guest+host memory pressure diagnostics and classify risk "
            "(low|moderate|high|critical)."
        ),
    )
    parser.add_argument(
        "--fail-on-risk",
        choices=["none", "high", "critical"],
        default="none",
        help=(
            "With --diagnose-crash, exit non-zero when risk meets the threshold "
            "(default: none)."
        ),
    )
    return parser


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    label = getattr(args, "label", "")
    if not isinstance(label, str) or not label.strip():
        errors.append("--label must be a non-empty string")

    min_mb = getattr(args, "min_mb", 0)
    if not isinstance(min_mb, int) or isinstance(min_mb, bool) or min_mb < 0:
        errors.append("--min-mb must be a non-negative integer")

    env_prefix = getattr(args, "env_prefix", "")
    if not isinstance(env_prefix, str) or not env_prefix.strip():
        errors.append("--env-prefix must be a non-empty string")

    stage = getattr(args, "stage", "")
    if not isinstance(stage, str):
        errors.append("--stage must be a string")

    for field in ["json", "check_memory_before_start", "diagnose_crash"]:
        value = getattr(args, field, False)
        if not isinstance(value, bool):
            errors.append(f"--{field.replace('_', '-')} flag must be boolean")

    fail_on_risk = getattr(args, "fail_on_risk", "none")
    if not isinstance(fail_on_risk, str) or fail_on_risk not in {"none", "high", "critical"}:
        errors.append("--fail-on-risk must be one of: none, high, critical")

    return errors


def _parse_meminfo(path: str = "/proc/meminfo") -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                parts = val.strip().split()
                if not parts:
                    continue
                out[key.strip()] = int(parts[0])
    except OSError:
        return {}
    return out


def _parse_psi_memory(path: str = "/proc/pressure/memory") -> tuple[dict[str, float], bool]:
    data = {
        "some_avg10": 0.0,
        "some_avg60": 0.0,
        "full_avg10": 0.0,
        "full_avg60": 0.0,
    }
    parse_error = False

    def _parse_required_float(value: object) -> float:
        if not isinstance(value, str):
            raise ValueError("PSI token value must be a string")
        text = value.strip()
        if not text:
            raise ValueError("PSI token value must be non-empty")
        return float(text)

    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                scope = parts[0]
                kv: dict[str, str] = {}
                for token in parts[1:]:
                    if "=" not in token:
                        continue
                    k, v = token.split("=", 1)
                    kv[k] = v
                if scope == "some":
                    try:
                        data["some_avg10"] = _parse_required_float(kv.get("avg10"))
                        data["some_avg60"] = _parse_required_float(kv.get("avg60"))
                    except ValueError:
                        parse_error = True
                elif scope == "full":
                    try:
                        data["full_avg10"] = _parse_required_float(kv.get("avg10"))
                        data["full_avg60"] = _parse_required_float(kv.get("avg60"))
                    except ValueError:
                        parse_error = True
    except OSError:
        return data, False
    return data, parse_error


def _read_host_snapshot_from_wsl() -> dict[str, int]:
    out = {
        "host_mem_total_mb": 0,
        "host_mem_free_mb": 0,
        "host_vm_total_mb": 0,
        "host_vm_free_mb": 0,
        "host_vm_used_pct": 0,
    }
    try:
        raw = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_OperatingSystem "
                "| Select-Object TotalVisibleMemorySize,FreePhysicalMemory,"
                "TotalVirtualMemorySize,FreeVirtualMemory "
                "| ConvertTo-Csv -NoTypeInformation",
            ],
            stderr=subprocess.DEVNULL,
            timeout=8,
            text=True,
        )
    except Exception:
        return out

    lines = [ln.strip().strip('"') for ln in raw.splitlines() if ln.strip()]
    if len(lines) < 2:
        return out

    headers = [h.strip('"') for h in lines[0].split(",")]
    values = [v.strip('"') for v in lines[1].split(",")]
    row = dict(zip(headers, values))

    def _parse_kb_field(name: str) -> int:
        raw = row.get(name, "0")
        if not isinstance(raw, str):
            return 0
        text = raw.strip()
        if not text:
            return 0
        if not text.isdigit():
            return 0
        return int(text)

    total_kb = _parse_kb_field("TotalVisibleMemorySize")
    free_kb = _parse_kb_field("FreePhysicalMemory")
    vm_total_kb = _parse_kb_field("TotalVirtualMemorySize")
    vm_free_kb = _parse_kb_field("FreeVirtualMemory")

    out["host_mem_total_mb"] = total_kb // 1024
    out["host_mem_free_mb"] = free_kb // 1024
    out["host_vm_total_mb"] = vm_total_kb // 1024
    out["host_vm_free_mb"] = vm_free_kb // 1024
    if out["host_vm_total_mb"] > 0:
        out["host_vm_used_pct"] = int(
            100 * (out["host_vm_total_mb"] - out["host_vm_free_mb"]) / out["host_vm_total_mb"]
        )
    return out


def _classify_wsl_risk(metrics: dict[str, Any]) -> tuple[str, int, list[str], list[str]]:
    def _metric_int(name: str, default: int = 0) -> int:
        raw = metrics.get(name, default)
        if isinstance(raw, int) and not isinstance(raw, bool):
            return raw
        return default

    def _metric_float(name: str, default: float = 0.0) -> float:
        raw = metrics.get(name, default)
        if isinstance(raw, bool):
            return default
        if isinstance(raw, (int, float)):
            return float(raw)
        return default

    def _metric_bool(name: str, default: bool = False) -> bool:
        raw = metrics.get(name, default)
        if isinstance(raw, bool):
            return raw
        return default

    score = 0
    causes: list[str] = []
    prevention: list[str] = []

    guest_mem_available_mb = _metric_int("guest_mem_available_mb", 0)
    guest_swap_used_pct = _metric_int("guest_swap_used_pct", 0)
    psi_some_avg10 = _metric_float("psi_some_avg10", 0.0)
    psi_full_avg10 = _metric_float("psi_full_avg10", 0.0)
    psi_parse_error = _metric_bool("psi_parse_error", False)
    host_vm_used_pct = _metric_int("host_vm_used_pct", 0)

    if guest_mem_available_mb < 1024:
        score += 2
        causes.append("guest available memory is below 1 GiB")
        prevention.append("reduce concurrent heavy processes in WSL and VS Code extension hosts")
    if guest_swap_used_pct >= 90:
        score += 2
        causes.append("guest swap usage is at or above 90%")
        prevention.append("increase .wslconfig swap and reduce memory spikes before heavy launches")
    if psi_full_avg10 >= 10:
        score += 2
        causes.append("guest full memory PSI avg10 is high (frequent stalls)")
        prevention.append("stagger memory-heavy tasks; avoid concurrent mypy/pylance/test bursts")
    if psi_some_avg10 >= 20:
        score += 1
        causes.append("guest some memory PSI avg10 indicates sustained contention")
        prevention.append("limit extension host count and long-running indexers during heavy jobs")
    if psi_parse_error:
        score += 2
        causes.append("guest memory PSI metrics are malformed and cannot be trusted")
        prevention.append(
            "validate /proc/pressure/memory format and rerun diagnostics before heavy subprocess launches"
        )
    if host_vm_used_pct >= 85:
        score += 1
        causes.append("host virtual memory usage is high")
        prevention.append("free host memory/pagefile pressure and verify Windows pagefile is system-managed")

    if score >= 5:
        level = "critical"
    elif score >= 3:
        level = "high"
    elif score >= 1:
        level = "moderate"
    else:
        level = "low"

    if not prevention:
        prevention.append("current pressure is low; keep WSL capped and monitor before heavy subprocess launches")

    return level, score, causes, prevention


def collect_wsl_crash_diagnostics() -> dict[str, Any]:
    meminfo = _parse_meminfo()
    psi, psi_parse_error = _parse_psi_memory()

    guest_mem_total_mb = int(meminfo.get("MemTotal", 0) // 1024)
    guest_mem_available_mb = int(meminfo.get("MemAvailable", 0) // 1024)
    guest_swap_total_mb = int(meminfo.get("SwapTotal", 0) // 1024)
    guest_swap_free_mb = int(meminfo.get("SwapFree", 0) // 1024)
    guest_swap_used_pct = (
        int(100 * (guest_swap_total_mb - guest_swap_free_mb) / guest_swap_total_mb)
        if guest_swap_total_mb > 0
        else 0
    )

    host = _read_host_snapshot_from_wsl() if os.path.exists("/proc/sys/fs/binfmt_misc") else _read_host_snapshot_from_wsl()

    metrics: dict[str, Any] = {
        "guest_mem_total_mb": guest_mem_total_mb,
        "guest_mem_available_mb": guest_mem_available_mb,
        "guest_swap_total_mb": guest_swap_total_mb,
        "guest_swap_free_mb": guest_swap_free_mb,
        "guest_swap_used_pct": guest_swap_used_pct,
        "psi_some_avg10": psi["some_avg10"],
        "psi_some_avg60": psi["some_avg60"],
        "psi_full_avg10": psi["full_avg10"],
        "psi_full_avg60": psi["full_avg60"],
        "psi_parse_error": psi_parse_error,
    }
    metrics.update(host)

    if host.get("host_mem_total_mb"):
        metrics["drift_mem_total_mb"] = guest_mem_total_mb - int(host["host_mem_total_mb"])
    else:
        metrics["drift_mem_total_mb"] = 0
    if host.get("host_mem_free_mb"):
        metrics["drift_mem_available_mb"] = guest_mem_available_mb - int(host["host_mem_free_mb"])
    else:
        metrics["drift_mem_available_mb"] = 0

    level, score, causes, prevention = _classify_wsl_risk(metrics)
    metrics["risk_level"] = level
    metrics["risk_score"] = score
    metrics["likely_causes"] = causes
    metrics["prevention_actions"] = prevention
    return metrics


def main() -> int:
    args = _build_parser().parse_args()

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    guard = RuntimeGuard(env_prefix=args.env_prefix)

    cap_ok, cap_warning = _check_wslconfig_cap()
    available_mb, total_mb, swap_used_pct = guard.memory_snapshot_mb()

    if args.diagnose_crash:
        payload = collect_wsl_crash_diagnostics()
        payload["wslconfig_cap_ok"] = cap_ok
        payload["wslconfig_cap_warning"] = cap_warning

        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(
                "[WSL diagnose] "
                f"risk={payload['risk_level']} score={payload['risk_score']} "
                f"guest_mem_available={payload['guest_mem_available_mb']}MB "
                f"guest_swap_used={payload['guest_swap_used_pct']}%"
            )
            if payload.get("host_mem_total_mb"):
                print(
                    "  host: "
                    f"mem_free={payload['host_mem_free_mb']}MB "
                    f"vm_used={payload['host_vm_used_pct']}%"
                )
                print(
                    "  drift: "
                    f"mem_available={payload['drift_mem_available_mb']}MB "
                    f"mem_total={payload['drift_mem_total_mb']}MB"
                )
            if payload["likely_causes"]:
                print("  likely causes:")
                for cause in payload["likely_causes"]:
                    print(f"    - {cause}")
            print("  prevention actions:")
            for action in payload["prevention_actions"]:
                print(f"    - {action}")
            if not cap_ok and cap_warning:
                print(f"  [WARN] {cap_warning}")

        if args.fail_on_risk == "critical":
            return 1 if payload["risk_level"] == "critical" else 0
        if args.fail_on_risk == "high":
            return 1 if payload["risk_level"] in {"high", "critical"} else 0
        return 0

    if args.check_memory_before_start:
        # Startup-only check: report .wslconfig cap + current memory, no subprocess gate
        payload = {
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
