# runtime-guard

Attribution-aware resource-pressure monitor for any Python project.

Instead of a generic "memory is low" message, it determines **which side** the
pressure is on — this process or an external one — and prints only the
commands relevant to that cause.

## Install

```bash
# from GitHub (once you have a repo)
pip install git+https://github.com/YOUR_ORG/runtime-guard.git

# local editable during development
pip install -e /path/to/runtime-guard
```

## Quickstart

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard()                    # default thresholds, env prefix RUNTIME_GUARD
report = guard.check(stage="data-load")  # returns None when pressure is low
if report:
    guard.log(report)
```

Or in one line:

```python
guard.check_and_log(stage="model-train")
```

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB` | 2048 | Free RAM floor in MB |
| `RUNTIME_GUARD_MAX_SWAP_USED_PCT` | 85 | Swap ceiling in % |
| `RUNTIME_GUARD_CRITICAL_MEM_MB` | 1024 | Threshold for CRITICAL vs WARNING |
| `RUNTIME_GUARD_CRITICAL_SWAP_PCT` | 95 | Threshold for CRITICAL vs WARNING |
| `RUNTIME_GUARD_SELF_INFLICTED_PCT` | 20 | Min % of total RAM this process must hold for self-inflicted classification |

Change the prefix at construction to avoid collisions between repos:

```python
guard = RuntimeGuard(env_prefix="MY_APP", log_tag="MyApp")
```

## CLI

```bash
runtime-guard           # prints snapshot + exits 1 if pressure detected
python -m runtime_guard # same
```

## Self-inflicted vs external

The monitor reads `/proc/self/status` (RSS) and `/proc/meminfo` (MemTotal).
If this process holds ≥ 20 % of total RAM *and* available memory is below the
floor, pressure is classified as **self-inflicted** and guidance shows
process-scoped `ps`/`pmap` commands with the actual PID pre-filled.

Otherwise guidance points at the host (`ps aux --sort=-%mem`, `smem`, WSL2
Task Manager) without mentioning anything specific to the calling codebase.

## Requirements

- Linux (reads `/proc`).  Non-Linux platforms return zero-filled snapshots and
  never report pressure.
- Python ≥ 3.10.  No third-party dependencies.
