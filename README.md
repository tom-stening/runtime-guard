# runtime-guard

**Attribution-aware resource-pressure monitor for any Python project.**

Instead of a generic "memory is low" alert, runtime-guard tells you _which side_ the pressure is on — _this process_ or _something else on the host_ — and surfaces actionable guidance pre-filled with your PID and process name.

- **Zero runtime dependencies** — pure Python stdlib; no NumPy, psutil, or similar required.
- **Cross-platform** — `/proc/meminfo` on Linux, `vm_stat`/`sysctl` on macOS, PowerShell `Get-CimInstance` on Windows (with `wmic` fallback).
- **Structured JSON events** — machine-readable emissions on the `runtime_guard.events` logger for log aggregation pipelines.
- **Threshold presets** — `tight`, `relaxed`, and `ci` bundles for instant configuration.
- **CLI first-class** — `runtime-guard --check` integrates cleanly into shell scripts, CI gates, and health-check loops.

---

## Table of Contents

1. [Install](#install)
2. [Quickstart](#quickstart)
3. [Configuration](#configuration)
4. [CLI Reference](#cli-reference)
5. [API Reference](#api-reference)
6. [Pytest Integration](#pytest-integration)
7. [Background Monitoring](#background-monitoring)
8. [WSL 2 Utilities](#wsl-2-utilities)
9. [Architecture](#architecture)
10. [FAQ](#faq)

---

## Install

```bash
pip install git+https://github.com/tom-stening/runtime-guard.git
```

For local development:

```bash
git clone https://github.com/tom-stening/runtime-guard.git
cd runtime-guard
pip install -e ".[dev]"
```

Requires **Python ≥ 3.10**. No third-party runtime dependencies.

---

## Quickstart

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard()
report = guard.check(stage="data-load")   # None when memory is healthy
if report:
    guard.log(report)                      # emits WARNING or CRITICAL to logger
```

One-liner:

```python
guard.check_and_log(stage="model-train")  # check + log in one call
```

Use a preset posture for instant threshold bundles:

```python
guard = RuntimeGuard()
# or set RUNTIME_GUARD_POSTURE=tight in the environment
```

```bash
RUNTIME_GUARD_POSTURE=ci python train.py
```

---

## Configuration

### Environment variables

All variables are read at `check()` time, not at construction, so you can change them between calls.

| Variable | Default | Meaning |
|---|---|---|
| `RUNTIME_GUARD_POSTURE` | _(none)_ | Preset: `tight`, `relaxed`, or `ci`. Individual numeric vars override the preset. |
| `RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB` | 2048 | Available RAM floor in MB. Pressure fires when available drops below this. |
| `RUNTIME_GUARD_MAX_SWAP_USED_PCT` | 85 | Swap ceiling in %. Pressure fires when swap usage exceeds this. |
| `RUNTIME_GUARD_CRITICAL_MEM_MB` | 1024 | Available RAM below this → CRITICAL severity (vs WARNING). |
| `RUNTIME_GUARD_CRITICAL_SWAP_PCT` | 95 | Swap above this → CRITICAL severity. |
| `RUNTIME_GUARD_SELF_INFLICTED_PCT` | 20 | Min % of total RAM this process must hold for self-inflicted attribution. |

### Threshold presets

| Posture | Min mem MB | Max swap % | Critical mem MB | Critical swap % | Self-inflicted % |
|---|---|---|---|---|---|
| `tight` | 2048 | 75 | 1024 | 90 | 15 |
| `relaxed` | 512 | 95 | 256 | 99 | 25 |
| `ci` | 1024 | 90 | 512 | 97 | 20 |

### Per-repo prefix

Avoid collisions when multiple repos share the same environment:

```python
guard = RuntimeGuard(env_prefix="MYAPP", log_tag="MyApp")
# reads MYAPP_MIN_MEM_AVAILABLE_MB, MYAPP_POSTURE, etc.
```

### Constructor parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `env_prefix` | `str` | `"RUNTIME_GUARD"` | Prefix for all environment variables. |
| `log_tag` | `str` | `"RuntimeGuard"` | Tag shown in human-readable log lines. |
| `cooldown_s` | `float` | `0.0` | Suppress repeat emissions within this many seconds. `0` = always emit. |
| `hints` | `list[str]` | `[]` | Repo-specific action strings appended to every pressure report. |
| `show_top_procs` | `bool` | `True` | Include top-RSS process table in log output. |

---

## CLI Reference

```bash
runtime-guard [OPTIONS]
python -m runtime_guard [OPTIONS]
```

With no options, prints a compact status line and exits 1 if pressure is detected.

| Flag | Description |
|---|---|
| `--snapshot` | Print a full memory snapshot with all fields. Exit 0. |
| `--check` | Check for pressure. Print report if found. **Exit 1 if pressure, 0 if healthy.** |
| `--report` | Print full WSL 2 system report (kernel params, memory, recommendations). |
| `--generate-wslconfig [MEM_GB]` | Generate `.wslconfig` content. Defaults to half of detected total RAM. |
| `--write PATH` | Write generated `.wslconfig` to PATH instead of printing. Backs up existing file. |
| `--posture {tight,relaxed,ci}` | Override threshold preset for this invocation. |
| `--stage STAGE` | Label for the check output (e.g. `--stage "data-load"`). |
| `--version` | Print package version and exit. |

### Examples

```bash
# CI gate — fail the job if memory is tight before the heavy test suite
runtime-guard --check --posture ci --stage "pre-test" || exit 1

# Print current snapshot for debugging
runtime-guard --snapshot

# Generate and apply a WSL 2 memory config
runtime-guard --generate-wslconfig 8 --write ~/.wslconfig

# Check version
runtime-guard --version
```

---

## API Reference

### `RuntimeGuard`

The main entry point. Construct once per process (or once per logical component).

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard(
    env_prefix="MY_PROJ",
    log_tag="MyProj",
    cooldown_s=30.0,
    hints=["Reduce batch size: --batch-size 256", "Run fewer workers: -n 2"],
    show_top_procs=True,
)
```

#### `check(stage="") → PressureReport | None`

Read current memory state. Returns a `PressureReport` when thresholds are exceeded, `None` otherwise.

```python
report = guard.check(stage="model-train")
if report:
    print(f"Pressure detected: {report.cause}")
    print(f"Critical: {report.is_critical}")
    print(f"Self-inflicted: {report.self_inflicted}")
    print(f"Missing MB: {report.missing_mem_mb}")
```

#### `log(report: PressureReport) → None`

Emit a structured log event. Also writes a compact JSON line to the `runtime_guard.events` logger.

#### `check_and_log(stage="") → PressureReport | None`

Convenience: calls `check()` then `log()` if pressure is found.

#### `intervene(...) → InterventionResult`

Attempt automatic mitigation: GC collection, page-cache drop, memory compaction, and optionally killing hog processes.

```python
result = guard.intervene(run_gc=True, drop_caches=True, compact_memory=False)
print(result.summary)   # "GC freed ~45 MB; page caches dropped"
```

#### `preflight_check(required_mb=0, ...) → None`

Assert minimum conditions before a heavy computation. Raises `MemoryError` if thresholds are not met.

```python
guard.preflight_check(required_mb=4096, stage="batch-inference")
```

#### `oom_protect(score=-500) → bool`

Write an OOM score adjustment to `/proc/self/oom_score_adj` (Linux only). Lower scores make the kernel less likely to kill this process under memory pressure.

```python
guard.oom_protect(score=-500)   # strongly protect this process from OOM killer
```

#### `memory_snapshot_mb() → tuple[int, int, int]`

Returns `(total_mb, available_mb, rss_mb)` directly, without triggering a `PressureReport`.

---

### `PressureReport`

Dataclass returned by `check()`.

| Field | Type | Description |
|---|---|---|
| `snapshot` | `MemSnapshot` | Raw memory numbers at check time. |
| `is_critical` | `bool` | `True` if below critical thresholds. |
| `cause` | `str` | Human-readable pressure cause string. |
| `self_inflicted` | `bool` | `True` if this process is the primary driver. |
| `self_pct` | `int` | This process's % of total system RAM. |
| `pid` | `int` | PID of the calling process. |
| `stage` | `str` | Stage label passed to `check()`. |
| `min_mem_mb` | `int` | Floor threshold that was applied. |
| `max_swap_pct` | `int` | Swap ceiling that was applied. |
| `missing_mem_mb` | `int` | How many MB below the floor. |
| `swap_excess_pct` | `int` | How many percentage points above the swap ceiling. |

---

### `MemSnapshot`

Raw memory values from the OS at a point in time.

| Field | Type | Description |
|---|---|---|
| `mem_total_mb` | `int` | Total physical RAM in MB. |
| `mem_available_mb` | `int` | Available (free + reclaimable) RAM in MB. |
| `swap_total_mb` | `int` | Total swap space in MB. |
| `swap_free_mb` | `int` | Free swap in MB. |
| `swap_used_pct` | `int` | Swap used as a percentage of total. |
| `rss_mb` | `int` | Resident Set Size of this process in MB. |
| `vm_swap_mb` | `int` | Swap consumed by this process in MB (Linux only). |

---

### Module-level functions

| Function | Description |
|---|---|
| `make_pytest_guard(**kwargs) → RuntimeGuard` | Return a `RuntimeGuard` configured for pytest environments. |
| `make_conftest_content(**kwargs) → str` | Generate a ready-to-use `conftest.py` string for pytest projects. |
| `attach_polars_guard(guard, stage="polars-collect", module=None) → Callable[[], None]` | Monkeypatch `polars.LazyFrame.collect` to run `guard.check_and_log()` before each collect call. Returns a restore function. |
| `attach_dask_guard(guard, stage="dask-compute", module=None) → Callable[[], None]` | Monkeypatch `dask.compute` (and `dask.persist` when present) to run `guard.check_and_log()` before each call. Returns a restore function. |
| `attach_ray_guard(guard, stage="ray-get", module=None) → Callable[[], None]` | Monkeypatch `ray.get` (and `ray.wait` when present) to run `guard.check_and_log()` before each call. Returns a restore function. |
| `generate_wslconfig(memory_gb, ...) → str` | Generate `.wslconfig` content (or write/merge to file). |
| `recommend_kernel_params(...) → list[KernelParamRecommendation]` | Return sysctl recommendations for WSL 2 memory tuning. |
| `apply_kernel_params(recommendations) → list[InterventionResult]` | Apply sysctl recommendations (requires root). |
| `wsl_system_report() → str` | Return a full formatted WSL 2 system diagnostics report. |

---

## Pytest Integration

Drop a `conftest.py` into your test root with one call:

```python
# conftest.py — generated by runtime-guard
from runtime_guard import make_conftest_content
print(make_conftest_content(posture="ci", stage="pytest"))
```

Or generate the file content and write it manually:

```python
from runtime_guard import make_conftest_content

content = make_conftest_content(
    posture="ci",
    stage="pytest",
    hints=["Use -x to stop on first failure", "Use -n 2 for fewer workers"],
)
with open("conftest.py", "w") as f:
    f.write(content)
```

This inserts a `check_memory_before_test` fixture that runs before every test and skips when memory is critically low, preventing OOM failures from masking the actual test result.

You can also use `make_pytest_guard()` directly in an existing `conftest.py`:

```python
import pytest
from runtime_guard import make_pytest_guard

_guard = make_pytest_guard(posture="ci", cooldown_s=60)

@pytest.fixture(autouse=True)
def _memory_gate():
    _guard.check_and_log(stage="pytest")
```

---

## Background Monitoring

Poll memory on a daemon thread between call sites:

```python
guard = RuntimeGuard(cooldown_s=60)
guard.start_background_check(interval_s=10.0)   # starts daemon thread

# ... your workload runs here ...

guard.stop_background_check()                    # clean shutdown
```

The background thread is **fork-safe**: after `os.fork()`, the child process gets a clean state with no active thread. Call `start_background_check()` again in the child if needed.

---

## WSL 2 Utilities

### System report

```python
from runtime_guard import wsl_system_report
print(wsl_system_report())
```

Or from the CLI:

```bash
runtime-guard --report
```

### Kernel parameter recommendations

```python
from runtime_guard import recommend_kernel_params, apply_kernel_params

recs = recommend_kernel_params()
for r in recs:
    if r.changed:
        print(f"  {r.sysctl_command}   # {r.reason}")

# Apply (requires root / sudo):
apply_kernel_params(recs)
```

### Generate `.wslconfig`

```python
from runtime_guard import generate_wslconfig

# Dry run — returns the content as a string
content = generate_wslconfig(memory_gb=8)
print(content)

# Write and merge — backs up existing file, preserves custom keys
generate_wslconfig(memory_gb=8, output_path="~/.wslconfig", dry_run=False)
```

---

## Architecture

```
runtime_guard/
├── _read_snapshot()          # dispatch: Linux → _read_linux(), macOS → _read_macos(), Windows → _read_windows()
├── RuntimeGuard
│   ├── check()               # threshold evaluation → PressureReport | None
│   ├── log()                 # human log + JSON event on runtime_guard.events
│   ├── intervene()           # GC, cache drop, compaction, kill
│   ├── preflight_check()     # assert-style guard for heavy computations
│   ├── oom_protect()         # write /proc/self/oom_score_adj
│   └── start/stop_background_check()  # daemon thread, fork-safe
├── PressureReport            # dataclass — what was found and why
├── MemSnapshot               # dataclass — raw OS memory values
├── make_pytest_guard()       # preconfigured guard for test environments
├── make_conftest_content()   # generates a ready-to-use conftest.py
├── generate_wslconfig()      # safe merge write to ~/.wslconfig
├── recommend_kernel_params() # sysctl tuning for WSL 2
├── apply_kernel_params()     # apply recommendations (root)
└── wsl_system_report()       # full diagnostic report string
```

### Data flow

```
OS (/proc, vm_stat, PowerShell)
    ↓  _read_snapshot()
  MemSnapshot
    ↓  RuntimeGuard.check()
  PressureReport            ← threshold comparison + attribution
    ↓  RuntimeGuard.log()
  logging.WARNING/CRITICAL  ← human-readable
  runtime_guard.events      ← structured JSON (machine-readable)
```

### Attribution logic

1. Read `rss_mb` (this process's RSS) and `mem_total_mb` from the OS.
2. Compute `self_pct = (rss_mb / mem_total_mb) * 100`.
3. If `self_pct ≥ self_inflicted_pct` (default 20 %) **and** available memory is below the floor → `self_inflicted = True`.
4. Self-inflicted reports include PID-specific commands (`pmap -x <pid>`, `py-spy`). External reports include host-wide commands (`ps aux --sort=-%mem`).

---

## FAQ

**Q: Does this work inside Docker/containers?**  
A: Yes. On Linux it reads `/proc/meminfo`, which reflects the host's memory (not cgroup limits). Container-aware memory limits (cgroup v2) are planned for Milestone 1 (M1-C06).

**Q: Does it require `root` or `sudo`?**  
A: No, for normal `check()` / `log()` usage. `apply_kernel_params()` and `oom_protect()` write to protected paths and do require elevated privileges (or `CAP_SYS_ADMIN`).

**Q: Can I use it with `asyncio`?**  
A: Yes. `check()` and `log()` are synchronous and do not block the event loop for significant time (sub-millisecond on Linux). For structured async spans, `async with guard.phase("load-csv")` is planned for M1-C08.

**Q: Why does `check()` return `None` on macOS/Windows when memory is clearly low?**  
A: The macOS and Windows snapshot readers are best-effort approximations. If subprocess calls to `vm_stat`/`sysctl`/PowerShell fail, the snapshot is zero-filled and no pressure is reported. Check the `runtime_guard` logger at `DEBUG` level for subprocess errors.

**Q: How do I suppress the "top processes" table in log output?**  
A: Pass `show_top_procs=False` to the constructor: `RuntimeGuard(show_top_procs=False)`.

**Q: What is the performance overhead?**  
A: On Linux, `_read_snapshot()` reads two `/proc` files and does a small `ps -o rss=` call — typically under 5 ms. The `ps` call is the only subprocess invocation on Linux and can be eliminated with `show_top_procs=False` for latency-sensitive code paths.

**Q: Can I use it in a forked process (multiprocessing)?**  
A: Yes. `os.register_at_fork()` ensures the child process gets a clean background-thread state after `fork()`. Call `start_background_check()` again in the child if you need it there.

**Q: How do I integrate with Prometheus or OpenTelemetry?**  
A: Log the `runtime_guard.events` logger output (structured JSON) into your aggregation pipeline today. Native OTEL and Prometheus exporters are planned for Milestone 1 (M1-C04, M1-C05).

---

## Contributing

See [ROADMAP.md](ROADMAP.md) for planned features, [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for open defects, and [RESEARCH.md](RESEARCH.md) for academic research directions. Maintenance cadences are defined in [MAINTENANCE.md](MAINTENANCE.md).

```bash
# Run tests
pytest tests/ -q

# Lint
ruff check src/

# Security scan
bandit -r src/
```

## License

MIT — see [LICENSE](LICENSE) for the full text.
