# runtime-guard

**Attribution-aware resource-pressure monitor for any Python project.**

Instead of a generic "memory is low" alert, runtime-guard tells you _which side_ the pressure is on — _this process_ or _something else on the host_ — and surfaces actionable guidance pre-filled with your PID and process name.

- **Zero runtime dependencies** — pure Python stdlib; no NumPy, psutil, or similar required.
- **Cross-platform** — `/proc/meminfo` on Linux, `vm_stat`/`sysctl` on macOS, PowerShell `Get-CimInstance` on Windows (with `wmic` fallback).
- **Structured JSON events** — machine-readable emissions on the `runtime_guard.events` logger for log aggregation pipelines.
- **Threshold presets** — `tight`, `relaxed`, and `ci` bundles for instant configuration.
- **CLI first-class** — `runtime-guard --check` integrates cleanly into shell scripts, CI gates, and health-check loops.

## Table of Contents

1. [Install](#install)
2. [Quickstart](#quickstart)
3. [Configuration](#configuration)
4. [CLI Reference](#cli-reference)
5. [API Reference](#api-reference)
6. [Pytest Integration](#pytest-integration)
7. [Background Monitoring](#background-monitoring)
8. [WSL 2 Utilities](#wsl-2-utilities)
9. [Framework Integration](#framework-integration)
10. [Enterprise Adoption](#enterprise-adoption)
11. [Team Adoption Guide](#team-adoption-guide)
12. [Architecture](#architecture)
13. [FAQ](#faq)

---

## Install

```bash
pip install git+https://github.com/tom-stening/runtime-guard.git
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
| `RUNTIME_GUARD_POSTURE` | _(none)_ | Preset: `tight`, `relaxed`, `ci`, or `wsl_dev`. Individual numeric vars override the preset. |
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
| `wsl_dev` | 256 | 97 | 128 | 99 | 10 |

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
| `--verify-audit-log PATH` | Verify audit hash-chain integrity at PATH. **Exit 0 if valid, 1 if invalid.** |
| `--audit-policy-taxonomy` | Print the audit policy taxonomy catalog (`severity`, `category`, `action`) as JSON. |
| `--report` | Print full WSL 2 system report (kernel params, memory, recommendations). |
| `--generate-wslconfig [MEM_GB]` | Generate `.wslconfig` content. Defaults to half of detected total RAM. |
| `--write PATH` | Write generated `.wslconfig` to PATH instead of printing. Backs up existing file. |
| `--policy-file PATH` | Load threshold/posture overrides from a JSON policy file. |
| `--policy-auto-reload` | Re-read `--policy-file` when it changes (for repeated/default check workflows). |
| `--posture {tight,relaxed,ci,wsl_dev}` | Override threshold preset for this invocation. |
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

# Import the community Grafana dashboard template (M1-I04)
# file: examples/grafana/runtime_guard_dashboard.json
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
| `attach_polars_guard(guard, stage="polars-collect", module=None) → Callable[[], None]` | Monkeypatch `polars.LazyFrame.collect` (and `fetch` when present) to run `guard.check_and_log()` before each call. Returns a restore function. |
| `validate_polars_integration(guard, stage="polars-collect", module=None) → dict[str, Any]` | Validate that Polars integration is correctly installed and functional. Used for M1-I01 adoption evidence collection. |
| `collect_polars_integration_evidence(guard, stage="polars-collect", module=None, version_info=None) → dict[str, Any]` | Collect integration readiness evidence compatible with ADOPTION_TRACKER.md. Records validation status, versions, and available hooks. |
| `attach_dask_guard(guard, stage="dask-compute", module=None) → Callable[[], None]` | Monkeypatch `dask.compute`/`dask.persist` plus `dask.base.compute`/`dask.base.persist` when present to run `guard.check_and_log()` before each call. Returns a restore function. |
| `validate_dask_integration(guard, stage="dask-compute", module=None) → dict[str, Any]` | Validate that Dask integration is correctly installed and functional. Used for M1-C02 adoption evidence collection. |
| `collect_dask_integration_evidence(guard, stage="dask-compute", module=None, version_info=None) → dict[str, Any]` | Collect integration readiness evidence compatible with ADOPTION_TRACKER.md. Records validation status, versions, and available hooks. |
| `attach_ray_guard(guard, stage="ray-get", module=None) → Callable[[], None]` | Monkeypatch `ray.get` plus `ray.wait`/`ray.put` when present to run `guard.check_and_log()` before each call. Returns a restore function. |
| `validate_ray_integration(guard, stage="ray-get", module=None) → dict[str, Any]` | Validate that Ray integration is correctly installed and functional. Used for M1-C03 adoption evidence collection. |
| `collect_ray_integration_evidence(guard, stage="ray-get", module=None, version_info=None) → dict[str, Any]` | Collect integration readiness evidence compatible with ADOPTION_TRACKER.md. Records validation status, versions, and available hooks. |
| `pressure_report_attributes(report) → dict[str, Any]` | Convert a `PressureReport` into OpenTelemetry-friendly flat attributes. |
| `trace_context_attributes(span=None, module=None, prefix="runtime_guard.trace") → dict[str, Any]` | Extract trace/span IDs from current/provided OTEL span for linking RuntimeGuard events with distributed traces. |
| `emit_otel_event(report, event_name="runtime_guard.pressure", span=None, module=None) → bool` | Emit a pressure event on the current OpenTelemetry span (or provided span). Returns `True` when emitted. |
| `render_prometheus_metrics(report, prefix="runtime_guard") → str` | Render a `PressureReport` as Prometheus exposition text for HTTP `/metrics` endpoints. |
| `validate_runtime_guard_config(config, use_pydantic=True) → dict[str, Any]` | Validate RuntimeGuard threshold/posture config with optional pydantic schema support and strict fallback validation. |
| `attach_signal_recovery(guard, ...) → Callable[[], None]` | Install signal handlers that run a final pressure check/log (and optional intervention), returning a restore function. |
| `resolve_signal_recovery_policy(env_prefix="RUNTIME_GUARD") → dict[str, Any]` | Resolve signal-recovery rollout settings from environment variables. |
| `install_signal_recovery_from_policy(guard, env_prefix="RUNTIME_GUARD") → Callable[[], None]` | Install signal recovery directly from environment-resolved policy defaults. |
| `audit_policy_taxonomy() → dict[str, list[str]]` | Return allowed severity/category/action vocab for policy-violation audit events. |
| `normalize_policy_violation_event(event) → dict[str, Any]` | Canonicalize policy-violation event fields to standardized taxonomy tokens. |
| `append_audit_log(path, event, hash_algo='sha256', deduplicator=None) → dict[str, Any]` | Append a tamper-evident (hash-chained) JSON record to an audit log file; when a deduplicator is provided, duplicate events are skipped with `{"skipped": true}`. |
| `fips_event_hash(payload, hash_algo="sha256") → str` | Hash payloads with FIPS-approved SHA-2 algorithms (`sha256`, `sha384`, `sha512`). |
| `verify_audit_log_chain(path) → dict[str, Any]` | Verify hash-chain integrity for audit logs and report first failing line/reason. |
| `soc2_required_controls() → dict[str, str]` | Return runtime-guard's default SOC2 control baseline (CC6.1, CC7.1, CC7.2). |
| `soc2_gap_assessment(control_state, required_controls=None) → dict[str, Any]` | Summarize SOC2 coverage, missing required controls, and unknown control IDs. |
| `soc2_evidence_requirements(required_controls=None) → dict[str, list[str]]` | Return expected evidence artifact IDs for tracked SOC2 controls. |
| `soc2_readiness_report(control_state, evidence_state=None, ...) → dict[str, Any]` | Evaluate SOC2 readiness with both control coverage and evidence completeness ratios. |
| `build_adoption_scorecard(team_records, success_stage="production") → dict[str, Any]` | Summarize multi-team adoption progress and flag teams missing evidence for audit. |
| `make_worker_report(guard, ...) → dict[str, Any]` | Build a process-local worker pressure report for parent-process orchestration. |
| `aggregate_worker_reports(reports) → dict[str, Any]` | Aggregate worker reports into pool/job-queue summary metrics and worst severity. |
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

### Automatic background service (Linux, systemd --user)

Use the repository watcher script to run checks only while the repo has active
processes (detected via `/proc/*/cwd`).

1. Ensure runtime-guard is installed in the repo environment:

```bash
cd /path/to/repo
python -m pip install -e .
```

2. Copy service template and create instance env:

```bash
mkdir -p ~/.config/systemd/user ~/.config/runtime-guard
cp scripts/systemd/runtime-guard-repo@.service ~/.config/systemd/user/
cp scripts/systemd/runtime-guard-repo.env.example ~/.config/runtime-guard/my-repo.env
```

3. Edit `~/.config/runtime-guard/my-repo.env`:
- `PYTHON_BIN` to the repo venv Python.
- `WATCHER_SCRIPT` to `scripts/runtime_guard_repo_watcher.py` absolute path.
- `REPO_PATH` to the repository root.

4. Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable --now runtime-guard-repo@my-repo.service
systemctl --user status runtime-guard-repo@my-repo.service
```

5. View logs:

```bash
journalctl --user -u runtime-guard-repo@my-repo.service -f
```

Notes:
- Current watcher implementation targets Linux `/proc` environments.
- Checks are skipped while repo is idle to reduce overhead.
- For highest attribution fidelity, keep in-process checks in app/test entrypoints as well.

### Seed Repo Autostart (sitecustomize)

For repo-local Python startup autowiring (without editing application code),
seed a `sitecustomize.py` file:

```bash
python scripts/seed_repo_autorun.py --repo-path /path/to/target-repo
```

What this does:
- Writes `/path/to/target-repo/sitecustomize.py`
- Auto-starts `RuntimeGuard.start_background_check(...)` in Python processes
    launched from that repo
- Allows runtime disable via `RUNTIME_GUARD_AUTOSTART=0`

Override defaults:

```bash
python scripts/seed_repo_autorun.py \
    --repo-path /path/to/target-repo \
    --stage repo-autostart \
    --interval-s 20 \
    --cooldown-s 15 \
    --env-prefix RUNTIME_GUARD
```

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

## Framework Integration

Runtime-guard integrates seamlessly with popular data and ML frameworks. Choose your framework for detailed integration patterns, demos, and adoption guides:

### Polars

**Best for:** Data loading, transformation, and interactive data science  
**Integration:** Lazy-frame collection hooks, streaming mode  
**Demo:** `python examples/polars_integration_demo.py`  
**Guide:** [INTEGRATION_POLARS.md](INTEGRATION_POLARS.md)

```python
from runtime_guard import RuntimeGuard, attach_polars_guard
import polars as pl

guard = RuntimeGuard()
attach_polars_guard(guard, stage="polars-collect")

# Guard activates before .collect() materializes large frames
df = pl.read_csv("data.csv").lazy()
result = df.filter(pl.col("value") > 0).collect()  # guarded
```

### Dask

**Best for:** Distributed data engineering, out-of-core operations  
**Integration:** Scheduler callbacks, per-worker monitoring  
**Demo:** `python examples/dask_integration_demo.py`

```python
from runtime_guard import RuntimeGuard, attach_dask_guard, install_dask_scheduler_callbacks
import dask.dataframe as dd

guard = RuntimeGuard()
attach_dask_guard(guard, stage="dask-compute")
get_worker_report = install_dask_scheduler_callbacks(guard)

# Guard monitors scheduler callbacks; per-worker pressure tracked
df = dd.read_csv("data.csv")
result = df.groupby("category").value.sum().compute()
report = get_worker_report()  # per-worker memory metrics
```

### Ray

**Best for:** ML training, distributed computing, actor-based services  
**Integration:** Remote function wrappers, actor method decorators  
**Demo:** `python examples/ray_integration_demo.py`

```python
from runtime_guard import RuntimeGuard, attach_ray_guard, enable_ray_actor_memory_monitoring
import ray

guard = RuntimeGuard()
attach_ray_guard(guard, stage="ray-get")
actor_config = enable_ray_actor_memory_monitoring(guard)

@ray.remote
class Trainer:
    @actor_config["method_decorator"]
    def train_step(self, data):
        return len(data)  # memory check before execution

trainer = Trainer.remote()
result = ray.get(trainer.train_step.remote([1, 2, 3]))
```

### Unified Framework Handbook

For organizations deploying across multiple frameworks, see [FRAMEWORK_INTEGRATION_HANDBOOK.md](FRAMEWORK_INTEGRATION_HANDBOOK.md) for:

- Architecture decisions (single guard vs. per-framework guards)
- Deployment patterns (application startup, pytest integration)
- 4-phase rollout (local dev → CI → staging → production)
- Environment variable quick reference
- Troubleshooting guide

---

## Enterprise Adoption

### For enterprises scaling across teams

**[ENTERPRISE_ADOPTION_GUIDE.md](ENTERPRISE_ADOPTION_GUIDE.md)** provides:

- 5-phase adoption roadmap (8 weeks: assessment → pilot → CI → staging → production)
- SOC2 compliance mapping and evidence collection
- Team training agenda and incident response runbooks
- KPI tracking and adoption scorecard
- Docker/Kubernetes deployment examples
- Escalation paths and support resources

### Operations and compliance

- **[OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md)** — Production deployment, systemd templates, dynamic policy reload, monitoring integration
- **[AUDIT_POLICY_EXAMPLES.md](AUDIT_POLICY_EXAMPLES.md)** — Real-world policy templates for data engineering, ML training, and multi-tenant SaaS
- **[ADOPTION_TRACKER.md](ADOPTION_TRACKER.md)** — Scorecard API and progress tracking

---

## Enterprise Support

Enterprise-facing support scope, severity definitions, response targets, and
incident runbook entry points are documented in
[ENTERPRISE_SUPPORT.md](ENTERPRISE_SUPPORT.md).

Production deployment steps, systemd examples, logging integration, metrics
export, and live policy reload procedures are documented in
[OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md).

SOC2 readiness can be generated from control/evidence JSON inputs with:

```bash
python scripts/soc2_readiness_report.py \
    --controls examples/soc2_controls_example.json \
    --evidence examples/soc2_evidence_example.json \
    --fail-on-gaps

# Optional: scope readiness to a specific required-controls file
python scripts/soc2_readiness_report.py \
    --controls controls.json \
    --evidence evidence.json \
    --required-controls required_controls.json
```

---

## Team Adoption Guide

### Why adopt runtime-guard?

When a Python process hits memory limits, teams don't know: **Is my code leaking memory, or is the system under pressure?** This distinction is critical for:

- **Debugging OOM crashes** — identify whether to optimize code or ask ops for more resources
- **CI/CD reliability** — avoid flaky test failures due to system pressure
- **Production stability** — alert on actionable memory issues before kernel OOM killer strikes
- **Cost optimization** — right-size infrastructure based on *actual* demand vs. *system* demand

### Adoption stages

Follow this 4-stage rollout to integrate runtime-guard safely into your workflow:

#### Stage 1: Developer snapshot (local dev)

**Goal:** Understand your code's memory footprint.

```python
# In your training script, inference pipeline, or data-load code:
from runtime_guard import RuntimeGuard

# Set env: RUNTIME_GUARD_POSTURE=tight
guard = RuntimeGuard()

# Before heavy workload
guard.check_and_log(stage="before-train")

# ... your model training / data processing ...

# After workload
guard.check_and_log(stage="after-train")
```

**Or from command line:**

```bash
RUNTIME_GUARD_POSTURE=tight python train.py
```

**Validation:** Check that logs appear in `stderr` during development. If memory is tight during development, you'll see reports like:
```json
{"timestamp": "...", "stage": "before-train", "cause": "Low available RAM", "self_inflicted": false, ...}
```

#### Stage 2: CI/CD gate (test & build pipelines)

**Goal:** Fail builds early if system memory is insufficient.

```bash
# In your CI config (GitHub Actions, CircleCI, etc.):
before_test_step:
  - runtime-guard --check --posture ci --stage "pre-test" || exit 1
  - pytest tests/
```

**Or** gate within Python test setup:

```python
# conftest.py
from runtime_guard import make_pytest_guard

_guard = make_pytest_guard(posture="ci", cooldown_s=60.0)

@pytest.fixture(autouse=True)
def _memory_gate():
    _guard.check_and_log(stage="test")
```

**Or use environment variables:**

```bash
export RUNTIME_GUARD_POSTURE=ci
pytest tests/  # guard automatically checks before tests
```

**Validation:** Run with `--stage "pre-test"` manually to confirm exit codes:
- Exit 0 = healthy (tests should run)
- Exit 1 = memory pressure (tests skipped automatically)

#### Stage 3: Staging environment (background monitoring)

**Goal:** Detect memory creep and OOM risks in realistic workloads.

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard(cooldown_s=30.0)
guard.start_background_check(interval_s=10.0)  # check every 10 seconds

# Long-running job:
for batch in data_batches:
    process_batch(batch)  # guard emits warnings if pressure rises

guard.stop_background_check()
```

**Or set environment:**

```bash
RUNTIME_GUARD_POSTURE=relaxed python long_job.py
```

**Validation:** Check application logs for structured JSON events on `runtime_guard.events` logger. Example:

```json
{"timestamp": "2025-01-15T10:23:45Z", "stage": "batch-inference", "missing_mem_mb": 512, "self_inflicted": true}
```

#### Stage 4: Production (adoption metrics & compliance)

**Goal:** Measure adoption success and compliance posture.

Once runtime-guard is deployed across your team, measure success using the **adoption scorecard**:

```python
from runtime_guard import build_adoption_scorecard

team_records = [
    {"team": "data-eng", "stage": "staging", "evidence": ["validated", "incidents:0"]},
    {"team": "ml-infra", "stage": "production", "evidence": ["validated", "incidents:2"]},
    {"team": "analytics", "stage": "ci-only", "evidence": ["validated"]},
]

scorecard = build_adoption_scorecard(team_records, success_stage="production")
print(scorecard)
# Output:
# {
#   "total_teams": 3,
#   "reached_success_stage": 1,
#   "adoption_ratio": 0.333,
#   "stage_counts": {"ci_only": 1, "staging": 1, "production": 1, ...},
#   "status": "in-progress",
#   "missing_evidence_teams": ["analytics"],
# }
```

Or use the CLI tool:

```bash
# team_adoption.json:
[
  {"team": "data-eng", "stage": "staging", "evidence": ["validated"]},
  {"team": "ml-infra", "stage": "production", "evidence": ["validated"]},
]

python scripts/adoption_scorecard.py \
    --input team_adoption.json \
  --success-stage production \
  --output scorecard.json

# Validate ADOPTION_TRACKER.md against M2-I02 criteria
python scripts/adoption_tracker_report.py \
    --tracker ADOPTION_TRACKER.md \
    --fail-on-gaps \
    --output tracker_report.json
```

**Validation:** Scorecard shows:
- Teams deployed and validated (`reached_success_stage` teams at target stage)
- % of teams reaching "production" stage (target: 80%+ → `adoption_ratio >= 0.8`)
- Audit trail for compliance / SOC2 evidence (`missing_evidence_teams` should be empty)

### Integration validation

After attaching runtime-guard to your framework (Polars, Dask, Ray), validate the integration:

```python
from runtime_guard import (
    RuntimeGuard,
    attach_polars_guard,
    validate_polars_integration,
    collect_polars_integration_evidence,
)

guard = RuntimeGuard()
restore = attach_polars_guard(guard)

# Verify integration succeeded
validation = validate_polars_integration(guard)
assert validation["ok"], f"Integration failed: {validation['errors']}"

# Collect adoption evidence
evidence = collect_polars_integration_evidence(guard)
print(f"Integration validated: {evidence['validation_ok']}")
print(f"Hook methods available: {evidence['evidence_items']}")
# Output: ['polars_integration_validated', 'polars_hooks_installed', 'collect_present', ...]
```

**Framework guides:**
- Polars: [INTEGRATION_POLARS.md](INTEGRATION_POLARS.md)
- Dask: [.github/ISSUE_TEMPLATE/dask-memory-diagnostics.yml](.github/ISSUE_TEMPLATE/dask-memory-diagnostics.yml)
- Ray: [INTEGRATION_RAY.md](INTEGRATION_RAY.md)

### Measuring success

**Baseline metrics to track:**

| Metric | Target | How to measure |
|---|---|---|
| Teams deployed | 5+ | Use `build_adoption_scorecard()` → `total_teams` |
| Teams at "production" stage | 80%+ | `adoption_ratio >= 0.8` |
| Incident response time | <1h | Audit log verification: `runtime-guard --verify-audit-log` |
| False positive rate | <5% | Ratio of "self_inflicted=false" events to total events |
| Memory savings (if intervening) | 5%+ | Sum of intervention results: `result.gc_freed_mb + result.cache_dropped_mb` |

---

## Framework Integration Guides

- Polars: [INTEGRATION_POLARS.md](INTEGRATION_POLARS.md)
- Dask triage template: [.github/ISSUE_TEMPLATE/dask-memory-diagnostics.yml](.github/ISSUE_TEMPLATE/dask-memory-diagnostics.yml)
- Ray cookbook: [INTEGRATION_RAY.md](INTEGRATION_RAY.md)

## Enablement

- Training and certification draft: [TRAINING_CURRICULUM.md](TRAINING_CURRICULUM.md)
- Certification rubric evaluation: `python scripts/training_certification_report.py --attendees attendees.json --fail-on-gaps --output certification_report.json`

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
A: Yes. `check()` and `log()` are synchronous and do not block the event loop for significant time (sub-millisecond on Linux). You can also use phase-scoped checks with `async with guard.phase("load-csv")` (and synchronous `with guard.phase(...)`).

**Q: Why does `check()` return `None` on macOS/Windows when memory is clearly low?**  
A: The macOS and Windows snapshot readers are best-effort approximations. If subprocess calls to `vm_stat`/`sysctl`/PowerShell fail, the snapshot is zero-filled and no pressure is reported. Check the `runtime_guard` logger at `DEBUG` level for subprocess errors.

**Q: How do I suppress the "top processes" table in log output?**  
A: Pass `show_top_procs=False` to the constructor: `RuntimeGuard(show_top_procs=False)`.

**Q: Can thresholds be reloaded without restarting the process?**  
A: Yes. Use `guard.load_policy_file("/path/policy.json", auto_reload=True)` and RuntimeGuard will refresh policy values when file mtime changes. Precedence is `environment variables > policy file > posture preset`.

**Q: What is the performance overhead?**  
A: On Linux, `_read_snapshot()` reads two `/proc` files and does a small `ps -o rss=` call — typically under 5 ms. The `ps` call is the only subprocess invocation on Linux and can be eliminated with `show_top_procs=False` for latency-sensitive code paths.

**Q: Can I use it in a forked process (multiprocessing)?**  
A: Yes. `os.register_at_fork()` ensures the child process gets a clean background-thread state after `fork()`. Call `start_background_check()` again in the child if you need it there.

**Q: How do I integrate with Prometheus or OpenTelemetry?**  
A: Use `install_prometheus_endpoint()` (or `render_prometheus_metrics()`) for Prometheus scraping and `install_otel_memory_exporter()` for OpenTelemetry span emission. A starter Grafana dashboard JSON is available at `examples/grafana/runtime_guard_dashboard.json` with sample exposition data in `examples/grafana/sample_metrics.prom`.

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

---

## Multi-Process Orchestration Example

To aggregate memory pressure across a process pool or job queue, each worker writes a report and the parent aggregates results:

```python
# examples/multiprocess_pool_guard_demo.py
from runtime_guard import RuntimeGuard, make_worker_report, append_worker_report_jsonl, aggregate_worker_reports_jsonl

# In each worker:
guard = RuntimeGuard()
report = make_worker_report(guard, stage="worker", worker_id=str(worker_id))
append_worker_report_jsonl("/tmp/worker_guard_reports.jsonl", report)

# In the parent:
summary = aggregate_worker_reports_jsonl("/tmp/worker_guard_reports.jsonl")
print(summary)
```

See the full demo: [examples/multiprocess_pool_guard_demo.py](examples/multiprocess_pool_guard_demo.py)

For parent-side aggregation from a JSONL worker transport file:

```bash
python scripts/aggregate_workers.py --input /tmp/worker_guard_reports.jsonl --pretty
```

To gate CI or orchestration on pressure:

```bash
# Exit 1 if any worker reported warning or critical pressure
python scripts/aggregate_workers.py --input /tmp/worker_guard_reports.jsonl --fail-on-pressure

# Exit 1 only on critical pressure (default recommended gate)
python scripts/aggregate_workers.py --input /tmp/worker_guard_reports.jsonl --fail-on-critical
```
