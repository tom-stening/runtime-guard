# Dask Integration Guide

This guide operationalizes roadmap item M1-C02 and M1-I02:
"Dask integration plugin and issue template integration".

## Integration Goal

Enable Dask-based data pipelines to detect memory pressure at compute boundaries
with full scheduler callback attribution, detailed worker telemetry, and low
adoption friction across distributed and local schedulers.

## Recommended Hook Strategy

Use `attach_dask_guard()` during application startup with optional scheduler
callbacks:

```python
from runtime_guard import RuntimeGuard, attach_dask_guard
import dask

guard = RuntimeGuard(cooldown_s=30.0, log_tag="DaskPipeline")
restore = attach_dask_guard(
    guard,
    stage="dask-compute",
    enable_scheduler_callbacks=True
)
```

The hook guards:
- `dask.compute()` — top-level compute calls
- `dask.base.persist()` — DataFrame and delayed persist
- Scheduler callbacks for worker-level telemetry (when available)

## Suggested Default Threshold Profile

For data engineering environments:
- start with posture `tight` for pre-prod and CI
- use posture `relaxed` for exploratory notebooks
- define explicit env var overrides in production

Example:

```bash
export RUNTIME_GUARD_POSTURE=tight
export RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB=2048
export RUNTIME_GUARD_MAX_SWAP_USED_PCT=75
export DASK_NUM_WORKERS=4
```

## Task Graph Guard (Optional Advanced)

Optionally enforce hard/soft caps on task graph complexity:

```python
from runtime_guard import install_dask_task_graph_guard

guard = RuntimeGuard(log_tag="DaskGraph")
install_dask_task_graph_guard(
    guard,
    warn_at=50000,  # soft cap: warn-log
    fail_at=100000  # hard cap: raise
)
```

## Adoption Readiness Checklist

- RuntimeGuard initialization is centralized (single startup path).
- Structured events are routed from `runtime_guard.events` logger.
- A fallback procedure exists to call the restore hook if needed.
- At least one load test validates compute/persist overhead.
- Scheduler callbacks emit per-worker telemetry when enabled.
- Pressure incidents include captured stage labels and worker attribution.
- Task graph size guards are configured if task explosion is a concern.

## Validation Steps

1. Run representative Dask workload with synthetic distributed pressure.
2. Confirm event emission and worker attribution across schedulers.
3. Verify cooldown behavior does not suppress critical incidents.
4. Confirm scheduler telemetry fields (`total_tasks`, `total_completed_tasks`,
   `total_healthy_events`, `total_pressure_events`) are emitted.
5. Verify restore path cleanly reverts monkeypatches.
6. Record outcome and baseline metrics in adoption tracker.

## Rollout Recommendation

- Phase 1: Local scheduler in CI/staging with synthetic pressure.
- Phase 2: Distributed scheduler (Kubernetes/YARN) in staging.
- Phase 3: One production workload with active monitoring.
- Phase 4: Default enablement for Dask data services.

## Evidence to Capture

- RuntimeGuard version and pipeline revision.
- Before/after incident triage time.
- Number of pressure alerts and false positive rate.
- Sample event payloads with worker attribution.
- Task graph size distribution (if guard enabled).
- Per-worker pressure reports during incidents.
- Scheduler type (local, distributed, threaded, etc.).

## Example 1: Basic compute guard with local scheduler

```python
from runtime_guard import RuntimeGuard, attach_dask_guard
import dask.dataframe as dd

guard = RuntimeGuard(log_tag="DaskBasic", cooldown_s=20.0)
restore = attach_dask_guard(guard, stage="dask-compute")

# Build lazy computation
df = dd.read_csv("s3://bucket/data-*.csv")
result = df.groupby("category").sum().compute()

restore()
```

## Example 2: Distributed scheduler with worker telemetry

```python
from runtime_guard import RuntimeGuard, attach_dask_guard
from dask.distributed import Client

guard = RuntimeGuard(log_tag="DaskDistributed", cooldown_s=30.0)

with Client("tcp://scheduler:8786") as client:
    restore = attach_dask_guard(
        guard,
        stage="dask-distributed",
        enable_scheduler_callbacks=True
    )
    
    # Run computation; scheduler telemetry automatically captured
    result = client.compute(delayed_work)
    
    restore()
```

## Example 3: Stage-scoped phases in orchestration

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard(log_tag="DaskStages", cooldown_s=20.0)

with guard.phase("dask-build"):
    # build task graph
    pass

with guard.phase("dask-compute"):
    # compute with guards
    pass

with guard.phase("dask-write"):
    # persist results
    pass
```

## Example 4: Task graph guard for explosion prevention

```python
from runtime_guard import RuntimeGuard, install_dask_task_graph_guard
import dask.dataframe as dd

guard = RuntimeGuard(log_tag="DaskGraphGuard")
install_dask_task_graph_guard(guard, fail_at=50000)

try:
    # This might build a very large graph
    df = dd.read_csv("large-*.csv").map_partitions(expensive_transform)
    result = df.compute()
except RuntimeError as e:
    guard.log(f"Task graph too large: {e}")
```

## Example 5: Audit trail for memory incidents

```python
from runtime_guard import RuntimeGuard, attach_dask_guard
import dask

guard = RuntimeGuard(log_tag="DaskAudit")
restore = attach_dask_guard(guard, stage="dask-critical")

try:
    result = dask.compute(work1, work2, work3)
finally:
    report = guard.check(stage="dask-post-compute")
    if report is not None:
        guard.log(report)
        guard.audit(
            report,
            path="./dask-pressure-audit.log",
            action="dask-pressure"
        )
    restore()
```

## Integration with CI

Add to your CI pipeline to catch memory regressions:

```bash
#!/bin/bash
set -e

export RUNTIME_GUARD_POSTURE=tight
export RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB=1024
export RUNTIME_GUARD_MAX_SWAP_USED_PCT=50

python -m pytest tests/dask_workflows_test.py -v \
  --runtime-guard-fail-on-pressure
```

## Troubleshooting

### "No scheduler callbacks captured"

- Confirm `enable_scheduler_callbacks=True` in `attach_dask_guard()`
- Some schedulers (e.g., `synchronous`) don't support callbacks; fallback telemetry still applies
- Check `validate_dask_integration.py --check-scheduler-api` to verify capability

### "Task graph guard not firing"

- Verify `install_dask_task_graph_guard()` was called before compute
- Check `fail_at` threshold; very large graphs may need higher limits
- Use custom `task_count_fn` if your task counting differs from default

### "Memory pressure not detected"

- Ensure `RuntimeGuard(...)` was initialized before attachment
- Verify `stage` label matches your monitoring queries
- Check that `/proc` or `vm_stat` is readable (permission/platform issues)
