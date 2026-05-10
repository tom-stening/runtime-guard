# Polars Integration Guide

This guide operationalizes roadmap item M1-I01:
"Polars adopts runtime-guard as default memory monitor in recommended libraries."

## Integration Goal

Enable Polars-heavy pipelines to detect memory pressure at query materialization
boundaries, with actionable attribution and low adoption friction.

## Recommended Hook Strategy

Use `attach_polars_guard()` during application startup:

```python
from runtime_guard import RuntimeGuard, attach_polars_guard

guard = RuntimeGuard(cooldown_s=30.0, log_tag="PolarsPipeline")
restore = attach_polars_guard(guard, stage="polars-materialize")
```

The hook guards:
- `LazyFrame.collect()`
- `LazyFrame.fetch()` when available

## Suggested Default Threshold Profile

For data engineering environments:
- start with posture `tight` for pre-prod and CI
- use posture `relaxed` for exploratory notebooks
- define explicit env var overrides in production

Example:

```bash
export RUNTIME_GUARD_POSTURE=tight
export RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB=4096
export RUNTIME_GUARD_MAX_SWAP_USED_PCT=80
```

## Adoption Readiness Checklist

- RuntimeGuard initialization is centralized (single startup path).
- Structured events are routed from `runtime_guard.events` logger.
- A fallback procedure exists to call the restore hook if needed.
- At least one load test validates overhead and event signal quality.
- Pressure incidents include captured stage labels and process attribution.

## Validation Steps

1. Run representative Polars workload with synthetic pressure.
2. Confirm event emission and attribution (`self_inflicted` and `cause`).
3. Verify cooldown behavior does not suppress required incidents.
4. Confirm restore path cleanly reverts monkeypatches.
5. Record outcome and baseline metrics in adoption tracker.

## Rollout Recommendation

- Phase 1: CI and staging only.
- Phase 2: One production workload with active monitoring.
- Phase 3: Default enablement for Polars data services.

## Evidence to Capture

- RuntimeGuard version and pipeline revision.
- Before/after incident triage time.
- Number of pressure alerts and false positive rate.
- Sample event payloads and remediation actions.
