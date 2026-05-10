# Ray Integration Cookbook

This guide advances roadmap item M1-I03:
"Ray tutorial and cookbook examples".

## Goal

Provide practical integration patterns for `runtime_guard` in Ray workloads,
covering driver-side hooks, stage attribution, and incident evidence capture.

## Example 1: Driver-side hook for get/wait/put

```python
from runtime_guard import RuntimeGuard, attach_ray_guard
import ray

ray.init()
guard = RuntimeGuard(log_tag="RayPipeline", cooldown_s=30.0)
restore = attach_ray_guard(guard, stage="ray-driver")

@ray.remote
def work(x: int) -> int:
    return x * 2

refs = [work.remote(i) for i in range(10)]
ready, remaining = ray.wait(refs, num_returns=5)
results = ray.get(ready)
extra_ref = ray.put({"batch": "A", "count": len(remaining)})

restore()
ray.shutdown()
```

## Example 2: Stage-scoped phases in orchestration code

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard(log_tag="RayStages", cooldown_s=20.0)

with guard.phase("ray-submit"):
    # submit tasks/actors
    pass

with guard.phase("ray-collect"):
    # gather results
    pass
```

## Example 3: Add audit trail for critical pressure

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard(log_tag="RayAudit")
report = guard.check(stage="ray-critical-window")
if report is not None:
    guard.log(report)
    guard.audit(report, path="./ray-pressure-audit.log", action="ray-pressure")
```

## Operational Checklist

- Use clear stage names (`ray-submit`, `ray-wait`, `ray-get`).
- Keep `cooldown_s` non-zero in high-frequency loops.
- Route `runtime_guard.events` logs to your observability pipeline.
- Retain audit logs for post-incident analysis.
- Validate with synthetic pressure before production rollout.

## Troubleshooting

- If no checks fire, verify `attach_ray_guard()` was called before `ray.get()`/`ray.wait()`/`ray.put()`.
- If logs are too noisy, increase `cooldown_s` and normalize stage labels.
- If attribution seems incorrect, capture `runtime-guard --snapshot` from the same time window.
