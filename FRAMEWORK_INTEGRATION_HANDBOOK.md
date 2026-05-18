# Framework Integration Handbook

**Roadmap items:** M1-I01, M1-I02, M1-I03  
**Purpose:** Unified guide for integrating runtime-guard across Polars, Dask, and Ray frameworks

This handbook shows how to consistently deploy runtime-guard across multiple data/ML frameworks in a team or organization.

---

## Overview

Runtime-guard integrates with three major Python frameworks:

| Framework | Use Case | Integration Point | Demo |
|---|---|---|---|
| **Polars** | Data loading, transformation | `LazyFrame.collect()` | `examples/polars_integration_demo.py` |
| **Dask** | Distributed data engineering | `dask.compute()`, `dask.persist()` | See Dask section below |
| **Ray** | ML training, distributed computing | `ray.get()`, actor methods | See Ray section below |

---

## Architecture Decision

### Single Guard vs. Multiple Guards

**Option A: One global guard (recommended for small teams)**

```python
from runtime_guard import RuntimeGuard, attach_polars_guard, attach_dask_guard, attach_ray_guard

# Single guard monitors all frameworks
guard = RuntimeGuard(
    env_prefix="MYCOMPANY",
    log_tag="data-platform",
    cooldown_s=30.0,
)

# Attach to all frameworks
restore_polars = attach_polars_guard(guard, stage="polars-collect")
restore_dask = attach_dask_guard(guard, stage="dask-compute")
restore_ray = attach_ray_guard(guard, stage="ray-get")

# Cleanup when done
def cleanup():
    restore_polars()
    restore_dask()
    restore_ray()
```

**Option B: Per-framework guards (recommended for large orgs)**

```python
from runtime_guard import RuntimeGuard, attach_polars_guard, attach_dask_guard, attach_ray_guard

# Separate guards for each framework with different policies
guards = {
    "polars": RuntimeGuard(env_prefix="MYCOMPANY_POLARS", cooldown_s=30.0),
    "dask": RuntimeGuard(env_prefix="MYCOMPANY_DASK", cooldown_s=60.0),
    "ray": RuntimeGuard(env_prefix="MYCOMPANY_RAY", cooldown_s=45.0),
}

# Attach with framework-specific stages
attach_polars_guard(guards["polars"], stage="polars-etl")
attach_dask_guard(guards["dask"], stage="dask-orchestration")
attach_ray_guard(guards["ray"], stage="ray-training")
```

---

## Deployment Pattern: Bootstrapping

### Pattern 1: Application Startup (Recommended)

```python
# app/main.py or your entry point

import logging
from runtime_guard import (
    RuntimeGuard,
    attach_polars_guard,
    attach_dask_guard,
    attach_ray_guard,
    append_audit_log,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    handlers=[
        logging.FileHandler("/var/log/myapp/runtime-guard.log"),
        logging.StreamHandler(),
    ],
)

# Initialize guard
_guard = RuntimeGuard(
    env_prefix="MYAPP",
    log_tag="main",
    cooldown_s=60.0,
    show_top_procs=True,
)

# Attach to frameworks
_restore_polars = attach_polars_guard(_guard, stage="polars-collect")
_restore_dask = attach_dask_guard(_guard, stage="dask-compute")
_restore_ray = attach_ray_guard(_guard, stage="ray-get")

# Audit configuration
_audit_log_path = "/var/log/myapp/audit-chain.jsonl"

def bootstrap():
    """Called once at application startup."""
    logger = logging.getLogger(__name__)
    logger.info("Runtime-guard initialized")
    logger.info(f"Audit log: {_audit_log_path}")
    return _guard, _audit_log_path

def cleanup():
    """Called at application shutdown."""
    _restore_polars()
    _restore_dask()
    _restore_ray()
```

### Pattern 2: Pytest Conftest Integration

```python
# tests/conftest.py

import pytest
from runtime_guard import make_pytest_guard

# Create a pytest-specific guard
_guard = make_pytest_guard(
    repo_name="MyDataPipeline",
    cooldown_s=10.0,  # Faster feedback in tests
    hints=[
        "Run with --tb=short to reduce memory use",
        "Reduce parallelism: pytest -n1",
        "Skip heavy tests: pytest -m 'not heavy'",
    ],
)

@pytest.fixture(scope="session", autouse=True)
def guard_session_start():
    """Check memory at session start."""
    _guard.check_and_log(stage="pytest-session-start")
    yield
    _guard.check_and_log(stage="pytest-session-end")

@pytest.fixture(autouse=True)
def guard_per_test(request):
    """Check memory before each test."""
    _guard.check_and_log(stage=f"test-{request.node.nodeid}")
    yield
    _guard.check_and_log(stage=f"test-{request.node.nodeid}:end")
```

---

## Framework-Specific Integration Guides

### Polars Integration

**Best for:** Data loading, lazy evaluation, tabular transformations

```python
from runtime_guard import RuntimeGuard, attach_polars_guard
import polars as pl

guard = RuntimeGuard(cooldown_s=30.0)
restore = attach_polars_guard(guard, stage="polars-collect")

# Example: Data pipeline
df = pl.read_csv("data.csv").lazy()
df = df.filter(pl.col("value") > 0)  # Lazy
result = df.collect()  # Guard checks before materialization

# Run the Polars demo to validate your setup:
# python examples/polars_integration_demo.py --scenario realistic
```

**See:** [INTEGRATION_POLARS.md](INTEGRATION_POLARS.md) for detailed guidance

### Dask Integration

**Best for:** Distributed data engineering, out-of-core operations

```python
from runtime_guard import RuntimeGuard, attach_dask_guard, install_dask_scheduler_callbacks
import dask.dataframe as dd

guard = RuntimeGuard(cooldown_s=60.0)
restore_api = attach_dask_guard(guard, stage="dask-compute")
get_worker_report = install_dask_scheduler_callbacks(guard)

# Example: Distributed computation
df = dd.read_csv("data.csv")
result = df.groupby("category").value.sum().compute()  # Guard checks

# After compute, get per-worker memory report
report = get_worker_report()
print(f"Pressure events: {report['total_pressure_events']}")
```

**See:** [README.md#dask](README.md#dask) (reference pattern)

### Ray Integration

**Best for:** ML training, distributed simulation, actor-based services

```python
from runtime_guard import RuntimeGuard, attach_ray_guard, enable_ray_actor_memory_monitoring
import ray

guard = RuntimeGuard(cooldown_s=45.0)
restore_api = attach_ray_guard(guard, stage="ray-get")
actor_config = enable_ray_actor_memory_monitoring(guard)

# Example: Actor with memory monitoring
@ray.remote
class DataProcessor:
    @actor_config["method_decorator"]
    def process(self, data):
        # Memory check before processing
        return len(data)

# Usage
processor = DataProcessor.remote()
result = ray.get(processor.process.remote([1, 2, 3]))
```

**See:** [INTEGRATION_RAY.md](INTEGRATION_RAY.md) for detailed guidance

---

## Deployment Phases

### Phase 0: Local Development (Week 1)

**Goal:** Familiarize with runtime-guard, run demos locally

```bash
# 1. Install runtime-guard
pip install runtime-guard

# 2. Run Polars demo
python examples/polars_integration_demo.py --scenario light

# 3. Add to your local project
cat > my_app.py << 'EOF'
from runtime_guard import RuntimeGuard, attach_polars_guard
guard = RuntimeGuard()
attach_polars_guard(guard)
# ... rest of your code
EOF

# 4. Monitor output
RUNTIME_GUARD_POSTURE=tight python my_app.py
```

### Phase 1: CI Integration (Week 2-3)

**Goal:** Add runtime-guard to CI pipeline for test jobs

```yaml
# .github/workflows/test.yml
name: Tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: |
          pip install pytest runtime-guard
          pip install -r requirements.txt
      - name: Run tests with memory monitoring
        env:
          RUNTIME_GUARD_POSTURE: tight
          RUNTIME_GUARD_LOG_TAG: ci-tests
        run: pytest tests/ -v
```

### Phase 2: Staging Deployment (Week 4-6)

**Goal:** Deploy to staging environment with monitoring

```dockerfile
# Dockerfile
FROM python:3.12
WORKDIR /app
RUN pip install runtime-guard
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

# Set environment variables for runtime-guard
ENV RUNTIME_GUARD_POSTURE=tight
ENV RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB=4096
ENV RUNTIME_GUARD_MAX_SWAP_USED_PCT=60
ENV RUNTIME_GUARD_AUDIT_LOG=/var/log/app/audit-chain.jsonl

CMD ["python", "-m", "myapp"]
```

### Phase 3: Production Rollout (Week 7+)

**Goal:** Gradual rollout to production with canary testing

```bash
# Canary deployment (5% of traffic)
# Set RUNTIME_GUARD_POSTURE=relaxed for production to avoid false positives
# Enable RUNTIME_GUARD_SIGNAL_RECOVERY_POLICY for automatic remediation

export RUNTIME_GUARD_POSTURE=relaxed
export RUNTIME_GUARD_SIGNAL_RECOVERY_POLICY=killhogs-then-pause
export RUNTIME_GUARD_AUDIT_LOG=/var/log/app/audit.log

python -m myapp
```

---

## Environment Variables Quick Reference

### All Frameworks

| Variable | Values | Effect |
|---|---|---|
| `RUNTIME_GUARD_POSTURE` | `tight`, `relaxed`, `ci` | Threshold preset |
| `RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB` | Integer | Minimum free memory (MB) |
| `RUNTIME_GUARD_MAX_SWAP_USED_PCT` | 0-100 | Maximum swap usage (%) |
| `RUNTIME_GUARD_LOG_TAG` | String | Logging identifier |
| `RUNTIME_GUARD_AUDIT_LOG` | Path | Audit log location |
| `RUNTIME_GUARD_SIGNAL_RECOVERY_POLICY` | Policy string | Auto-recovery behavior |

### Polars

| Variable | Effect |
|---|---|
| `POLARS_STREAMING` | Enable streaming for large datasets |
| `POLARS_VERBOSE` | Debug output |

### Dask

| Variable | Effect |
|---|---|
| `DASK_DATAFRAME__SHUFFLE_METHOD` | Shuffling strategy |
| `DASK_NUM_WORKERS` | Number of workers |

### Ray

| Variable | Effect |
|---|---|
| `RAY_memory` | Per-node memory limit (bytes) |
| `RAY_object_store_memory` | Object store size |

---

## Troubleshooting

### Symptom: "No pressure detected, but memory is clearly high"

**Solution:** Tune thresholds

```python
guard = RuntimeGuard()
# Check current thresholds
report = guard.check()  # Returns None if OK
# Or set explicit thresholds
os.environ["RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB"] = "2048"
```

### Symptom: "Audit log hash chain verification fails"

**Solution:** Check file integrity and roll back

```python
from runtime_guard import verify_audit_log_chain

result = verify_audit_log_chain("/path/to/audit.log")
if not result["ok"]:
    print(f"Chain broken at line {result['line']}")
    print(f"Reason: {result['reason']}")
    # Restore from backup
```

### Symptom: "Memory checks are slowing down my code"

**Solution:** Increase cooldown or use background checks

```python
# Option A: Increase cooldown
guard = RuntimeGuard(cooldown_s=120.0)  # Check at most once per 2 minutes

# Option B: Use background check (thread-based, async)
guard.start_background_check(interval_s=60.0)  # Check every 60s in background

# Option C: Check only at specific stages
# Don't attach globally; call guard.check() manually in critical paths
report = guard.check(stage="expensive-operation")
if report is None:  # No pressure
    do_expensive_work()
```

---

## Compliance & Audit

### SOC2 Compliance

```python
from runtime_guard import (
    soc2_required_controls,
    soc2_evidence_requirements,
    soc2_readiness_report,
)

# Check what controls are required
controls = soc2_required_controls()  # Returns 5+ SOC2 controls

# See what evidence is needed
requirements = soc2_evidence_requirements()

# Generate compliance report
report = soc2_readiness_report(audit_log_path="/var/log/app/audit.log")
print(f"SOC2 compliance: {report['coverage_pct']}%")
```

### Audit Evidence Checklist

- [ ] Integration version and deployment date documented
- [ ] Audit log configured and actively logging
- [ ] Audit log hash-chain verified weekly
- [ ] Memory pressure incidents reviewed monthly
- [ ] Recovery actions tested in staging
- [ ] Performance baseline established (latency/memory overhead)
- [ ] Team trained on interpretation of audit events
- [ ] Monitoring dashboard set up (if applicable)

---

## Examples & Demos

- [Polars Integration Demo](examples/polars_integration_demo.py) — End-to-end example
- [Dask Memory Diagnostics Issue Template](.github/ISSUE_TEMPLATE/dask-memory-diagnostics.yml) — Debug workflow
- [Adoption Scorecard](ADOPTION_TRACKER.md) — Track integration progress
- [Audit Policy Examples](AUDIT_POLICY_EXAMPLES.md) — Real policy templates

---

## FAQ

**Q: Which framework should I integrate first?**  
A: Start with Polars (simplest), then Dask (if distributed), then Ray (if ML).

**Q: Can I use different thresholds for each framework?**  
A: Yes — create separate RuntimeGuard instances or use environment variables with prefixes.

**Q: What happens if a framework is not installed?**  
A: RuntimeGuard gracefully skips attachment; other frameworks continue working.

**Q: How do I know if integration is working?**  
A: Check logs for events, run demos, or use adoption scorecard CLI.

**Q: Can I use this in production?**  
A: Yes — start with `posture=relaxed` and `observe` actions, then progress to enforcement.

---

## Further Reading

- [README.md](README.md) — Main documentation
- [ADOPTION_TRACKER.md](ADOPTION_TRACKER.md) — Track adoption progress
- [AUDIT_POLICY_EXAMPLES.md](AUDIT_POLICY_EXAMPLES.md) — Policy templates
- [ROADMAP.md](ROADMAP.md) — Development roadmap
