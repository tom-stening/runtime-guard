---

### Policy 4: Regulated Sector Compliance (Healthcare/Finance)

**Goal:** Ensure all memory pressure and access events are logged for compliance (HIPAA/SOC2), with mandatory escalation and retention.

**Policy Definition:**

```json
{
  "policy_id": "regulated-sector-compliance-v1",
  "name": "Regulated Sector Compliance",
  "description": "Log all memory, access, and integrity events for HIPAA/SOC2.",
  "stages": [
    {
      "stage": "etl-load",
      "min_mem_available_mb": 8192,
      "max_swap_used_pct": 50,
      "action_on_pressure": "notify"
    },
    {
      "stage": "etl-transform",
      "min_mem_available_mb": 4096,
      "max_swap_used_pct": 70,
      "action_on_pressure": "throttle"
    }
  ],
  "audit_events": [
    {"category": "memory", "action": "notify"},
    {"category": "access", "action": "observe"},
    {"category": "integrity", "action": "policy_violation"}
  ],
  "retention_days": 365,
  "escalation": "All critical events must be escalated to compliance officer within 1 hour."
}
```

**Example Audit Events:**

```json
{
  "timestamp": 1715335000,
  "event_type": "policy_violation",
  "policy_id": "regulated-sector-compliance-v1",
  "stage": "etl-load",
  "category": "memory",
  "action": "notify",
  "severity": "warning",
  "snapshot": {"mem_available_mb": 7900, "swap_used_pct": 51},
  "cause": "MemAvailable=7900 MB (threshold: 8192 MB)",
  "self_inflicted": true,
  "process_id": 22222
}
```

```json
{
  "timestamp": 1715335100,
  "event_type": "policy_violation",
  "policy_id": "regulated-sector-compliance-v1",
  "category": "integrity",
  "action": "policy_violation",
  "severity": "critical",
  "cause": "Audit log hash-chain broken at line 1201",
  "escalation": "compliance-officer@company.com"
}
```

**Integration Notes:**
- Store audit logs in a secure, access-controlled location (0600 permissions).
- Run `verify_audit_log_chain()` after every batch job.
- Integrate with SIEM for real-time alerting on integrity or access events.
- Retain logs for at least 1 year for compliance.

---

### Policy 5: Ephemeral CI/CD Runner Enforcement

**Goal:** Aggressively enforce memory limits in short-lived CI/CD runners to prevent host instability and speed up failure feedback.

**Policy Definition:**

```json
{
  "policy_id": "ci-runner-enforcement-v1",
  "name": "CI Runner Enforcement",
  "description": "Terminate jobs on memory pressure in CI/CD ephemeral runners.",
  "stages": [
    {
      "stage": "ci-test",
      "min_mem_available_mb": 2048,
      "max_swap_used_pct": 40,
      "action_on_pressure": "kill_hogs"
    }
  ],
  "audit_events": [
    {"category": "memory", "action": "kill_hogs"},
    {"category": "incident", "action": "abort"}
  ],
  "retention_days": 30
}
```

**Example Audit Event:**

```json
{
  "timestamp": 1715335200,
  "event_type": "policy_violation",
  "policy_id": "ci-runner-enforcement-v1",
  "stage": "ci-test",
  "category": "memory",
  "action": "kill_hogs",
  "severity": "critical",
  "snapshot": {"mem_available_mb": 1800, "swap_used_pct": 45},
  "processes_killed": [
    {"pid": 33333, "name": "pytest", "rss_mb": 900, "cmdline": "pytest tests/"}
  ],
  "cause": "MemAvailable=1800 MB (threshold: 2048 MB)",
  "self_inflicted": true,
  "job_id": "ci-123456"
}
```

**Integration Notes:**
- Use in GitHub Actions, GitLab CI, Jenkins ephemeral runners, etc.
- Set `RUNTIME_GUARD_POSTURE=ci` and `RUNTIME_GUARD_AUDIT_LOG=/tmp/ci-audit.log`.
- Fail the job immediately if a critical event is logged.
- Retain logs for 30 days for debugging and compliance.
# Audit Policy Examples & Rollout Guide

This document operationalizes roadmap item M2-C02:
"Audit log for all policy violations with hash-chain integrity and broader policy catalog rollout."

## Overview

The runtime-guard audit system tracks memory pressure events, policy decisions, and system changes with:
- **Hash-chain verification** for tamper detection
- **Taxonomy normalization** for compliance classification
- **Evidence collection** for SOC2/regulatory audits
- **Structured JSON logging** for log aggregation

This guide shows practical policies and integration patterns.

---

## Policy Categories & Actions

### Available Categories

| Category | Use Cases | Example Events |
|---|---|---|
| `memory` | Out-of-memory conditions, memory pressure | High memory usage, swap exhaustion |
| `system` | System resource constraints, host-level issues | CPU throttling, disk full |
| `swap` | Swap usage anomalies, swap exhaustion | Excessive swap, swap initialization |
| `process` | Process lifecycle, resource attribution | Process created/destroyed, resource limits |
| `incident` | Incident detection, response initiation | Anomaly detected, escalation needed |
| `integrity` | Data integrity, hash verification, tampering | Hash mismatch, audit chain break |
| `access` | Access control, privileged operations | Permission change, unauthorized access attempt |
| `availability` | Service availability, capacity planning | Service unavailable, capacity exceeded |
| `config` | Configuration changes, policy updates | Config loaded, override applied |
| `compliance` | Compliance events, audit trail | SOC2 event, regulatory requirement |

### Available Actions

| Action | Semantics | Example Use |
|---|---|---|
| `observe` | Log event without intervention | Monitor mode in staging |
| `notify` | Alert without blocking | Send to logging/alerting |
| `throttle` | Rate-limit resource usage | Limit query concurrency |
| `kill_hogs` | Terminate resource-heavy processes | Kill memory hogs |
| `snapshot` | Capture diagnostic data | Save memory dump before action |
| `recover` | Automatic recovery/restart | Restart service, clear cache |
| `remediate` | Corrective action | Scale down, request resources |
| `acknowledge` | Manual acknowledgment | Team confirms incident |
| `escalate` | Escalate to higher priority | Route to on-call |
| `pressure_detected` | Initial pressure detection | Threshold exceeded |
| `policy_violation` | Policy constraint violated | Custom policy violated |
| `abort` | Halt operation | Abort query/job |
| `custom` | Custom action (unmapped) | Integration-specific |

### Available Severities

- `info` — Informational, no action needed
- `warning` — Attention recommended, not critical
- `critical` — Immediate action required

---

## Example Policies

### Policy 1: Memory Pressure Detection (Data Engineering)

**Goal:** Detect memory pressure in data pipeline, alert ops team.

**Policy Definition:**

```json
{
  "policy_id": "dask-pipeline-memory-v1",
  "name": "Dask Pipeline Memory Pressure",
  "description": "Monitor Dask compute operations for memory pressure.",
  "stages": [
    {
      "stage": "dask-compute",
      "min_mem_available_mb": 4096,
      "max_swap_used_pct": 60,
      "action_on_pressure": "notify"
    },
    {
      "stage": "dask-materialize",
      "min_mem_available_mb": 2048,
      "max_swap_used_pct": 80,
      "action_on_pressure": "throttle"
    }
  ],
  "audit_events": [
    {
      "category": "memory",
      "severity": "warning"
    },
    {
      "category": "incident",
      "severity": "critical"
    }
  ]
}
```

**Example Audit Event:**

```json
{
  "timestamp": 1715334144,
  "event_type": "policy_violation",
  "policy_id": "dask-pipeline-memory-v1",
  "stage": "dask-compute",
  "category": "memory",
  "action": "notify",
  "severity": "warning",
  "snapshot": {
    "mem_available_mb": 3512,
    "mem_total_mb": 65536,
    "swap_used_pct": 55,
    "rss_mb": 28672
  },
  "cause": "MemAvailable=3512 MB (threshold: 4096 MB)",
  "self_inflicted": true,
  "process_id": 12345,
  "stage_label": "dask-compute"
}
```

**Integration Pattern:**

```python
from runtime_guard import RuntimeGuard, attach_dask_guard, append_audit_log

guard = RuntimeGuard(
    env_prefix="DASK_PIPELINE",
    log_tag="dask-pipeline-v1",
    cooldown_s=60.0,
)

# Enable audit logging
audit_path = "/var/log/dask-pipeline/audit.log"

# Attach guard to Dask
restore = attach_dask_guard(guard, stage="dask-compute")

# In your compute code:
def compute_job(data):
    report = guard.check(stage="dask-compute")
    if report is not None:
        # Pressure detected
        audit_log = {
            "event_type": "policy_violation",
            "policy_id": "dask-pipeline-memory-v1",
            "category": "memory",
            "action": "notify",
            "severity": "warning" if not report.is_critical else "critical",
            "cause": report.cause,
        }
        append_audit_log(audit_path, audit_log)
        # Alert ops
        send_alert(f"Memory pressure detected: {report.cause}")
    # Continue with compute...
```

---

### Policy 2: ML Training Resource Limits (AI/ML)

**Goal:** Enforce resource limits during ML training, trigger checkpointing on pressure.

**Policy Definition:**

```json
{
  "policy_id": "ml-training-resources-v1",
  "name": "ML Training Resource Limits",
  "description": "Monitor memory and GPU resources during training.",
  "stages": [
    {
      "stage": "ml-data-load",
      "min_mem_available_mb": 8192,
      "max_swap_used_pct": 40,
      "action_on_pressure": "throttle",
      "description": "Data loading phase — aggressive limit"
    },
    {
      "stage": "ml-forward-pass",
      "min_mem_available_mb": 6144,
      "max_swap_used_pct": 60,
      "action_on_pressure": "observe",
      "description": "Forward pass — monitor mode"
    },
    {
      "stage": "ml-backward-pass",
      "min_mem_available_mb": 4096,
      "max_swap_used_pct": 80,
      "action_on_pressure": "snapshot",
      "description": "Backward pass — capture diagnostics if pressure"
    }
  ],
  "audit_events": [
    {
      "category": "memory",
      "action": "snapshot"
    },
    {
      "category": "incident",
      "action": "recover"
    }
  ]
}
```

**Example Audit Event (Snapshot Before Recovery):**

```json
{
  "timestamp": 1715334255,
  "event_type": "policy_violation",
  "policy_id": "ml-training-resources-v1",
  "stage": "ml-backward-pass",
  "category": "memory",
  "action": "snapshot",
  "severity": "critical",
  "snapshot": {
    "mem_available_mb": 3890,
    "mem_total_mb": 65536,
    "swap_used_pct": 82,
    "rss_mb": 52800
  },
  "cause": "MemAvailable=3890 MB (threshold: 4096 MB), SwapUsed=82% (threshold: 80%)",
  "self_inflicted": true,
  "process_id": 54321,
  "diagnostic_data": {
    "checkpoint_path": "/checkpoints/training-2024-05-10-12-34-55.pt",
    "epoch": 42,
    "batch_idx": 1024
  }
}
```

**Integration Pattern:**

```python
from runtime_guard import RuntimeGuard, append_audit_log

class TrainingMonitor:
    def __init__(self, guard: RuntimeGuard, audit_path: str):
        self.guard = guard
        self.audit_path = audit_path

    def on_batch_start(self, epoch: int, batch_idx: int) -> bool:
        """Check memory before batch. Return True to continue, False to stop."""
        report = self.guard.check(stage="ml-forward-pass")
        
        if report is None:
            return True  # All good
        
        # Pressure detected — log and decide
        audit_log = {
            "event_type": "policy_violation",
            "policy_id": "ml-training-resources-v1",
            "stage": "ml-backward-pass",
            "category": "memory" if not report.is_critical else "incident",
            "action": "snapshot" if not report.is_critical else "recover",
            "severity": "warning" if not report.is_critical else "critical",
            "cause": report.cause,
            "epoch": epoch,
            "batch_idx": batch_idx,
        }
        append_audit_log(self.audit_path, audit_log)
        
        if report.is_critical:
            # Critical: save checkpoint and pause
            checkpoint_path = f"/checkpoints/critical-{epoch}-{batch_idx}.pt"
            torch.save(model.state_dict(), checkpoint_path)
            audit_log["action_taken"] = f"Checkpoint saved to {checkpoint_path}"
            return False  # Stop training
        
        return True  # Pressure but not critical; continue
```

---

### Policy 3: Multi-Tenant Isolation (SaaS)

**Goal:** Isolate tenants, prevent one tenant from affecting others.

**Policy Definition:**

```json
{
  "policy_id": "multitenant-isolation-v1",
  "name": "Multi-Tenant Resource Isolation",
  "description": "Enforce per-tenant memory limits and isolation.",
  "tenant_tiers": [
    {
      "tier": "premium",
      "min_mem_available_mb": 10240,
      "max_swap_used_pct": 30,
      "action_on_pressure": "throttle"
    },
    {
      "tier": "standard",
      "min_mem_available_mb": 4096,
      "max_swap_used_pct": 60,
      "action_on_pressure": "throttle"
    },
    {
      "tier": "free",
      "min_mem_available_mb": 1024,
      "max_swap_used_pct": 80,
      "action_on_pressure": "kill_hogs"
    }
  ],
  "audit_events": [
    {
      "category": "access",
      "action": "observe",
      "description": "Log tenant access attempts"
    },
    {
      "category": "compliance",
      "action": "pressure_detected",
      "description": "Log SLA violations"
    }
  ]
}
```

**Example Audit Events:**

```json
[
  {
    "timestamp": 1715334300,
    "event_type": "policy_violation",
    "policy_id": "multitenant-isolation-v1",
    "tenant_id": "acme-corp-premium",
    "tenant_tier": "premium",
    "category": "compliance",
    "action": "pressure_detected",
    "severity": "warning",
    "snapshot": {
      "mem_available_mb": 9800,
      "swap_used_pct": 28
    },
    "cause": "Tier premium threshold approaching"
  },
  {
    "timestamp": 1715334400,
    "event_type": "policy_violation",
    "policy_id": "multitenant-isolation-v1",
    "tenant_id": "startup-xyz-free",
    "tenant_tier": "free",
    "category": "memory",
    "action": "kill_hogs",
    "severity": "critical",
    "snapshot": {
      "mem_available_mb": 890,
      "swap_used_pct": 85
    },
    "processes_killed": [
      {"pid": 19999, "name": "python", "rss_mb": 512, "cmdline": "train.py --no-limit"}
    ]
  }
]
```

**Integration Pattern:**

```python
from runtime_guard import RuntimeGuard, append_audit_log

class TenantMemoryGate:
    def __init__(self, audit_path: str):
        self.guards: dict[str, RuntimeGuard] = {}
        self.audit_path = audit_path
        self._setup_tiers()

    def _setup_tiers(self):
        tiers = {
            "premium": {"min_mem": 10240, "max_swap": 30},
            "standard": {"min_mem": 4096, "max_swap": 60},
            "free": {"min_mem": 1024, "max_swap": 80},
        }
        for tier, limits in tiers.items():
            self.guards[tier] = RuntimeGuard(
                env_prefix=f"TENANT_{tier.upper()}",
                log_tag=f"tenant-{tier}",
            )

    def check_tenant_access(self, tenant_id: str, tenant_tier: str) -> bool:
        """Return True if tenant can proceed, False if access denied."""
        guard = self.guards.get(tenant_tier)
        if guard is None:
            return False
        
        report = guard.check(stage=f"tenant-{tenant_tier}-compute")
        
        if report is not None:
            # Pressure detected
            audit_log = {
                "event_type": "policy_violation",
                "policy_id": "multitenant-isolation-v1",
                "tenant_id": tenant_id,
                "tenant_tier": tenant_tier,
                "category": "memory",
                "severity": "critical" if report.is_critical else "warning",
                "action": "kill_hogs" if tenant_tier == "free" else "throttle",
                "cause": report.cause,
            }
            append_audit_log(self.audit_path, audit_log)
            
            if tenant_tier == "free" and report.is_critical:
                # Kill the tenant's process
                return False
        
        return True
```

---

## Audit Log Verification & Compliance

### Verify Audit Log Integrity

```python
from runtime_guard import verify_audit_log_chain

# After policy enforcement, verify the audit log is tamper-proof
result = verify_audit_log_chain("/var/log/runtime-guard/audit.log")

if result["ok"]:
    print(f"✓ Audit log verified: {result['records']} records")
else:
    print(f"✗ Audit log tampered at line {result['line']}")
    # Alert security team
```

### Compliance Reporting

```python
from runtime_guard import (
    soc2_required_controls,
    soc2_evidence_requirements,
    soc2_gap_assessment,
)

# Check SOC2 compliance status
controls = soc2_required_controls()
requirements = soc2_evidence_requirements()
gaps = soc2_gap_assessment(audit_log_path="/var/log/runtime-guard/audit.log")

print(f"Compliance: {gaps['compliance_pct']}% of SOC2 controls")
for gap in gaps["gaps"]:
    print(f"  - {gap}")
```

---

## Rollout Phases

### Phase 1: Monitor (Week 1-2)

1. Deploy guards to staging environments
2. Enable `observe` action (logging only)
3. Collect baseline audit events
4. Verify hash-chain integrity

```bash
RUNTIME_GUARD_POSTURE=relaxed \
RUNTIME_GUARD_AUDIT_LOG=/var/log/runtime-guard/audit.log \
python your_pipeline.py
```

### Phase 2: Validate (Week 3-4)

1. Review audit events in staging
2. Tune thresholds based on workload
3. Test `notify` action (alerting)
4. Verify compliance gaps are covered

```bash
RUNTIME_GUARD_POSTURE=tight \
RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB=4096 \
RUNTIME_GUARD_MAX_SWAP_USED_PCT=60 \
python your_pipeline.py
```

### Phase 3: Enforce (Week 5+)

1. Gradually enable `throttle`, `recover`, etc.
2. Monitor incident volume
3. Scale remediation capability
4. Audit for compliance evidence

```bash
RUNTIME_GUARD_SIGNAL_RECOVERY_POLICY=killhogs-then-pause \
RUNTIME_GUARD_AUDIT_LOG=/var/log/runtime-guard/audit.log \
python your_pipeline.py
```

---

## Best Practices

1. **Separate concerns**: Different policies for different stages/teams
2. **Layer actions**: Start with `observe`, progress to `throttle`, then `kill_hogs`
3. **Verify integrity**: Run `verify_audit_log_chain()` regularly
4. **Document policies**: Keep policy definitions in version control
5. **Alert on violations**: Integrate with on-call systems
6. **Monthly reviews**: Audit compliance gaps and policy effectiveness
7. **Test recovery**: Simulate pressure scenarios in staging

---

## Further Reading

- [ROADMAP.md](ROADMAP.md) — M2-C02 item details
- [ADOPTION_TRACKER.md](ADOPTION_TRACKER.md) — Track policy adoption across teams
- [OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md) — Deployment runbooks
- [README.md](README.md) — Main documentation
