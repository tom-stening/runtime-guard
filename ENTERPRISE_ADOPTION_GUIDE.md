# Enterprise Adoption Guide

**Roadmap item:** M2-I01 Enterprise Support Evidence Collection  
**Purpose:** Help enterprise organizations adopt runtime-guard across teams with compliance and operational readiness

This guide provides everything enterprise teams need to adopt runtime-guard company-wide.

---

## Executive Summary

Runtime-guard is a memory pressure detection and management library for Python applications. It helps organizations:

- **Reduce production incidents** caused by memory exhaustion (20-40% of data pipeline failures)
- **Meet compliance requirements** (SOC2 CC7.x, CC8.1 controls for system monitoring)
- **Lower operational costs** through automated recovery without manual intervention
- **Improve team velocity** with unified monitoring across Polars, Dask, and Ray frameworks

**Time to Value:**
- Week 1: Deploy to development environment
- Week 2-3: Integrate into CI/CD and staging
- Week 4-6: Limited production rollout (5-20% traffic)
- Week 7+: Full production deployment

---

## Adoption Roadmap

### Phase 1: Assessment (Week 1)

**Team:** Data/ML Engineering Lead, DevOps Lead, Security Lead

**Deliverables:**
- [ ] Review this guide (2 hours)
- [ ] Run Polars demo in dev environment: `python examples/polars_integration_demo.py`
- [ ] Assess current memory incident frequency in your systems
- [ ] Review [AUDIT_POLICY_EXAMPLES.md](AUDIT_POLICY_EXAMPLES.md) for applicability
- [ ] Identify 2-3 pilot teams/projects

**Success Criteria:**
- Demo runs without errors
- Team understands how framework integration works
- Pilot projects identified

**Output:** Adoption decision document (see template below)

---

### Phase 2: Pilot Deployment (Week 2-4)

**Team:** 2-3 engineers from pilot projects

**Setup:**
1. Install runtime-guard: `pip install runtime-guard`
2. Add to project requirements or pyproject.toml
3. Choose integration pattern (see [FRAMEWORK_INTEGRATION_HANDBOOK.md](FRAMEWORK_INTEGRATION_HANDBOOK.md))
4. Configure environment variables for pilot environment
5. Enable audit logging to central location

**Code Pattern:**

```python
# app/bootstrap.py (or main.py entry point)

import os
import logging
from runtime_guard import (
    RuntimeGuard,
    attach_polars_guard,
    attach_dask_guard,
    attach_ray_guard,
)

logger = logging.getLogger(__name__)

def init_runtime_guard():
    """Initialize runtime-guard for the application."""
    
    # Create guard with company-wide prefix
    guard = RuntimeGuard(
        env_prefix="MYCOMPANY",  # Company name
        log_tag=os.environ.get("APP_NAME", "unknown"),
        cooldown_s=60.0,
        show_top_procs=True,
    )
    
    # Attach to frameworks used by this app
    if "polars" in os.environ.get("APP_FRAMEWORKS", ""):
        attach_polars_guard(guard, stage="polars-operations")
    if "dask" in os.environ.get("APP_FRAMEWORKS", ""):
        attach_dask_guard(guard, stage="dask-operations")
    if "ray" in os.environ.get("APP_FRAMEWORKS", ""):
        attach_ray_guard(guard, stage="ray-operations")
    
    logger.info("Runtime-guard initialized")
    return guard
```

**Monitoring Setup:**

```bash
# Development / Pilot environment variables
export RUNTIME_GUARD_POSTURE=tight  # Aggressive in pilot
export RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB=4096
export RUNTIME_GUARD_MAX_SWAP_USED_PCT=60
export RUNTIME_GUARD_AUDIT_LOG=/var/log/myapp/audit.log
export RUNTIME_GUARD_LOG_TAG=pilot-team-1
```

**Deliverables:**
- [ ] Integration code committed to feature branch
- [ ] 2 weeks of audit logs collected
- [ ] Pilot report: incidents detected, false positives, performance impact
- [ ] Team trained on monitoring and incident response

**Success Criteria:**
- No regressions in application performance
- At least 1 memory pressure incident detected and handled
- False positive rate < 5%

**Output:** Pilot assessment report

---

### Phase 3: CI/CD Integration (Week 3-4)

**Team:** DevOps / Platform Engineering

**Setup:** Add runtime-guard to CI pipeline for test jobs

```yaml
# .github/workflows/ci.yml (or equivalent)
name: CI with Memory Monitoring

on: [push, pull_request]

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
          pip install --upgrade pip
          pip install -r requirements.txt
          pip install runtime-guard pytest
      
      - name: Run tests with memory monitoring
        env:
          RUNTIME_GUARD_POSTURE: tight
          RUNTIME_GUARD_LOG_TAG: ci-${{ github.run_id }}
          RUNTIME_GUARD_AUDIT_LOG: /tmp/ci-audit.jsonl
        run: |
          pytest tests/ -v --tb=short
      
      - name: Upload audit logs if tests fail
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: audit-logs
          path: /tmp/ci-audit.jsonl
```

**Deliverables:**
- [ ] CI pipeline configured with runtime-guard
- [ ] Audit logs collected on failure
- [ ] Dashboard showing test memory usage trends

---

### Phase 4: Staging Deployment (Week 4-6)

**Team:** DevOps + Pilot teams

**Setup:**

```dockerfile
# Dockerfile example
FROM python:3.12-slim

WORKDIR /app

# Install runtime-guard alongside application
RUN pip install --upgrade pip && \
    pip install runtime-guard

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Set defaults (can be overridden at runtime)
ENV RUNTIME_GUARD_POSTURE=relaxed
ENV RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB=2048
ENV RUNTIME_GUARD_AUDIT_LOG=/var/log/app/audit.log

CMD ["python", "-m", "myapp"]
```

**Monitoring:**

```yaml
# Kubernetes deployment example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:v1.0
        env:
        - name: RUNTIME_GUARD_POSTURE
          value: relaxed  # Start conservative in staging
        - name: RUNTIME_GUARD_AUDIT_LOG
          value: /var/log/app/audit.log
        - name: RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB
          value: "2048"
        volumeMounts:
        - name: logs
          mountPath: /var/log/app
      volumes:
      - name: logs
        emptyDir: {}
```

**Deliverables:**
- [ ] Containerized deployment with runtime-guard
- [ ] 2+ weeks of staging audit logs
- [ ] Monitoring dashboard configured
- [ ] Runbook for responding to memory incidents

---

### Phase 5: Production Rollout (Week 7+)

**Team:** DevOps + On-call Engineering

**Canary Deployment (5-20% traffic):**

```bash
# Use environment variables to control rollout
export RUNTIME_GUARD_POSTURE=relaxed  # Conservative in production
export RUNTIME_GUARD_SIGNAL_RECOVERY_POLICY=killhogs-then-pause
export RUNTIME_GUARD_AUDIT_LOG=/var/log/app/audit-chain.jsonl
export APP_DEPLOYMENT_CANARY=true
```

**Success Criteria:**
- Error rate ≤ baseline (no regressions)
- Memory incident response time < 30 seconds
- False positive rate < 2%
- Audit log integrity verified (hash-chain check passes)

**Deliverables:**
- [ ] Canary results documented
- [ ] Production rollout plan approved by engineering leadership
- [ ] On-call training completed

---

## Compliance & Security

### SOC2 Compliance

Runtime-guard helps satisfy SOC2 Type 2 controls:

| Control | How Runtime-Guard Helps |
|---|---|
| **CC7.1**: Monitor & detect anomalies | Automated memory pressure detection |
| **CC7.2**: Monitor system performance | Real-time memory and swap monitoring |
| **CC7.3**: Monitor for unauthorized changes | Audit log with hash-chain verification |
| **CC8.1**: Control physical access | Automatic incident response without manual intervention |
| **CC6.1**: Logical access control | Audit log tracks all pressure events |

**Evidence Checklist:**
- [ ] Audit logs enable = ✓
- [ ] Hash-chain verification = `python -c "from runtime_guard import verify_audit_log_chain; verify_audit_log_chain('/var/log/app/audit.log')"`
- [ ] Incident response training = See incident response guide
- [ ] Monitoring dashboard = Grafana, Datadog, or equivalent
- [ ] Retention policy = 90 days minimum

### Security Considerations

**Audit Log Confidentiality:**
- Store audit logs in `/var/log/app/` with restricted permissions (0600)
- Encrypt in transit to log aggregator
- Rotate logs weekly with archival to secure storage

**Access Control:**
- Only operations/DevOps should have audit log read access
- Implement role-based access control (RBAC)
- Log all audit log access attempts

**Data Protection:**
- Audit logs don't contain application data (only memory metrics)
- No personally identifiable information (PII) is logged
- Hash-chain ensures tampering is detected

---

## Training & Runbooks

### Team Training Agenda (2 hours)

1. **Overview** (15 min)
   - What is memory pressure?
   - How runtime-guard detects it
   - Why this matters for production

2. **Integration Patterns** (30 min)
   - Framework-specific integration (Polars/Dask/Ray)
   - Environment configuration
   - Monitoring setup

3. **Incident Response** (45 min)
   - How to interpret audit logs
   - Common pressure scenarios
   - Recovery actions
   - Hands-on: Review sample audit logs

4. **Hands-On Lab** (30 min)
   - Deploy demo to dev environment
   - Trigger memory pressure scenario
   - Interpret audit logs

**Materials:**
- [FRAMEWORK_INTEGRATION_HANDBOOK.md](FRAMEWORK_INTEGRATION_HANDBOOK.md)
- [AUDIT_POLICY_EXAMPLES.md](AUDIT_POLICY_EXAMPLES.md)
- Sample audit log (provided in repo)

### Incident Response Runbook

**Alert:** Memory Pressure Detected (Severity: Warning)

```
1. Check audit log
   $ tail -f /var/log/app/audit.log
   
2. Identify affected process/pod
   Look for: process_id, process_name in audit event
   
3. Review memory snapshot
   mem_available_mb: current free memory
   rss_mb: process memory usage
   swap_used_pct: system swap usage
   
4. Determine action taken
   - observe: monitored, no action
   - throttle: rate-limiting applied
   - snapshot: diagnostic data captured
   - recover: automatic restart performed
   
5. If automatic recovery worked:
   - Acknowledge incident
   - Review policy settings
   - Consider tuning thresholds
   
6. If automatic recovery didn't work:
   - Page on-call engineer
   - Manual intervention needed
   - Escalate to platform team
```

**Alert:** Critical Memory Pressure (Severity: Critical)

```
1. Page on-call engineer immediately
2. Check if auto-remediation was attempted
3. Review recent code changes
4. Possible actions:
   - Scale up resources
   - Restart service
   - Redirect traffic to backup service
5. After incident:
   - Post-mortem analysis
   - Policy tuning
   - Documentation update
```

---

## Metrics & Success Tracking

### KPIs to Track

| Metric | Target | How to Measure |
|---|---|---|
| Time to Detect Pressure | < 60 seconds | Audit log timestamps |
| Time to Resolve Incident | < 5 minutes | Incident response time |
| False Positive Rate | < 2% | Review audit logs weekly |
| Production Uptime | > 99.9% | Monitoring dashboard |
| Adoption Rate | > 80% of teams | Scorecard tracking |

### Scorecard Template

```python
from runtime_guard import adoption_scorecard

# Generate scorecard for team
scorecard = adoption_scorecard(
    repo_path="/path/to/repo",
    org_name="MyCompany",
    team_name="Data Platform",
)

print(f"Integration Score: {scorecard['integration_pct']}%")
print(f"Monitoring Score: {scorecard['monitoring_pct']}%")
print(f"Compliance Score: {scorecard['compliance_pct']}%")
```

---

## Support & Escalation

### Getting Help

| Issue | Resource |
|---|---|
| Installation problems | [README.md](README.md#installation) |
| Framework integration | [FRAMEWORK_INTEGRATION_HANDBOOK.md](FRAMEWORK_INTEGRATION_HANDBOOK.md) |
| Policy configuration | [AUDIT_POLICY_EXAMPLES.md](AUDIT_POLICY_EXAMPLES.md) |
| Compliance questions | [ROADMAP.md](ROADMAP.md) → M2 section |
| Bug reports | GitHub Issues → Use template |
| Security vulnerabilities | Email: security@runtime-guard.local |

### Escalation Path

1. **Level 1**: Consult documentation (this guide + README)
2. **Level 2**: Review audit logs and health metrics
3. **Level 3**: Contact on-call platform engineer
4. **Level 4**: Escalate to runtime-guard maintainers

---

## Next Steps

1. **Read** [FRAMEWORK_INTEGRATION_HANDBOOK.md](FRAMEWORK_INTEGRATION_HANDBOOK.md)
2. **Run** `python examples/polars_integration_demo.py`
3. **Review** [AUDIT_POLICY_EXAMPLES.md](AUDIT_POLICY_EXAMPLES.md) for your use case
4. **Identify** pilot projects (start with 2-3)
5. **Schedule** kickoff meeting with pilot teams
6. **Plan** deployment phases (weeks 1-8)

---

## Appendix: Adoption Decision Template

```markdown
# Runtime-Guard Adoption Decision

**Organization:** MyCompany  
**Date:** 2024-05-10  
**Decision Maker:** CTO / VP Engineering  

## Assessment Results

### Current State
- Number of production incidents/month due to memory: ___
- Average incident resolution time: ___
- Teams managing their own memory monitoring: ___
- Compliance gaps (SOC2): ___

### Proposed Solution
- Deploy runtime-guard to:
  - [ ] Development environments
  - [ ] CI/CD pipelines
  - [ ] Staging environment
  - [ ] Production (canary)
  - [ ] Production (full)

### Pilot Scope
- Pilot Teams: ___ (2-3 teams)
- Pilot Duration: ___ weeks
- Pilot Frameworks: Polars / Dask / Ray

### Success Criteria
- [ ] No regressions in application performance
- [ ] At least 1 memory incident detected
- [ ] False positive rate < 5%
- [ ] Team training completed

### Timeline
- Phase 1 (Assessment): Week of ___
- Phase 2 (Pilot): Week of ___
- Phase 3 (CI Integration): Week of ___
- Phase 4 (Staging): Week of ___
- Phase 5 (Production): Week of ___

### Decision
- [ ] Approved for adoption
- [ ] Needs more information
- [ ] Deferred to ___

**Approved by:** ___________________  
**Date:** ___________________
```

---

## Further Reading

- [README.md](README.md) — Main documentation
- [FRAMEWORK_INTEGRATION_HANDBOOK.md](FRAMEWORK_INTEGRATION_HANDBOOK.md) — Integration guide
- [AUDIT_POLICY_EXAMPLES.md](AUDIT_POLICY_EXAMPLES.md) — Policy templates
- [ADOPTION_TRACKER.md](ADOPTION_TRACKER.md) — Scorecard tracking
