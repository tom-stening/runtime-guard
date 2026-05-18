# GDPR & HIPAA Compliance Guide

**Document Version:** 1.0  
**Last Updated:** May 19, 2026  
**Compliance Scope:** EU GDPR Article 32, HIPAA § 164.308(a)(3), and related privacy regulations.

---

## Executive Summary

runtime-guard monitors application memory pressure without storing, processing, or transmitting personally identifiable information (PII) by default. This guide explains:

1. **What data runtime-guard collects** (and what it doesn't)
2. **Data residency guarantees** (all data stays on the host/process where monitoring occurs)
3. **Redaction patterns** for applications that emit sensitive data to memory traces
4. **Compliance design principles** (privacy by design, data minimization)
5. **Incident response playbook** for audit log breaches

---

## 1. Data Minimization: What runtime-guard Collects

### Collected (Non-PII by Default)

runtime-guard monitors **memory resource metrics only**. The following data is *always* collected locally:

| Metric | Type | Sensitivity | Example |
|--------|------|-------------|---------|
| **Memory available (MB)** | Integer | Low | `8192` |
| **Swap used (%)** | Integer (0–100) | Low | `45` |
| **RSS (resident set) size** | Integer (bytes) | Low | `521932800` |
| **Process PID** | Integer | Low | `12345` |
| **Timestamp** | ISO 8601 UTC | Low | `2026-05-19T14:30:00Z` |
| **Check stage** (label) | String | Low | `test_suite` |
| **Severity** (ok/warning/critical) | Enum | Low | `critical` |
| **Attribution** (self / external) | Enum | Low | `self_inflicted` |

**None of the above contains PII, financial data, or health information by default.**

### NOT Collected

runtime-guard **does not capture**:
- ✅ Application code, variables, or function names
- ✅ Command-line arguments
- ✅ Environment variables (unless explicitly logged by your application)
- ✅ File paths or filenames (beyond the monitoring process itself)
- ✅ Network traffic or request payloads
- ✅ Database queries or credentials
- ✅ Personal health information (PHI) or medical identifiers
- ✅ Financial account numbers or transaction details

---

## 2. Data Residency: Where Data Lives

### On-Host Guarantee

All runtime-guard telemetry **remains on the host** where monitoring occurs:

```
┌─────────────────────────────────────────────────────────┐
│ Host Machine (Linux / macOS / Windows)                  │
│                                                         │
│ ┌──────────────────────────────────────────────────┐   │
│ │ Python Application (e.g., Dask worker)           │   │
│ │                                                  │   │
│ │  guard = RuntimeGuard(                          │   │
│ │     min_mem_available_mb=512,                  │   │
│ │     json_logger_name="my_app.memory"           │   │
│ │  )                                              │   │
│ │                                                  │   │
│ │  event = guard.check()    ← Monitored           │   │
│ └──────────────────────────────────────────────────┘   │
│           ↓                                             │
│ ┌──────────────────────────────────────────────────┐   │
│ │ Local Logging (JSON to stdout/files/syslog)     │   │
│ │ • Kernel snapshots (/proc, vm_stat, PowerShell) │   │
│ │ • Process-local only                            │   │
│ └──────────────────────────────────────────────────┘   │
│           ↓ (Optional)                                  │
│ ┌──────────────────────────────────────────────────┐   │
│ │ Local Audit Log (hash-chain verified)           │   │
│ │ File: audit_log.jsonl                           │   │
│ │ Stored on disk where process runs               │   │
│ └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                       ↓ (Your Choice)
              ┌─────────────────────┐
              │ External Log Store  │
              │ (CloudWatch,        │
              │  DataDog, etc.)     │
              │ ← YOU control what  │
              │   data is sent      │
              └─────────────────────┘
```

### Key Principle: Data Never Leaves the Process Unless You Send It

1. **runtime-guard produces logs** (stdout, files, or logger callbacks).
2. **You decide what to do with those logs** (keep local, aggregate, forward to SaaS).
3. **runtime-guard never automatically forwards data** to external services.

**GDPR Implication:** runtime-guard is a local processor. Data residency depends on where you store the logs, not on runtime-guard itself.

---

## 3. Structured Events: Redaction Patterns for Sensitive Data

If your application's JSON logs contain sensitive data (PII, PHI, financial info), use the **event redactor** to sanitize events *before* they are emitted:

### Example 1: Redacting Patient IDs in Healthcare Pipelines

```python
import json
import logging
from runtime_guard import RuntimeGuard

# Define a redaction function
def redact_phi(event_dict: dict) -> dict:
    """Redact Protected Health Information from runtime-guard events."""
    sanitized = event_dict.copy()
    # Example: mask patient_id if present
    if "patient_id" in sanitized:
        sanitized["patient_id"] = "REDACTED_PHI"
    if "mrn" in sanitized:  # Medical Record Number
        sanitized["mrn"] = "***"
    return sanitized

# Create guard with redaction
guard = RuntimeGuard(
    min_mem_available_mb=512,
    event_redactor=redact_phi,
)

# Logs now emit sanitized events
event = guard.check()
```

### Example 2: Removing PII from Financial Workflows

```python
def redact_pii(event_dict: dict) -> dict:
    """Redact Personally Identifiable Information."""
    sanitized = event_dict.copy()
    # Remove or mask sensitive fields
    fields_to_redact = ["user_id", "email", "account_number", "ssn"]
    for field in fields_to_redact:
        if field in sanitized:
            sanitized[field] = "REDACTED"
    return sanitized

guard = RuntimeGuard(event_redactor=redact_pii)
```

### Example 3: Compliance Presets

runtime-guard includes **predefined redaction presets** for common regulatory frameworks:

```python
from runtime_guard import (
    redaction_preset_gdpr,
    redaction_preset_hipaa,
    redaction_preset_sox,
)

# GDPR: Redact consent flags and user identifiers
guard_eu = RuntimeGuard(event_redactor=redaction_preset_gdpr())

# HIPAA: Redact PHI (patient IDs, medical record numbers, etc.)
guard_healthcare = RuntimeGuard(event_redactor=redaction_preset_hipaa())

# SOX (Sarbanes-Oxley): Redact financial metrics
guard_financial = RuntimeGuard(event_redactor=redaction_preset_sox())
```

### Redaction Guarantees

1. **Fail-safe:** If the redactor raises an exception, runtime-guard emits the original event (not sanitized).
2. **Serialization-safe:** If the redacted output is not JSON-serializable, runtime-guard falls back to the original.
3. **No silent data loss:** Redaction failures are logged with a `redaction_failed=true` flag for audit.

**Configuration:**

```python
from runtime_guard import RuntimeGuard

def safe_redactor(event: dict) -> dict:
    try:
        # Your custom redaction logic
        return {**event, "user_id": "REDACTED"}
    except Exception:
        # Return original on failure
        return event

guard = RuntimeGuard(
    event_redactor=safe_redactor,
    json_logger_name="my_app.memory_safe",
)
```

---

## 4. Audit Logging for Compliance Evidence

### Hash-Chained Audit Log

runtime-guard supports audit logging with cryptographic integrity verification:

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard(
    min_mem_available_mb=512,
    audit_log_path="/var/log/app/runtime_guard_audit.jsonl",  # Hash-chain verified
)

# Every policy event is appended with SHA-256 hash chain
event = guard.check()
```

### Sample Audit Log Entry

```json
{
  "ts": "2026-05-19T14:30:00.123456Z",
  "event_type": "memory_pressure_critical",
  "severity": "critical",
  "mem_available_mb": 128,
  "min_mem_available_mb": 512,
  "attribution": "self_inflicted",
  "stage": "production_pipeline",
  "prev_hash": "abc123...",
  "event_hash": "def456...",
  "hash_algo": "sha256",
  "dedup_suppressed": false
}
```

### Verifying Audit Integrity

```bash
# CLI command to verify hash chain
runtime-guard --verify-audit-log /var/log/app/runtime_guard_audit.jsonl

# Output:
# ✓ Hash chain valid (1,042 records)
# ✓ No tampering detected
# ✓ Chronological order maintained
```

**HIPAA § 164.312(b):** Audit logs provide accountability and non-repudiation evidence.

**GDPR Article 32(b):** Integrity verification demonstrates technical and organizational measures.

---

## 5. Data Retention & Deletion

### Recommended Retention Schedule

| Data Type | Retention Period | Rationale |
|-----------|-----------------|-----------|
| **Memory pressure events** (non-sensitive) | 7 days | Operational troubleshooting window |
| **Audit logs** (compliance) | 1 year | Regulatory requirement (SOC2, PCI-DSS) |
| **Critical incidents** | 2 years | Legal hold for incident investigation |
| **Redacted events** (PII-free) | User policy | No regulatory minimum; keep for trending |

### Deletion & Rotation Policy

```python
import datetime as dt
from pathlib import Path

# Rotate audit logs by date
def rotate_audit_logs(log_dir: str, retention_days: int = 365) -> None:
    """Delete audit logs older than retention period."""
    cutoff = dt.datetime.utcnow() - dt.timedelta(days=retention_days)
    for log_file in Path(log_dir).glob("*.jsonl"):
        mtime = dt.datetime.fromtimestamp(log_file.stat().st_mtime)
        if mtime < cutoff:
            log_file.unlink()
            print(f"Deleted expired log: {log_file}")

# Schedule this daily in cron or systemd timer
# 0 0 * * * /path/to/rotate_audit_logs.py /var/log/runtime_guard
```

**GDPR Compliance:** Document your retention policy in your Privacy Notice (Privacy Policy).

---

## 6. Data Subject Rights & DPIA

### Data Subject Access Requests (DSARs)

If an individual requests their data under GDPR Article 15:

1. **Search audit logs** for references to their identifier (if used as `stage` label):
   ```bash
   grep "user_id_12345" /var/log/runtime_guard_audit.jsonl
   ```

2. **Redact sensitive information** from the response:
   - Remove internal hostnames, IP addresses, stack traces.
   - Keep timestamps, event severity, attribution.

3. **Provide in human-readable format** (e.g., CSV export).

### Data Protection Impact Assessment (DPIA)

runtime-guard itself **does not require a DPIA** because:
- ✅ It processes **non-sensitive metrics** (memory, CPU, timestamps).
- ✅ **No external transmission** of personal data.
- ✅ **Fail-safe redaction** for edge cases.
- ✅ **Hash-chain audit** logs for accountability.

**However,** if you use runtime-guard in a system that processes PII (e.g., a data pipeline with patient data), include runtime-guard in your **existing DPIA** for that system.

### Sample DPIA Entry

```markdown
## Data Processing Activity: Memory Monitoring

- **Process:** RuntimeGuard memory pressure detection
- **Data Categories:** Memory usage (non-personal), process IDs, timestamps
- **Legal Basis:** Legitimate interest (system reliability)
- **Recipients:** System operators, incident response team
- **Safeguards:** Local-only storage, redaction on demand, audit logging
- **Risks:** Indirect PII leakage if application logs are monitored
- **Mitigation:** Event redactor configured; audit trails maintained
```

---

## 7. HIPAA Compliance in Healthcare Pipelines

### Minimum Safeguards for HIPAA § 164.308(a)(3)

| HIPAA Requirement | runtime-guard Support | Implementation |
|------------------|----------------------|-----------------|
| **Encryption at rest** | Yes (via host OS) | Audit logs stored on encrypted filesystem |
| **Encryption in transit** | N/A (local only) | Not applicable; no data leaves host |
| **Access controls** | Yes (via host OS) | File permissions on audit logs (0600) |
| **Audit controls** | Yes (native) | Hash-chain audit logs with timestamps |
| **Integrity controls** | Yes (native) | SHA-256 hash-chain verification |
| **Transmission security** | N/A (local only) | Not applicable |

### Compliance Checklist for Healthcare Deployments

```yaml
HIPAA Compliance Checklist:
  - [ ] Audit logs stored on encrypted volume
  - [ ] File permissions set to 0600 (owner read/write only)
  - [ ] Retention policy documented (min. 6 years for healthcare)
  - [ ] Access logged via host syslog or auditd
  - [ ] Breach response plan includes runtime_guard audit logs
  - [ ] Risk assessment completed (see HIPAA DPIA template)
```

### Deploying runtime-guard in HIPAA Environments

```python
import os
from runtime_guard import RuntimeGuard

# HIPAA-compliant guard configuration
guard = RuntimeGuard(
    min_mem_available_mb=2048,  # Stricter threshold for healthcare workloads
    audit_log_path="/var/log/hipaa_compliant/runtime_guard_audit.jsonl",
    event_redactor=redaction_preset_hipaa(),  # Redact PHI automatically
)

# Ensure audit log directory has strict permissions
os.makedirs("/var/log/hipaa_compliant", mode=0o700, exist_ok=True)

# Verify hash chain daily
# Scheduled task: runtime-guard --verify-audit-log /var/log/hipaa_compliant/runtime_guard_audit.jsonl
```

---

## 8. Incident Response & Breach Notification

### If Your Audit Logs Are Compromised

**Scenario:** An attacker gains access to `/var/log/runtime_guard_audit.jsonl`.

**Impact Assessment:**
1. **What they could see:**
   - Memory usage patterns (process allocation, swap thrashing)
   - Timestamps of memory pressure events
   - Process IDs (potentially re-linked to running processes)
   - Stage labels (if you tag logs with user/org IDs — **discouraged**)

2. **What they cannot see:**
   - Application code, variables, or function names
   - User input, requests, or payloads
   - Database queries or credentials
   - Financial transactions or health records

**Response Steps:**

```bash
# 1. Rotate credentials and keys
cd /var/log/runtime_guard && \
  sudo rotate-api-keys.sh

# 2. Verify audit log integrity after breach
runtime-guard --verify-audit-log /var/log/runtime_guard_audit.jsonl

# 3. Check for tampering (hash chain breaks indicate modification)
# If hash chain is broken, the log has been modified and is unreliable

# 4. Archive compromised log for forensics
sudo tar czf /secure/backup/audit_backup_$(date +%s).tar.gz \
  /var/log/runtime_guard_audit.jsonl

# 5. Rotate the log file (start fresh)
sudo mv /var/log/runtime_guard_audit.jsonl \
  /var/log/runtime_guard_audit_backup_$(date +%s).jsonl
```

### GDPR Breach Notification (72-Hour Rule)

If you store redacted memory events that *could* be linked to individuals:

```python
# Example: Notifying GDPR authority if audit logs breach
NOTIFICATION = """
Breach Notification to DPA:

- Controller: {company_name}
- Data Processed: Application memory metrics (timestamps, process IDs)
- Breach Date: {date}
- Discovery Date: {date}
- Affected Individuals: None directly (data is non-personal)
- Safeguard Measure: Hash-chain audit logs
- Mitigation: Event redactor prevents PII emission
- Likelihood of Rights/Freedoms Harm: Low (metrics only, no PII)
"""
```

**Key Point:** If you're using runtime-guard correctly (with redaction enabled), there's **minimal breach risk** to individuals because the data is inherently non-sensitive.

---

## 9. FAQ: Common Compliance Questions

### Q1: Does runtime-guard "see" the data inside my application?

**A:** No. runtime-guard only monitors OS-level memory metrics (available memory, swap usage, RSS). It does not:
- Read application variables or state
- Inspect function stacks (unless you explicitly pass them to a redactor)
- Capture user input or requests

---

### Q2: Is runtime-guard suitable for HIPAA environments?

**A:** Yes, **with proper configuration**:
1. Use `event_redactor=redaction_preset_hipaa()` to sanitize any PHI references.
2. Store audit logs on an encrypted volume with restricted file permissions.
3. Implement a 6-year retention policy (standard for healthcare).
4. Include runtime-guard audit logs in your regular HIPAA risk assessment.

---

### Q3: Can runtime-guard help us pass a SOC2 audit?

**A:** Yes. runtime-guard provides evidence for:
- **CC6.2** (Processing Integrity): Memory pressure monitoring detects anomalies.
- **CC7.3** (Restricted System Access): Audit logs track access to sensitive thresholds.
- **CC8.1** (Change Management): Policy reloading with versioning (see ROADMAP M2-C03).

---

### Q4: What if my company has stricter data retention than GDPR?

**A:** Configure a custom retention policy:

```python
import datetime as dt
from pathlib import Path

RETENTION_DAYS = 90  # Stricter than GDPR minimum (7 days)

def delete_old_logs(log_dir: str) -> None:
    cutoff = dt.datetime.utcnow() - dt.timedelta(days=RETENTION_DAYS)
    for log in Path(log_dir).glob("*.jsonl"):
        if dt.datetime.fromtimestamp(log.stat().st_mtime) < cutoff:
            log.unlink()
```

---

### Q5: Can I anonymize runtime-guard logs for analytics?

**A:** Yes. Before sharing logs externally:

```python
import json
from pathlib import Path

def anonymize_logs(log_path: str) -> list[dict]:
    """Remove potentially identifiable information."""
    anonymized = []
    with open(log_path) as f:
        for line in f:
            event = json.loads(line)
            # Remove process IDs (could be linked to users)
            event.pop("pid", None)
            # Remove stage labels if they contain user identifiers
            event["stage"] = "anonymized"
            # Keep only: severity, mem_available_mb, timestamp
            anonymized.append({
                "severity": event.get("severity"),
                "mem_available_mb": event.get("mem_available_mb"),
                "ts": event.get("ts"),
            })
    return anonymized
```

---

## 10. Compliance Evidence Checklist

Use this checklist to demonstrate runtime-guard compliance during audits:

```markdown
## Compliance Evidence Inventory

### Data Minimization (GDPR Article 5)
- [ ] Documentation: Data minimization policy (this document)
- [ ] Code: Event redactor configured for application
- [ ] Test: Redaction tests in CI/CD pipeline
- [ ] Evidence: Sample redacted log entries

### Data Residency (GDPR Article 32)
- [ ] Architecture: Data never leaves the host (diagram included)
- [ ] Code: No external transmissions in runtime_guard module
- [ ] Test: Integration test blocking external calls
- [ ] Evidence: Network capture showing local-only traffic

### Access Control (GDPR Article 32, HIPAA § 164.308(a)(3))
- [ ] Config: File permissions on audit logs (0600)
- [ ] Config: SELinux/AppArmor policy restricting access
- [ ] Logging: auditd tracking access to audit logs
- [ ] Evidence: auditd logs for audit period

### Audit Logging (GDPR Article 32(b), HIPAA § 164.312(b))
- [ ] Feature: Hash-chain audit logs enabled
- [ ] Process: Daily verification via `--verify-audit-log`
- [ ] Monitoring: Alerts if hash chain breaks
- [ ] Evidence: Sample verified audit logs

### Retention Policy (GDPR Article 17)
- [ ] Policy: Documented retention schedule (90 days for ops, 1 year for audit)
- [ ] Automation: Cron job to rotate logs on schedule
- [ ] Testing: Log rotation test in test suite
- [ ] Evidence: Rotation logs showing successful deletion

### Incident Response
- [ ] Playbook: Breach response plan references runtime_guard
- [ ] Contact: DPA notification template (if required)
- [ ] Testing: Tabletop exercise confirming response steps
```

---

## 11. References & Further Reading

- **GDPR:** EU General Data Protection Regulation (2018/679)
  - Article 5: Principles relating to processing of personal data
  - Article 17: Right to erasure
  - Article 32: Security of processing
  
- **HIPAA:** U.S. Health Insurance Portability and Accountability Act (45 CFR § 164)
  - § 164.308(a)(3): Administrative safeguards
  - § 164.312: Technical safeguards
  
- **SOC2:** American Institute of Certified Public Accountants (AICPA)
  - Trust Service Criteria: CC6 (Logical/Physical Access), CC7 (Change Management), CC8.1 (Monitoring)

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-05-19 | Initial release: GDPR/HIPAA guide, redaction patterns, incident response |

---

**Questions?** Contact the runtime-guard team at [support email] or open an issue on GitHub.
