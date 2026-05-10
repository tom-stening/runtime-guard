# Enterprise Support Package — runtime-guard

This document defines the initial enterprise support package for production users.

## Scope

The package covers:
- Incident response expectations and severity classification.
- Support-level objectives (SLOs) for first response and status updates.
- Runbook entry points for common runtime-guard operational incidents.
- Evidence and audit artifacts for regulated environments.

## Service Levels

| Severity | Definition | Initial Response Target | Update Cadence | Mitigation Target |
|---|---|---|---|---|
| Sev 1 | Active production outage or data pipeline halt tied to runtime-guard behavior. | 4 hours | Every 4 hours | 24 hours for workaround or rollback guidance |
| Sev 2 | Significant degradation or repeated pressure misclassification impacting operations. | 8 business hours | Daily | 3 business days for mitigation plan |
| Sev 3 | Non-blocking bug or documentation gap with moderate impact. | 2 business days | Every 3 business days | Next minor release target |
| Sev 4 | Questions, enhancement requests, or low-impact edge cases. | 3 business days | Weekly | Best effort; roadmap triage |

Notes:
- Targets are objective goals, not legal guarantees.
- "Business hours" defaults to Monday-Friday, 09:00-17:00 UTC.

## Support Tiers

| Tier | Intended Users | Included Channels | Sev 1 Initial Response | Sev 2 Initial Response | Notes |
|---|---|---|---|---|---|
| Standard | Small teams, pilot deployments | GitHub issues + async maintainer triage | 8 hours | 2 business days | Best for evaluation and early rollout. |
| Priority | Production teams with regular workloads | Dedicated triage queue + issue escalation labels | 4 hours | 8 business hours | Recommended default for enterprise production. |
| Mission Critical | Regulated and high-availability pipelines | Priority channel + hotfix coordination | 1 hour | 4 business hours | Includes coordinated incident bridge for Sev 1. |

Tier mapping guidance:
- Start with `Priority` once a team reaches production stage.
- Move to `Mission Critical` for workloads with strict SLA penalties or compliance commitments.
- Maintain a per-team on-call roster and escalation contact for Sev 1 qualification.

## Intake Requirements

To speed triage, include:
- runtime-guard version (`runtime-guard --version`).
- Platform details (OS, kernel, Python version).
- Check stage and pressure event context.
- Structured event sample from `runtime_guard.events` logger.
- Whether `self_inflicted` was true/false and top process table snippet.

## Incident Runbook Entry Points

### RB-01: False Positive Pressure Alerts

1. Capture one full `--snapshot` and one `--check --stage` output.
2. Confirm threshold posture and explicit env var overrides.
3. Compare `self_inflicted` attribution against host process table.
4. Adjust posture to `relaxed` as short-term mitigation if safe.
5. Create issue with event payload and override history.

### RB-02: Missing Alerts During Known Pressure

1. Confirm check cadence (manual, phase context, or background checker).
2. Verify `cooldown_s` is not suppressing expected repeats.
3. Validate stage labels are unique enough for dedupe semantics.
4. Re-run with `cooldown_s=0` to confirm detection path.
5. Capture reproducer and file issue with snapshots.

### RB-03: WSL or Kernel-Tuning Concerns

1. Run `runtime-guard --report` and store output artifact.
2. Generate proposed `.wslconfig` with `--generate-wslconfig`.
3. Review recommendations before write/apply.
4. Roll forward with backup/rollback plan.
5. Record outcome and any performance delta.

## Audit and Evidence Artifacts

For regulated environments, retain:
- Audit records from `append_audit_log()` / `RuntimeGuard.audit()`.
- Integrity verification outputs from `verify_audit_log_chain()`.
- SOC2 gap snapshots from `soc2_gap_assessment()`.
- Release validation logs (`pytest`, `ruff`, `bandit`) per change window.

## Escalation Model

- Maintainer triage handles Sev 2-4 and initial Sev 1 response.
- Sev 1 incidents escalate to patch/hotfix path immediately.
- Security-relevant incidents also follow [SECURITY.md](SECURITY.md).

## Review Cadence

Review this package at least once per quarter or whenever release rhythm changes.
