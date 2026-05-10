# Mastering Memory Diagnostics (1-Day Curriculum)

This curriculum advances roadmap item M2-I03.

## Audience

- Data engineers and ML platform engineers
- SRE and observability practitioners supporting Python pipelines
- Tech leads onboarding runtime-guard in regulated environments

## Learning Outcomes

By the end of the workshop, participants can:
- Explain runtime pressure attribution (`self_inflicted` vs external).
- Integrate runtime-guard with Polars, Dask, and Ray entry points.
- Configure thresholds/postures per environment.
- Build incident evidence from snapshots, event logs, and audit chains.
- Operate repo-level background monitoring with systemd user services.

## Agenda (1 Day)

| Time (UTC) | Module | Format |
|---|---|---|
| 09:00-09:45 | Module 1: Attribution-first memory diagnostics | Lecture + demo |
| 09:45-10:45 | Module 2: Core API and threshold tuning | Hands-on |
| 11:00-12:00 | Module 3: Framework integration (Polars/Dask/Ray) | Hands-on |
| 13:00-14:00 | Module 4: Observability and event pipelines | Workshop |
| 14:00-15:00 | Module 5: Audit integrity and compliance evidence | Workshop |
| 15:15-16:15 | Module 6: Service automation and runbook operations | Hands-on |
| 16:15-17:00 | Capstone: Incident simulation and remediation plan | Team exercise |

## Labs

1. Baseline check and posture tuning in a sample pipeline.
2. Integrate hooks in one framework path and verify event output.
3. Generate and verify audit log chain for pressure incidents.
4. Deploy background watcher service for repository-level monitoring.
5. Perform triage with issue template and runbook artifacts.

## Certification Rubric

Certification requires all of:
- Completion of all labs.
- Capstone incident report with attribution and remediation plan.
- Demonstration of one framework integration and one automation path.
- Minimum score 80% on post-workshop assessment.

## Delivery Assets

- Slide deck: architecture and attribution model.
- Lab handbook with step-by-step instructions.
- Sample datasets and synthetic pressure scenarios.
- Grading rubric and answer guide.

## Maintenance Cadence

- Review curriculum quarterly.
- Update examples after major runtime-guard release.
- Sync compliance module with latest SOC2/GDPR guidance updates.
