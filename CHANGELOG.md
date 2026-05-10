# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added
- GitHub Actions CI workflow with test, lint, and high-severity security checks.
- Open-source project policy files: LICENSE, SECURITY.md, and CODE_OF_CONDUCT.md.
- `attach_polars_guard()` integration helper for hooking RuntimeGuard into
  `polars.LazyFrame.collect` without introducing a hard runtime dependency.
- `attach_polars_guard()` now also hooks `polars.LazyFrame.fetch` when
  available, with shared restore/idempotent semantics.
- `attach_dask_guard()` integration helper for hooking RuntimeGuard into
  `dask.compute`/`dask.persist` without introducing a hard runtime dependency.
- `attach_dask_guard()` now also hooks `dask.base.compute` and
  `dask.base.persist` when available.
- `attach_ray_guard()` integration helper for hooking RuntimeGuard into
  `ray.get`/`ray.wait` without introducing a hard runtime dependency.
- `attach_ray_guard()` now also hooks `ray.put` when available.
- OpenTelemetry exporter scaffolding: `pressure_report_attributes()` and
  `emit_otel_event()` for optional span event emission.
- Prometheus scaffolding: `render_prometheus_metrics()` for dependency-free
  exposition text rendering suitable for `/metrics` endpoints.
- Distributed tracing context scaffolding: `trace_context_attributes()` and
  OTEL event enrichment with trace/span IDs when available.
- Config schema validation scaffolding: `validate_runtime_guard_config()` with
  optional pydantic support and strict fallback validation.
- Phase context scaffolding: `guard.phase(...)` supports `with` and
  `async with` for phase-scoped memory checks.
- Signal recovery scaffolding: `attach_signal_recovery()` and
  `RuntimeGuard.install_signal_recovery()` for final signal-triggered checks.
- Audit scaffolding: `append_audit_log()` and `RuntimeGuard.audit()` for
  append-only hash-chained policy event records.
- Dynamic policy reloading scaffolding: `set_policy_overrides()`,
  `load_policy_file()`, and `reload_policy_if_changed()`.
- Multi-process orchestration scaffolding: `make_worker_report()` and
  `aggregate_worker_reports()` plus RuntimeGuard wrappers.
- Integrity hardening: FIPS SHA-2 hash selection (`sha256|sha384|sha512`) and
  audit-chain verification via `verify_audit_log_chain()`.
- Compliance scaffold: `soc2_gap_assessment()` for SOC2 control coverage,
  missing-control reporting, and readiness status.
- SOC2 baseline helper: `soc2_required_controls()` and expanded gap output
  with missing required controls and unknown control detection.
- Enterprise support package draft in `ENTERPRISE_SUPPORT.md` with incident
  severities, response targets, and runbook entry points.
- Enterprise adoption execution tracker in `ADOPTION_TRACKER.md` with stage
  definitions, per-team evidence checklist, and milestone success criteria.
- Polars adoption playbook in `INTEGRATION_POLARS.md` with rollout phases,
  validation workflow, and evidence checklist for M1-I01.
- Dask issue intake template in `.github/ISSUE_TEMPLATE/dask-memory-diagnostics.yml`
  to collect runtime-guard check/snapshot evidence for incident triage.
- Linux background service automation: `scripts/runtime_guard_repo_watcher.py`
  plus user-service templates in `scripts/systemd/` for repo-activity-aware
  monitoring.
- Repo autostart seeding utility: `scripts/seed_repo_autorun.py` and
  `make_sitecustomize_content()` for generating `sitecustomize.py` bootstrap
  files that self-start RuntimeGuard background checks.
- CLI audit verification mode: `--verify-audit-log PATH` to validate
  hash-chained audit logs with exit-code semantics for CI/ops workflows.
- Signal-recovery rollout defaults: `resolve_signal_recovery_policy()` and
  `install_signal_recovery_from_policy()` for environment-driven recovery
  behavior standardization.
- Audit policy taxonomy helpers: `audit_policy_taxonomy()` and
  `normalize_policy_violation_event()` with canonical token normalization for
  `event_type=policy_violation` records.
- Adoption execution automation: `build_adoption_scorecard()` API for multi-team
  rollout progress tracking plus `scripts/adoption_scorecard.py` CLI for
  stage aggregation and missing-evidence reporting.
- Polars integration validation: `validate_polars_integration()` and
  `collect_polars_integration_evidence()` for adoption evidence collection
  and M1-I01 rollout verification.
- Dask integration validation: `validate_dask_integration()` and
  `collect_dask_integration_evidence()` for adoption evidence collection
  and M1-C02 integration verification.
- SOC2 readiness enhancements: `soc2_evidence_requirements()` and
  `soc2_readiness_report()` now track evidence completeness alongside control
  coverage for audit-readiness evaluation.
- Ray integration cookbook in `INTEGRATION_RAY.md` with staged hook,
  orchestration, and audit logging examples.
- Training/certification program draft in `TRAINING_CURRICULUM.md` with
  1-day agenda, lab structure, and certification rubric.

### Changed
- Roadmap M1-C01 moved to IN PROGRESS based on implemented integration scaffold.
- Roadmap M1-C02 moved to IN PROGRESS based on implemented integration scaffold.
- Roadmap M1-C03 moved to IN PROGRESS based on implemented integration scaffold.
- Roadmap M1-C04 moved to IN PROGRESS based on implemented exporter scaffold.
- Roadmap M1-C05 moved to IN PROGRESS based on implemented metrics scaffold.
- Roadmap M1-C06 moved to IN PROGRESS based on implemented tracing scaffold.
- Roadmap M1-C07 moved to IN PROGRESS based on implemented config scaffold.
- Roadmap M1-C08 moved to IN PROGRESS based on implemented phase scaffold.
- Roadmap M2-C01 moved to IN PROGRESS based on implemented signal scaffold.
- Roadmap M2-C02 moved to IN PROGRESS based on implemented audit scaffold.
- Roadmap M2-C03 moved to IN PROGRESS based on implemented policy scaffold.
- Roadmap M2-C04 moved to IN PROGRESS based on implemented orchestration scaffold.
- Roadmap M2-C05 moved to IN PROGRESS based on implemented integrity scaffold.
- Roadmap M2-C06 moved to IN PROGRESS based on implemented compliance scaffold.
- Roadmap M2-I01 moved to IN PROGRESS based on enterprise support package draft.
- Roadmap M2-I02 moved to IN PROGRESS based on adoption tracker kickoff.
- Roadmap M1-I01 moved to IN PROGRESS based on Polars integration playbook kickoff.
- Roadmap M1-I02 moved to IN PROGRESS based on Dask issue template kickoff.
- Roadmap M2-I01 note expanded with repo background-service automation artifacts.
- Roadmap M1-I03 moved to IN PROGRESS based on Ray cookbook kickoff.
- Roadmap M2-I03 moved to IN PROGRESS based on curriculum draft kickoff.

## [0.3.0] - 2026-05-10

### Added
- Full argparse CLI (`runtime-guard`) with `--snapshot`, `--check`, `--report`,
  `--generate-wslconfig`, `--posture`, `--stage`, and `--version`.
- 19 additional tests for recent fixes and CLI behavior.
- README expansion: full API reference, architecture, WSL utilities, and FAQ.

### Changed
- Windows memory reader now uses PowerShell `Get-CimInstance` first with `wmic`
  fallback for older builds.
- macOS snapshot reader now uses `sysctl hw.pagesize` and locale-safe parsing.
- Cooldown deduplication is now per `(stage, severity)` instead of global.
- `generate_wslconfig()` now merges managed keys and creates backups.

### Fixed
- KI-001: macOS locale-sensitive page-size parsing.
- KI-002: reliance on deprecated `wmic` on modern Windows.
- KI-003: forked child process stale background-thread state.
- KI-004: cooldown suppression incorrectly shared across stages.
- KI-005: unsupported-platform path returned silent zero snapshot.
- KI-006: `.wslconfig` overwrite without backup/merge.

## [0.2.0] - 2026-05-02

### Added
- Threshold presets (`tight`, `relaxed`, `ci`).
- Structured JSON events on `runtime_guard.events`.
- Cooldown/deduplication support.
- Background daemon check support.
- Initial WSL reporting and kernel tuning helpers.
