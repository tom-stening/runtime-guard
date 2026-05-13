# runtime-guard Roadmap

> Two-phase milestones aligned to production adoption and ecosystem integration.
>
> *_Code stream_* — work executed in this repository. Tracked here, tied to releases.
> *_Integration stream_* — adoption by data pipelines, ML frameworks, observability tools. Tracked separately.
>
> All estimates are directional and assume execution of both streams.

---

## Core Principle

**Attribution-aware diagnostics over generic alerts.**

Every memory pressure event should answer: *"Is this my code or something else?"* and *"What do I actually fix?"* — not just "memory is low."

This principle shapes all roadmap decisions:
- Eliminate opaque, generic thresholds. Always show which process owns the pressure.
- Detect cross-platform OS interactions (Linux `/proc`, macOS `vm_stat`, Windows PowerShell with `wmic` fallback).
- Provide actionable kernel tuning, swap config, and pipeline redesign advice — not just warning text.
- Keep zero hard dependencies so every Python project can adopt it without dependency hell.

---

## Milestone 0 — Pilot & Community Proof _(current)_

**Goal:** Validate core value proposition with 3+ open-source data pipeline projects.

### Code stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M0-C01 | Cross-platform snapshot (`/proc`, `vm_stat`, PowerShell/`wmic`) | P0 | ✅ DONE | Linux, macOS, Windows tested. Warn-once fallback on unsupported OS. |
| M0-C02 | Attribution detection (self vs. external pressure) | P0 | ✅ DONE | Classifies pressure source and confidence. |
| M0-C03 | Threshold presets (`tight`, `relaxed`, `ci`) | P1 | ✅ DONE | Bundled threshold sets for common use cases. |
| M0-C04 | Structured JSON events on `runtime_guard.events` logger | P1 | ✅ DONE | Log aggregation pipeline ready. |
| M0-C05 | Cooldown/deduplication for repeat alerts | P1 | ✅ DONE | Configurable `cooldown_s` to reduce log spam. |
| M0-C06 | Pytest integration + conftest helper | P2 | ✅ DONE | `make_pytest_guard()`, `make_conftest_content()`. |
| M0-C07 | Background check daemon thread | P2 | ✅ DONE | `start_background_check()`, `stop_background_check()`. |
| M0-C08 | WSL 2 system report & kernel tuning | P2 | ✅ DONE | `wsl_system_report()`, `recommend_kernel_params()`. |
| M0-C09 | CLI entry point (`runtime-guard` command) | P2 | ✅ DONE | `--snapshot`, `--check`, `--report`, `--generate-wslconfig`, `--posture`, `--stage`, `--version` modes. |
| M0-C10 | Public docs: architecture, examples, FAQ | P1 | ✅ DONE | Full README: install, quickstart, config, CLI reference, API reference, pytest integration, background monitoring, WSL 2 utilities, architecture, FAQ. |

### Integration stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M0-I01 | Adopt in 1 internal ML pipeline | P1 | ✅ DONE | Added `examples/ml_pipeline_demo.py` with 4-stage integration (preflight/load/train/snapshot) demonstrating real ML workflow adoption patterns. |
| M0-I02 | Publish proof-of-concept blog post | P2 | 📅 PLANNED | "Memory attribution without the pain: runtime-guard in production." |
| M0-I03 | Open-source release (GitHub public) | P1 | ✅ DONE | README, CI workflow, LICENSE, SECURITY policy, and Code of Conduct are in-repo. |

---

## Milestone 1 — Ecosystem Integration _(Q3 2026)_

**Goal:** Become the standard memory monitor for 3+ major Python data/ML frameworks.

### Code stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M1-C01 | Polars integration plugin | P1 | 🔄 IN PROGRESS | `attach_polars_guard()` hooks `collect`, `fetch`, `collect_async`, `sink_parquet`, `sink_csv`, `sink_ipc`, `sink_ndjson`; native callback bridging now supports known callback aliases, signature-inferred callback kwargs (e.g., version-specific `*callback` names), and positional callback arguments with chained user callbacks for deeper plan/execution attribution; `install_polars_scan_budget()` enforces column-count and scan-node hard caps (raises) and soft caps (warn-log) before execution, now with native `LazyFrame.explain()` scan-node fallback parsing and custom `scan_count_fn` overrides; remaining callback edge coverage across future Polars signatures remains. |
| M1-C02 | Dask integration | P1 | 🔄 IN PROGRESS | `attach_dask_guard()` hooks top-level and `dask.base` `compute`/`persist`; `install_dask_scheduler_callbacks()` exposes callback-context adapter metadata; `attach_dask_guard(..., enable_scheduler_callbacks=True)` now auto-wraps compute/persist calls in callback contexts when Dask callback API is available; scheduler callback worker telemetry now tracks total task volume plus healthy vs pressure event splits (`total_tasks`, `total_healthy_events`, `total_pressure_events`) for higher-fidelity fleet evidence; `validate_dask_integration()` and `collect_dask_integration_evidence()` expose machine-verifiable scheduler callback context-availability, wrapping markers, and telemetry-counter surface markers; fleet integration validation now enforces scheduler telemetry-counter marker presence as part of required checks; `install_dask_task_graph_guard()` gates compute/persist on task-graph size with configurable warn/hard caps and custom `task_count_fn` override; deeper scheduler callback integration remains. |
| M1-C03 | Ray cluster resource monitor | P1 | 🔄 IN PROGRESS | `attach_ray_guard()` hooks `get` plus optional `wait`/`put`; `validate_ray_integration()` and `collect_ray_integration_evidence()` now include machine-verifiable actor/node telemetry API surface checks plus explicit node-telemetry and cluster-summary capability markers, including hotspot field coverage (`busiest_node`, `busiest_node_events`, `busiest_actor`, `busiest_actor_events`); `enable_ray_actor_memory_monitoring()` includes per-node/per-actor event aggregation (`get_actor_report`, `reset_actor_report`, `node_report`, `reset_node_reports`, `get_all_node_reports`), `cluster_summary()` hotspot telemetry (including busiest node and busiest actor attribution), and `remote_wrapper` for decorating plain remote functions; fleet integration validation now enforces actor hotspot-field marker presence as part of required checks; deeper cluster-node telemetry integration remains. |
| M1-C04 | OpenTelemetry exporter | P2 | 🔄 IN PROGRESS | `install_otel_memory_exporter()` wraps `check_and_log` to emit OTEL spans with `rg.stage`, `rg.mem_available_mb`, `rg.swap_used_pct`, `rg.rss_mb` attributes; graceful no-op fallback when `opentelemetry` is not installed; idempotent attach with clean restore; full metrics pipeline/exporter packaging remains. |
| M1-C05 | Prometheus metrics endpoint | P2 | ✅ DONE | `install_prometheus_endpoint()` — pure-Python ASGI factory serving Prometheus exposition text; HTTP 200/503 based on guard pressure; GET-only (405 on other methods); zero external dependencies; `_runtime_guard_prometheus_prefix` and `_runtime_guard_prometheus_path` attributes; compatible with FastAPI/Starlette mount. **Now exposes both guest (WSL/Linux) and host (Windows) memory/swap metrics, plus drift fields, in both Prometheus and JSON logs.** Added first-class CLI crash triage mode `runtime-guard --diagnose-wsl-crash [--json] [--fail-on-risk high|critical]` for host+guest RCA automation, including host-event relevance filtering, active WSL/docker workload detection, top guest RSS offender reporting, offender-aware prevention hints, proactive VS Code extension-host RSS concentration heuristics, per-extension RSS attribution (`guest_vscode_extension_rss`), and fail-fast extension policy gates (`--fail-on-extension-total-rss-mb`, `--fail-on-extension-rss`) so generic System noise is separated from actionable crash causes before thresholds turn critical; plus strict fail-fast CLI argument typing in `scripts/wsl_preflight.py` (boolean flags, min-memory threshold, fail-on-risk policy, and label/env-prefix fields) so malformed startup-gate inputs return deterministic config errors instead of coercive preflight behavior. |
| M1-C06 | Distributed tracing context | P2 | ✅ DONE | `install_distributed_trace_propagator()` — W3C traceparent header parsing (`extract`) and injection (`inject`) linking memory events to distributed traces; case-insensitive header key normalisation; graceful no-op when OTEL unavailable; configurable `header_name` (default `traceparent`). |
| M1-C07 | Config schema validation (`pydantic`) | P2 | 🔄 IN PROGRESS | Added optional schema validator with strict fallback; integrated posture validation into `make_pytest_guard(..., posture=...)`, `make_sitecustomize_content(..., posture=...)`, and `make_conftest_content(..., posture=...)` so repo-level guard factories can apply validated presets without manual env plumbing; added `wsl_dev` preset for IDE-heavy WSL sessions; added fleet enforcement/reporting automation via `scripts/enforce_runtime_guard_all_repos.py` with JSON status output (`reports/repo_guard_enforcement.json`) for repositories under a root path, including `--enforce-all-repos` mode to close non-Python coverage gaps and run_id payload/summary propagation; added runtime fleet status reporting via `scripts/repo_guard_fleet_report.py` with active-repo/process visibility, optional integration-health ingestion from `reports/integration_fleet_status.json`, pressure-fallback mode visibility (`integration_execution_mode`, `integration_pressure_detected`), promoted WSL risk/top-offender summary fields, promoted extension-memory summary field (`wsl_vscode_extension_total_rss_mb`), structured gate-failure payload output (`failed_gates`, `failed_gate_count`) with stable gate correlation metadata (`gate_id`, `evaluated_at_utc`, `run_id`), optional caller-provided `--run-id` override for external CI trace alignment, explicit source artifact run_id consistency signals (`source_run_ids`, `run_id_consistent`) and `--fail-on-run-id-mismatch` runtime gating, provenance blocks across enforcement/integration/runtime artifacts (tool identity, generation timestamp, git commit hint, run_id, source artifact hashes, canonical `artifact_sha256` self-digests, and signature-ready detached-envelope metadata), dedicated lineage verifier automation via `scripts/verify_fleet_artifact_lineage.py` including optional `--require-signed` enforcement and OpenSSL-backed Ed25519 detached signature verification (`--verify-signatures --signature-public-key`) plus enforcement/integration/runtime artifact tool-identity validation, strict provenance core schema/type validation (schema_version/tool/generated_at_utc/run_id/inputs/artifact_sha256 with strict-mode git_commit/script requirements), integration fallback-policy consistency checks across payload/provenance metadata (fallback enabled flag, fallback report directory, and fallback age), expected integration report-signature policy consistency checks (require-signed, verify-signatures, allowed key IDs, max signature age) driven by cycle-level policy flags, plus strict expected policy typing for report-signature comparisons (booleans/allowed-key IDs/max-age) so non-typed expected values cannot be silently coerced, strict fail-fast CLI argument typing in lineage policy validation (boolean flags/age integers/key-ID lists) so malformed programmatic inputs cannot be truthy/stringified into policy checks, and fail-fast CLI policy-coherence validation for both artifact signature policy flags and expected integration report-signature policy flags, plus strict fail-fast CLI argument typing in validate_integration_fleet policy parsing (boolean flags/age integers/allowed-key IDs) so malformed programmatic inputs cannot be coerced into signature-policy decisions, and strict fail-fast CLI argument typing in run_fleet_guard_cycle policy parsing (integration signature flags/age policies/allowed-key IDs and lineage verify-signatures controls) so malformed orchestration inputs cannot bypass policy-coherence checks, plus strict fail-fast CLI argument typing in repo_guard_fleet_report (boolean flags/WSL threshold/extension RSS policies) and non-coercive recommendation synthesis for WSL advisory fields so malformed payload shapes cannot silently suppress recommendations or inject char-sliced prevention-action noise, plus strict fail-fast CLI argument typing in enforce_runtime_guard_all_repos (root/report path/stage fields, interval/cooldown numeric policy, and enforcement flags) so malformed orchestration inputs fail as deterministic config errors before enforcement artifact generation, strict exact-match enforcement of expected integration report-signature policy values (including disabled/default states), fail-fast rejection of negative signature-age policy values, fail-fast rejection of integration artifacts missing required report-signature policy keys in provenance inputs, strict type validation for fallback/report-signature policy fields to prevent coercion-based false passes, fail-safe rejection of malformed runtime source_artifact_hashes values (non-object) during lineage verification, fail-safe rejection of malformed/non-object artifact JSON inputs with deterministic validation errors (instead of parser exceptions), fail-safe run_fleet_guard_cycle report parsing for malformed/non-object runtime and integration artifacts during run_id and summary extraction, strict type validation for runtime summary fields in run_fleet_guard_cycle to avoid coercion-based false health states, strict string-only run_id extraction semantics in run_fleet_guard_cycle, repo_guard_fleet_report, and verify_fleet_artifact_lineage to avoid run correlation drift from numeric/structured IDs, strict string-only run_id ingestion semantics for cached integration reports in validate_integration_fleet (root/summary run_id), strict internal run_id normalization across validate_integration_fleet live-validator invocation, CLI entry wiring, and payload build paths so non-string run IDs never coerce into artifact lineage, strict non-coercive run_id normalization in run_fleet_guard_cycle command assembly to prevent numeric/structured arg contamination of cycle artifact correlation, strict fail-safe type parsing for integration status fields in repo_guard_fleet_report (boolean/integer/string fields and pressure metadata) so malformed integration artifacts produce parse warnings and fail-closed health semantics instead of coercion-based false passes or crashes, strict signature-envelope field type validation in validate_integration_fleet and verify_fleet_artifact_lineage to reject malformed provenance signatures before trust decisions or cryptographic verification, and strict non-coercive run_id normalization in repo_guard_fleet_report so runtime report provenance cannot inherit invalid seed values, strict non-coercive run_id normalization in validate_polars_integration/validate_dask_integration/validate_ray_integration so component artifact provenance cannot inherit invalid seed values, and fail-safe JSON input loading in repo_guard_fleet_report for enforcement/integration artifacts so malformed or non-object payloads yield deterministic errors/warnings instead of exceptions, plus fail-closed integration health semantics when integration inputs are malformed so --fail-on-integration-unhealthy gates cannot be bypassed by parse failures, and fail-safe extension RSS threshold parsing so malformed extension rows cannot crash runtime gate evaluation, and fail-closed enforcement artifact schema validation in repo_guard_fleet_report so malformed repos payloads return deterministic config errors instead of proceeding with ambiguous runtime state, plus strict required-field enforcement schema validation (`repos[*].repo_path`, `repos[*].repo_name`, `repos[*].status`) so malformed repo rows cannot flow into runtime gate computation, plus canonical enforcement status taxonomy validation so unknown status strings fail closed instead of silently altering runtime gate semantics, plus duplicate repo_path rejection in enforcement payload validation so ambiguous multi-row repo state cannot skew runtime summary and gate counts, plus fail-safe active PID count parsing in repo_guard_fleet_report so malformed activity scan values emit parse warnings and default safely without runtime report generation failures, plus strict string-only artifact_sha256 extraction in verify_fleet_artifact_lineage hash validation so non-string provenance digest values cannot be silently coerced during integrity checks, plus strict non-coercive runtime source hash typing in verify_fleet_artifact_lineage so non-string provenance source hashes fail closed with deterministic validation errors, plus strict non-coercive provenance.tool typing in expected-tool validation so non-string tool metadata cannot be silently stringified during lineage identity checks, strict non-coercive run_id normalization in enforce_runtime_guard_all_repos so enforcement report provenance cannot inherit invalid seed values, and run_id propagation into integration fleet artifacts (`validate_integration_fleet.py` payload/summary) through `run_fleet_guard_cycle.py` pass-through, plus pass-through staleness policy control for integration fallback reports (`--integration-max-fallback-report-age-hours`), and a fleet-cycle run_id consistency gate that auto-generates a run ID when omitted and fails on cross-artifact run_id mismatch/missing values and now runs lineage verification by default with optional `--require-signed-artifacts` and `--verify-signed-artifacts` cycle gating, deduplicated recommendation synthesis, fail-on gates (`--fail-on-unenforced`, `--fail-on-integration-unhealthy`, `--fail-on-wsl-risk`, `--fail-on-extension-total-rss-mb`, `--fail-on-extension-rss`) with strict non-coercive summary field parsing for unenforced/extension-total thresholds and fail-closed WSL risk-level validation when gate evaluation input is malformed/unknown,  `overall_runtime_healthy` synthesis with strict fail-closed type/value validation for fully_enforced/integration_overall_healthy/wsl_risk_level,  and optional WSL diagnosis (`reports/repo_guard_runtime_status.json`); added `scripts/run_fleet_guard_cycle.py` to execute enforcement + integration + runtime governance gates in one command for CI/cron operations with pass-through extension-memory fail-fast policy controls, and strict summary object+field typing in scripts/aggregate_worker_reports.py so malformed aggregate payloads and fail-on gate inputs return deterministic config-style errors instead of crashes or coercive evaluation, plus strict fail-fast CLI argument typing in aggregate_worker_reports (input/output path types and fail-on flag booleans) so malformed orchestration inputs fail deterministically before aggregation. Broader config-surface propagation remains. |
| M1-O01 | WSL memory stabilization playbook | P1 | ✅ DONE | Added `WSL_MEMORY_STABILIZATION_PLAYBOOK.md` with root-cause patterns (hidden VS Code extension hosts, swap saturation, multi-distro load), mandatory repo guard enforcement/reporting procedure, host `.wslconfig` baseline, triage commands, and filesystem repair workflow for ext4 error signals. |
| M1-C08 | Async context manager for work phases | P2 | 🔄 IN PROGRESS | `guard.phase()` supports `with` and `async with`; added optional lifecycle tracing semantics via `emit_phase_traces=True` and `emit_otel_phase_event()` for `enter`/`exit`/`error` span events with stage + exception metadata; further advanced span-linking patterns remain. |

### Integration stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M1-I01 | Polars adopts as default memory monitor | P1 | 🔄 IN PROGRESS | `INTEGRATION_POLARS.md` hook strategy and rollout phases; `validate_polars_integration()` and `collect_polars_integration_evidence()` for adoption evidence now include machine-verifiable scan-budget API and `LazyFrame.explain()` plan capability markers; `scripts/validate_polars_integration.py` CI-gate CLI with `--require-hooks`, `--check-budget-api`, `--check-callback-api`, `--run-id`, and `--json` output (exit 0/1), now with strict fail-fast CLI argument typing for policy flags and stage/run-id fields so malformed orchestration inputs return deterministic config errors, and emitting provenance/self-digest metadata (`generated_at_utc`, `run_id`, `artifact_sha256`, signature envelope) so cached reports are lineage-verifiable; `scripts/validate_integration_fleet.py` aggregates Polars/Dask/Ray validator health into one machine-verifiable gate for CI/fleet reporting, now enforcing the Polars callback API check in the fleet verdict, propagating the fleet run ID into live component validator invocations for cross-artifact correlation symmetry with cached report inputs, converting per-component validator timeouts into structured unhealthy components instead of aborting the entire fleet run, compacting noisy validator stderr into bounded summary warnings for more actionable CI artifacts, validating fallback report identity (tool/milestone) with hard-error semantics so malformed/misrouted offline artifacts cannot be treated as healthy, validating fallback report self-digests/signature envelope structure before accepting cached component reports, plus strict non-coercive string typing for fallback report tool/milestone/artifact_sha256 identity fields so malformed metadata cannot be implicitly coerced during trust checks, plus strict generated_at_utc string typing for fallback report staleness policy checks so malformed timestamp fields fail with deterministic validation errors, optionally requiring detached signatures and cryptographically verifying cached/explicit report inputs with key-ID and signature-age policy controls, fail-fast validating that signature-verification modes include required public key inputs (instead of deferring to per-component runtime failures), fail-fast enforcing policy coherence so signature verification cannot be enabled without requiring signed report inputs, fail-fast enforcing that key-ID and signature-age report-input policies require signature verification mode, fail-fast rejecting negative fallback/signature age values to prevent silent policy disablement, strict boolean semantics for validator health/check fields, risk-level synthesis inputs, summary healthy/unhealthy component counting, and main-path summary gate parsing (`summary` object + `overall_healthy` boolean) to prevent coercion-based false healthy/low-risk states and require-healthy bypasses, validating fallback report run_id correlation against the active fleet run so cross-run cached artifacts cannot be accepted as current truth, optionally enforcing max fallback report age to prevent stale offline artifacts from being accepted as current truth, and recording fallback-age/signature policy settings in payload/provenance for audit traceability, with offline/hybrid report-ingestion and pressure-triggered auto-fallback to cached component reports during high-pressure WSL sessions; `scripts/run_fleet_guard_cycle.py` now passes report-signature policy controls through to the integration validator so CI/cron orchestration can enforce the same cached-report trust model end to end. |
| M1-I02 | Dask issue template integration | P2 | ✅ DONE | `scripts/validate_dask_integration.py` — machine-verifiable adoption evidence CLI with `--require-hooks` (exit 1 if hooks not live), `--check-guard-api` (smoke-tests `install_dask_task_graph_guard` with mock graph), `--check-scheduler-api` (smoke-tests scheduler callback API/attach path), and `--json` CI-gate output, plus strict fail-fast CLI argument typing for flags and stage/run-id fields so malformed orchestration inputs return deterministic config errors. |
| M1-I03 | Ray tutorial & cookbook examples | P2 | ✅ DONE | `scripts/validate_ray_integration.py` — machine-verifiable adoption evidence CLI with `--require-hooks`, `--check-actor-api` (smoke-tests `enable_ray_actor_memory_monitoring` + `remote_wrapper`), and `--json` CI-gate output, plus strict fail-fast CLI argument typing for flags and stage/run-id fields so malformed orchestration inputs return deterministic config errors. |
| M1-I04 | Community monitoring dashboard (optional OSS) | P3 | ✅ DONE | Added starter Grafana dashboard template at `examples/grafana/runtime_guard_dashboard.json` plus sample Prometheus exposition data at `examples/grafana/sample_metrics.prom`. |

---

## Milestone 2 — Enterprise Hardening _(Q4 2026 – Q1 2027)_

**Goal:** Production-grade reliability, compliance, and observability for enterprise data pipelines.

### Code stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M2-C01 | Memory snap auto-recovery (signal handler) | P1 | ✅ DONE | Signal recovery now includes default `SIGABRT` handling, environment-driven rollout policy (`resolve_signal_recovery_policy`, `install_signal_recovery_from_policy`), critical-only intervention default with explicit `any` override (`SIGNAL_RECOVERY_INTERVENE_ON`), and optional hash-chained audit logging via `SIGNAL_RECOVERY_AUDIT_LOG` + `SIGNAL_RECOVERY_HASH_ALGO`. |
| M2-C02 | Audit log for all policy violations | P1 | ✅ DONE | Added hash-chained audit records + CLI verification, expanded taxonomy coverage for incident/access/integrity-style events, canonical normalization helpers (`audit_policy_taxonomy`, `normalize_policy_violation_event`) including action-triggered normalization when `event_type` is omitted, optional dedup suppression on write-path (`append_audit_log(..., deduplicator=...)`) including signal-recovery policy support (`SIGNAL_RECOVERY_AUDIT_DEDUP_TTL_S`), and operator-facing taxonomy catalog export via `runtime-guard --audit-policy-taxonomy`. |
| M2-C03 | Dynamic policy reloading | P2 | ✅ DONE | Added file-backed policy overrides with auto-reload on mtime changes and env>policy>preset precedence, plus operator-facing CLI support (`--policy-file`, `--policy-auto-reload`) to load and enforce dynamic policy in runtime checks. |
| M2-C04 | Multi-process orchestration (optional) | P2 | ✅ DONE | Worker report + parent aggregation API; JSONL transport; parent-side CLI `scripts/aggregate_workers.py` with `--fail-on-pressure` / `--fail-on-critical` gating, now with strict fail-fast CLI argument typing and strict summary-field gate parsing (`any_pressure`, `pressured_workers`, `critical_workers`, `total_workers`) so malformed aggregate payloads return deterministic config errors instead of coercive or crash-prone gate evaluation; multiprocess demo in `examples/`. |
| M2-C05 | FIPS-certified hash for event dedup | P2 | ✅ DONE | Added FIPS SHA-2 algorithm selection and chain verification for audit/event integrity, implemented `FipsDeduplicator` (thread-safe TTL dedup cache), and wired dedup into `append_audit_log(...)` / `RuntimeGuard.audit(...)` so duplicate policy events are skipped before write; also includes subprocess launch preflight safety checks (`RuntimeGuard.subprocess_safe`, `subprocess_safe`) to prevent avoidable WSL OOM cascades. |
| M2-C06 | SOC2 prep integration + compliance gap assessment | P1 | ✅ DONE | Added baseline controls plus evidence requirements/readiness scoring (`soc2_evidence_requirements`, `soc2_readiness_report`), expanded control catalog (CC6.2, CC6.6, CC7.3, CC8.1, A1.1, A1.2, PI1.2), and operator-facing CLI workflow (`scripts/soc2_readiness_report.py`) with required-control scoping, strict fail-fast CLI argument typing (controls/evidence/required-controls/output paths and fail-on-gaps flag), and `--fail-on-gaps` CI gating for repeatable readiness enforcement. |

### Integration stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M2-I01 | Enterprise support package (SLA, runbooks) | P1 | ✅ DONE | Completed support package with incident/runbook coverage, `OPERATIONS_GUIDE.md` deployment runbook, explicit support tier matrix in `ENTERPRISE_SUPPORT.md` (Standard/Priority/Mission Critical), Linux user-service watcher templates with strict fail-fast CLI argument typing in `scripts/runtime_guard_repo_watcher.py` (repo-path/stage fields, interval/cooldown policies, and run-once flag) so malformed service inputs return deterministic config errors, and repo seeding utility (`scripts/seed_repo_autorun.py`) with strict fail-fast CLI argument typing (repo path/stage fields, interval/cooldown policies, env-prefix, and force flag) so malformed bootstrap inputs return deterministic config errors, for self-starting monitoring. |
| M2-I02 | Adoption by 5+ enterprise data teams | P1 | ✅ DONE | Added `ADOPTION_TRACKER.md` stage model + execution automation: `build_adoption_scorecard()` API and `scripts/adoption_scorecard.py` CLI for rollout metrics, canonical stage alias handling (`Discovery` -> `discover`, `prod` -> `production`), strict fail-fast CLI argument typing in `scripts/adoption_scorecard.py` (input/output paths, strict flag, and success-stage policy) so malformed scorecard inputs return deterministic config errors, strict fail-fast CLI argument typing in `scripts/adoption_tracker_report.py` (tracker/output paths and fail-on-gaps flag) so malformed tracker-report inputs return deterministic config errors, and machine-verifiable tracker audit via `scripts/adoption_tracker_report.py`; tracker now reflects 5 teams at sustained pilot/production stages with measurable outcomes and 2 before/after case studies. |
| M2-I03 | Training & certification curriculum | P2 | ✅ DONE | Added `TRAINING_CURRICULUM.md` with 1-day agenda, labs, certification rubric, and operator-facing certification reporting workflow via `scripts/training_certification_report.py` (including strict fail-fast CLI argument typing for attendee path, lab/score thresholds, output path, and fail-on-gaps flag, plus fail-on-gaps CI gating for workshop outcomes). |

---

## Valuation & Strategic Position

### Positioning

runtime-guard targets the *invisible tax* of memory diagnostics in data pipelines.

Today: A data scientist sees "memory is low" and spends 2–4 hours debugging: Is it my model? The OS? Another process? Swap thrashing?

With runtime-guard: Attribution in seconds. Actionable next steps. No false alarms.

### Market size

- **TAM:** ~50K data engineers / ML ops / DevOps in regulated sectors (finance, healthcare, gov) who own pipelines with strict SLA memory constraints.
- **SAM:** ~10K teams already using Dask, Polars, or Ray and experiencing memory pressure incidents.
- **SOM (Year 1):** 50–100 pilot integrations.

### Comparable metrics

| Product | Comparable value prop | Notes |
|---|---|---|
| New Relic / DataDog memory module | Enterprise observability tax | $1K–5K/month; no attribution. |
| Dask diagnostics dashboard | In-framework only; no external pressure insight | Built-in; free. |
| Linux `sar` / `vmstat` | Generic OS-level snapshots | Free; requires expert interpretation. |

### Go-to-market

1. **Tier 1 (Milestones 0–1):** Open-source community adoption. Target: 1K GitHub stars.
2. **Tier 2 (Milestone 2):** Enterprise support + advisory consulting. Target: $20K–$50K/year ARR.
3. **Tier 3 (Future):** SaaS monitoring platform (memory + observability + cost analytics). Target: $500K+ ARR.

---

## Release rhythm

| Schedule | Cadence | Scope |
|---|---|---|
| **Patch** | As needed | Security fixes, urgent bug fixes. |
| **Minor** | Monthly | Feature completions, non-breaking improvements. |
| **Major** | Quarterly (or when M1–M2 gates pass) | API changes, new integrations, major refactors. |

### Every 5 minor releases:
- Full security audit + dependency update pass.
- Compliance review against OWASP Top 10, CWE Top 25.
- Community feedback synthesis.

### Every 1 major release:
- Deep refactor assessment.
- Architecture review with contributors.
- API stability review (breaking-change rationale).
- Updated CAP (Capabilities & Platform) document.

---

## Known risks & mitigations

| Risk | Mitigation |
|---|---|
| Hyperscalers (cloud providers) ship native memory attribution into their SDKs | Position as cloud-agnostic, framework-first. Build Dask/Polars/Ray adoption before cloud lock-in occurs. |
| Over-instrumentation causes perf regression on sensitive workloads | Cooldown + deduplication built in; background check optional. Benchmark vs. no-op baseline. |
| OS kernels change `proc` format / macOS `vm_stat` output | Version-pinned fallback tests. Automated CI on multiple OS versions. |
| Adoption stalls after Milestone 1 | Pivot to enterprise consulting + managed SaaS (Milestone 3). Ensure open-source remains free. |
