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
| M1-C05 | Prometheus metrics endpoint | P2 | ✅ DONE | `install_prometheus_endpoint()` — pure-Python ASGI factory serving Prometheus exposition text; HTTP 200/503 based on guard pressure; GET-only (405 on other methods); zero external dependencies; `_runtime_guard_prometheus_prefix` and `_runtime_guard_prometheus_path` attributes; compatible with FastAPI/Starlette mount. **Now exposes both guest (WSL/Linux) and host (Windows) memory/swap metrics, plus drift fields, in both Prometheus and JSON logs.** Added first-class CLI crash triage mode `runtime-guard --diagnose-wsl-crash [--json] [--fail-on-risk high|critical]` for host+guest RCA automation, including host-event relevance filtering, active WSL/docker workload detection, top guest RSS offender reporting, offender-aware prevention hints, proactive VS Code extension-host RSS concentration heuristics, per-extension RSS attribution (`guest_vscode_extension_rss`), and fail-fast extension policy gates (`--fail-on-extension-total-rss-mb`, `--fail-on-extension-rss`) so generic System noise is separated from actionable crash causes before thresholds turn critical. |
| M1-C06 | Distributed tracing context | P2 | ✅ DONE | `install_distributed_trace_propagator()` — W3C traceparent header parsing (`extract`) and injection (`inject`) linking memory events to distributed traces; case-insensitive header key normalisation; graceful no-op when OTEL unavailable; configurable `header_name` (default `traceparent`). |
| M1-C07 | Config schema validation (`pydantic`) | P2 | 🔄 IN PROGRESS | Added optional schema validator with strict fallback; integrated posture validation into `make_pytest_guard(..., posture=...)`, `make_sitecustomize_content(..., posture=...)`, and `make_conftest_content(..., posture=...)` so repo-level guard factories can apply validated presets without manual env plumbing; added `wsl_dev` preset for IDE-heavy WSL sessions; added fleet enforcement/reporting automation via `scripts/enforce_runtime_guard_all_repos.py` with JSON status output (`reports/repo_guard_enforcement.json`) for repositories under a root path, including `--enforce-all-repos` mode to close non-Python coverage gaps and run_id payload/summary propagation; added runtime fleet status reporting via `scripts/repo_guard_fleet_report.py` with active-repo/process visibility, optional integration-health ingestion from `reports/integration_fleet_status.json`, pressure-fallback mode visibility (`integration_execution_mode`, `integration_pressure_detected`), promoted WSL risk/top-offender summary fields, promoted extension-memory summary field (`wsl_vscode_extension_total_rss_mb`), structured gate-failure payload output (`failed_gates`, `failed_gate_count`) with stable gate correlation metadata (`gate_id`, `evaluated_at_utc`, `run_id`), optional caller-provided `--run-id` override for external CI trace alignment, explicit source artifact run_id consistency signals (`source_run_ids`, `run_id_consistent`) and `--fail-on-run-id-mismatch` runtime gating, provenance blocks across enforcement/integration/runtime artifacts (tool identity, generation timestamp, git commit hint, run_id, source artifact hashes, canonical `artifact_sha256` self-digests, and signature-ready detached-envelope metadata), dedicated lineage verifier automation via `scripts/verify_fleet_artifact_lineage.py` including optional `--require-signed` enforcement and OpenSSL-backed Ed25519 detached signature verification (`--verify-signatures --signature-public-key`), and run_id propagation into integration fleet artifacts (`validate_integration_fleet.py` payload/summary) through `run_fleet_guard_cycle.py` pass-through, plus pass-through staleness policy control for integration fallback reports (`--integration-max-fallback-report-age-hours`), and a fleet-cycle run_id consistency gate that auto-generates a run ID when omitted and fails on cross-artifact run_id mismatch/missing values and now runs lineage verification by default with optional `--require-signed-artifacts` and `--verify-signed-artifacts` cycle gating, deduplicated recommendation synthesis, fail-on gates (`--fail-on-unenforced`, `--fail-on-integration-unhealthy`, `--fail-on-wsl-risk`, `--fail-on-extension-total-rss-mb`, `--fail-on-extension-rss`), `overall_runtime_healthy` synthesis, and optional WSL diagnosis (`reports/repo_guard_runtime_status.json`); added `scripts/run_fleet_guard_cycle.py` to execute enforcement + integration + runtime governance gates in one command for CI/cron operations with pass-through extension-memory fail-fast policy controls. Broader config-surface propagation remains. |
| M1-O01 | WSL memory stabilization playbook | P1 | ✅ DONE | Added `WSL_MEMORY_STABILIZATION_PLAYBOOK.md` with root-cause patterns (hidden VS Code extension hosts, swap saturation, multi-distro load), mandatory repo guard enforcement/reporting procedure, host `.wslconfig` baseline, triage commands, and filesystem repair workflow for ext4 error signals. |
| M1-C08 | Async context manager for work phases | P2 | 🔄 IN PROGRESS | `guard.phase()` supports `with` and `async with`; added optional lifecycle tracing semantics via `emit_phase_traces=True` and `emit_otel_phase_event()` for `enter`/`exit`/`error` span events with stage + exception metadata; further advanced span-linking patterns remain. |

### Integration stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M1-I01 | Polars adopts as default memory monitor | P1 | 🔄 IN PROGRESS | `INTEGRATION_POLARS.md` hook strategy and rollout phases; `validate_polars_integration()` and `collect_polars_integration_evidence()` for adoption evidence now include machine-verifiable scan-budget API and `LazyFrame.explain()` plan capability markers; `scripts/validate_polars_integration.py` CI-gate CLI with `--require-hooks`, `--check-budget-api`, `--check-callback-api`, and `--json` output (exit 0/1); `scripts/validate_integration_fleet.py` aggregates Polars/Dask/Ray validator health into one machine-verifiable gate for CI/fleet reporting, now enforcing the Polars callback API check in the fleet verdict, converting per-component validator timeouts into structured unhealthy components instead of aborting the entire fleet run, compacting noisy validator stderr into bounded summary warnings for more actionable CI artifacts, validating fallback report identity (tool/milestone) with hard-error semantics so malformed/misrouted offline artifacts cannot be treated as healthy, and optionally enforcing max fallback report age to prevent stale offline artifacts from being accepted as current truth, with offline/hybrid report-ingestion and pressure-triggered auto-fallback to cached component reports during high-pressure WSL sessions. |
| M1-I02 | Dask issue template integration | P2 | ✅ DONE | `scripts/validate_dask_integration.py` — machine-verifiable adoption evidence CLI with `--require-hooks` (exit 1 if hooks not live), `--check-guard-api` (smoke-tests `install_dask_task_graph_guard` with mock graph), `--check-scheduler-api` (smoke-tests scheduler callback API/attach path), and `--json` CI-gate output. |
| M1-I03 | Ray tutorial & cookbook examples | P2 | ✅ DONE | `scripts/validate_ray_integration.py` — machine-verifiable adoption evidence CLI with `--require-hooks`, `--check-actor-api` (smoke-tests `enable_ray_actor_memory_monitoring` + `remote_wrapper`), and `--json` CI-gate output. |
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
| M2-C04 | Multi-process orchestration (optional) | P2 | ✅ DONE | Worker report + parent aggregation API; JSONL transport; parent-side CLI `scripts/aggregate_workers.py` with `--fail-on-pressure` / `--fail-on-critical` gating; multiprocess demo in `examples/`. |
| M2-C05 | FIPS-certified hash for event dedup | P2 | ✅ DONE | Added FIPS SHA-2 algorithm selection and chain verification for audit/event integrity, implemented `FipsDeduplicator` (thread-safe TTL dedup cache), and wired dedup into `append_audit_log(...)` / `RuntimeGuard.audit(...)` so duplicate policy events are skipped before write; also includes subprocess launch preflight safety checks (`RuntimeGuard.subprocess_safe`, `subprocess_safe`) to prevent avoidable WSL OOM cascades. |
| M2-C06 | SOC2 prep integration + compliance gap assessment | P1 | ✅ DONE | Added baseline controls plus evidence requirements/readiness scoring (`soc2_evidence_requirements`, `soc2_readiness_report`), expanded control catalog (CC6.2, CC6.6, CC7.3, CC8.1, A1.1, A1.2, PI1.2), and operator-facing CLI workflow (`scripts/soc2_readiness_report.py`) with required-control scoping and `--fail-on-gaps` CI gating for repeatable readiness enforcement. |

### Integration stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M2-I01 | Enterprise support package (SLA, runbooks) | P1 | ✅ DONE | Completed support package with incident/runbook coverage, `OPERATIONS_GUIDE.md` deployment runbook, explicit support tier matrix in `ENTERPRISE_SUPPORT.md` (Standard/Priority/Mission Critical), Linux user-service watcher templates, and repo seeding utility (`scripts/seed_repo_autorun.py`) for self-starting monitoring. |
| M2-I02 | Adoption by 5+ enterprise data teams | P1 | ✅ DONE | Added `ADOPTION_TRACKER.md` stage model + execution automation: `build_adoption_scorecard()` API and `scripts/adoption_scorecard.py` CLI for rollout metrics, canonical stage alias handling (`Discovery` -> `discover`, `prod` -> `production`), and machine-verifiable tracker audit via `scripts/adoption_tracker_report.py`; tracker now reflects 5 teams at sustained pilot/production stages with measurable outcomes and 2 before/after case studies. |
| M2-I03 | Training & certification curriculum | P2 | ✅ DONE | Added `TRAINING_CURRICULUM.md` with 1-day agenda, labs, certification rubric, and operator-facing certification reporting workflow via `scripts/training_certification_report.py` (including fail-on-gaps CI gating for workshop outcomes). |

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
