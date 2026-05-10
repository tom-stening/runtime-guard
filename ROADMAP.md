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
| M1-C01 | Polars integration plugin | P1 | 🔄 IN PROGRESS | `attach_polars_guard()` hooks `LazyFrame.collect` and `LazyFrame.fetch`; full native Polars callback integration remains. |
| M1-C02 | Dask integration | P1 | 🔄 IN PROGRESS | `attach_dask_guard()` hooks top-level and `dask.base` `compute`/`persist`; added `validate_dask_integration()` and `collect_dask_integration_evidence()` for adoption tracking; deeper scheduler callback integration remains. |
| M1-C03 | Ray cluster resource monitor | P1 | 🔄 IN PROGRESS | `attach_ray_guard()` hooks `get` plus optional `wait`/`put`; added `validate_ray_integration()` and `collect_ray_integration_evidence()` for adoption tracking; actor-based per-node monitoring remains. |
| M1-C04 | OpenTelemetry exporter | P2 | 🔄 IN PROGRESS | Added optional span-event exporter helpers; full metrics pipeline/exporter packaging remains. |
| M1-C05 | Prometheus metrics endpoint | P2 | 🔄 IN PROGRESS | Added metrics renderer helper; endpoint wiring (FastAPI/ASGI examples) remains. |
| M1-C06 | Distributed tracing context | P2 | 🔄 IN PROGRESS | Added trace-context attribute extraction and OTEL event trace-ID linkage; broader tracing propagation patterns remain. |
| M1-C07 | Config schema validation (`pydantic`) | P2 | 🔄 IN PROGRESS | Added optional schema validator with strict fallback; integration into broader config surfaces remains. |
| M1-C08 | Async context manager for work phases | P2 | 🔄 IN PROGRESS | `guard.phase()` supports `with` and `async with`; deeper tracing/span semantics remain. |

### Integration stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M1-I01 | Polars adopts as default memory monitor | P1 | 🔄 IN PROGRESS | Added `INTEGRATION_POLARS.md` with hook strategy, rollout phases, validation steps, and evidence checklist plus `validate_polars_integration()` and `collect_polars_integration_evidence()` for adoption evidence collection. |
| M1-I02 | Dask issue template integration | P2 | 🔄 IN PROGRESS | Added `.github/ISSUE_TEMPLATE/dask-memory-diagnostics.yml` to pre-fill runtime-guard memory context in Dask bug reports. |
| M1-I03 | Ray tutorial & cookbook examples | P2 | 🔄 IN PROGRESS | Added `INTEGRATION_RAY.md` with driver hook, staged orchestration, and audit-trail cookbook patterns. |
| M1-I04 | Community monitoring dashboard (optional OSS) | P3 | 📅 PLANNED | Grafana dashboard template + sample data. |

---

## Milestone 2 — Enterprise Hardening _(Q4 2026 – Q1 2027)_

**Goal:** Production-grade reliability, compliance, and observability for enterprise data pipelines.

### Code stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M2-C01 | Memory snap auto-recovery (signal handler) | P1 | 🔄 IN PROGRESS | Added signal handler scaffold plus environment-driven rollout policy helpers (`resolve_signal_recovery_policy`, `install_signal_recovery_from_policy`); incident policy tuning remains. |
| M2-C02 | Audit log for all policy violations | P1 | 🔄 IN PROGRESS | Added hash-chained audit records + CLI verification and canonical taxonomy helpers (`audit_policy_taxonomy`, `normalize_policy_violation_event`); policy catalog completeness remains. |
| M2-C03 | Dynamic policy reloading | P2 | 🔄 IN PROGRESS | Added file-backed policy overrides with auto-reload on mtime changes and env>policy>preset precedence. |
| M2-C04 | Multi-process orchestration (optional) | P2 | 🔄 IN PROGRESS | Added worker report + parent aggregation scaffolding for process pools/job queues; transport/adapters remain. |
| M2-C05 | FIPS-certified hash for event dedup | P2 | 🔄 IN PROGRESS | Added FIPS SHA-2 algorithm selection and chain verification for audit/event integrity. |
| M2-C06 | SOC2 prep integration + compliance gap assessment | P1 | 🔄 IN PROGRESS | Added baseline controls plus evidence requirements/readiness scoring (`soc2_evidence_requirements`, `soc2_readiness_report`); broader control catalog expansion remains. |

### Integration stream

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| M2-I01 | Enterprise support package (SLA, runbooks) | P1 | 🔄 IN PROGRESS | Added incident/runbook package plus both Linux user-service watcher templates and repo seeding utility (`scripts/seed_repo_autorun.py`) for self-starting monitoring. |
| M2-I02 | Adoption by 5+ enterprise data teams | P1 | 🔄 IN PROGRESS | Added `ADOPTION_TRACKER.md` stage model + execution automation: `build_adoption_scorecard()` API and `scripts/adoption_scorecard.py` CLI for rollout metrics; 5-team procurement/evidence execution remains. |
| M2-I03 | Training & certification curriculum | P2 | 🔄 IN PROGRESS | Added `TRAINING_CURRICULUM.md` with 1-day agenda, labs, and certification rubric. |

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
