# Research — runtime-guard

> Academic and industry research foundation for this project.  
> Each section links theory to planned implementation items in [ROADMAP.md](ROADMAP.md).

---

## Research Methodology

For each area:
1. **Survey** — identify seminal papers, RFCs, and authoritative documentation.
2. **Benchmark** — reproduce key results in a controlled environment (Linux 6.x, WSL 2, macOS Sonoma).
3. **Design** — translate findings into concrete API or algorithm decisions.
4. **Validate** — write integration tests that exercise the implemented behaviour and confirm it matches the theoretical model.
5. **Cite** — add citations to docstrings and architecture docs.

---

## Area 1 — Memory Attribution Models

### Problem statement
When available RAM drops below a threshold, the immediate question is: *Who caused this?* Attribution requires correlating this-process RSS with total memory usage — accounting for kernel reclaimable memory, buffer/cache, shared memory, and swap.

### Key sources

| Source | Type | Relevance |
|---|---|---|
| Gorman, M. (2004). *Understanding the Linux Virtual Memory Manager*. Prentice Hall. | Book | Canonical reference for Linux page reclaim, kswapd, and zone pressure. Core model for `/proc/meminfo` interpretation. |
| Bovet, D. & Cesati, M. (2005). *Understanding the Linux Kernel*, 3rd ed. O'Reilly. | Book | Page frame management, slab allocator internals, OOM killer algorithm. |
| Linux kernel documentation: `Documentation/filesystems/proc.rst` | Primary source | Authoritative field definitions for `/proc/meminfo`, `/proc/self/status`, `/proc/self/smaps_rollup`. |
| Hekmat, S. & Petersen, R. (2019). "Memory pressure characterization and adaptive throttling in large-scale distributed systems." *USENIX ATC '19*. | Paper | Large-scale attribution — how hyperscalers detect per-service memory pressure without kernel modification. |
| Enberg, P. et al. (2020). "Memory Management in Linux: NUMA, Cgroups, and OOM." *Linux Plumbers Conference 2020*. | Conference talk | cgroup v2 memory accounting and container-aware attribution — directly relevant to M1 roadmap item. |

### Research tasks

| Task | Status | Target version | Notes |
|---|---|---|---|
| R1.1 — Compare `MemAvailable` vs. `MemFree + Buffers + Cached` as pressure signal | 📅 Planned | v0.3.0 | `MemAvailable` is more accurate per kernel docs but not available on kernels < 3.14. Need fallback formula. |
| R1.2 — Validate RSS from `/proc/self/status` vs. `smaps_rollup` for attribution accuracy | 📅 Planned | v0.3.0 | `smaps_rollup` gives PSS (proportional set size) which is more accurate for shared-memory workloads. |
| R1.3 — Study OOM killer scoring (`/proc/<pid>/oom_score_adj`) as a predictor of eviction risk | 📅 Planned | v0.4.0 | Could expose `oom_risk` in `MemSnapshot` as an early warning. |
| R1.4 — cgroup v2 memory limits for container-aware attribution | 📅 Planned | M1 | `/sys/fs/cgroup/memory.max` overrides `/proc/meminfo` MemTotal in containers. |

---

## Area 2 — Cross-platform Memory Enumeration

### Problem statement
macOS and Windows do not expose `/proc`. Reliable, locale-independent memory enumeration requires different OS APIs on each platform. The goal is parity of *semantics* (available RAM, swap used, process RSS) not parity of implementation.

### Key sources

| Source | Type | Relevance |
|---|---|---|
| Apple Developer Documentation: `host_statistics64`, `mach_host_info` | Primary source | The authoritative API for macOS physical memory statistics. Avoids parsing `vm_stat` text output. |
| Microsoft Docs: `GlobalMemoryStatusEx` (Win32), `Get-CimInstance Win32_OperatingSystem` (PowerShell) | Primary source | Replaces deprecated `wmic` (KI-002). `dwAvailPhys` = available RAM. |
| OSX Daily (2023). "Understanding vm_stat output on macOS." | Tutorial | Documents `vm_stat` fields vs. `mach` VM concepts. Useful for cross-checking parsed output. |
| Russinovich, M. & Solomon, D. (2012). *Windows Internals*, 6th ed. Microsoft Press. | Book | Windows paging, working set, and `MemAvailBytes` semantics. Equivalent of Gorman for Windows. |

### Research tasks

| Task | Status | Target version | Notes |
|---|---|---|---|
| R2.1 — Prototype `ctypes`-based `host_statistics64` call for macOS (no subprocess) | 📅 Planned | v0.3.0 | Eliminates `vm_stat` locale dependency (KI-001). |
| R2.2 — Prototype PowerShell `Get-CimInstance` fallback for Windows (KI-002 fix) | 📅 Planned | v0.3.0 | Must handle PowerShell execution policy and version differences. |
| R2.3 — FreeBSD: assess `sysctl vm.stats.vm.v_free_count` for future support | 📅 Planned | M1 | Low priority but needed for BSD-based NAS / homelab deployments. |
| R2.4 — WSL 2 memory reporting: document delta between `/proc/meminfo` and Windows Task Manager | 📅 Planned | v0.3.0 | WSL 2 `MemTotal` reflects the dynamic VM ceiling, not the host Windows RAM. Document and expose in `wsl_system_report()`. |

---

## Area 3 — Alert Fatigue and Deduplication Theory

### Problem statement
A resource monitor that emits the same alert repeatedly under sustained pressure causes alert fatigue and is ignored. The cooldown mechanism must balance: (a) not missing new or worsening pressure, (b) not repeating known pressure, (c) not losing data for downstream aggregation.

### Key sources

| Source | Type | Relevance |
|---|---|---|
| Jakub Czajkowski et al. (2015). "Alert Fatigue: The Challenge and Opportunity for Health Monitoring Systems." *IEEE ICHI 2015*. | Paper | Framework for evaluating false-positive and nuisance alert rates. Applicable to DevOps monitoring. |
| Lerner, A. et al. (2018). "AIOps: Handling Alert Storms." *SREcon18 Americas*. | Talk | Industry patterns for deduplication, correlation windows, and escalation. |
| Prometheus documentation: "Alerting Rules" and "Inhibition Rules". | Primary source | Canonical SRE pattern for grouping, inhibiting, and deduplicating alerts in production. |

### Research tasks

| Task | Status | Target version | Notes |
|---|---|---|---|
| R3.1 — Design per-stage cooldown store (fixes KI-004) | 📅 Planned | v0.4.0 | `dict[str, float]` keyed by stage. Assess memory cost vs. correctness. |
| R3.2 — Exponential backoff for repeat alerts (pressure that persists but worsens) | 📅 Planned | v0.5.0 | Suppress repeated same-level alerts but escalate when severity increases. |
| R3.3 — Dead man's switch: emit alert if *no* check has run in N seconds | 📅 Planned | M1 | Detect silently hung pipeline stages that never call `check()`. |

---

## Area 4 — Observability and Structured Events

### Problem statement
runtime-guard's `runtime_guard.events` structured JSON logger must interoperate with industry-standard observability stacks (OpenTelemetry, Prometheus, Loki, Grafana). The schema design determines long-term usability.

### Key sources

| Source | Type | Relevance |
|---|---|---|
| OpenTelemetry Specification (OTLP): Logs, Metrics, Traces. opentelemetry.io | Standard | Defines semantic conventions for memory metrics (`process.memory.usage`, `system.memory.usage`). |
| Prometheus Data Model: Metric types and naming conventions. prometheus.io | Standard | Gauge naming patterns for memory metrics. Informs `runtime_guard_mem_available_mb` gauge naming. |
| Grafana Loki: LogQL structured metadata. grafana.com | Standard | How to emit structured fields that Loki can index without full JSON parsing. |
| CNCF TAG Observability: "Observability Whitepaper" (2023). github.com/cncf/tag-observability | Whitepaper | Best practices for correlating logs, metrics, and traces across microservices. |

### Research tasks

| Task | Status | Target version | Notes |
|---|---|---|---|
| R4.1 — Align `runtime_guard.events` JSON schema with OTLP semantic conventions | 📅 Planned | M1-C04 | Map `mem_available_mb` → `system.memory.usage`, `rss_mb` → `process.memory.usage`. |
| R4.2 — Prototype OpenTelemetry exporter (zero-dep optional) | 📅 Planned | M1-C04 | Use `opentelemetry-sdk` as optional extra; no-op if not installed. |
| R4.3 — Prometheus gauge registration pattern (thread-safe, no double-registration) | 📅 Planned | M1-C05 | Evaluate `prometheus_client` registry patterns for library use vs. app use. |
| R4.4 — Structured log schema versioning | 📅 Planned | v0.4.0 | Add `schema_version` field to JSON events so consumers can handle breaking changes. |

---

## Area 5 — Security and Compliance

### Problem statement
A tool that reads process memory statistics must not leak sensitive information, must not allow privilege escalation, and must be auditable for regulated industries (finance, healthcare, government). International compliance (GDPR, HIPAA, SOC 2) must be addressed.

### Key sources

| Source | Type | Relevance |
|---|---|---|
| OWASP Top 10 (2021). owasp.org | Standard | Baseline security checklist: A01 Broken Access Control, A02 Cryptographic Failures, A09 Security Logging. |
| CWE Top 25 (2024). cwe.mitre.org | Standard | CWE-532 (Insertion of Sensitive Information into Log File) directly relevant to pressure reports. |
| NIST SP 800-92: Guide to Computer Security Log Management. | Standard | Framework for audit log integrity, retention, and protection — relevant to M2-C02 (audit log). |
| GDPR: Recital 49, Article 32. gdpr.eu | Regulation | Memory logs that capture process names or user activity may be personal data under GDPR in EU contexts. |
| HIPAA Security Rule: 45 CFR §164.312. hhs.gov | Regulation | Audit controls requirement — relevant if runtime-guard is deployed in healthcare data pipelines. |

### Research tasks

| Task | Status | Target version | Notes |
|---|---|---|---|
| R5.1 — Threat model: enumerate all data surfaces (logs, JSON events, CLI output, state files) | 📅 Planned | v0.3.0 | Identify which fields could leak PII or sensitive process info. |
| R5.2 — Redaction policy design for structured events | 📅 Planned | v0.3.0 | Allow caller to register a redaction function. Defaults to no-op. |
| R5.3 — FIPS-140 hash algorithm selection for event deduplication (M2-C05) | 📅 Planned | M2 | SHA-256 via `hashlib`. Verify FIPS mode availability on target kernels. |
| R5.4 — GDPR / HIPAA compliance guide for deployments in regulated sectors | 📅 Planned | M2 | Written guide: what to redact, log retention recommendations, data residency. Include non-EU / non-US jurisdictions (PIPL, PDPA, LGPD). |

---

## Area 6 — Performance Overhead of Monitoring

### Problem statement
runtime-guard must not meaningfully impact the very workloads it monitors. The overhead of `/proc` reads, subprocess calls (`vm_stat`, PowerShell), and background thread scheduling must be benchmarked and bounded.

### Key sources

| Source | Type | Relevance |
|---|---|---|
| Gregg, B. (2020). *Systems Performance*, 2nd ed. Addison-Wesley. | Book | Profiling methodology for latency-sensitive Linux tools. Chapter 5 covers memory subsystem benchmarking. |
| Linux `perf` tool documentation. | Primary source | `perf stat -e cache-misses` for measuring `/proc` read overhead. |
| Python `timeit` and `cProfile` documentation. | Primary source | Baseline overhead measurement approach. |

### Research tasks

| Task | Status | Target version | Notes |
|---|---|---|---|
| R6.1 — Benchmark `/proc/meminfo` parse latency (P50, P99) across kernel versions | 📅 Planned | v0.3.0 | Target: < 1 ms P99 on any kernel ≥ 4.14. |
| R6.2 — Benchmark `vm_stat` subprocess call latency on macOS | 📅 Planned | v0.3.0 | Target: < 50 ms. If higher, motivates `ctypes` approach (R2.1). |
| R6.3 — Background thread scheduling overhead vs. poll interval trade-off | 📅 Planned | v0.4.0 | Model: at what poll interval does the background thread itself meaningfully consume CPU? |
| R6.4 — No-op baseline: confirm `check()` overhead is < 0.1 ms when no pressure exists | 📅 Planned | v0.3.0 | Gate on CI: fail if `check()` cold-path exceeds 1 ms. |

---

## Citation Format

All citations in this document follow [APA 7th edition](https://apastyle.apa.org/). When adding new sources:
1. Add to the relevant area table above.
2. Add a corresponding research task if implementation work is planned.
3. Reproduce key findings as a comment in the source file that consumes the result.
