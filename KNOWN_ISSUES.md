# Known Issues — runtime-guard

> Defect and limitation registry. Each entry includes a severity rating, reproduction steps or conditions, and current workaround. Issues are resolved at the milestone or patch version indicated.

**Severity scale:**
- **S0 — Blocker:** Data loss, silent wrong result, crash with no recovery path.
- **S1 — High:** Incorrect attribution or missed pressure detection in documented scenarios.
- **S2 — Medium:** Degraded accuracy or usability; workaround exists.
- **S3 — Low:** Cosmetic, edge-case, or minor UX issue.

---

## Open Issues

*(KI-001 through KI-003, KI-005, KI-006 resolved in v0.3.0 — see Closed Issues below.)*

### KI-004 — `cooldown_s` timer is not per-stage, it is global
- **Severity:** S2
- **Affects:** Callers using multiple named stages with different cooldown expectations
- **Version introduced:** 0.2.0
- **Description:** The cooldown deduplication clock is a single timestamp shared across all `check()` / `log()` calls. If stage `"data-load"` fires a pressure event and starts the cooldown, stage `"model-train"` called 2 seconds later will also be suppressed even though it is a different logical phase.
- **Workaround:** Construct a separate `RuntimeGuard` instance per stage, or set `cooldown_s=0` to disable deduplication.
- **Fix target:** v0.4.0 — Make `_last_log_time` a `dict[str, float]` keyed by stage name.
- **Linked PR:** (pending)

---

## Closed Issues

| ID | Summary | Resolution | Fixed in |
|---|---|---|---|
| KI-001 | macOS `vm_stat` page-size parsing not locale-aware | Use `sysctl hw.pagesize` subprocess call; locale-insensitive regex for page counts | v0.3.0 |
| KI-002 | Windows `wmic` deprecated on Win11 23H2+ | Replaced with PowerShell `Get-CimInstance Win32_OperatingSystem`; `wmic` retained as fallback | v0.3.0 |
| KI-003 | Background check daemon thread not restarted after fork | `os.register_at_fork(after_in_child=…)` clears `_bg_thread` / `_bg_stop` in child | v0.3.0 |
| KI-005 | Zero-filled snapshot on unsupported platforms raises no warning | `logging.WARNING` emitted once via module-level sentinel `_unsupported_platform_warned` | v0.3.0 |
| KI-006 | `generate_wslconfig` overwrites existing `.wslconfig` without backup | New `_merge_wslconfig()` helper: backs up existing file, merges only managed `[wsl2]` keys, preserves all other keys and sections | v0.3.0 |

---

## Limitations (by design, not defects)

| Limitation | Rationale |
|---|---|
| Linux only for full feature set | `attributing` pressure requires `/proc/self/status` (RSS) and `/proc/meminfo`. macOS and Windows approximations are best-effort. | 
| No GPU memory monitoring | Out of scope for v0.x. Planned as optional plugin in M1 (CUDA/ROCm). |
| No cgroup v2 / container-aware attribution | Container memory limits differ from host `MemTotal`. Planned for M1-C06 area. |
| No network or I/O pressure attribution | Focused solely on RAM and swap. Disk I/O and network backpressure are separate problem domains. |
| Single-process attribution only | Distributed pressure across a process pool is out of scope until M2-C04. |
