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

*(All known issues resolved in v0.3.0 — see Closed Issues below.)*

---

## Closed Issues

| ID | Summary | Resolution | Fixed in |
|---|---|---|---|
| KI-001 | macOS `vm_stat` page-size parsing not locale-aware | Use `sysctl hw.pagesize` subprocess call; locale-insensitive regex for page counts | v0.3.0 |
| KI-002 | Windows `wmic` deprecated on Win11 23H2+ | Replaced with PowerShell `Get-CimInstance Win32_OperatingSystem`; `wmic` retained as fallback | v0.3.0 |
| KI-003 | Background check daemon thread not restarted after fork | `os.register_at_fork(after_in_child=…)` clears `_bg_thread` / `_bg_stop` in child | v0.3.0 |
| KI-005 | Zero-filled snapshot on unsupported platforms raises no warning | `logging.WARNING` emitted once via module-level sentinel `_unsupported_platform_warned` | v0.3.0 |
| KI-006 | `generate_wslconfig` overwrites existing `.wslconfig` without backup | New `_merge_wslconfig()` helper: backs up existing file, merges only managed `[wsl2]` keys, preserves all other keys and sections | v0.3.0 |
| KI-004 | `cooldown_s` timer is global, not per-stage | `_last_logged` dict keyed by `f"{stage}\x00{severity}"` — each (stage, severity) pair now has an independent cooldown clock | v0.3.0 |

---

## Limitations (by design, not defects)

| Limitation | Rationale |
|---|---|
| Linux only for full feature set | `attributing` pressure requires `/proc/self/status` (RSS) and `/proc/meminfo`. macOS and Windows approximations are best-effort. | 
| No GPU memory monitoring | Out of scope for v0.x. Planned as optional plugin in M1 (CUDA/ROCm). |
| No cgroup v2 / container-aware attribution | Container memory limits differ from host `MemTotal`. Planned for M1-C06 area. |
| No network or I/O pressure attribution | Focused solely on RAM and swap. Disk I/O and network backpressure are separate problem domains. |
| Single-process attribution only | Distributed pressure across a process pool is out of scope until M2-C04. |
