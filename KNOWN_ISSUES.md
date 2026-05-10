# Known Issues — runtime-guard

> Defect and limitation registry. Each entry includes a severity rating, reproduction steps or conditions, and current workaround. Issues are resolved at the milestone or patch version indicated.

**Severity scale:**
- **S0 — Blocker:** Data loss, silent wrong result, crash with no recovery path.
- **S1 — High:** Incorrect attribution or missed pressure detection in documented scenarios.
- **S2 — Medium:** Degraded accuracy or usability; workaround exists.
- **S3 — Low:** Cosmetic, edge-case, or minor UX issue.

---

## Open Issues

### KI-001 — macOS `vm_stat` page-size parsing is not locale-aware
- **Severity:** S2
- **Affects:** macOS with non-English locale or non-standard page size
- **Version introduced:** 0.1.0
- **Description:** `vm_stat` output is parsed with a hard-coded page size of 4096 bytes and an English text pattern (`"Pages free:"`) for the field label. Systems configured with a different locale may fail to parse the output, returning a zero-filled snapshot instead of raising an error.
- **Workaround:** Set `LANG=en_US.UTF-8` before invoking the process, or force Linux mode on the host if running in a VM.
- **Fix target:** v0.3.0 — Refactor macOS snapshot reader to use `sysctl hw.pagesize` for the page size and regex with locale-insensitive flags.
- **Linked PR:** (pending)

---

### KI-002 — Windows `wmic` deprecated on Windows 11 23H2+
- **Severity:** S1
- **Affects:** Windows 11 builds ≥ 23H2, Windows Server 2025
- **Version introduced:** 0.1.0
- **Description:** Microsoft deprecated `wmic` in Windows 11 22H2 and removed it from Windows 11 23H2 in some editions. `_read_snapshot()` calls `wmic OS get FreePhysicalMemory` which silently returns an empty string on affected builds, producing a zero-filled snapshot. No warning is surfaced to the caller.
- **Workaround:** Use Linux or macOS, or run inside WSL 2 where `/proc/meminfo` is available.
- **Fix target:** v0.3.0 — Replace `wmic` with PowerShell `Get-CimInstance Win32_OperatingSystem` with a `wmic` fallback for older builds.
- **Linked PR:** (pending)

---

### KI-003 — Background check daemon thread is not restarted after fork
- **Severity:** S1
- **Affects:** Any code using `multiprocessing` with `fork` start method + `start_background_check()`
- **Version introduced:** 0.2.0
- **Description:** Python `multiprocessing` with `fork` copies the daemon thread handle but does not restart the thread in the child process. The child process has no active background check, but `_bg_thread` is truthy, so `start_background_check()` silently no-ops in the child. Pressure events in forked child processes are missed.
- **Workaround:** Do not call `start_background_check()` before forking. Call it explicitly inside each child process after the fork, or use `spawn` as the multiprocessing start method.
- **Fix target:** v0.3.0 — Register an `os.register_at_fork` `after_in_child` callback to clear `_bg_thread` so child processes can restart the check.
- **Linked PR:** (pending)

---

### KI-004 — `cooldown_s` timer is not per-stage, it is global
- **Severity:** S2
- **Affects:** Callers using multiple named stages with different cooldown expectations
- **Version introduced:** 0.2.0
- **Description:** The cooldown deduplication clock is a single timestamp shared across all `check()` / `log()` calls. If stage `"data-load"` fires a pressure event and starts the cooldown, stage `"model-train"` called 2 seconds later will also be suppressed even though it is a different logical phase.
- **Workaround:** Construct a separate `RuntimeGuard` instance per stage, or set `cooldown_s=0` to disable deduplication.
- **Fix target:** v0.4.0 — Make `_last_log_time` a `dict[str, float]` keyed by stage name.
- **Linked PR:** (pending)

---

### KI-005 — Zero-filled snapshot on non-Linux/macOS/Windows platforms raises no warning
- **Severity:** S3
- **Affects:** Any platform that is not Linux, macOS, or Windows (e.g., FreeBSD, Haiku, WASM)
- **Version introduced:** 0.1.0
- **Description:** On unsupported platforms, `_read_snapshot()` returns a `MemSnapshot` with all fields set to 0. `check()` interprets 0 MB available as "no pressure detected" (because the comparison is `available < floor` and 0 is not negative). This means pressure is *silently never reported* rather than raising `RuntimeError` or emitting a log warning.
- **Workaround:** Check `platform.system()` before relying on runtime-guard in production on non-standard platforms.
- **Fix target:** v0.3.0 — Emit a `logging.WARNING` once (using a module-level flag) when a zero-filled fallback is returned.
- **Linked PR:** (pending)

---

### KI-006 — `generate_wslconfig` overwrites existing `.wslconfig` without backup
- **Severity:** S1
- **Affects:** Any user with a hand-crafted `.wslconfig` who calls `generate_wslconfig()`
- **Version introduced:** 0.2.0
- **Description:** `generate_wslconfig()` writes the generated content to `~/.wslconfig` directly. If the file already exists with custom settings (e.g., custom `processors`, `kernelCommandLine`, proxy config), those settings are silently overwritten.
- **Workaround:** Back up `~/.wslconfig` manually before calling `generate_wslconfig()`.
- **Fix target:** v0.3.0 — Read existing file, merge only the `[wsl2]` keys managed by runtime-guard, and write back. Never remove unrecognised keys.
- **Linked PR:** (pending)

---

## Closed Issues

| ID | Summary | Resolution | Fixed in |
|---|---|---|---|
| — | — | — | — |

*(No closed issues yet — this registry was opened at v0.2.0.)*

---

## Limitations (by design, not defects)

| Limitation | Rationale |
|---|---|
| Linux only for full feature set | `attributing` pressure requires `/proc/self/status` (RSS) and `/proc/meminfo`. macOS and Windows approximations are best-effort. | 
| No GPU memory monitoring | Out of scope for v0.x. Planned as optional plugin in M1 (CUDA/ROCm). |
| No cgroup v2 / container-aware attribution | Container memory limits differ from host `MemTotal`. Planned for M1-C06 area. |
| No network or I/O pressure attribution | Focused solely on RAM and swap. Disk I/O and network backpressure are separate problem domains. |
| Single-process attribution only | Distributed pressure across a process pool is out of scope until M2-C04. |
