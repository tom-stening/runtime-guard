"""runtime_guard — attribution-aware resource-pressure monitor.

Zero third-party dependencies.  Reads /proc on Linux; falls back to
``vm_stat``/``sysctl`` on macOS and PowerShell ``Get-CimInstance`` on
Windows (``wmic`` retained as fallback for older builds).

Public API
----------
RuntimeGuard   — main class; construct once, call check() or check_and_log()
PressureReport — dataclass returned by check() when pressure is detected
MemSnapshot    — dataclass holding the memory snapshot values

New in v0.3.0
-------------
* **macOS locale-safe page size** — uses ``sysctl hw.pagesize`` rather than
    parsing English text headers from ``vm_stat`` output (KI-001).
* **Windows PowerShell primary path** — ``Get-CimInstance Win32_OperatingSystem``
    replaces ``wmic`` as the primary Windows backend; ``wmic`` is retained as a
    fallback for builds that pre-date its deprecation (KI-002).
* **Fork-safe background thread** — ``os.register_at_fork`` clears background
    thread handles in forked child processes so workers can restart cleanly (KI-003).
* **Unsupported-platform warning** — a single ``logging.WARNING`` is emitted when
    a zero-filled snapshot is returned on an unknown platform (KI-005).
* **Safe ``.wslconfig`` merge** — ``generate_wslconfig()`` backs up any existing
    file and merges only the keys it owns; custom keys and sections are preserved
    (KI-006).
* **Full argparse CLI** — ``runtime-guard --snapshot|--check|--report|
    --generate-wslconfig|--posture|--stage|--version`` (M0-C09).

New in v0.2.0
-------------
* **Threshold presets** — set ``<PREFIX>_POSTURE=tight|relaxed|ci`` to select a
    named threshold bundle instead of tuning four numeric env vars individually.
    Explicit numeric env vars always win over the preset default.
* **Structured JSON events** — every ``log()`` call also emits a compact JSON
    line at the same severity level on the ``runtime_guard.events`` logger so
    log-aggregation pipelines can filter and forward structured events without
    parsing human text.
* **Cooldown / deduplication** — pass ``cooldown_s=N`` (seconds) to suppress
    repeat log emissions when the same pressure condition persists.  Defaults to
    0 (emit every call, preserving previous behaviour).
* **Periodic background check** — call ``start_background_check(interval_s)``
    to poll memory on a daemon thread so pressure is detected between call sites.
    Stop with ``stop_background_check()``.
* **Cross-platform snapshot** — ``_read_snapshot()`` now falls back to
    ``vm_stat``/``sysctl hw.memsize``/``ps`` on macOS and PowerShell/``wmic``
    on Windows.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
import weakref
from dataclasses import dataclass, field

__all__ = [
    "RuntimeGuard",
    "PressureReport",
    "MemSnapshot",
    "make_pytest_guard",
    "InterventionResult",
    "KernelParamRecommendation",
    "generate_wslconfig",
    "recommend_kernel_params",
    "apply_kernel_params",
    "wsl_system_report",
    "make_conftest_content",
]

logger = logging.getLogger(__name__)
_json_logger = logging.getLogger("runtime_guard.events")

# ---------------------------------------------------------------------------
# Fork-safety: reset background-check thread state in child processes (KI-003)
# ---------------------------------------------------------------------------

_active_guards: list[weakref.ref] = []
_atfork_registered: bool = False


def _atfork_child_reset() -> None:  # pragma: no cover
    """Called in the child process after os.fork().  Clears thread handles so
    the child can call start_background_check() without the stale parent ref."""
    for ref in list(_active_guards):
        guard = ref()
        if guard is not None:
            guard._bg_stop = None  # type: ignore[attr-defined]
            guard._bg_thread = None  # type: ignore[attr-defined]
    _active_guards.clear()


# ---------------------------------------------------------------------------
# Unsupported-platform warning sentinel (KI-005)
# ---------------------------------------------------------------------------

_unsupported_platform_warned: bool = False


# ---------------------------------------------------------------------------
# Threshold presets
# ---------------------------------------------------------------------------

# Each preset is (min_mem_mb, max_swap_pct, critical_mem_mb, critical_swap_pct,
#                 self_inflicted_pct)
_PRESETS: dict[str, tuple[int, int, int, int, int]] = {
    "tight": (2048, 75, 1024, 90, 15),
    "relaxed": (512, 95, 256, 99, 25),
    "ci": (1024, 90, 512, 97, 20),
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class MemSnapshot:
    mem_total_mb: int = 0
    mem_available_mb: int = 0
    swap_total_mb: int = 0
    swap_free_mb: int = 0
    swap_used_pct: int = 0
    rss_mb: int = 0
    vm_swap_mb: int = 0


@dataclass
class InterventionResult:
    """Records what mitigating actions RuntimeGuard took."""

    actions_taken: list[str] = field(default_factory=list)
    gc_freed_mb: int = 0
    caches_dropped: bool = False
    memory_compacted: bool = False
    procs_killed: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return bool(self.actions_taken)

    @property
    def summary(self) -> str:
        parts: list[str] = []
        if self.gc_freed_mb:
            parts.append(f"GC freed ~{self.gc_freed_mb} MB")
        if self.caches_dropped:
            parts.append("page caches dropped")
        if self.memory_compacted:
            parts.append("memory compacted")
        if self.procs_killed:
            parts.append(f"killed PIDs {self.procs_killed}")
        return "; ".join(parts) if parts else "no actions taken"


@dataclass
class KernelParamRecommendation:
    """A single sysctl parameter recommendation."""

    param: str
    current_value: str
    recommended_value: str
    reason: str

    @property
    def sysctl_command(self) -> str:
        return f"sudo sysctl -w {self.param}={self.recommended_value}"

    @property
    def changed(self) -> bool:
        return self.current_value.strip() != self.recommended_value.strip()


@dataclass
class PressureReport:
    """Returned by RuntimeGuard.check() when pressure is detected."""

    snapshot: MemSnapshot
    is_critical: bool
    cause: str
    self_inflicted: bool  # True → this process is the primary driver
    self_pct: int  # this process's % of total system RAM
    pid: int = field(default_factory=os.getpid)
    stage: str = ""  # caller-supplied label, e.g. "data-load"
    min_mem_mb: int = 2048
    max_swap_pct: int = 85
    missing_mem_mb: int = 0  # how many MB below the min_mem_mb floor
    swap_excess_pct: int = 0  # how many percentage points above max_swap_pct


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------


class RuntimeGuard:
    """Lightweight resource-pressure checker with attribution-aware logging.

    Parameters
    ----------
    env_prefix:
        Prefix for environment-variable thresholds.  Default ``RUNTIME_GUARD``.
        Change this per-repo to avoid collisions when multiple repos use the
        library on the same machine.
    log_tag:
        The tag shown in brackets in log lines.  Default ``RuntimeGuard``.
    cooldown_s:
        Minimum seconds between successive log emissions for the *same*
        severity level.  ``0`` (default) disables cooldown and emits on every
        call, preserving the original behaviour.
    hints:
        Optional list of repo-specific actionable strings shown under the
        "Repo-specific actions" section.  Useful to record the heavy test
        commands, data-loading patterns, or skip flags that are unique to
        this repository.  Example::

            RuntimeGuard(
                hints=[
                    "Skip the slowest test group: pytest -m 'not slow'",
                    "Run with -x to stop after first failure: pytest -x",
                    "Reduce worker count: WORKERS=2 pytest -n2",
                ]
            )
    show_top_procs:
        When ``True`` (default) include a short table of the top RSS
        consumers from ``ps`` in every log emission.  Set to ``False`` to
        suppress the subprocess call.
    """

    def __init__(
        self,
        env_prefix: str = "RUNTIME_GUARD",
        log_tag: str = "RuntimeGuard",
        cooldown_s: float = 0.0,
        hints: list[str] | None = None,
        show_top_procs: bool = True,
    ) -> None:
        self._prefix = env_prefix.rstrip("_")
        self._tag = log_tag
        self._cooldown_s = cooldown_s
        self._hints: list[str] = hints or []
        self._show_top_procs = show_top_procs
        # Cooldown tracking: keyed by "critical"|"warning"
        self._last_logged: dict[str, float] = {}
        # Background-check state
        self._bg_stop: threading.Event | None = None
        self._bg_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API — synchronous
    # ------------------------------------------------------------------

    def check(self, stage: str = "") -> PressureReport | None:
        """Read a memory snapshot and return a PressureReport if pressure
        exceeds thresholds, or ``None`` if everything is fine."""
        min_mem_mb, max_swap_pct, critical_mem_mb, critical_swap_pct, self_inflicted_pct = (
            self._resolve_thresholds()
        )

        snap = _read_snapshot()
        mem_ok = snap.mem_available_mb >= min_mem_mb
        swap_ok = snap.swap_used_pct <= max_swap_pct

        if mem_ok and swap_ok:
            return None

        causes: list[str] = []
        if not mem_ok:
            causes.append(f"MemAvailable={snap.mem_available_mb} MB (threshold: {min_mem_mb} MB)")
        if not swap_ok:
            causes.append(f"SwapUsed={snap.swap_used_pct}% (threshold: {max_swap_pct}%)")

        is_critical = (
            snap.mem_available_mb < critical_mem_mb or snap.swap_used_pct > critical_swap_pct
        )

        self_pct = (snap.rss_mb * 100 // snap.mem_total_mb) if snap.mem_total_mb > 0 else 0
        self_inflicted = self_pct >= self_inflicted_pct and snap.mem_available_mb < min_mem_mb

        return PressureReport(
            snapshot=snap,
            is_critical=is_critical,
            cause=", ".join(causes),
            self_inflicted=self_inflicted,
            self_pct=self_pct,
            pid=os.getpid(),
            stage=stage,
            min_mem_mb=min_mem_mb,
            max_swap_pct=max_swap_pct,
            missing_mem_mb=max(0, min_mem_mb - snap.mem_available_mb),
            swap_excess_pct=max(0, snap.swap_used_pct - max_swap_pct),
        )

    def log(self, report: PressureReport) -> None:
        """Emit an attribution-aware log message.

        Calls ``logger.critical`` for critical pressure, ``logger.warning``
        otherwise.  Respects the ``cooldown_s`` deduplication window per stage:
        each (stage, severity) pair has an independent cooldown clock so that
        a pressure event in stage ``"data-load"`` does not suppress events from
        a concurrent ``"model-train"`` stage (KI-004).
        Also emits a compact JSON event on the ``runtime_guard.events`` logger
        at the same level for log-aggregation pipelines.
        """
        severity_key = "critical" if report.is_critical else "warning"
        # Key by stage so different stages have independent cooldown windows.
        cooldown_key = f"{report.stage}\x00{severity_key}"
        if self._cooldown_s > 0:
            now = time.monotonic()
            last = self._last_logged.get(cooldown_key, 0.0)
            if now - last < self._cooldown_s:
                return
            self._last_logged[cooldown_key] = now

        snap = report.snapshot
        severity = "CRITICAL" if report.is_critical else "HIGH"
        stage_label = f" stage={report.stage!r}" if report.stage else ""

        if report.self_inflicted:
            attribution = (
                f"This process is consuming ~{report.self_pct}% of total system RAM "
                f"({snap.rss_mb:,} MB RSS of {snap.mem_total_mb:,} MB total). "
                "The pressure is self-inflicted."
            )
            stage_hint = (
                (
                    f"  [This process] Stage {report.stage!r} is where the current work is happening.\n"
                    "                 Look at what data volumes and in-memory structures that stage\n"
                    "                 builds — reducing scope (shorter history window, smaller\n"
                    "                 batches, fewer parallel workers) will free RAM.\n"
                )
                if report.stage
                else (
                    "  [This process] Identify which part of your workload builds large in-memory\n"
                    "                 structures and reduce its scope to free RAM.\n"
                )
            )
            actions = (
                stage_hint
                + "  [This process] Inspect child-process memory from a separate shell:\n"
                + f"                 ps -o pid,rss,vsz,comm --ppid {report.pid} | sort -k2 -rn\n"
                + f"                 pmap -x {report.pid} | tail -1\n"
                + f"  [Thresholds]   Raise env {self._prefix}_MIN_MEM_AVAILABLE_MB "
                + f"(currently {report.min_mem_mb} MB) if the threshold is too aggressive."
            )
        else:
            attribution = (
                f"This process RSS is {snap.rss_mb:,} MB "
                f"(~{report.self_pct}% of total {snap.mem_total_mb:,} MB RAM). "
                "Pressure is most likely from another process on this host."
            )
            actions = (
                "  [External]     Find the process(es) consuming the missing RAM:\n"
                "                 ps aux --sort=-%mem | head -20\n"
                "                 smem -r | head -10  (if smem is available)\n"
                f"  [Thresholds]   Raise env {self._prefix}_MIN_MEM_AVAILABLE_MB "
                f"(currently {report.min_mem_mb} MB) if the threshold is too aggressive."
            )

        # Memory gap math
        gap_info = ""
        if report.missing_mem_mb > 0:
            gap_info += f"  Gap        : {report.missing_mem_mb:,} MB below available-RAM floor\n"
        if report.swap_excess_pct > 0:
            gap_info += f"  Swap excess: {report.swap_excess_pct}pp above swap threshold\n"

        # Repo-specific hints section
        hints_block = ""
        if self._hints:
            hints_block = (
                "  \u2500\u2500 Repo-specific actions \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                + "\n".join(f"  {h}" for h in self._hints)
                + "\n"
            )

        # Top processes table (always include — gives per-invocation context)
        top_procs_block = ""
        if self._show_top_procs:
            table = _top_memory_processes(n=7)
            if table:
                top_procs_block = (
                    "  \u2500\u2500 Top RSS consumers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                    + "\n".join(f"  {ln}" for ln in table.splitlines())
                    + "\n"
                )

        # WSL2 note — only when running in WSL; more nuanced guidance than "just shutdown"
        wsl_note = ""
        if _is_wsl():
            wsl_note = (
                "  [WSL2]     `memory=<N>GB` in %UserProfile%\\.wslconfig controls the VM\n"
                "             memory ceiling.  Increase it if you regularly see this warning.\n"
                "             After editing, run `wsl --shutdown` from PowerShell to apply.\n"
                "             Shutdown is a last resort \u2014 prefer freeing RAM within WSL first\n"
                "             (kill idle venvs / node servers, reduce test parallelism).\n"
            )

        log_fn = logger.critical if report.is_critical else logger.warning
        log_fn(
            "[%s] %s \u2014 resource pressure%s\n"
            "  Cause      : %s\n"
            "  Attribution: %s\n"
            "  Process    : RSS=%s MB  VmSwap=%s MB  (pid=%s)\n"
            "%s"
            "  \u2500\u2500 How to resolve \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            "%s\n"
            "%s"
            "%s"
            "%s"
            "  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500",
            self._tag,
            severity,
            stage_label,
            report.cause,
            attribution,
            snap.rss_mb,
            snap.vm_swap_mb,
            report.pid,
            gap_info,
            actions,
            hints_block,
            top_procs_block,
            wsl_note,
        )

        # --- Structured JSON event (runtime_guard.events logger) ---
        json_log_fn = _json_logger.critical if report.is_critical else _json_logger.warning
        json_log_fn(
            json.dumps(
                {
                    "event": "runtime_guard.pressure",
                    "severity": severity_key,
                    "tag": self._tag,
                    "stage": report.stage,
                    "pid": report.pid,
                    "cause": report.cause,
                    "self_inflicted": report.self_inflicted,
                    "self_pct": report.self_pct,
                    "is_critical": report.is_critical,
                    "mem_available_mb": snap.mem_available_mb,
                    "mem_total_mb": snap.mem_total_mb,
                    "swap_used_pct": snap.swap_used_pct,
                    "rss_mb": snap.rss_mb,
                    "vm_swap_mb": snap.vm_swap_mb,
                    "missing_mem_mb": report.missing_mem_mb,
                    "swap_excess_pct": report.swap_excess_pct,
                },
                separators=(",", ":"),
            )
        )

    def check_and_log(self, stage: str = "") -> PressureReport | None:
        """Convenience: check() then log() if pressure is found."""
        report = self.check(stage=stage)
        if report is not None:
            self.log(report)
        return report

    # ------------------------------------------------------------------
    # Background check
    # ------------------------------------------------------------------

    def start_background_check(
        self,
        interval_s: float = 60.0,
        stage: str = "background",
    ) -> None:  # noqa: E501
        """Start a periodic background pressure check on a daemon thread.

        Pressure events detected between call sites are logged via the normal
        ``log()`` path (including cooldown and JSON events).  Call
        ``stop_background_check()`` to cancel.

        Calling this method while a background check is already running
        replaces the existing interval and stage without creating a second
        thread.
        """
        # Register the fork handler once so child processes start clean (KI-003).
        global _atfork_registered
        if not _atfork_registered and hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=_atfork_child_reset)  # type: ignore[attr-defined]
            _atfork_registered = True
        _active_guards.append(weakref.ref(self))

        self.stop_background_check()
        self._bg_stop = threading.Event()
        stop_event = self._bg_stop  # local ref for closure
        interval = interval_s
        check_stage = stage
        guard = self

        def _loop() -> None:
            while not stop_event.wait(interval):
                guard.check_and_log(stage=check_stage)

        self._bg_thread = threading.Thread(target=_loop, daemon=True, name="runtime-guard-bg")
        self._bg_thread.start()

    def stop_background_check(self) -> None:
        """Stop the background check thread if one is running."""
        if self._bg_stop is not None:
            self._bg_stop.set()
            self._bg_stop = None
        if self._bg_thread is not None:
            self._bg_thread.join(timeout=1.0)
            self._bg_thread = None

    # ------------------------------------------------------------------
    # Active intervention
    # ------------------------------------------------------------------

    def intervene(
        self,
        report: PressureReport,
        *,
        kill_hogs_above_mb: int | None = None,
    ) -> "InterventionResult":
        """Take active mitigation steps to reduce memory pressure.

        Actions are applied in order of aggressiveness and safety:

        1. **GC collect** — always safe; frees unreachable Python objects.
        2. **Drop page caches** — frees clean (non-dirty) OS page cache.
           Requires write access to /proc (run as root or with CAP_SYS_ADMIN).
        3. **Compact memory** — defragments physical memory pages.
           Requires write access to /proc.
        4. **Kill hog processes** — sends SIGTERM to processes exceeding
           *kill_hogs_above_mb* RSS.  Only executed when ``is_critical=True``
           and a threshold is explicitly supplied.

        Returns an :class:`InterventionResult` describing every action taken.
        """
        result = InterventionResult()

        # 1. Python GC
        freed = _gc_collect()
        if freed > 0:
            result.gc_freed_mb = freed
            result.actions_taken.append(f"gc.collect() freed ~{freed} MB")
        else:
            result.actions_taken.append("gc.collect() ran (0 MB delta — already collected)")

        # 2. Drop page cache (pagecache only — safe, does NOT touch dirty pages)
        if _drop_caches():
            result.caches_dropped = True
            result.actions_taken.append("dropped page caches (/proc/sys/vm/drop_caches=1)")
        else:
            result.errors.append("drop_caches: no write access (needs root/CAP_SYS_ADMIN)")

        # 3. Compact memory
        if _compact_memory():
            result.memory_compacted = True
            result.actions_taken.append("triggered memory compaction (/proc/sys/vm/compact_memory)")

        # 4. Kill hog processes (only when critical and explicitly requested)
        if kill_hogs_above_mb is not None and report.is_critical:
            killed = _kill_hog_processes(
                kill_hogs_above_mb,
                exclude_pids=[os.getpid()],
            )
            if killed:
                result.procs_killed.extend(killed)
                result.actions_taken.append(
                    f"sent SIGTERM to {len(killed)} process(es) using >{kill_hogs_above_mb} MB RSS"
                )

        logger.info("[%s] Intervention complete: %s", self._tag, result.summary)
        return result

    def preflight_check(
        self,
        *,
        abort_on_critical: bool = True,
        auto_intervene: bool = True,
    ) -> "PressureReport | None":
        """Check memory before starting work and optionally take action.

        Call from ``pytest_configure`` or at the top of any heavy script.

        Parameters
        ----------
        abort_on_critical:
            If True and pressure is still CRITICAL after intervention, raises
            ``MemoryError`` so the caller can abort cleanly instead of OOM-ing.
        auto_intervene:
            If True, automatically call ``intervene()`` when pressure is found.

        Returns the :class:`PressureReport` (or ``None`` if no pressure).
        Raises ``MemoryError`` when *abort_on_critical* and pressure is critical.
        """
        report = self.check()
        if report is None:
            return None
        self.log(report)
        if auto_intervene:
            self.intervene(report)
            report = self.check()
            if report is None:
                logger.info("[%s] Pressure resolved after preflight intervention.", self._tag)
                return None
            self.log(report)
        if abort_on_critical and report is not None and report.is_critical:
            raise MemoryError(
                f"[RuntimeGuard:{self._tag}] Critical memory pressure before run: "
                f"{report.cause}. Free RAM or increase WSL memory limit."
            )
        return report

    def oom_protect(self, score: int = -500) -> bool:
        """Adjust the OOM killer score for this process.

        A lower oom_score_adj makes the OOM killer less likely to choose this
        process.  Range: -1000 (never kill) to +1000 (kill first).

        Default −500 strongly discourages the OOM killer while still allowing
        the kernel to kill the process in genuine extremis.

        Returns True if the score was written successfully.
        """
        success = _write_oom_score_adj(max(-1000, min(1000, score)))
        if success:
            logger.debug("[%s] OOM score adjusted to %d for pid=%d", self._tag, score, os.getpid())
        else:
            logger.debug(
                "[%s] Could not set OOM score (expected in unprivileged environments)",
                self._tag,
            )
        return success

    def memory_snapshot_mb(self) -> tuple[int, int, int]:
        """Return ``(available_mb, total_mb, swap_used_pct)`` as a quick snapshot."""
        snap = _read_snapshot()
        return snap.mem_available_mb, snap.mem_total_mb, snap.swap_used_pct

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_thresholds(self) -> tuple[int, int, int, int, int]:
        """Return (min_mem_mb, max_swap_pct, critical_mem_mb, critical_swap_pct,
        self_inflicted_pct) honouring the optional POSTURE preset."""
        posture_key = os.environ.get(f"{self._prefix}_POSTURE", "").strip().lower()
        preset = _PRESETS.get(posture_key, (2048, 85, 1024, 95, 20))

        min_mem_mb = self._int_env("MIN_MEM_AVAILABLE_MB", preset[0])
        max_swap_pct = self._int_env("MAX_SWAP_USED_PCT", preset[1])
        critical_mem_mb = self._int_env("CRITICAL_MEM_MB", preset[2])
        critical_swap_pct = self._int_env("CRITICAL_SWAP_PCT", preset[3])
        self_inflicted_pct = self._int_env("SELF_INFLICTED_PCT", preset[4])
        return min_mem_mb, max_swap_pct, critical_mem_mb, critical_swap_pct, self_inflicted_pct

    def _int_env(self, suffix: str, default: int) -> int:
        key = f"{self._prefix}_{suffix}"
        raw = os.environ.get(key, "")
        try:
            return int(raw) if raw.strip() else default
        except ValueError:
            return default


# ---------------------------------------------------------------------------
# Cross-platform snapshot reader
# ---------------------------------------------------------------------------


def _read_snapshot() -> MemSnapshot:
    """Read memory usage from the host OS.

    Tries three strategies in order:
    1. Linux  — ``/proc/meminfo`` + ``/proc/self/status``
    2. macOS  — ``sysctl hw.memsize`` + ``vm_stat`` + ``ps``
    3. Windows — ``wmic`` queries
    Falls back to zeros if nothing is available (no exceptions raised).
    """
    snap = MemSnapshot()

    if sys.platform.startswith("linux"):
        _read_linux(snap)
    elif sys.platform == "darwin":
        _read_macos(snap)
    elif sys.platform == "win32":
        _read_windows(snap)
    else:
        # KI-005: warn once so callers know monitoring is inactive.
        global _unsupported_platform_warned
        if not _unsupported_platform_warned:
            logger.warning(
                "[RuntimeGuard] Unsupported platform %r: memory snapshot will be "
                "zero-filled and pressure will never be reported.",
                sys.platform,
            )
            _unsupported_platform_warned = True

    return snap


# -- Linux -----------------------------------------------------------------


def _read_linux(snap: MemSnapshot) -> None:
    try:
        meminfo: dict[str, int] = {}
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                raw = parts[1].strip().split()
                if raw:
                    meminfo[key] = int(raw[0])

        mem_total_kb = meminfo.get("MemTotal", 0)
        mem_available_kb = meminfo.get("MemAvailable", 0)
        swap_total_kb = meminfo.get("SwapTotal", 0)
        swap_free_kb = meminfo.get("SwapFree", 0)
        swap_used_pct = 0
        if swap_total_kb > 0:
            swap_used_pct = int(100 * (swap_total_kb - swap_free_kb) / swap_total_kb)
        snap.mem_total_mb = mem_total_kb // 1024
        snap.mem_available_mb = mem_available_kb // 1024
        snap.swap_total_mb = swap_total_kb // 1024
        snap.swap_free_mb = swap_free_kb // 1024
        snap.swap_used_pct = swap_used_pct
    except OSError:
        pass

    try:
        status: dict[str, str] = {}
        with open("/proc/self/status", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    status[parts[0].strip()] = parts[1].strip()

        def _kb(key: str) -> int:
            raw = status.get(key, "0 kB").split()
            return int(raw[0]) if raw else 0

        snap.rss_mb = _kb("VmRSS") // 1024
        snap.vm_swap_mb = _kb("VmSwap") // 1024
    except OSError:
        pass


# -- macOS -----------------------------------------------------------------


def _read_macos(snap: MemSnapshot) -> None:
    """Populate snap using ``sysctl``, ``vm_stat``, and ``ps``."""
    try:
        # Total RAM
        out = subprocess.check_output(
            ["sysctl", "-n", "hw.memsize"], stderr=subprocess.DEVNULL, timeout=3
        )
        snap.mem_total_mb = int(out.strip()) // (1024 * 1024)
    except Exception:
        pass

    try:
        # KI-001: use sysctl hw.pagesize instead of parsing the vm_stat header
        # to avoid locale-sensitive text matching.
        try:
            ps_out = subprocess.check_output(
                ["sysctl", "-n", "hw.pagesize"], stderr=subprocess.DEVNULL, timeout=3
            )
            page_size = int(ps_out.strip())
        except Exception:
            page_size = 4096  # safe fallback for any kernel

        # Available memory: vm_stat gives page counts in a fixed-format output.
        # We match lines by their page-count field name using a locale-independent
        # regex so the parse works regardless of LANG / LC_ALL settings.
        import re as _re

        out = subprocess.check_output(["vm_stat"], stderr=subprocess.DEVNULL, timeout=3, text=True)
        _VM_STAT_RE = _re.compile(r"^\s*Pages\s+(free|inactive|speculative):\s+(\d+)", _re.M)
        counts: dict[str, int] = {}
        for m in _VM_STAT_RE.finditer(out):
            counts[m.group(1)] = int(m.group(2))
        pages_available = (
            counts.get("free", 0) + counts.get("inactive", 0) + counts.get("speculative", 0)
        )
        snap.mem_available_mb = (pages_available * page_size) // (1024 * 1024)
    except Exception:
        pass

    # macOS does not expose a simple swap figure via vm_stat; omit swap fields.

    try:
        # This process RSS
        out = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(os.getpid())],
            stderr=subprocess.DEVNULL,
            timeout=3,
            text=True,
        )
        snap.rss_mb = int(out.strip()) // 1024
    except Exception:
        pass


# -- Windows ---------------------------------------------------------------


def _read_windows(snap: MemSnapshot) -> None:
    """Populate snap using PowerShell Get-CimInstance (KI-002 fix), falling
    back to ``wmic`` on older Windows builds where PowerShell is restricted."""
    # --- System memory: try PowerShell first (Win11 23H2+ safe) ---
    _read_windows_powershell(snap)
    if snap.mem_total_mb == 0:
        _read_windows_wmic(snap)


def _read_windows_powershell(snap: MemSnapshot) -> bool:
    """Populate snap via PowerShell Get-CimInstance.  Returns True on success."""
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_OperatingSystem "
                "| Select-Object FreePhysicalMemory,TotalVisibleMemorySize "
                "| ConvertTo-Csv -NoTypeInformation",
            ],
            stderr=subprocess.DEVNULL,
            timeout=8,
            text=True,
        )
        lines = [ln.strip().strip('"') for ln in out.splitlines() if ln.strip()]
        if len(lines) >= 2:
            headers = [h.strip('"') for h in lines[0].split(",")]
            values = [v.strip('"') for v in lines[1].split(",")]
            row: dict[str, str] = dict(zip(headers, values))
            snap.mem_total_mb = int(row.get("TotalVisibleMemorySize", 0) or 0) // 1024
            snap.mem_available_mb = int(row.get("FreePhysicalMemory", 0) or 0) // 1024
    except Exception:
        return False

    # Process RSS via PowerShell
    try:
        pid = os.getpid()
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-Process -Id {pid}).WorkingSet64",
            ],
            stderr=subprocess.DEVNULL,
            timeout=5,
            text=True,
        )
        snap.rss_mb = int(out.strip()) // (1024 * 1024)
    except Exception:
        pass

    return snap.mem_total_mb > 0


def _read_windows_wmic(snap: MemSnapshot) -> None:
    """Legacy wmic fallback for Windows 10 and earlier."""
    try:
        out = subprocess.check_output(
            ["wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/value"],
            stderr=subprocess.DEVNULL,
            timeout=5,
            text=True,
        )
        fields: dict[str, int] = {}
        for line in out.splitlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                try:
                    fields[k.strip()] = int(v.strip())
                except ValueError:
                    pass
        snap.mem_total_mb = fields.get("TotalVisibleMemorySize", 0) // 1024
        snap.mem_available_mb = fields.get("FreePhysicalMemory", 0) // 1024
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            [
                "wmic",
                "process",
                "where",
                f"processid={os.getpid()}",
                "get",
                "WorkingSetSize",
                "/value",
            ],
            stderr=subprocess.DEVNULL,
            timeout=5,
            text=True,
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("WorkingSetSize="):
                _, _, v = line.partition("=")
                snap.rss_mb = int(v.strip()) // (1024 * 1024)
                break
    except Exception:
        pass


# ---------------------------------------------------------------------------
# System helpers
# ---------------------------------------------------------------------------


def _is_wsl() -> bool:
    """Return True when running inside WSL2 (Linux kernel built by Microsoft)."""
    try:
        with open("/proc/version") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def _top_memory_processes(n: int = 5) -> str:
    """Return a short human-readable table of the top *n* RSS consumers.

    Falls back gracefully if ``/proc`` is unavailable or ``ps`` fails.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["ps", "axo", "pid,rss,comm", "--no-headers", "--sort=-rss"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        lines = [ln for ln in result.stdout.splitlines() if ln.strip()][:n]
        if not lines:
            return ""
        rows = []
        for ln in lines:
            parts = ln.split(None, 2)
            if len(parts) == 3:
                pid, rss_kb, comm = parts
                try:
                    rss_mb = int(rss_kb) // 1024
                    rows.append(f"    {pid:>7}  {rss_mb:>6} MB  {comm}")
                except ValueError:
                    continue
        if not rows:
            return ""
        header = "       PID     RSS   COMMAND"
        return header + "\n" + "\n".join(rows)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Active intervention helpers
# ---------------------------------------------------------------------------


def _gc_collect() -> int:
    """Force a full Python garbage-collection cycle.

    Returns the approximate MB freed (delta of MemAvailable before/after).
    The delta may be 0 if nothing was collected or if the OS hadn't yet
    reclaimed the pages.
    """
    import gc

    before = _read_snapshot().mem_available_mb
    gc.collect(2)  # generation 2 = full collection
    after = _read_snapshot().mem_available_mb
    return max(0, after - before)


def _drop_caches() -> bool:
    """Drop the Linux page cache by writing ``1`` to drop_caches.

    This is safe: only clean (non-dirty) pages are reclaimed.  Dirty pages
    are flushed to disk first by the kernel before being reclaimed.  Requires
    write access to /proc/sys/vm/drop_caches (root or CAP_SYS_ADMIN).

    Returns True if the write succeeded.
    """
    try:
        with open("/proc/sys/vm/drop_caches", "w") as fh:
            fh.write("1\n")
        return True
    except OSError:
        return False


def _compact_memory() -> bool:
    """Trigger Linux memory compaction to reduce fragmentation.

    Writes ``1`` to /proc/sys/vm/compact_memory.  Requires root.
    Returns True if the write succeeded.
    """
    try:
        with open("/proc/sys/vm/compact_memory", "w") as fh:
            fh.write("1\n")
        return True
    except OSError:
        return False


def _write_oom_score_adj(score: int) -> bool:
    """Write an OOM score adjustment for the current process.

    Scores range from -1000 (never kill) to +1000 (kill first).  A process
    can write to its own oom_score_adj without root.  Returns True on success.
    """
    try:
        with open(f"/proc/{os.getpid()}/oom_score_adj", "w") as fh:
            fh.write(f"{score}\n")
        return True
    except OSError:
        return False


def _kill_hog_processes(
    above_mb: int,
    exclude_pids: list[int] | None = None,
) -> list[int]:
    """Send SIGTERM to processes using more than *above_mb* RSS.

    Processes in *exclude_pids* (defaulting to just the current process)
    are never touched.  Returns the list of PIDs that were signalled.
    """
    import signal

    exclude = set(exclude_pids or [])
    exclude.add(os.getpid())
    killed: list[int] = []
    try:
        result = subprocess.run(
            ["ps", "axo", "pid,rss", "--no-headers", "--sort=-rss"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                pid = int(parts[0])
                rss_mb = int(parts[1]) // 1024
            except ValueError:
                continue
            if rss_mb > above_mb and pid not in exclude:
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed.append(pid)
                except (ProcessLookupError, PermissionError):
                    pass
    except Exception:
        pass
    return killed


def _read_sysctl(path: str) -> str:
    """Read a /proc/sys value safely, returning 'unknown' on failure."""
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return "unknown"


def _read_proc_version() -> str:
    """Read /proc/version safely, truncated to 100 chars."""
    try:
        with open("/proc/version") as fh:
            return fh.read().strip()[:100]
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# Convenience factory for pytest conftest.py integration
# ---------------------------------------------------------------------------


def make_pytest_guard(
    *,
    repo_name: str,
    env_prefix: str | None = None,
    hints: list[str] | None = None,
    cooldown_s: float = 30.0,
) -> "RuntimeGuard":
    """Return a ``RuntimeGuard`` instance pre-configured for pytest use.

    This factory is the recommended way to add RuntimeGuard to a repo's
    ``conftest.py``.  It auto-derives the ``env_prefix`` from *repo_name*
    if not supplied, and sets a sensible 30 s cooldown to avoid flooding
    CI logs when pressure persists across many tests.

    Typical ``conftest.py`` usage::

        from runtime_guard import make_pytest_guard

        _guard = make_pytest_guard(
            repo_name="MyRepo",
            hints=[
                "Skip heavy tests: pytest -m 'not slow'",
                "Reduce parallelism: pytest -n2",
                "Clear build artefacts: rm -rf .pytest_cache __pycache__",
            ],
        )

        def pytest_sessionstart(session):
            _guard.check_and_log(stage="pytest-session-start")

        def pytest_runtest_setup(item):
            _guard.check_and_log(stage=item.nodeid)

    Parameters
    ----------
    repo_name:
        Human-readable name of this repository (used in ``log_tag`` and
        as the default ``env_prefix`` base).
    env_prefix:
        Override the auto-derived env prefix.  Defaults to
        ``REPO_NAME_GUARD`` (upper-cased, spaces → underscores).
    hints:
        Repo-specific actionable strings shown under the
        "Repo-specific actions" section when pressure is detected.
    cooldown_s:
        Seconds between successive log emissions.  Defaults to 30.
    """
    derived_prefix = (
        env_prefix
        if env_prefix is not None
        else repo_name.upper().replace(" ", "_").replace("-", "_") + "_GUARD"
    )
    return RuntimeGuard(
        env_prefix=derived_prefix,
        log_tag=repo_name,
        cooldown_s=cooldown_s,
        hints=hints or [],
    )


# ---------------------------------------------------------------------------
# WSL2 / kernel utilities  (public API)
# ---------------------------------------------------------------------------


def generate_wslconfig(
    *,
    memory_gb: int = 8,
    swap_gb: int | None = None,
    processors: int | None = None,
    output_path: str | None = None,
    dry_run: bool = True,
) -> str:
    """Generate a recommended ``.wslconfig`` for the Windows host.

    Without ``.wslconfig``, the WSL2 VM can consume ALL Windows host RAM +
    pagefile, starving the Windows kernel and causing the WSL2 VM to crash.
    This is the single most impactful WSL crash-prevention step.

    Parameters
    ----------
    memory_gb:
        Hard RAM ceiling for the WSL2 VM.  Rule of thumb: 60–70% of total
        host RAM (leave the remainder for Windows + GPU drivers).
    swap_gb:
        WSL2 swap file size.  Maps to Windows pagefile space.  Defaults to
        50% of *memory_gb* (minimum 2 GB).
    processors:
        Virtual CPU count.  Defaults to half the available CPUs.
    output_path:
        Path to write the file (Linux path, e.g. ``~/.wslconfig.recommended``).
        On the **Windows** host the file lives at ``%UserProfile%\\.wslconfig``.
    dry_run:
        If True (default), return content only without writing.

    Returns the generated file content as a string.
    """
    if swap_gb is None:
        swap_gb = max(2, memory_gb // 2)
    if processors is None:
        processors = max(1, (os.cpu_count() or 4) // 2)

    content = (
        "# .wslconfig — WSL2 resource limits\n"
        "# Generated by RuntimeGuard.generate_wslconfig()\n"
        "# ─────────────────────────────────────────────────────────────────\n"
        "# IMPORTANT: This file belongs on the WINDOWS host at:\n"
        "#   %UserProfile%\\.wslconfig   (e.g. C:\\Users\\YourName\\.wslconfig)\n"
        "# Apply with: wsl --shutdown  (run in PowerShell, then restart WSL)\n"
        "# ─────────────────────────────────────────────────────────────────\n"
        "\n"
        "[wsl2]\n"
        "# Hard memory ceiling.  Without this, WSL2 can consume all host\n"
        "# RAM + pagefile, causing Windows to stall and WSL to crash.\n"
        f"memory={memory_gb}GB\n"
        "\n"
        "# WSL2 swap (backed by Windows pagefile).  Smaller = less pagefile\n"
        "# pressure on the Windows host; prefer RAM over swap.\n"
        f"swap={swap_gb}GB\n"
        "\n"
        "# Limit vCPUs to avoid starving the Windows host under heavy builds.\n"
        f"processors={processors}\n"
        "\n"
        "# Return unused WSL memory back to Windows more aggressively.\n"
        "# Prevents balloon driver from hoarding memory after peak usage.\n"
        "pageReporting=true\n"
        "\n"
        "localhostForwarding=true\n"
        "nestedVirtualization=false\n"
    )

    if output_path and not dry_run:
        expanded = os.path.expanduser(output_path)
        # KI-006: merge existing file rather than overwriting it blindly.
        _merge_wslconfig(expanded, content)

    return content


def _merge_wslconfig(path: str, generated: str) -> None:
    """Safely merge the runtime-guard [wsl2] keys into an existing .wslconfig.

    Algorithm:
    1. If the file does not exist, write *generated* directly.
    2. If it exists, back it up as ``<path>.bak``, then merge:
       - Preserve all sections and keys NOT produced by runtime-guard.
       - Overwrite only the keys in the ``[wsl2]`` section that runtime-guard
         manages: ``memory``, ``swap``, ``processors``, ``pageReporting``,
         ``localhostForwarding``, ``nestedVirtualization``.
    """
    _MANAGED_KEYS = {
        "memory",
        "swap",
        "processors",
        "pagereporting",
        "localhostforwarding",
        "nestedvirtualization",
    }

    if not os.path.isfile(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(generated)
        logger.info("[RuntimeGuard] Wrote .wslconfig to %s", path)
        return

    # Back up the existing file before touching it.
    backup = path + ".bak"
    try:
        with open(path, encoding="utf-8") as fh:
            existing = fh.read()
        with open(backup, "w", encoding="utf-8") as fh:
            fh.write(existing)
        logger.info("[RuntimeGuard] Backed up existing .wslconfig to %s", backup)
    except OSError as exc:
        logger.warning("[RuntimeGuard] Could not back up .wslconfig: %s", exc)

    # Parse existing file line-by-line, replacing managed keys in [wsl2].
    # Parse generated content to extract the values to inject.
    new_vals: dict[str, str] = {}
    for line in generated.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            new_vals[k.strip().lower()] = line.rstrip()

    in_wsl2 = False
    output_lines: list[str] = []
    replaced: set[str] = set()

    for line in existing.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_wsl2 = stripped.lower() == "[wsl2]"
            output_lines.append(line)
            continue
        if in_wsl2 and "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip().lower()
            if key in _MANAGED_KEYS and key in new_vals:
                output_lines.append(new_vals[key])
                replaced.add(key)
                continue
        output_lines.append(line)

    # Append any managed keys that were absent in the existing file.
    missing = set(new_vals) - replaced
    if missing:
        # Ensure we're inside [wsl2]
        if "[wsl2]" not in "\n".join(output_lines).lower():
            output_lines.append("[wsl2]")
        for key in sorted(missing):
            output_lines.append(new_vals[key])

    merged = "\n".join(output_lines) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(merged)
    logger.info("[RuntimeGuard] Merged .wslconfig at %s", path)


def recommend_kernel_params(
    snap: "MemSnapshot | None" = None,
) -> "list[KernelParamRecommendation]":
    """Return Linux kernel parameter recommendations for WSL2 dev workloads.

    Reads current values from /proc/sys and returns a list of
    :class:`KernelParamRecommendation` objects.  Only parameters whose
    current value differs from the recommendation are flagged ``changed``.
    """
    if snap is None:
        snap = _read_snapshot()

    recs: list[KernelParamRecommendation] = []

    # ── vm.swappiness ────────────────────────────────────────────────────
    recs.append(
        KernelParamRecommendation(
            param="vm.swappiness",
            current_value=_read_sysctl("/proc/sys/vm/swappiness"),
            recommended_value="10",
            reason=(
                "Default 60 causes Linux to swap aggressively under moderate load. "
                "10 keeps active data in RAM longer, avoiding I/O-induced stalls "
                "that can appear as WSL2 VM hangs or crashes."
            ),
        )
    )

    # ── vm.min_free_kbytes ───────────────────────────────────────────────
    # Recommended: ~2% of total RAM, clamped to [128 MB, 1 GB]
    mem_total_kb = snap.mem_total_mb * 1024
    rec_min_free = max(131072, min(1048576, mem_total_kb // 50))
    recs.append(
        KernelParamRecommendation(
            param="vm.min_free_kbytes",
            current_value=_read_sysctl("/proc/sys/vm/min_free_kbytes"),
            recommended_value=str(rec_min_free),
            reason=(
                f"Reserve {rec_min_free // 1024} MB as a free-memory floor for the kernel. "
                "The current value is too low for a large-RAM WSL2 VM: the OOM killer fires "
                "without enough headroom to reclaim cleanly, crashing processes unexpectedly."
            ),
        )
    )

    # ── vm.dirty_ratio ───────────────────────────────────────────────────
    recs.append(
        KernelParamRecommendation(
            param="vm.dirty_ratio",
            current_value=_read_sysctl("/proc/sys/vm/dirty_ratio"),
            recommended_value="10",
            reason=(
                "Limit dirty (unwritten) pages to 10% of RAM. "
                "The default 20% can accumulate ~4 GB of dirty pages on a 19 GB VM, "
                "causing a large writeback storm that stalls all processes."
            ),
        )
    )

    # ── vm.dirty_background_ratio ────────────────────────────────────────
    recs.append(
        KernelParamRecommendation(
            param="vm.dirty_background_ratio",
            current_value=_read_sysctl("/proc/sys/vm/dirty_background_ratio"),
            recommended_value="5",
            reason=(
                "Start background writeback at 5% dirty pages (default 10%). "
                "Spreads disk I/O evenly and prevents burst write storms during test teardown."
            ),
        )
    )

    # ── vm.overcommit_memory ─────────────────────────────────────────────
    recs.append(
        KernelParamRecommendation(
            param="vm.overcommit_memory",
            current_value=_read_sysctl("/proc/sys/vm/overcommit_memory"),
            recommended_value="0",
            reason=(
                "Value 1 (always overcommit) allows unlimited allocation, hiding OOM "
                "conditions until too late. Value 0 (heuristic) refuses obviously "
                "excessive allocations early, giving controlled errors instead of "
                "surprise OOM kills."
            ),
        )
    )

    # ── vm.vfs_cache_pressure ────────────────────────────────────────────
    recs.append(
        KernelParamRecommendation(
            param="vm.vfs_cache_pressure",
            current_value=_read_sysctl("/proc/sys/vm/vfs_cache_pressure"),
            recommended_value="50",
            reason=(
                "Lower value (50 vs. default 100) keeps filesystem metadata "
                "(dentry/inode) in cache longer, reducing repeated disk reads "
                "during test runs that scan many Python source files."
            ),
        )
    )

    return recs


def apply_kernel_params(
    params: "list[KernelParamRecommendation] | None" = None,
    *,
    dry_run: bool = True,
) -> list[str]:
    """Apply kernel parameter recommendations via /proc/sys writes.

    Parameters
    ----------
    params:
        Recommendations to apply.  Defaults to ``recommend_kernel_params()``.
    dry_run:
        If True (default), log what would be done but make no writes.

    Returns a list of parameter names that were (or would be) applied.
    """
    if params is None:
        params = recommend_kernel_params()

    applied: list[str] = []
    for rec in params:
        if not rec.changed:
            continue
        if dry_run:
            logger.info(
                "[RuntimeGuard] (dry-run) Would apply: %s  (%s → %s)  — %s",
                rec.param,
                rec.current_value,
                rec.recommended_value,
                rec.reason[:60],
            )
            applied.append(rec.param)
        else:
            path = f"/proc/sys/{rec.param.replace('.', '/')}"
            try:
                with open(path, "w") as fh:
                    fh.write(rec.recommended_value + "\n")
                logger.info(
                    "[RuntimeGuard] Applied: %s = %s (was %s)",
                    rec.param,
                    rec.recommended_value,
                    rec.current_value,
                )
                applied.append(rec.param)
            except OSError as exc:
                logger.warning(
                    "[RuntimeGuard] Could not apply %s: %s  hint: %s",
                    rec.param,
                    exc,
                    rec.sysctl_command,
                )
    return applied


def wsl_system_report() -> str:
    """Generate a comprehensive WSL2 system health report.

    Returns a multi-line string covering: detected platform, memory/swap
    state, kernel parameter recommendations, .wslconfig presence, top RSS
    consumers, and actionable next steps.
    """
    snap = _read_snapshot()
    is_wsl = _is_wsl()

    def _fmt_status(ok: bool, warn_msg: str = "LOW \u26a0", ok_msg: str = "OK") -> str:
        return ok_msg if ok else warn_msg

    swap_warn_msg = "HIGH ⚠" if snap.swap_used_pct < 90 else "CRITICAL ✖"

    lines: list[str] = [
        "\u2550" * 66,
        "  RuntimeGuard \u2014 WSL2 System Health Report",
        "\u2550" * 66,
        f"  Platform       : {'WSL2 (Linux on Windows)' if is_wsl else sys.platform}",
        f"  Kernel         : {_read_proc_version()}",
        "",
        "  \u2500\u2500 Memory " + "\u2500" * 55,
        f"  Total RAM      : {snap.mem_total_mb:,} MB",
        f"  Available RAM  : {snap.mem_available_mb:,} MB  "
        f"[{_fmt_status(snap.mem_available_mb >= 2048)}]",
        f"  Swap Total     : {snap.swap_total_mb:,} MB",
        f"  Swap Free      : {snap.swap_free_mb:,} MB",
        f"  Swap Used      : {snap.swap_used_pct}%  "
        f"[{_fmt_status(snap.swap_used_pct < 75, warn_msg=swap_warn_msg)}]",
        "",
        "  \u2500\u2500 Kernel Parameters " + "\u2500" * 44,
    ]

    recs = recommend_kernel_params(snap)
    for rec in recs:
        status = "OK" if not rec.changed else "CHANGE RECOMMENDED \u26a0"
        lines.append(f"  {rec.param:<35} = {rec.current_value:<10} [{status}]")
        if rec.changed:
            lines.append(f"    \u2192 Recommended: {rec.recommended_value} — {rec.reason[:72]}...")
    lines.append("")

    if is_wsl:
        lines.append("  \u2500\u2500 .wslconfig " + "\u2500" * 51)
        wslconfig_candidates = [
            os.path.expanduser("~/.wslconfig"),
            "/mnt/c/Users/" + os.environ.get("USER", "") + "/.wslconfig",
        ]
        found_config: str | None = None
        for candidate in wslconfig_candidates:
            if os.path.isfile(candidate):
                found_config = candidate
                break
        if found_config:
            lines.append(f"  .wslconfig     : FOUND at {found_config}")
            try:
                with open(found_config) as fh:
                    for ln in fh:
                        lines.append(f"    {ln.rstrip()}")
            except OSError:
                pass
        else:
            lines.append("  .wslconfig     : NOT FOUND \u26a0\u26a0")
            lines.append("  Without this file WSL2 has NO memory ceiling and can consume")
            lines.append("  ALL Windows host RAM + pagefile \u2192 Windows stall \u2192 WSL crash.")
            mem_gb = snap.mem_total_mb // 1024
            rec_mem = max(8, int(mem_gb * 0.65))
            rec_swap = max(4, rec_mem // 2)
            rec_procs = max(2, (os.cpu_count() or 4) // 2)
            lines.append("  Recommended %UserProfile%\\.wslconfig settings:")
            lines.append(f"    memory={rec_mem}GB  swap={rec_swap}GB  processors={rec_procs}")
            lines.append(
                '  Run: python -c "from runtime_guard import generate_wslconfig; '
                'print(generate_wslconfig())"'
            )
        lines.append("")

    top = _top_memory_processes(n=10)
    if top:
        lines.append("  \u2500\u2500 Top RSS Consumers " + "\u2500" * 44)
        for ln in top.splitlines():
            lines.append(f"  {ln}")
        lines.append("")

    lines.append("  \u2500\u2500 Next Steps " + "\u2500" * 51)
    changed = [r for r in recs if r.changed]
    if changed:
        lines.append(f"  {len(changed)} kernel parameter(s) below recommended values:")
        for rec in changed:
            lines.append(f"    {rec.sysctl_command}")
        lines.append(
            "  For persistence add to /etc/sysctl.d/99-wsl2-memory.conf "
            "and run: sudo sysctl -p /etc/sysctl.d/99-wsl2-memory.conf"
        )
    else:
        lines.append("  All monitored kernel parameters are at recommended values.")
    lines.append("\u2550" * 66)
    return "\n".join(lines)


def make_conftest_content(
    *,
    repo_name: str,
    hints: list[str] | None = None,
    skip_on_critical: bool = True,
    intervene_on_warning: bool = True,
    kill_hogs_above_mb: int | None = None,
) -> str:
    """Return a complete ``conftest.py`` string for a repository.

    The generated conftest integrates RuntimeGuard with pytest to:

    - OOM-protect the test process on session start
    - Run preflight memory checks before the suite begins
    - Check pressure before each test; intervene if pressure is detected
    - Skip individual tests when memory is CRITICAL (avoids OOM crashes)
    - Run a background polling thread throughout the session
    - Log a final memory summary at session end

    Usage in a seeding script::

        from runtime_guard import make_conftest_content
        content = make_conftest_content(
            repo_name="MyRepo",
            hints=["Skip slow tests: pytest -m 'not slow'"],
        )
        with open("tests/conftest.py", "w") as fh:
            fh.write(content)
    """
    hints_repr = repr(hints or [])
    kill_repr = repr(kill_hogs_above_mb)
    skip_repr = repr(skip_on_critical)
    intervene_repr = repr(intervene_on_warning)

    lines: list[str] = [
        f'"""conftest.py \u2014 RuntimeGuard integration for {repo_name}.',
        "",
        "Auto-generated by RuntimeGuard.make_conftest_content().",
        "Provides proactive WSL2 crash prevention via memory-pressure monitoring.",
        "",
        "Behaviours",
        "----------",
        "- OOM-protects the pytest process (adjusts /proc/self/oom_score_adj).",
        "- Pre-flight check before the suite: intervenes if pressure detected.",
        "- Per-test check: skips tests when memory is CRITICAL (vs. crashing).",
        "- Background polling thread throughout the session.",
        "- Post-session memory summary logged to the root logger.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "import logging",
        "",
        "import pytest",
        "",
        "try:",
        "    from runtime_guard import make_pytest_guard",
        "    _GUARD = make_pytest_guard(",
        f"        repo_name={repo_name!r},",
        f"        hints={hints_repr},",
        "    )",
        "    _GUARD_AVAILABLE = True",
        "except ImportError:",
        "    _GUARD_AVAILABLE = False",
        "    _GUARD = None  # type: ignore[assignment]",
        "",
        '_logger = logging.getLogger("runtime_guard.conftest")',
        "",
        "",
        "def pytest_configure(config: pytest.Config) -> None:",
        '    """Startup: OOM-protect this process + preflight memory check."""',
        "    if not _GUARD_AVAILABLE or _GUARD is None:",
        "        return",
        "    # Reduce OOM-killer priority for the test process.",
        "    _GUARD.oom_protect()",
        "    # Preflight: intervene but do NOT abort (only warn).",
        "    try:",
        "        _GUARD.preflight_check(abort_on_critical=False, auto_intervene=True)",
        "    except Exception:",
        "        pass  # Never block test startup",
        "    # Background polling throughout the session.",
        "    _GUARD.start_background_check(interval_s=30.0)",
        "",
        "",
        "def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:",
        '    """Teardown: stop background check + log memory summary."""',
        "    if not _GUARD_AVAILABLE or _GUARD is None:",
        "        return",
        "    _GUARD.stop_background_check()",
        "    avail, total, swap_pct = _GUARD.memory_snapshot_mb()",
        "    _logger.info(",
        f'        "[{repo_name}] Session end \u2014 MemAvail=%d MB / %d MB total  SwapUsed=%d%%",',
        "        avail,",
        "        total,",
        "        swap_pct,",
        "    )",
        "",
        "",
        "def pytest_runtest_setup(item: pytest.Item) -> None:",
        '    """Before each test: check memory, intervene, skip if critical."""',
        "    if not _GUARD_AVAILABLE or _GUARD is None:",
        "        return",
        "    report = _GUARD.check_and_log(stage=item.nodeid)",
        "    if report is None:",
        "        return",
        f"    if {intervene_repr} or report.is_critical:",
        f"        _GUARD.intervene(report, kill_hogs_above_mb={kill_repr})",
        "        report = _GUARD.check()",
        f"    if {skip_repr} and report is not None and report.is_critical:",
        "        pytest.skip(",
        '            f"Skipping {item.nodeid}: memory pressure CRITICAL",',
        '            f" ({report.cause}) — preventing OOM crash",',
        "        )",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI  (`runtime-guard` entry-point or `python -m runtime_guard`)
# ---------------------------------------------------------------------------


def _cli() -> None:  # pragma: no cover
    """CLI entry point for ``runtime-guard`` and ``python -m runtime_guard``.

    Modes
    -----
    (no flags)         Print a one-line snapshot; exit 1 if pressure detected.
    --snapshot         Print a detailed human-readable memory snapshot and exit 0.
    --check            Exit 0 (no pressure) or 1 (pressure detected); always prints cause.
    --report           Full WSL2 system health report (same as wsl_system_report()).
    --generate-wslconfig [MEM_GB]
                       Print a recommended .wslconfig; optionally write it with
                       --write (respects existing file — merges, does not overwrite).
    --posture POSTURE  Override threshold preset for this invocation (tight|relaxed|ci).
    --stage STAGE      Label for the check (shown in log output).
    --version          Print the package version and exit.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="runtime-guard",
        description="Attribution-aware resource-pressure monitor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--snapshot",
        action="store_true",
        help="Print a detailed memory snapshot and exit 0.",
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Check for pressure; exit 1 if detected.",
    )
    group.add_argument(
        "--report",
        action="store_true",
        help="Print a full WSL2 / system health report.",
    )
    group.add_argument(
        "--generate-wslconfig",
        metavar="MEM_GB",
        type=int,
        nargs="?",
        const=0,  # sentinel: auto-detect from current RAM
        help="Print a recommended .wslconfig (optionally with --write to save it).",
    )
    parser.add_argument(
        "--write",
        metavar="PATH",
        help="Write output to PATH instead of stdout (used with --generate-wslconfig).",
    )
    parser.add_argument(
        "--posture",
        choices=list(_PRESETS),
        help="Override threshold preset for this check.",
    )
    parser.add_argument(
        "--stage",
        default="",
        help="Label to attach to the check (shown in log output).",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the package version and exit.",
    )

    args = parser.parse_args()

    logging.basicConfig(format="%(message)s", level=logging.DEBUG, stream=sys.stderr)

    if args.version:
        try:
            from importlib.metadata import version as _pkg_version

            print(_pkg_version("runtime-guard"))
        except Exception:
            print("unknown")
        return

    if args.report:
        print(wsl_system_report())
        return

    if args.generate_wslconfig is not None:
        snap = _read_snapshot()
        mem_gb = (
            args.generate_wslconfig
            if args.generate_wslconfig > 0
            else max(4, snap.mem_total_mb // 1024)
        )
        write_path = args.write
        content = generate_wslconfig(
            memory_gb=mem_gb,
            output_path=write_path,
            dry_run=(write_path is None),
        )
        if write_path is None:
            print(content)
        else:
            print(f"[RuntimeGuard] .wslconfig written (merged) to {write_path}", file=sys.stderr)
        return

    if args.snapshot:
        snap = _read_snapshot()
        print(
            f"Platform      : {sys.platform}\n"
            f"MemTotal      : {snap.mem_total_mb:,} MB\n"
            f"MemAvailable  : {snap.mem_available_mb:,} MB\n"
            f"SwapTotal     : {snap.swap_total_mb:,} MB\n"
            f"SwapFree      : {snap.swap_free_mb:,} MB\n"
            f"SwapUsed      : {snap.swap_used_pct}%\n"
            f"RSS (this pid): {snap.rss_mb:,} MB\n"
            f"VmSwap        : {snap.vm_swap_mb:,} MB\n"
            f"PID           : {os.getpid()}"
        )
        return

    # Default and --check share the same logic; --check is explicit, default is compact.
    env_overrides: dict[str, str] = {}
    if args.posture:
        env_overrides["RUNTIME_GUARD_POSTURE"] = args.posture

    old_env = {k: os.environ.get(k) for k in env_overrides}
    for k, v in env_overrides.items():
        os.environ[k] = v
    try:
        guard = RuntimeGuard()
        report = guard.check(stage=args.stage)
    finally:
        for k, original in old_env.items():
            if original is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = original

    if report is None:
        snap = _read_snapshot()
        print(
            f"[RuntimeGuard] OK — MemAvail={snap.mem_available_mb} MB  "
            f"SwapUsed={snap.swap_used_pct}%  "
            f"RSS={snap.rss_mb} MB  pid={os.getpid()}"
        )
        sys.exit(0)
    else:
        guard.log(report)
        sys.exit(1)


if __name__ == "__main__":
    _cli()
