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
import hashlib
import logging
import os
import subprocess
import sys
import threading
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable

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
    "diagnose_wsl_crash",
    "make_conftest_content",
    "make_sitecustomize_content",
    "attach_polars_guard",
    "attach_dask_guard",
    "install_dask_scheduler_callbacks",
    "attach_ray_guard",
    "enable_ray_actor_memory_monitoring",
    "pressure_report_attributes",
    "trace_context_attributes",
    "emit_otel_event",
    "emit_otel_phase_event",
    "render_prometheus_metrics",
    "validate_runtime_guard_config",
    "attach_signal_recovery",
    "resolve_signal_recovery_policy",
    "install_signal_recovery_from_policy",
    "audit_policy_taxonomy",
    "normalize_policy_violation_event",
    "append_audit_log",
    "fips_event_hash",
    "FipsDeduplicator",
    "verify_audit_log_chain",
    "soc2_required_controls",
    "soc2_gap_assessment",
    "soc2_evidence_requirements",
    "soc2_readiness_report",
    "build_adoption_scorecard",
    "validate_polars_integration",
    "collect_polars_integration_evidence",
    "validate_dask_integration",
    "collect_dask_integration_evidence",
    "validate_ray_integration",
    "collect_ray_integration_evidence",
    "make_worker_report",
    "aggregate_worker_reports",
    "append_worker_report_jsonl",
    "load_worker_reports_jsonl",
    "aggregate_worker_reports_jsonl",
    "subprocess_safe",
    "install_polars_scan_budget",
    "install_dask_task_graph_guard",
    "install_otel_memory_exporter",
    "install_prometheus_endpoint",
    "install_distributed_trace_propagator",
]

logger = logging.getLogger(__name__)
_json_logger = logging.getLogger("runtime_guard.events")
# Fork-safety: reset background-check thread state in child processes (KI-003)
# ---------------------------------------------------------------------------

_active_guards: list[weakref.ref] = []
_atfork_registered: bool = False
_FIPS_HASH_ALGOS: set[str] = {"sha256", "sha384", "sha512"}
_AUDIT_POLICY_SEVERITIES: set[str] = {"info", "warning", "critical"}
_AUDIT_POLICY_CATEGORIES: set[str] = {
    "access",
    "auth",
    "availability",
    "compliance",
    "config",
    "data_quality",
    "incident",
    "integrity",
    "memory",
    "network",
    "pipeline",
    "process",
    "resource",
    "scheduler",
    "storage",
    "swap",
    "system",
    "unknown",
}
_AUDIT_POLICY_ACTIONS: set[str] = {
    "abort",
    "acknowledge",
    "alert",
    "checkpoint",
    "custom",
    "drain",
    "escalate",
    "evict",
    "kill_hogs",
    "notify",
    "observe",
    "policy_violation",
    "pressure_detected",
    "quarantine",
    "rebalance",
    "recover",
    "remediate",
    "rollback",
    "snapshot",
    "suspend",
    "throttle",
    "validate",
}
_SOC2_RUNTIME_GUARD_CONTROLS: dict[str, str] = {
    "CC6.1": "Logical access controls and role-bound privileged actions.",
    "CC6.2": "Restrict logical access to protected resources using least-privilege principles.",
    "CC6.6": "Detect and protect against threats from external sources.",
    "CC7.1": "Monitoring for anomalies and operational events.",
    "CC7.2": "Incident response workflow and escalation evidence.",
    "CC7.3": "Detected anomalies are investigated, triaged, and remediated.",
    "CC8.1": "Changes to monitoring and recovery policy are authorized, tested, and approved.",
    "A1.1": "Capacity planning and performance monitoring against availability commitments.",
    "A1.2": "Recovery and continuity procedures maintain availability during disruptions.",
    "PI1.2": "Inputs to processing are complete, accurate, and authorized.",
}
_SOC2_CONTROL_EVIDENCE_REQUIREMENTS: dict[str, list[str]] = {
    "CC6.1": [
        "access-review-log",
        "privileged-action-audit-trail",
    ],
    "CC6.2": [
        "least-privilege-policy-doc",
        "resource-access-role-matrix",
        "privileged-access-review-log",
    ],
    "CC6.6": [
        "external-threat-detection-log",
        "anomaly-alert-configuration",
        "threat-response-runbook",
    ],
    "CC7.1": [
        "monitoring-alert-history",
        "on-call-acknowledgement-record",
    ],
    "CC7.2": [
        "incident-timeline",
        "post-incident-corrective-actions",
    ],
    "CC7.3": [
        "alert-triage-record",
        "incident-retrospective",
    ],
    "CC8.1": [
        "change-approval-record",
        "rollback-validation-log",
    ],
    "A1.1": [
        "capacity-baseline-report",
        "memory-pressure-trend-log",
        "availability-sla-evidence",
    ],
    "A1.2": [
        "recovery-procedure-doc",
        "signal-recovery-test-log",
        "business-continuity-plan",
    ],
    "PI1.2": [
        "input-validation-policy",
        "authorized-pipeline-run-log",
        "data-integrity-audit-record",
    ],
}


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
    # Host (Windows) metrics when running under WSL
    host_mem_total_mb: int = 0
    host_mem_available_mb: int = 0
    host_swap_total_mb: int = 0
    host_swap_free_mb: int = 0
    host_swap_used_pct: int = 0
    # Drift fields (guest - host)
    drift_mem_total_mb: int = 0
    drift_mem_available_mb: int = 0
    drift_swap_used_pct: int = 0


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


class _GuardPhaseContext:
    """Sync/async context manager for phase-scoped RuntimeGuard checks."""

    def __init__(
        self,
        guard: "RuntimeGuard",
        stage: str,
        *,
        check_on_enter: bool,
        check_on_exit: bool,
        emit_phase_traces: bool,
        trace_module: Any | None,
    ) -> None:
        self._guard = guard
        self._stage = stage
        self._check_on_enter = check_on_enter
        self._check_on_exit = check_on_exit
        self._emit_phase_traces = emit_phase_traces
        self._trace_module = trace_module

    def __enter__(self) -> "_GuardPhaseContext":
        if self._emit_phase_traces:
            emit_otel_phase_event(
                self._stage,
                lifecycle="enter",
                module=self._trace_module,
            )
        if self._check_on_enter:
            self._guard.check_and_log(stage=f"{self._stage}:enter")
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if self._emit_phase_traces:
            lifecycle = "error" if exc is not None else "exit"
            attrs = {"runtime_guard.phase.exception_type": str(exc_type.__name__)} if exc_type else None
            emit_otel_phase_event(
                self._stage,
                lifecycle=lifecycle,
                module=self._trace_module,
                attributes=attrs,
            )
        if self._check_on_exit:
            self._guard.check_and_log(stage=f"{self._stage}:exit")
        return False

    async def __aenter__(self) -> "_GuardPhaseContext":
        if self._emit_phase_traces:
            emit_otel_phase_event(
                self._stage,
                lifecycle="enter",
                module=self._trace_module,
            )
        if self._check_on_enter:
            self._guard.check_and_log(stage=f"{self._stage}:enter")
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if self._emit_phase_traces:
            lifecycle = "error" if exc is not None else "exit"
            attrs = {"runtime_guard.phase.exception_type": str(exc_type.__name__)} if exc_type else None
            emit_otel_phase_event(
                self._stage,
                lifecycle=lifecycle,
                module=self._trace_module,
                attributes=attrs,
            )
        if self._check_on_exit:
            self._guard.check_and_log(stage=f"{self._stage}:exit")
        return False


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
        # Dynamic policy-reload state (M2-C03)
        self._policy_overrides: dict[str, Any] = {}
        self._policy_path: str | None = None
        self._policy_mtime_ns: int | None = None
        self._policy_auto_reload: bool = False

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
        json_log = {
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
        }
        # If host metrics are present, include them and drift
        if getattr(snap, "host_mem_total_mb", 0):
            json_log["host_mem_total_mb"] = snap.host_mem_total_mb
            json_log["host_mem_available_mb"] = snap.host_mem_available_mb
            json_log["host_swap_total_mb"] = snap.host_swap_total_mb
            json_log["host_swap_free_mb"] = snap.host_swap_free_mb
            json_log["host_swap_used_pct"] = snap.host_swap_used_pct
            json_log["drift_mem_total_mb"] = snap.drift_mem_total_mb
            json_log["drift_mem_available_mb"] = snap.drift_mem_available_mb
            json_log["drift_swap_used_pct"] = snap.drift_swap_used_pct
        json_log_fn(json.dumps(json_log, separators=(",", ":")))

    def check_and_log(self, stage: str = "", *, auto_intervene: bool = False, kill_hogs_above_mb: int | None = None) -> PressureReport | None:
        """Convenience: check() then log() if pressure is found.
        
        Args:
            stage: Name of the check stage for logging
            auto_intervene: If True, calls intervene() when critical pressure is detected
            kill_hogs_above_mb: Memory threshold (MB) for killing hog processes
        """
        report = self.check(stage=stage)
        if report is not None:
            self.log(report)
            if auto_intervene and report.is_critical:
                self.intervene(report, kill_hogs_above_mb=kill_hogs_above_mb)
        return report
    def phase(
        self,
        stage: str,
        *,
        check_on_enter: bool = True,
        check_on_exit: bool = True,
        emit_phase_traces: bool = False,
        trace_module: Any | None = None,
    ) -> "_GuardPhaseContext":
        """Return a context manager that checks memory around a named phase.

        Supports both ``with`` and ``async with`` usage. By default, memory is
        checked on both enter and exit with stage labels ``<stage>:enter`` and
        ``<stage>:exit``.

        When ``emit_phase_traces=True``, lightweight OpenTelemetry lifecycle
        events are emitted with stage and lifecycle attributes
        (``enter``, ``exit``, ``error``), without requiring pressure.
        """
        return _GuardPhaseContext(
            self,
            stage,
            check_on_enter=check_on_enter,
            check_on_exit=check_on_exit,
            emit_phase_traces=emit_phase_traces,
            trace_module=trace_module,
        )

    def install_signal_recovery(
        self,
        *,
        signals_to_handle: list[int] | None = None,
        stage_prefix: str = "signal",
        auto_intervene: bool = False,
        intervene_on: str = "critical",
        kill_hogs_above_mb: int | None = None,
        chain_previous: bool = False,
    ) -> Callable[[], None]:
        """Install signal handlers that perform a final pressure check.

        Returns a restore function that reinstates original signal handlers.
        """
        return attach_signal_recovery(
            self,
            signals_to_handle=signals_to_handle,
            stage_prefix=stage_prefix,
            auto_intervene=auto_intervene,
            intervene_on=intervene_on,
            kill_hogs_above_mb=kill_hogs_above_mb,
            chain_previous=chain_previous,
        )

    def audit(
        self,
        report: "PressureReport",
        *,
        path: str,
        action: str = "pressure-detected",
        metadata: dict[str, Any] | None = None,
        hash_algo: str = "sha256",
        deduplicator: "FipsDeduplicator" | None = None,
    ) -> dict[str, Any]:
        """Append a pressure event to an audit log file."""
        event: dict[str, Any] = {
            "action": action,
            "severity": "critical" if report.is_critical else "warning",
            "stage": report.stage,
            "pid": report.pid,
            "cause": report.cause,
            "self_inflicted": report.self_inflicted,
            "self_pct": report.self_pct,
            "missing_mem_mb": report.missing_mem_mb,
            "swap_excess_pct": report.swap_excess_pct,
        }
        if metadata:
            event["metadata"] = metadata
        return append_audit_log(
            path,
            event,
            hash_algo=hash_algo,
            deduplicator=deduplicator,
        )

    def worker_report(
        self,
        *,
        stage: str = "worker",
        worker_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a process-local worker report for parent aggregation."""
        return make_worker_report(
            self,
            stage=stage,
            worker_id=worker_id,
            metadata=metadata,
        )

    def aggregate_workers(self, reports: list[dict[str, Any]]) -> dict[str, Any]:
        """Aggregate worker reports into a single orchestration summary."""
        return aggregate_worker_reports(reports)

    def append_worker_report(
        self,
        path: str,
        *,
        stage: str = "worker",
        worker_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build and append a worker report to a JSONL transport file."""
        report = self.worker_report(stage=stage, worker_id=worker_id, metadata=metadata)
        return append_worker_report_jsonl(path, report)

    def aggregate_workers_from_jsonl(self, path: str) -> dict[str, Any]:
        """Load worker reports from JSONL and aggregate into a summary."""
        return aggregate_worker_reports_jsonl(path)

    def set_policy_overrides(self, config: dict[str, Any]) -> dict[str, Any]:
        """Set validated in-memory policy overrides for thresholds/posture."""
        validated = validate_runtime_guard_config(config)
        self._policy_overrides = dict(validated)
        return dict(self._policy_overrides)

    def clear_policy_overrides(self) -> None:
        """Clear all in-memory policy overrides."""
        self._policy_overrides = {}

    def load_policy_file(
        self,
        path: str,
        *,
        auto_reload: bool = True,
    ) -> dict[str, Any]:
        """Load validated policy overrides from a JSON file.

        When *auto_reload* is True, ``check()`` will automatically refresh
        policy values when the file's modification timestamp changes.
        """
        expanded = os.path.expanduser(path)
        with open(expanded, encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise ValueError("Policy file must contain a JSON object")
        validated = validate_runtime_guard_config(raw)
        self._policy_path = expanded
        self._policy_overrides = dict(validated)
        self._policy_auto_reload = auto_reload
        self._policy_mtime_ns = os.stat(expanded).st_mtime_ns
        return dict(self._policy_overrides)

    def reload_policy_if_changed(self) -> bool:
        """Reload policy file if changed on disk.

        Returns True when the policy was reloaded, False otherwise.
        """
        if not self._policy_path or not self._policy_auto_reload:
            return False
        try:
            stat = os.stat(self._policy_path)
        except OSError:
            return False
        if self._policy_mtime_ns is not None and stat.st_mtime_ns == self._policy_mtime_ns:
            return False

        with open(self._policy_path, encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise ValueError("Policy file must contain a JSON object")
        validated = validate_runtime_guard_config(raw)
        self._policy_overrides = dict(validated)
        self._policy_mtime_ns = stat.st_mtime_ns
        return True

    # ------------------------------------------------------------------
    # Background check
    # ------------------------------------------------------------------

    def start_background_check(
        self,
        interval_s: float = 60.0,
        stage: str = "background",
        auto_intervene: bool = False,
        kill_hogs_above_mb: int | None = None,
    ) -> None:
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
                auto_int = auto_intervene
                kill_hogs_mb = kill_hogs_above_mb
                guard.check_and_log(stage=check_stage, auto_intervene=auto_int, kill_hogs_above_mb=kill_hogs_mb)

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

    def subprocess_safe(
        self,
        label: str = "subprocess",
        *,
        min_mb: int = 500,
        stage: str = "",
    ) -> tuple[bool, str]:
        """Check whether it is safe to launch a memory-hungry subprocess.

        Intended for callers that are about to fork a heavy process
        (e.g. Chrome/Selenium, Java VM, data-processing workers) and want
        to bail out gracefully rather than crash with an OOM error.

        Parameters
        ----------
        label:
            Human-readable name of the subprocess being launched, used in
            the returned reason string for diagnostics (e.g. ``"Chrome"``).
        min_mb:
            Minimum available RAM (MB) required to proceed.  Defaults to
            500 MB — a conservative floor for browser processes on WSL2.
            Increase for known heavy processes (e.g. 1024 for JVM).
        stage:
            Optional stage label forwarded to ``check()`` so pressure events
            are attributed to this launch site in structured logs.

        Returns
        -------
        ``(True, "")`` when it is safe to proceed.
        ``(False, reason)`` when memory pressure is critical or available
        RAM is below *min_mb*.  *reason* is a human-readable string
        suitable for use in log messages or exception text.

        Example
        -------
        ::

            safe, reason = guard.subprocess_safe("Chrome", min_mb=500)
            if not safe:
                raise RuntimeError(
                    f"Skipping Chrome launch — {reason}. "
                    "Free memory before retrying."
                )
        """
        snap = _read_snapshot()
        if snap.mem_available_mb < min_mb:
            return (
                False,
                f"{label} launch skipped — "
                f"MemAvailable={snap.mem_available_mb} MB < {min_mb} MB threshold",
            )

        report = self.check(stage=stage or f"pre-launch:{label}")
        if report is not None and report.is_critical:
            return False, f"{label} launch skipped — system under memory pressure ({report.cause})"

        return True, ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_thresholds(self) -> tuple[int, int, int, int, int]:
        """Return (min_mem_mb, max_swap_pct, critical_mem_mb, critical_swap_pct,
        self_inflicted_pct) honouring the optional POSTURE preset."""
        # M2-C03: optionally hot-reload policy file on every threshold resolve.
        self.reload_policy_if_changed()

        env_posture_key = os.environ.get(f"{self._prefix}_POSTURE", "").strip().lower()
        policy_posture_key = str(self._policy_overrides.get("posture", "")).strip().lower()
        posture_key = env_posture_key or policy_posture_key
        preset = _PRESETS.get(posture_key, (2048, 85, 1024, 95, 20))

        min_mem_mb = self._int_env(
            "MIN_MEM_AVAILABLE_MB",
            int(self._policy_overrides.get("min_mem_available_mb", preset[0])),
        )
        max_swap_pct = self._int_env(
            "MAX_SWAP_USED_PCT",
            int(self._policy_overrides.get("max_swap_used_pct", preset[1])),
        )
        critical_mem_mb = self._int_env(
            "CRITICAL_MEM_MB",
            int(self._policy_overrides.get("critical_mem_mb", preset[2])),
        )
        critical_swap_pct = self._int_env(
            "CRITICAL_SWAP_PCT",
            int(self._policy_overrides.get("critical_swap_pct", preset[3])),
        )
        self_inflicted_pct = self._int_env(
            "SELF_INFLICTED_PCT",
            int(self._policy_overrides.get("self_inflicted_pct", preset[4])),
        )
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

    # If running under WSL, also snapshot host (Windows) metrics and drift.
    if _is_wsl():
        _read_windows_host_from_wsl(snap)
        if snap.host_mem_total_mb:
            snap.drift_mem_total_mb = snap.mem_total_mb - snap.host_mem_total_mb
        if snap.host_mem_available_mb:
            snap.drift_mem_available_mb = snap.mem_available_mb - snap.host_mem_available_mb
        if snap.host_swap_used_pct:
            snap.drift_swap_used_pct = snap.swap_used_pct - snap.host_swap_used_pct


# -- WSL Host (Windows) snapshot from WSL -----------------------------------


def _read_windows_host_from_wsl(snap: MemSnapshot) -> None:
    """Populate host_* fields on snap by calling PowerShell from WSL."""
    try:
        out = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_OperatingSystem | "
                "Select-Object TotalVisibleMemorySize,FreePhysicalMemory,"
                "TotalVirtualMemorySize,FreeVirtualMemory | "
                "ConvertTo-Csv -NoTypeInformation",
            ],
            stderr=subprocess.DEVNULL,
            timeout=8,
            text=True,
        )
        lines = [ln.strip().strip('"') for ln in out.splitlines() if ln.strip()]
        if len(lines) >= 2:
            headers = [h.strip('"') for h in lines[0].split(",")]
            values = [v.strip('"') for v in lines[1].split(",")]
            row = dict(zip(headers, values))
            snap.host_mem_total_mb = int(row.get("TotalVisibleMemorySize", 0) or 0) // 1024
            snap.host_mem_available_mb = int(row.get("FreePhysicalMemory", 0) or 0) // 1024
            swap_total_kb = int(row.get("TotalVirtualMemorySize", 0) or 0)
            swap_free_kb = int(row.get("FreeVirtualMemory", 0) or 0)
            snap.host_swap_total_mb = swap_total_kb // 1024
            snap.host_swap_free_mb = swap_free_kb // 1024
            if snap.host_swap_total_mb > 0:
                snap.host_swap_used_pct = int(
                    100
                    * (snap.host_swap_total_mb - snap.host_swap_free_mb)
                    / snap.host_swap_total_mb
                )
    except Exception:
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


def attach_polars_guard(
    guard: "RuntimeGuard",
    *,
    stage: str = "polars-collect",
    module: Any | None = None,
) -> Callable[[], None]:
    """Attach RuntimeGuard checks to Polars LazyFrame execution entry points.

    This helper provides M1-C01 integration scaffolding without introducing
    a hard runtime dependency on Polars. If ``module`` is not supplied, the
    function attempts to import ``polars`` lazily at call time.

    Returns
    -------
    Callable[[], None]
        Restore function that undoes the monkeypatch.
    """
    if module is None:
        try:
            import polars as module  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Polars is not installed. Install polars or pass module=<polars module>."
            ) from exc

    lazyframe_cls = getattr(module, "LazyFrame", None)
    if lazyframe_cls is None:
        raise RuntimeError("The provided module does not expose polars.LazyFrame.")

    original_collect = getattr(lazyframe_cls, "collect", None)
    if original_collect is None or not callable(original_collect):
        raise RuntimeError("polars.LazyFrame.collect is missing or not callable.")

    candidate_methods = (
        "collect",
        "fetch",
        "collect_async",
        "sink_parquet",
        "sink_csv",
        "sink_ipc",
        "sink_ndjson",
    )
    original_methods: dict[str, Any] = {
        name: getattr(lazyframe_cls, name, None) for name in candidate_methods
    }

    # Idempotent attach to avoid nested wrappers and duplicated checks.
    if getattr(original_collect, "_runtime_guard_wrapped", False):
        original_unwrapped: dict[str, Any] = {}
        for name, fn in original_methods.items():
            if callable(fn) and getattr(fn, "_runtime_guard_wrapped", False):
                original_unwrapped[name] = getattr(fn, "_runtime_guard_original", fn)
            else:
                original_unwrapped[name] = fn

        def _restore() -> None:
            for name, fn in original_unwrapped.items():
                if callable(fn):
                    setattr(lazyframe_cls, name, fn)

        return _restore

    def _wrap_lazyframe_method(name: str, fn: Any) -> Any:
        def _guarded(self: Any, *args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return fn(self, *args, **kwargs)

        setattr(_guarded, "_runtime_guard_wrapped", True)
        setattr(_guarded, "_runtime_guard_original", fn)
        setattr(_guarded, "_runtime_guard_method", name)
        return _guarded

    for name, fn in original_methods.items():
        if callable(fn):
            setattr(lazyframe_cls, name, _wrap_lazyframe_method(name, fn))

    def _restore() -> None:
        for name, fn in original_methods.items():
            if callable(fn):
                setattr(lazyframe_cls, name, fn)

    return _restore


def attach_dask_guard(
    guard: "RuntimeGuard",
    *,
    stage: str = "dask-compute",
    module: Any | None = None,
) -> Callable[[], None]:
    """Attach RuntimeGuard checks to Dask compute/persist entry points.

    This helper provides M1-C02 integration scaffolding without introducing
    a hard runtime dependency on Dask. If ``module`` is not supplied, the
    function attempts to import ``dask`` lazily at call time.

    Returns
    -------
    Callable[[], None]
        Restore function that undoes the monkeypatch.
    """
    if module is None:
        try:
            import dask as module  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Dask is not installed. Install dask or pass module=<dask module>."
            ) from exc

    compute_fn = getattr(module, "compute", None)
    if compute_fn is None or not callable(compute_fn):
        raise RuntimeError("The provided module does not expose callable dask.compute.")

    base_mod = getattr(module, "base", None)
    base_compute_fn = getattr(base_mod, "compute", None) if base_mod is not None else None
    base_persist_fn = getattr(base_mod, "persist", None) if base_mod is not None else None

    # Idempotent attach to avoid nested wrappers and duplicated checks.
    if getattr(compute_fn, "_runtime_guard_wrapped", False):
        original_compute = getattr(compute_fn, "_runtime_guard_original", compute_fn)
        persist_fn = getattr(module, "persist", None)
        original_persist = persist_fn
        if callable(persist_fn) and getattr(persist_fn, "_runtime_guard_wrapped", False):
            original_persist = getattr(persist_fn, "_runtime_guard_original", persist_fn)

        original_base_compute = base_compute_fn
        if callable(base_compute_fn) and getattr(base_compute_fn, "_runtime_guard_wrapped", False):
            original_base_compute = getattr(
                base_compute_fn, "_runtime_guard_original", base_compute_fn
            )

        original_base_persist = base_persist_fn
        if callable(base_persist_fn) and getattr(base_persist_fn, "_runtime_guard_wrapped", False):
            original_base_persist = getattr(
                base_persist_fn, "_runtime_guard_original", base_persist_fn
            )

        def _restore() -> None:
            setattr(module, "compute", original_compute)
            if callable(original_persist):
                setattr(module, "persist", original_persist)
            if base_mod is not None and callable(original_base_compute):
                setattr(base_mod, "compute", original_base_compute)
            if base_mod is not None and callable(original_base_persist):
                setattr(base_mod, "persist", original_base_persist)

        return _restore

    original_compute = compute_fn
    original_persist = getattr(module, "persist", None)
    original_base_compute = base_compute_fn
    original_base_persist = base_persist_fn

    def _guarded_compute(*args: Any, **kwargs: Any) -> Any:
        guard.check_and_log(stage=stage)
        return original_compute(*args, **kwargs)

    setattr(_guarded_compute, "_runtime_guard_wrapped", True)
    setattr(_guarded_compute, "_runtime_guard_original", original_compute)
    setattr(module, "compute", _guarded_compute)

    if callable(original_persist):

        def _guarded_persist(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return original_persist(*args, **kwargs)

        setattr(_guarded_persist, "_runtime_guard_wrapped", True)
        setattr(_guarded_persist, "_runtime_guard_original", original_persist)
        setattr(module, "persist", _guarded_persist)

    if base_mod is not None and callable(original_base_compute):

        def _guarded_base_compute(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return original_base_compute(*args, **kwargs)

        setattr(_guarded_base_compute, "_runtime_guard_wrapped", True)
        setattr(_guarded_base_compute, "_runtime_guard_original", original_base_compute)
        setattr(base_mod, "compute", _guarded_base_compute)

    if base_mod is not None and callable(original_base_persist):

        def _guarded_base_persist(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return original_base_persist(*args, **kwargs)

        setattr(_guarded_base_persist, "_runtime_guard_wrapped", True)
        setattr(_guarded_base_persist, "_runtime_guard_original", original_base_persist)
        setattr(base_mod, "persist", _guarded_base_persist)

    def _restore() -> None:
        setattr(module, "compute", original_compute)
        if callable(original_persist):
            setattr(module, "persist", original_persist)
        if base_mod is not None and callable(original_base_compute):
            setattr(base_mod, "compute", original_base_compute)
        if base_mod is not None and callable(original_base_persist):
            setattr(base_mod, "persist", original_base_persist)

    return _restore


def install_dask_scheduler_callbacks(
    guard: "RuntimeGuard",
    *,
    stage_prefix: str = "dask",
    enable_worker_reports: bool = True,
    module: Any | None = None,
) -> Callable[[str], dict[str, Any]]:
    """Install memory monitoring callbacks into Dask scheduler.

    This provides deeper M1-C02 scheduler-level integration, enabling per-task
    and per-worker memory monitoring without modifying user task code.

    Parameters
    ----------
    guard : RuntimeGuard
        Guard instance to use for memory checks.
    stage_prefix : str, optional
        Prefix for stage labels (default: "dask").
    enable_worker_reports : bool, optional
        If True, return worker report aggregator for post-compute analysis (default: True).

    Parameters
    ----------
    module : Any, optional
        Optional dask module object. When provided and it exposes
        ``dask.callbacks.Callback``, the returned reporter is annotated with a
        callback-context adapter suitable for direct registration.

    Returns
    -------
    Callable[[str], dict[str, Any]]
        Function to collect memory reports by worker. Call with worker name to get
        that worker's memory snapshot.

    Example
    -------
    >>> guard = RuntimeGuard(posture="tight")
    >>> get_worker_report = install_dask_scheduler_callbacks(guard)
    >>> # Later, after compute:
    >>> report = get_worker_report("tcp://127.0.0.1:8786")

    Notes
    -----
    - Callbacks are stateless and thread-safe.
    - Memory checks run synchronously before task execution.
    - Pressure events are logged to runtime_guard.events logger.
    """
    worker_snapshots: dict[str, dict[str, Any]] = {}
    callback_count: int = 0

    def _callback_start(key: str, *_: Any, worker_id: str | None = None) -> None:
        """Called before task execution (requires dask.callbacks.Callback.start)."""
        nonlocal callback_count
        callback_count += 1

        # Get current worker context if available
        worker_label = worker_id or "unknown-worker"
        stage = f"{stage_prefix}-task-{callback_count}"

        # Check memory before task
        report = guard.check_and_log(stage=stage)

        if enable_worker_reports and report is not None:
            if worker_label not in worker_snapshots:
                worker_snapshots[worker_label] = {
                    "worker_id": worker_label,
                    "task_count": 0,
                    "pressure_events": 0,
                    "snapshots": [],
                }
            worker_snapshots[worker_label]["task_count"] += 1
            worker_snapshots[worker_label]["pressure_events"] += 1
            worker_snapshots[worker_label]["snapshots"].append(
                {
                    "key": str(key),
                    "timestamp": int(time.time()),
                    "severity": "critical" if report.is_critical else "warning",
                    "cause": report.cause,
                    "missing_mem_mb": report.missing_mem_mb,
                }
            )

    def _callback_finish(key: str, value: Any, *_: Any, worker_id: str | None = None) -> None:
        """Called after task execution (requires dask.callbacks.Callback.finish)."""
        # Optional: Could track completion metrics here
        pass

    def _get_worker_report(worker_id: str | None = None) -> dict[str, Any]:
        """Retrieve memory report for a specific worker."""
        if worker_id is None:
            # Return aggregated view
            total_events = sum(w.get("pressure_events", 0) for w in worker_snapshots.values())
            return {
                "ok": True,
                "workers_monitored": len(worker_snapshots),
                "total_pressure_events": total_events,
                "worker_details": worker_snapshots,
            }

        worker_data = worker_snapshots.get(worker_id)
        if worker_data is None:
            return {
                "ok": True,
                "worker_id": worker_id,
                "pressure_events": 0,
                "task_count": 0,
            }

        return {
            "ok": True,
            "worker_id": worker_id,
            "task_count": worker_data.get("task_count", 0),
            "pressure_events": worker_data.get("pressure_events", 0),
            "snapshots": worker_data.get("snapshots", []),
        }

    # Create a callback object compatible with dask.callbacks.Callback
    class _SchedulerCallback:
        """Dask scheduler callback for memory monitoring."""

        _start = _callback_start
        _finish = _callback_finish

        @staticmethod
        def start(key: str, *args: Any, **kwargs: Any) -> None:
            _callback_start(key, *args, worker_id=kwargs.get("worker_id"), **kwargs)

        @staticmethod
        def finish(key: str, value: Any, *args: Any, **kwargs: Any) -> None:
            _callback_finish(key, value, *args, worker_id=kwargs.get("worker_id"), **kwargs)

    _SchedulerCallback.get_worker_report = staticmethod(_get_worker_report)  # type: ignore

    callback_api_available = False
    callback_context_cls: Any = _SchedulerCallback

    callbacks_mod = getattr(module, "callbacks", None) if module is not None else None
    callback_base = getattr(callbacks_mod, "Callback", None) if callbacks_mod is not None else None

    if isinstance(callback_base, type):
        callback_api_available = True

        class _RuntimeGuardDaskCallback(callback_base):
            def _pretask(self, key: str, *_args: Any, **kwargs: Any) -> None:
                _callback_start(key, worker_id=kwargs.get("worker_id"))

            def _posttask(self, key: str, value: Any, *_args: Any, **kwargs: Any) -> None:
                _callback_finish(key, value, worker_id=kwargs.get("worker_id"))

        callback_context_cls = _RuntimeGuardDaskCallback

    def _create_callback_context() -> Any:
        if not callback_api_available:
            raise RuntimeError(
                "Dask callback API unavailable; pass module=<dask module with callbacks.Callback>."
            )
        return callback_context_cls()

    setattr(_get_worker_report, "callback_api_available", callback_api_available)
    setattr(_get_worker_report, "callback_context_class", callback_context_cls)
    setattr(_get_worker_report, "create_callback_context", _create_callback_context)
    setattr(_get_worker_report, "stage_prefix", stage_prefix)

    return _get_worker_report


def validate_dask_integration(
    guard: "RuntimeGuard",
    *,
    stage: str = "dask-compute",
    module: Any | None = None,
) -> dict[str, Any]:
    """Validate that Dask integration is correctly installed and functional.

    Returns a verification report showing:
    - Dask availability
    - compute/persist method status
    - scheduler callback API availability
    - Guard hook status
    - Any errors encountered

    Useful for M1-C02 adoption evidence collection.
    """
    errors: list[str] = []
    dask_available = False
    methods_wrapped = False

    try:
        dask_mod = module
        if dask_mod is None:
            try:
                import dask as dask_mod  # type: ignore
            except Exception as exc:  # pragma: no cover
                errors.append(f"Dask import failed: {exc}")
                return {
                    "ok": False,
                    "dask_available": False,
                    "methods_wrapped": False,
                    "errors": errors,
                }
        dask_available = True

        compute_fn = getattr(dask_mod, "compute", None)
        if compute_fn is None or not callable(compute_fn):
            errors.append("dask.compute not found or not callable")
            return {
                "ok": False,
                "dask_available": True,
                "methods_wrapped": False,
                "errors": errors,
            }

        persist_fn = getattr(dask_mod, "persist", None)
        base_mod = getattr(dask_mod, "base", None)
        base_compute = getattr(base_mod, "compute", None) if base_mod else None
        base_persist = getattr(base_mod, "persist", None) if base_mod else None
        callbacks_mod = getattr(dask_mod, "callbacks", None)
        callback_cls = getattr(callbacks_mod, "Callback", None) if callbacks_mod else None

        methods_wrapped = bool(getattr(compute_fn, "_runtime_guard_wrapped", False))

        return {
            "ok": True,
            "dask_available": True,
            "methods_wrapped": methods_wrapped,
            "compute_present": compute_fn is not None,
            "persist_present": persist_fn is not None,
            "base_module_present": base_mod is not None,
            "base_compute_present": base_compute is not None,
            "base_persist_present": base_persist is not None,
            "scheduler_callback_api_present": callable(callback_cls),
            "errors": errors,
        }
    except Exception as exc:  # pragma: no cover
        errors.append(f"Validation error: {exc}")
        return {
            "ok": False,
            "dask_available": dask_available,
            "methods_wrapped": methods_wrapped,
            "errors": errors,
        }


def collect_dask_integration_evidence(
    guard: "RuntimeGuard",
    *,
    stage: str = "dask-compute",
    module: Any | None = None,
    version_info: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Collect evidence of Dask integration readiness for adoption tracking.

    Returns a report compatible with ADOPTION_TRACKER.md evidence arrays.
    Useful for M1-C02 rollout validation and audit.
    """
    validation = validate_dask_integration(guard, stage=stage, module=module)

    evidence_items: list[str] = []

    if validation.get("ok"):
        evidence_items.append("dask_integration_validated")

    if validation.get("methods_wrapped"):
        evidence_items.append("dask_hooks_installed")

    if validation.get("compute_present"):
        evidence_items.append("dask_compute_available")

    if validation.get("persist_present"):
        evidence_items.append("dask_persist_available")

    if validation.get("base_module_present"):
        evidence_items.append("dask_base_module_available")

    if validation.get("scheduler_callback_api_present"):
        evidence_items.append("dask_scheduler_callback_api_available")

    runtime_guard_version = "0.3.0"
    try:
        from importlib.metadata import version as _pkg_version

        runtime_guard_version = _pkg_version("runtime-guard")
    except Exception:
        pass

    dask_version = "unknown"
    try:
        dask_mod = module
        if dask_mod is None:
            import dask as dask_mod  # type: ignore
        dask_version = str(getattr(dask_mod, "__version__", "unknown"))
    except Exception:
        pass

    return {
        "evidence_items": evidence_items,
        "validation_ok": validation.get("ok", False),
        "runtime_guard_version": runtime_guard_version,
        "dask_version": dask_version,
        "errors": validation.get("errors", []),
        **(version_info or {}),
    }


def attach_ray_guard(
    guard: "RuntimeGuard",
    *,
    stage: str = "ray-get",
    module: Any | None = None,
) -> Callable[[], None]:
    """Attach RuntimeGuard checks to Ray get/wait/put entry points.

    This helper provides M1-C03 integration scaffolding without introducing
    a hard runtime dependency on Ray. If ``module`` is not supplied, the
    function attempts to import ``ray`` lazily at call time.

    Returns
    -------
    Callable[[], None]
        Restore function that undoes the monkeypatch.
    """
    if module is None:
        try:
            import ray as module  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Ray is not installed. Install ray or pass module=<ray module>."
            ) from exc

    get_fn = getattr(module, "get", None)
    if get_fn is None or not callable(get_fn):
        raise RuntimeError("The provided module does not expose callable ray.get.")

    # Idempotent attach to avoid nested wrappers and duplicated checks.
    if getattr(get_fn, "_runtime_guard_wrapped", False):
        original_get = getattr(get_fn, "_runtime_guard_original", get_fn)
        wait_fn = getattr(module, "wait", None)
        original_wait = wait_fn
        if callable(wait_fn) and getattr(wait_fn, "_runtime_guard_wrapped", False):
            original_wait = getattr(wait_fn, "_runtime_guard_original", wait_fn)
        put_fn = getattr(module, "put", None)
        original_put = put_fn
        if callable(put_fn) and getattr(put_fn, "_runtime_guard_wrapped", False):
            original_put = getattr(put_fn, "_runtime_guard_original", put_fn)

        def _restore() -> None:
            setattr(module, "get", original_get)
            if callable(original_wait):
                setattr(module, "wait", original_wait)
            if callable(original_put):
                setattr(module, "put", original_put)

        return _restore

    original_get = get_fn
    original_wait = getattr(module, "wait", None)
    original_put = getattr(module, "put", None)

    def _guarded_get(*args: Any, **kwargs: Any) -> Any:
        guard.check_and_log(stage=stage)
        return original_get(*args, **kwargs)

    setattr(_guarded_get, "_runtime_guard_wrapped", True)
    setattr(_guarded_get, "_runtime_guard_original", original_get)
    setattr(module, "get", _guarded_get)

    if callable(original_wait):

        def _guarded_wait(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return original_wait(*args, **kwargs)

        setattr(_guarded_wait, "_runtime_guard_wrapped", True)
        setattr(_guarded_wait, "_runtime_guard_original", original_wait)
        setattr(module, "wait", _guarded_wait)

    if callable(original_put):

        def _guarded_put(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return original_put(*args, **kwargs)

        setattr(_guarded_put, "_runtime_guard_wrapped", True)
        setattr(_guarded_put, "_runtime_guard_original", original_put)
        setattr(module, "put", _guarded_put)

    def _restore() -> None:
        setattr(module, "get", original_get)
        if callable(original_wait):
            setattr(module, "wait", original_wait)
        if callable(original_put):
            setattr(module, "put", original_put)

    return _restore


def enable_ray_actor_memory_monitoring(
    guard: "RuntimeGuard",
    *,
    stage_prefix: str = "ray-actor",
    check_on_entry: bool = True,
    check_on_exit: bool = False,
) -> dict[str, Any]:
    """Enable memory monitoring for Ray actor methods.

    This provides deeper M1-C03 integration by instrumenting actor methods
    with memory checks. Can be applied to individual methods or all methods
    in an actor class.

    Parameters
    ----------
    guard : RuntimeGuard
        Guard instance to use for memory checks.
    stage_prefix : str, optional
        Prefix for stage labels (default: "ray-actor").
    check_on_entry : bool, optional
        If True, check memory before method execution (default: True).
    check_on_exit : bool, optional
        If True, check memory after method execution (default: False).

    Returns
    -------
    dict
        Configuration dict with monitoring settings and instructions.

    Example
    -------
    Enable monitoring on an actor method::

        guard = RuntimeGuard()
        config = enable_ray_actor_memory_monitoring(guard)

        @ray.remote
        class MyActor:
            def __init__(self):
                self.guard = guard

            def method_with_monitoring(self):
                '''Method with manual memory checks.'''
                if self.guard.check(stage='actor-method-start') is not None:
                    # Pressure detected; could skip work or scale down
                    return None
                # Do work...
                return self.compute()

    Notes
    -----
    - Actors can call ``ray.get_runtime_context().worker.memory_monitor`` for direct access
    - Memory events are logged to runtime_guard.events logger
    - Each actor instance maintains independent pressure tracking
    - Remote function wrappers are recommended for lightweight monitoring
    """
    actor_event_state: dict[str, dict[str, Any]] = {}

    config: dict[str, Any] = {
        "ok": True,
        "stage_prefix": stage_prefix,
        "check_on_entry": check_on_entry,
        "check_on_exit": check_on_exit,
        "method_decorator": None,
        "remote_wrapper": None,
        "get_actor_report": None,
        "reset_actor_report": None,
        "instructions": [
            "1. Add 'from runtime_guard import guard' to actor module (or pass via init)",
            "2. Wrap method calls with: if guard.check(stage='actor-method') is not None: handle_pressure()",
            "3. Or use decorator: @monitored_actor_method (if using method_decorator below)",
            "4. For remote functions: wrap with check_and_log(stage=stage_prefix + '-' + function_name)",
        ],
    }

    def _record_actor_event(
        *,
        node_id: str,
        actor_id: str,
        method_name: str,
        event_type: str,
    ) -> None:
        node_key = str(node_id or "unknown-node").strip() or "unknown-node"
        actor_key = str(actor_id or "unknown-actor").strip() or "unknown-actor"
        method_key = str(method_name or "unknown-method").strip() or "unknown-method"

        node_row = actor_event_state.setdefault(
            node_key,
            {
                "node_id": node_key,
                "events": 0,
                "entry_checks": 0,
                "exit_checks": 0,
                "actors": {},
            },
        )
        node_row["events"] += 1
        if event_type == "entry":
            node_row["entry_checks"] += 1
        elif event_type == "exit":
            node_row["exit_checks"] += 1

        actors = node_row["actors"]
        actor_row = actors.setdefault(
            actor_key,
            {
                "actor_id": actor_key,
                "events": 0,
                "entry_checks": 0,
                "exit_checks": 0,
                "methods": {},
            },
        )
        actor_row["events"] += 1
        if event_type == "entry":
            actor_row["entry_checks"] += 1
        elif event_type == "exit":
            actor_row["exit_checks"] += 1

        methods = actor_row["methods"]
        methods[method_key] = int(methods.get(method_key, 0)) + 1

    def _get_actor_report(*, node_id: str | None = None, actor_id: str | None = None) -> dict[str, Any]:
        if node_id is None and actor_id is None:
            return {
                "ok": True,
                "nodes": actor_event_state,
                "nodes_monitored": len(actor_event_state),
                "total_events": sum(int(v.get("events", 0)) for v in actor_event_state.values()),
            }

        if node_id is not None:
            node_key = str(node_id)
            node_row = actor_event_state.get(node_key)
            if node_row is None:
                return {"ok": True, "node_id": node_key, "events": 0, "actors": {}}
            if actor_id is None:
                return {"ok": True, **node_row}
            actor_key = str(actor_id)
            actor_row = node_row.get("actors", {}).get(actor_key)
            if actor_row is None:
                return {
                    "ok": True,
                    "node_id": node_key,
                    "actor_id": actor_key,
                    "events": 0,
                    "methods": {},
                }
            return {"ok": True, "node_id": node_key, **actor_row}

        actor_key = str(actor_id)
        for node_key, node_row in actor_event_state.items():
            actor_row = node_row.get("actors", {}).get(actor_key)
            if actor_row is not None:
                return {"ok": True, "node_id": node_key, **actor_row}

        return {"ok": True, "actor_id": actor_key, "events": 0, "methods": {}}

    def _reset_actor_report() -> None:
        actor_event_state.clear()

    def _method_decorator(method: Any) -> Any:
        """Decorator for actor methods to add memory monitoring."""

        def _wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            stage = f"{stage_prefix}::{method.__name__}"
            node_id = str(getattr(self, "_runtime_guard_node_id", "unknown-node"))
            actor_id = str(
                getattr(self, "_runtime_guard_actor_id", f"{self.__class__.__name__}:{id(self)}")
            )
            if check_on_entry:
                guard.check_and_log(stage=f"{stage}:entry")
                _record_actor_event(
                    node_id=node_id,
                    actor_id=actor_id,
                    method_name=method.__name__,
                    event_type="entry",
                )
            try:
                result = method(self, *args, **kwargs)
            finally:
                if check_on_exit:
                    guard.check_and_log(stage=f"{stage}:exit")
                    _record_actor_event(
                        node_id=node_id,
                        actor_id=actor_id,
                        method_name=method.__name__,
                        event_type="exit",
                    )
            return result

        return _wrapper

    def _remote_wrapper(fn: Any) -> Any:
        """Wrapper for remote functions to add memory monitoring."""

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            stage = f"{stage_prefix}::{fn.__name__}"
            node_id = str(kwargs.pop("node_id", "remote-node"))
            actor_id = str(kwargs.pop("actor_id", f"remote::{fn.__name__}"))
            if check_on_entry:
                guard.check_and_log(stage=f"{stage}:entry")
                _record_actor_event(
                    node_id=node_id,
                    actor_id=actor_id,
                    method_name=fn.__name__,
                    event_type="entry",
                )
            try:
                result = fn(*args, **kwargs)
            finally:
                if check_on_exit:
                    guard.check_and_log(stage=f"{stage}:exit")
                    _record_actor_event(
                        node_id=node_id,
                        actor_id=actor_id,
                        method_name=fn.__name__,
                        event_type="exit",
                    )
            return result

        return _wrapper

    config["method_decorator"] = _method_decorator
    config["remote_wrapper"] = _remote_wrapper
    config["get_actor_report"] = _get_actor_report
    config["reset_actor_report"] = _reset_actor_report

    return config


def validate_ray_integration(
    guard: "RuntimeGuard",
    *,
    stage: str = "ray-get",
    module: Any | None = None,
) -> dict[str, Any]:
    """Validate that Ray integration is correctly installed and functional.

    Returns a verification report showing:
    - Ray availability
    - get/wait/put method status
    - Guard hook status
    - Any errors encountered

    Useful for M1-C03 adoption evidence collection.
    """
    errors: list[str] = []
    ray_available = False
    methods_wrapped = False

    try:
        ray_mod = module
        if ray_mod is None:
            try:
                import ray as ray_mod  # type: ignore
            except Exception as exc:  # pragma: no cover
                errors.append(f"Ray import failed: {exc}")
                return {
                    "ok": False,
                    "ray_available": False,
                    "methods_wrapped": False,
                    "errors": errors,
                }
        ray_available = True

        get_fn = getattr(ray_mod, "get", None)
        if get_fn is None or not callable(get_fn):
            errors.append("ray.get not found or not callable")
            return {
                "ok": False,
                "ray_available": True,
                "methods_wrapped": False,
                "errors": errors,
            }

        wait_fn = getattr(ray_mod, "wait", None)
        put_fn = getattr(ray_mod, "put", None)

        methods_wrapped = bool(getattr(get_fn, "_runtime_guard_wrapped", False))

        return {
            "ok": True,
            "ray_available": True,
            "methods_wrapped": methods_wrapped,
            "get_present": get_fn is not None,
            "wait_present": wait_fn is not None,
            "put_present": put_fn is not None,
            "errors": errors,
        }
    except Exception as exc:  # pragma: no cover
        errors.append(f"Validation error: {exc}")
        return {
            "ok": False,
            "ray_available": ray_available,
            "methods_wrapped": methods_wrapped,
            "errors": errors,
        }


def collect_ray_integration_evidence(
    guard: "RuntimeGuard",
    *,
    stage: str = "ray-get",
    module: Any | None = None,
    version_info: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Collect evidence of Ray integration readiness for adoption tracking.

    Returns a report compatible with ADOPTION_TRACKER.md evidence arrays.
    Useful for M1-C03 rollout validation and audit.
    """
    validation = validate_ray_integration(guard, stage=stage, module=module)

    evidence_items: list[str] = []

    if validation.get("ok"):
        evidence_items.append("ray_integration_validated")

    if validation.get("methods_wrapped"):
        evidence_items.append("ray_hooks_installed")

    if validation.get("get_present"):
        evidence_items.append("ray_get_available")

    if validation.get("wait_present"):
        evidence_items.append("ray_wait_available")

    if validation.get("put_present"):
        evidence_items.append("ray_put_available")

    runtime_guard_version = "0.3.0"
    try:
        from importlib.metadata import version as _pkg_version

        runtime_guard_version = _pkg_version("runtime-guard")
    except Exception:
        pass

    ray_version = "unknown"
    try:
        ray_mod = module
        if ray_mod is None:
            import ray as ray_mod  # type: ignore
        ray_version = str(getattr(ray_mod, "__version__", "unknown"))
    except Exception:
        pass

    return {
        "evidence_items": evidence_items,
        "validation_ok": validation.get("ok", False),
        "runtime_guard_version": runtime_guard_version,
        "ray_version": ray_version,
        "errors": validation.get("errors", []),
        **(version_info or {}),
    }


def validate_polars_integration(
    guard: "RuntimeGuard",
    *,
    stage: str = "polars-collect",
    module: Any | None = None,
) -> dict[str, Any]:
    """Validate that Polars integration is correctly installed and functional.

    Returns a verification report showing:
    - Polars availability
    - LazyFrame execution entry point status (collect/fetch/collect_async/sink_*)
    - Guard hook status
    - Any errors encountered

    Useful for M1-I01 adoption evidence collection.
    """
    errors: list[str] = []
    polars_available = False
    methods_wrapped = False

    try:
        polars_mod = module
        if polars_mod is None:
            try:
                import polars as polars_mod  # type: ignore
            except Exception as exc:  # pragma: no cover
                errors.append(f"Polars import failed: {exc}")
                return {
                    "ok": False,
                    "polars_available": False,
                    "methods_wrapped": False,
                    "errors": errors,
                }
        polars_available = True

        lazyframe_cls = getattr(polars_mod, "LazyFrame", None)
        if lazyframe_cls is None:
            errors.append("LazyFrame class not found")
            return {
                "ok": False,
                "polars_available": True,
                "methods_wrapped": False,
                "errors": errors,
            }

        collect_method = getattr(lazyframe_cls, "collect", None)
        fetch_method = getattr(lazyframe_cls, "fetch", None)
        collect_async_method = getattr(lazyframe_cls, "collect_async", None)
        sink_parquet_method = getattr(lazyframe_cls, "sink_parquet", None)
        sink_csv_method = getattr(lazyframe_cls, "sink_csv", None)
        sink_ipc_method = getattr(lazyframe_cls, "sink_ipc", None)
        sink_ndjson_method = getattr(lazyframe_cls, "sink_ndjson", None)

        methods_wrapped = bool(getattr(collect_method, "_runtime_guard_wrapped", False))

        wrapped_methods: list[str] = []
        for name, fn in {
            "collect": collect_method,
            "fetch": fetch_method,
            "collect_async": collect_async_method,
            "sink_parquet": sink_parquet_method,
            "sink_csv": sink_csv_method,
            "sink_ipc": sink_ipc_method,
            "sink_ndjson": sink_ndjson_method,
        }.items():
            if bool(getattr(fn, "_runtime_guard_wrapped", False)):
                wrapped_methods.append(name)

        return {
            "ok": True,
            "polars_available": True,
            "methods_wrapped": methods_wrapped,
            "collect_present": collect_method is not None,
            "fetch_present": fetch_method is not None,
            "collect_async_present": collect_async_method is not None,
            "sink_parquet_present": sink_parquet_method is not None,
            "sink_csv_present": sink_csv_method is not None,
            "sink_ipc_present": sink_ipc_method is not None,
            "sink_ndjson_present": sink_ndjson_method is not None,
            "wrapped_methods": wrapped_methods,
            "errors": errors,
        }
    except Exception as exc:  # pragma: no cover
        errors.append(f"Validation error: {exc}")
        return {
            "ok": False,
            "polars_available": polars_available,
            "methods_wrapped": methods_wrapped,
            "errors": errors,
        }


def collect_polars_integration_evidence(
    guard: "RuntimeGuard",
    *,
    stage: str = "polars-collect",
    module: Any | None = None,
    version_info: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Collect evidence of Polars integration readiness for adoption tracking.

    Returns a report compatible with ADOPTION_TRACKER.md evidence arrays.
    Useful for M1-I01 rollout validation and audit.
    """
    validation = validate_polars_integration(guard, stage=stage, module=module)

    evidence_items: list[str] = []

    if validation.get("ok"):
        evidence_items.append("polars_integration_validated")

    if validation.get("methods_wrapped"):
        evidence_items.append("polars_hooks_installed")

    if validation.get("collect_present"):
        evidence_items.append("polars_collect_available")

    if validation.get("fetch_present"):
        evidence_items.append("polars_fetch_available")

    if validation.get("collect_async_present"):
        evidence_items.append("polars_collect_async_available")

    if validation.get("sink_parquet_present"):
        evidence_items.append("polars_sink_parquet_available")

    if validation.get("sink_csv_present"):
        evidence_items.append("polars_sink_csv_available")

    if validation.get("sink_ipc_present"):
        evidence_items.append("polars_sink_ipc_available")

    if validation.get("sink_ndjson_present"):
        evidence_items.append("polars_sink_ndjson_available")

    runtime_guard_version = "0.3.0"
    try:
        from importlib.metadata import version as _pkg_version

        runtime_guard_version = _pkg_version("runtime-guard")
    except Exception:
        pass

    polars_version = "unknown"
    try:
        polars_mod = module
        if polars_mod is None:
            import polars as polars_mod  # type: ignore
        polars_version = str(getattr(polars_mod, "__version__", "unknown"))
    except Exception:
        pass

    return {
        "evidence_items": evidence_items,
        "validation_ok": validation.get("ok", False),
        "runtime_guard_version": runtime_guard_version,
        "polars_version": polars_version,
        "errors": validation.get("errors", []),
        **(version_info or {}),
    }


def pressure_report_attributes(report: "PressureReport") -> dict[str, Any]:
    """Convert a PressureReport into OpenTelemetry-friendly attributes."""
    snap = report.snapshot
    return {
        "runtime_guard.is_critical": report.is_critical,
        "runtime_guard.cause": report.cause,
        "runtime_guard.self_inflicted": report.self_inflicted,
        "runtime_guard.self_pct": report.self_pct,
        "runtime_guard.pid": report.pid,
        "runtime_guard.stage": report.stage,
        "runtime_guard.min_mem_mb": report.min_mem_mb,
        "runtime_guard.max_swap_pct": report.max_swap_pct,
        "runtime_guard.missing_mem_mb": report.missing_mem_mb,
        "runtime_guard.swap_excess_pct": report.swap_excess_pct,
        "runtime_guard.mem_total_mb": snap.mem_total_mb,
        "runtime_guard.mem_available_mb": snap.mem_available_mb,
        "runtime_guard.swap_total_mb": snap.swap_total_mb,
        "runtime_guard.swap_free_mb": snap.swap_free_mb,
        "runtime_guard.swap_used_pct": snap.swap_used_pct,
        "runtime_guard.rss_mb": snap.rss_mb,
        "runtime_guard.vm_swap_mb": snap.vm_swap_mb,
    }


def trace_context_attributes(
    *,
    span: Any | None = None,
    module: Any | None = None,
    prefix: str = "runtime_guard.trace",
) -> dict[str, Any]:
    """Extract trace/span IDs from an OpenTelemetry span into flat attributes.

    Returns an empty dict when OpenTelemetry is unavailable or when no usable
    span context is present.
    """
    target_span = span
    if target_span is None:
        trace_mod = module
        if trace_mod is None:
            try:
                from opentelemetry import trace as trace_mod  # type: ignore
            except Exception:
                return {}
        get_current_span = getattr(trace_mod, "get_current_span", None)
        if not callable(get_current_span):
            return {}
        target_span = get_current_span()

    if target_span is None:
        return {}

    get_span_context = getattr(target_span, "get_span_context", None)
    if not callable(get_span_context):
        return {}

    span_context = get_span_context()
    if span_context is None:
        return {}

    trace_id = getattr(span_context, "trace_id", 0)
    span_id = getattr(span_context, "span_id", 0)
    if not isinstance(trace_id, int) or not isinstance(span_id, int):
        return {}
    if trace_id <= 0 or span_id <= 0:
        return {}

    attrs: dict[str, Any] = {
        f"{prefix}_id": f"{trace_id:032x}",
        f"{prefix}_span_id": f"{span_id:016x}",
    }

    trace_flags = getattr(span_context, "trace_flags", None)
    sampled = getattr(trace_flags, "sampled", None)
    if isinstance(sampled, bool):
        attrs[f"{prefix}_sampled"] = sampled

    return attrs


def emit_otel_event(
    report: "PressureReport",
    *,
    event_name: str = "runtime_guard.pressure",
    span: Any | None = None,
    module: Any | None = None,
) -> bool:
    """Emit a RuntimeGuard pressure event on the current OpenTelemetry span.

    Returns ``True`` when an event is emitted. Returns ``False`` when
    OpenTelemetry is unavailable or there is no active recording span.
    """
    target_span = span
    if target_span is None:
        trace_mod = module
        if trace_mod is None:
            try:
                from opentelemetry import trace as trace_mod  # type: ignore
            except Exception:
                return False
        get_current_span = getattr(trace_mod, "get_current_span", None)
        if not callable(get_current_span):
            return False
        target_span = get_current_span()

    if target_span is None:
        return False

    is_recording = getattr(target_span, "is_recording", None)
    if callable(is_recording) and not is_recording():
        return False

    add_event = getattr(target_span, "add_event", None)
    if not callable(add_event):
        return False

    attrs = pressure_report_attributes(report)
    attrs.update(trace_context_attributes(span=target_span))
    add_event(event_name, attributes=attrs)
    return True


def emit_otel_phase_event(
    stage: str,
    *,
    lifecycle: str,
    event_name: str = "runtime_guard.phase",
    span: Any | None = None,
    module: Any | None = None,
    attributes: dict[str, Any] | None = None,
) -> bool:
    """Emit a phase lifecycle event on the current OpenTelemetry span.

    Lifecycle is typically one of ``enter``, ``exit``, or ``error``.
    Returns ``True`` when an event is emitted, otherwise ``False``.
    """
    target_span = span
    if target_span is None:
        trace_mod = module
        if trace_mod is None:
            try:
                from opentelemetry import trace as trace_mod  # type: ignore
            except Exception:
                return False
        get_current_span = getattr(trace_mod, "get_current_span", None)
        if not callable(get_current_span):
            return False
        target_span = get_current_span()

    if target_span is None:
        return False

    is_recording = getattr(target_span, "is_recording", None)
    if callable(is_recording) and not is_recording():
        return False

    add_event = getattr(target_span, "add_event", None)
    if not callable(add_event):
        return False

    attrs: dict[str, Any] = {
        "runtime_guard.phase.stage": stage,
        "runtime_guard.phase.lifecycle": str(lifecycle),
    }
    attrs.update(trace_context_attributes(span=target_span))
    if attributes:
        attrs.update(attributes)
    add_event(event_name, attributes=attrs)
    return True


def render_prometheus_metrics(report: "PressureReport", *, prefix: str = "runtime_guard") -> str:
    """Render a PressureReport as Prometheus exposition text.

    This helper provides M1-C05 scaffolding without requiring
    ``prometheus_client``. It can be served by any HTTP endpoint.
    """
    snap = report.snapshot
    stage = report.stage.replace('"', '\\"')
    lines = [
        f"{prefix}_is_critical {1 if report.is_critical else 0}",
        f"{prefix}_self_inflicted {1 if report.self_inflicted else 0}",
        f'{prefix}_self_pct{{stage="{stage}"}} {report.self_pct}',
        f'{prefix}_min_mem_mb{{stage="{stage}"}} {report.min_mem_mb}',
        f'{prefix}_max_swap_pct{{stage="{stage}"}} {report.max_swap_pct}',
        f'{prefix}_missing_mem_mb{{stage="{stage}"}} {report.missing_mem_mb}',
        f'{prefix}_swap_excess_pct{{stage="{stage}"}} {report.swap_excess_pct}',
        f'{prefix}_mem_total_mb{{stage="{stage}"}} {snap.mem_total_mb}',
        f'{prefix}_mem_available_mb{{stage="{stage}"}} {snap.mem_available_mb}',
        f'{prefix}_swap_total_mb{{stage="{stage}"}} {snap.swap_total_mb}',
        f'{prefix}_swap_free_mb{{stage="{stage}"}} {snap.swap_free_mb}',
        f'{prefix}_swap_used_pct{{stage="{stage}"}} {snap.swap_used_pct}',
        f'{prefix}_rss_mb{{stage="{stage}"}} {snap.rss_mb}',
        f'{prefix}_vm_swap_mb{{stage="{stage}"}} {snap.vm_swap_mb}',
    ]
    # Add host (Windows) metrics if present
    if getattr(snap, "host_mem_total_mb", 0):
        lines.append(f'{prefix}_host_mem_total_mb{{stage="{stage}"}} {snap.host_mem_total_mb}')
        lines.append(f'{prefix}_host_mem_available_mb{{stage="{stage}"}} {snap.host_mem_available_mb}')
        lines.append(f'{prefix}_host_swap_total_mb{{stage="{stage}"}} {snap.host_swap_total_mb}')
        lines.append(f'{prefix}_host_swap_free_mb{{stage="{stage}"}} {snap.host_swap_free_mb}')
        lines.append(f'{prefix}_host_swap_used_pct{{stage="{stage}"}} {snap.host_swap_used_pct}')
        lines.append(f'{prefix}_drift_mem_total_mb{{stage="{stage}"}} {snap.drift_mem_total_mb}')
        lines.append(f'{prefix}_drift_mem_available_mb{{stage="{stage}"}} {snap.drift_mem_available_mb}')
        lines.append(f'{prefix}_drift_swap_used_pct{{stage="{stage}"}} {snap.drift_swap_used_pct}')
    return "\n".join(lines) + "\n"



def install_prometheus_endpoint(
    guard: "RuntimeGuard",
    *,
    prefix: str = "runtime_guard",
    path: str = "/metrics",
    stage: str = "prometheus",
) -> "tuple[Any, Callable[[], None]]":
    """Create a standalone ASGI application that serves Prometheus metrics.

    The returned app implements the ASGI HTTP interface and can be:

    * **Mounted on FastAPI / Starlette**::

        from fastapi import FastAPI
        from runtime_guard import install_prometheus_endpoint

        guard = RuntimeGuard()
        app = FastAPI()
        metrics_app, _ = install_prometheus_endpoint(guard)
        app.mount("/metrics", metrics_app)

    * **Served standalone** (e.g. via ``uvicorn``)::

        metrics_app, _ = install_prometheus_endpoint(guard)
        # uvicorn.run(metrics_app, host="0.0.0.0", port=9090)

    Parameters
    ----------
    guard:
        Guard instance whose live memory snapshot is exposed on each scrape.
    prefix:
        Prometheus metric name prefix (default ``runtime_guard``).
    path:
        URL path the app will be mounted at (documentation only).
    stage:
        Stage label forwarded to ``guard.check()`` on every scrape.

    Returns
    -------
    tuple[asgi_app, restore_fn]
        ``asgi_app`` — async ASGI callable.
        ``restore_fn`` — no-op for API symmetry.

    Notes
    -----
    * HTTP 200 when memory is healthy; 503 when ``guard.check()`` reports critical.
    * Responds 405 to any method other than GET.
    * Zero external dependencies.
    """
    _CONTENT_TYPE = b"text/plain; version=0.0.4; charset=utf-8"
    _ALLOW_HEADER = b"GET"

    async def _asgi_metrics_app(scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            return

        method = scope.get("method", "GET").upper()
        if method != "GET":
            await send(
                {
                    "type": "http.response.start",
                    "status": 405,
                    "headers": [
                        (b"content-length", b"0"),
                        (b"allow", _ALLOW_HEADER),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        report = guard.check(stage=stage)

        if report is None:
            snap = _read_snapshot()
            report_for_render = PressureReport(
                snapshot=snap,
                is_critical=False,
                cause="",
                self_inflicted=False,
                self_pct=snap.rss_mb * 100 // max(snap.mem_total_mb, 1),
                stage=stage,
                pid=os.getpid(),
            )
            status = 200
        else:
            report_for_render = report
            status = 503 if report.is_critical else 200

        body = render_prometheus_metrics(report_for_render, prefix=prefix).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", _CONTENT_TYPE),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def _restore() -> None:
        pass

    setattr(_asgi_metrics_app, "_runtime_guard_prometheus_prefix", prefix)
    setattr(_asgi_metrics_app, "_runtime_guard_prometheus_path", path)
    return _asgi_metrics_app, _restore


def install_distributed_trace_propagator(
    guard: "RuntimeGuard",
    *,
    header_name: str = "traceparent",
    module: Any | None = None,
    warn_on_missing: bool = False,
) -> dict[str, Any]:
    """Install a W3C Trace Context propagator for distributed memory tracing.

    Provides two callable helpers that link runtime-guard memory events to a
    distributed trace across service boundaries using the W3C ``traceparent``
    header format (``00-<trace_id>-<parent_id>-<flags>``).

    No hard dependency on the OpenTelemetry SDK is required.

    Parameters
    ----------
    guard:
        Guard instance (reserved for future span-annotation integration).
    header_name:
        HTTP header name to read/write (default ``traceparent``).
    module:
        Optional OpenTelemetry ``trace`` module for span context reading.
    warn_on_missing:
        If ``True``, log a warning when the header is absent in ``extract()``.

    Returns
    -------
    dict with keys:

    ``extract(headers) -> dict``
        Parse ``header_name`` from *headers* (case-insensitive).
        Returns ``{trace_id, span_id, flags, traceparent}`` or ``{}``.

    ``inject(headers, *, span=None) -> dict``
        Enrich a copy of *headers* with the current span's traceparent.
        Returns *headers* unchanged when OTEL is unavailable.

    ``restore()``
        No-op for API symmetry.

    ``header_name``
        The configured header name.
    """
    import re as _re_mod
    _TRACEPARENT_RE = _re_mod.compile(
        r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
    )

    def _normalise_headers(headers: Any) -> dict[str, str]:
        if isinstance(headers, dict):
            return {k.lower(): str(v) for k, v in headers.items()}
        try:
            return {k.lower(): str(v) for k, v in headers}
        except (TypeError, ValueError):
            return {}

    def extract(headers: Any) -> dict[str, Any]:
        normalised = _normalise_headers(headers)
        raw = normalised.get(header_name.lower(), "").strip()
        if not raw:
            if warn_on_missing:
                logger.warning(
                    "[RuntimeGuard] Distributed trace header %r not found in request.",
                    header_name,
                )
            return {}
        m = _TRACEPARENT_RE.match(raw)
        if m is None:
            logger.debug(
                "[RuntimeGuard] Malformed %r header value: %r", header_name, raw[:64]
            )
            return {}
        return {
            "trace_id": m.group(1),
            "span_id": m.group(2),
            "flags": m.group(3),
            "traceparent": raw,
        }

    def inject(headers: Any, *, span: Any = None) -> dict[str, str]:
        out = dict(_normalise_headers(headers))

        target_span = span
        if target_span is None:
            trace_mod = module
            if trace_mod is None:
                try:
                    from opentelemetry import trace as trace_mod  # type: ignore
                except Exception:
                    return out
            get_current_span = getattr(trace_mod, "get_current_span", None)
            if callable(get_current_span):
                target_span = get_current_span()

        if target_span is None:
            return out

        get_span_context = getattr(target_span, "get_span_context", None)
        if not callable(get_span_context):
            return out
        span_context = get_span_context()
        if span_context is None:
            return out

        trace_id = getattr(span_context, "trace_id", 0)
        span_id = getattr(span_context, "span_id", 0)
        if not (isinstance(trace_id, int) and isinstance(span_id, int)):
            return out
        if trace_id <= 0 or span_id <= 0:
            return out

        trace_flags = getattr(span_context, "trace_flags", None)
        sampled = getattr(trace_flags, "sampled", None)
        flags = "01" if sampled else "00"

        out[header_name.lower()] = f"00-{trace_id:032x}-{span_id:016x}-{flags}"
        return out

    def _restore() -> None:
        pass

    return {
        "extract": extract,
        "inject": inject,
        "restore": _restore,
        "header_name": header_name,
    }


def validate_runtime_guard_config(
    config: dict[str, Any], *, use_pydantic: bool = True
) -> dict[str, Any]:
    """Validate RuntimeGuard config overrides.

    Accepted keys are:
    - posture: one of ``tight|relaxed|ci``
    - min_mem_available_mb, max_swap_used_pct, critical_mem_mb,
      critical_swap_pct, self_inflicted_pct: integer thresholds

    Returns a normalized dict with validated values.
    """
    allowed_keys = {
        "posture",
        "min_mem_available_mb",
        "max_swap_used_pct",
        "critical_mem_mb",
        "critical_swap_pct",
        "self_inflicted_pct",
    }
    unknown = set(config) - allowed_keys
    if unknown:
        raise ValueError(f"Unknown config keys: {sorted(unknown)}")

    if use_pydantic:
        try:
            from pydantic import BaseModel, ConfigDict, Field

            class _ConfigModel(BaseModel):
                model_config = ConfigDict(extra="forbid")

                posture: str | None = None
                min_mem_available_mb: int | None = Field(default=None, ge=0)
                max_swap_used_pct: int | None = Field(default=None, ge=0, le=100)
                critical_mem_mb: int | None = Field(default=None, ge=0)
                critical_swap_pct: int | None = Field(default=None, ge=0, le=100)
                self_inflicted_pct: int | None = Field(default=None, ge=0, le=100)

            model = _ConfigModel(**config)
            out = model.model_dump(exclude_none=True)
            posture = out.get("posture")
            if posture is not None and posture not in _PRESETS:
                raise ValueError(f"Invalid posture {posture!r}; expected one of {sorted(_PRESETS)}")
            return out
        except ImportError:
            pass

    out: dict[str, Any] = {}

    posture = config.get("posture")
    if posture is not None:
        posture_norm = str(posture).strip().lower()
        if posture_norm not in _PRESETS:
            raise ValueError(f"Invalid posture {posture!r}; expected one of {sorted(_PRESETS)}")
        out["posture"] = posture_norm

    def _coerce_int(name: str, *, minimum: int = 0, maximum: int | None = None) -> None:
        if name not in config:
            return
        value = config[name]
        try:
            ivalue = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if ivalue < minimum:
            raise ValueError(f"{name} must be >= {minimum}")
        if maximum is not None and ivalue > maximum:
            raise ValueError(f"{name} must be <= {maximum}")
        out[name] = ivalue

    _coerce_int("min_mem_available_mb", minimum=0)
    _coerce_int("max_swap_used_pct", minimum=0, maximum=100)
    _coerce_int("critical_mem_mb", minimum=0)
    _coerce_int("critical_swap_pct", minimum=0, maximum=100)
    _coerce_int("self_inflicted_pct", minimum=0, maximum=100)

    return out


def attach_signal_recovery(
    guard: "RuntimeGuard",
    *,
    signals_to_handle: list[int] | None = None,
    stage_prefix: str = "signal",
    auto_intervene: bool = False,
    intervene_on: str = "critical",
    kill_hogs_above_mb: int | None = None,
    chain_previous: bool = False,
    audit_log_path: str | None = None,
    hash_algo: str = "sha256",
    audit_deduplicator: "FipsDeduplicator" | None = None,
    module: Any | None = None,
) -> Callable[[], None]:
    """Install signal handlers that emit a final pressure report.

    This provides M2-C01 scaffolding for signal-driven auto-recovery while
    keeping runtime dependencies at zero.

    If ``audit_log_path`` is provided, each signal event is also written to the
    hash-chained audit log, satisfying M2-C02 audit trail requirements.
    """
    signal_mod = module
    if signal_mod is None:
        import signal as signal_mod

    signal_func = getattr(signal_mod, "signal", None)
    if not callable(signal_func):
        raise RuntimeError("Signal module does not provide callable signal().")

    if signals_to_handle is None:
        default_signals: list[int] = []
        for name in ("SIGTERM", "SIGINT", "SIGUSR1", "SIGABRT"):
            value = getattr(signal_mod, name, None)
            if isinstance(value, int):
                default_signals.append(value)
        signals_to_handle = default_signals

    previous_handlers: dict[int, Any] = {}
    intervene_on_key = str(intervene_on).strip().lower()
    if intervene_on_key not in {"critical", "any"}:
        intervene_on_key = "critical"

    def _stage_name(signum: int) -> str:
        signals_enum = getattr(signal_mod, "Signals", None)
        if signals_enum is not None:
            try:
                return str(signals_enum(signum).name).lower()
            except Exception:
                pass
        return f"sig{signum}"

    def _handler(signum: int, frame: Any) -> None:
        report = guard.check(stage=f"{stage_prefix}:{_stage_name(signum)}")
        if report is not None:
            guard.log(report)
            should_intervene = report.is_critical or intervene_on_key == "any"
            if auto_intervene and should_intervene:
                guard.intervene(report, kill_hogs_above_mb=kill_hogs_above_mb)

            if audit_log_path is not None:
                _severity = "critical" if report.is_critical else "warning"
                _action = "recover" if auto_intervene and should_intervene else "observe"
                try:
                    append_audit_log(
                        audit_log_path,
                        {
                            "event_type": "signal_recovery",
                            "category": "incident",
                            "action": _action,
                            "severity": _severity,
                            "signal": _stage_name(signum),
                            "stage": f"{stage_prefix}:{_stage_name(signum)}",
                            "rss_mb": getattr(report, "rss_mb", None),
                            "swap_pct": getattr(report, "swap_pct", None),
                            "is_critical": report.is_critical,
                            "intervened": auto_intervene and should_intervene,
                        },
                        hash_algo=hash_algo,
                        deduplicator=audit_deduplicator,
                    )
                except Exception:
                    pass  # never let audit-log failure interrupt signal handling

        if chain_previous:
            prev = previous_handlers.get(signum)
            if callable(prev):
                prev(signum, frame)

    for sig in signals_to_handle:
        previous_handlers[sig] = signal_func(sig, _handler)

    def _restore() -> None:
        for sig, prev in previous_handlers.items():
            signal_func(sig, prev)

    return _restore


def resolve_signal_recovery_policy(
    *,
    env_prefix: str = "RUNTIME_GUARD",
    module: Any | None = None,
) -> dict[str, Any]:
    """Resolve signal-recovery behavior from environment variables.

    Variables:
    - ``<PREFIX>_SIGNAL_RECOVERY_ENABLE`` (bool, default: true)
    - ``<PREFIX>_SIGNAL_RECOVERY_AUTO_INTERVENE`` (bool, default: false)
    - ``<PREFIX>_SIGNAL_RECOVERY_INTERVENE_ON`` ("critical" or "any", default: "critical")
    - ``<PREFIX>_SIGNAL_RECOVERY_CHAIN_PREVIOUS`` (bool, default: false)
    - ``<PREFIX>_SIGNAL_RECOVERY_STAGE_PREFIX`` (str, default: signal)
    - ``<PREFIX>_SIGNAL_RECOVERY_KILL_HOGS_MB`` (int or unset)
    - ``<PREFIX>_SIGNAL_RECOVERY_SIGNALS`` (CSV: names or ints)
      default: ``SIGTERM,SIGINT,SIGUSR1,SIGABRT``
    - ``<PREFIX>_SIGNAL_RECOVERY_AUDIT_LOG`` (path or unset)
    - ``<PREFIX>_SIGNAL_RECOVERY_HASH_ALGO`` (sha256|sha384|sha512, default: sha256)
    - ``<PREFIX>_SIGNAL_RECOVERY_AUDIT_DEDUP_TTL_S`` (float seconds or unset)
    """
    signal_mod = module
    if signal_mod is None:
        import signal as signal_mod

    def _env(name: str, default: str | None = None) -> str | None:
        return os.getenv(f"{env_prefix}_{name}", default)

    def _as_bool(raw: str | None, default: bool) -> bool:
        if raw is None:
            return default
        value = str(raw).strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        return default

    def _as_positive_int(raw: str | None) -> int | None:
        if raw is None:
            return None
        value = str(raw).strip()
        if value == "":
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        if parsed <= 0:
            return None
        return parsed

    def _as_positive_float(raw: str | None) -> float | None:
        if raw is None:
            return None
        value = str(raw).strip()
        if value == "":
            return None
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        if parsed <= 0:
            return None
        return parsed

    enabled = _as_bool(_env("SIGNAL_RECOVERY_ENABLE"), True)
    auto_intervene = _as_bool(_env("SIGNAL_RECOVERY_AUTO_INTERVENE"), False)
    intervene_on = str(_env("SIGNAL_RECOVERY_INTERVENE_ON", "critical") or "critical").strip().lower()
    if intervene_on not in {"critical", "any"}:
        intervene_on = "critical"
    chain_previous = _as_bool(_env("SIGNAL_RECOVERY_CHAIN_PREVIOUS"), False)
    stage_prefix = str(_env("SIGNAL_RECOVERY_STAGE_PREFIX", "signal") or "signal").strip()
    if stage_prefix == "":
        stage_prefix = "signal"

    kill_hogs_above_mb = _as_positive_int(_env("SIGNAL_RECOVERY_KILL_HOGS_MB"))

    signals_csv = _env("SIGNAL_RECOVERY_SIGNALS", "SIGTERM,SIGINT,SIGUSR1,SIGABRT") or ""
    signals_to_handle: list[int] = []
    seen_signals: set[int] = set()
    for token in signals_csv.split(","):
        item = token.strip()
        if not item:
            continue
        if item.isdigit():
            signum = int(item)
            if signum > 0 and signum not in seen_signals:
                signals_to_handle.append(signum)
                seen_signals.add(signum)
            continue
        name = item if item.startswith("SIG") else f"SIG{item}"
        signum = getattr(signal_mod, name.upper(), None)
        if isinstance(signum, int) and signum > 0 and signum not in seen_signals:
            signals_to_handle.append(signum)
            seen_signals.add(signum)

    audit_log_path = _env("SIGNAL_RECOVERY_AUDIT_LOG") or None
    if audit_log_path is not None:
        audit_log_path = audit_log_path.strip() or None

    hash_algo_env = str(_env("SIGNAL_RECOVERY_HASH_ALGO", "sha256") or "sha256").strip().lower()
    if hash_algo_env not in _FIPS_HASH_ALGOS:
        hash_algo_env = "sha256"
    audit_dedup_ttl_s = _as_positive_float(_env("SIGNAL_RECOVERY_AUDIT_DEDUP_TTL_S"))

    return {
        "enabled": enabled,
        "signals_to_handle": signals_to_handle,
        "stage_prefix": stage_prefix,
        "auto_intervene": auto_intervene,
        "intervene_on": intervene_on,
        "kill_hogs_above_mb": kill_hogs_above_mb,
        "chain_previous": chain_previous,
        "audit_log_path": audit_log_path,
        "hash_algo": hash_algo_env,
        "audit_dedup_ttl_s": audit_dedup_ttl_s,
    }


def install_signal_recovery_from_policy(
    guard: "RuntimeGuard",
    *,
    env_prefix: str = "RUNTIME_GUARD",
    module: Any | None = None,
) -> Callable[[], None]:
    """Install signal recovery using environment-resolved policy settings."""
    policy = resolve_signal_recovery_policy(env_prefix=env_prefix, module=module)
    if not bool(policy.get("enabled", True)):
        return lambda: None

    audit_deduplicator: FipsDeduplicator | None = None
    if policy.get("audit_log_path"):
        ttl_s = policy.get("audit_dedup_ttl_s")
        if ttl_s is not None:
            audit_deduplicator = FipsDeduplicator(
                hash_algo=str(policy.get("hash_algo", "sha256")),
                ttl_s=float(ttl_s),
            )

    return attach_signal_recovery(
        guard,
        signals_to_handle=list(policy.get("signals_to_handle", [])),
        stage_prefix=str(policy.get("stage_prefix", "signal")),
        auto_intervene=bool(policy.get("auto_intervene", False)),
        intervene_on=str(policy.get("intervene_on", "critical")),
        kill_hogs_above_mb=policy.get("kill_hogs_above_mb"),
        chain_previous=bool(policy.get("chain_previous", False)),
        audit_log_path=policy.get("audit_log_path"),
        hash_algo=str(policy.get("hash_algo", "sha256")),
        audit_deduplicator=audit_deduplicator,
        module=module,
    )


def fips_event_hash(payload: str, *, hash_algo: str = "sha256") -> str:
    """Hash event payload with a FIPS-approved SHA algorithm."""
    algo = hash_algo.strip().lower()
    if algo not in _FIPS_HASH_ALGOS:
        raise ValueError(
            f"Unsupported hash algorithm {hash_algo!r}; use one of {sorted(_FIPS_HASH_ALGOS)}"
        )
    h = hashlib.new(algo)
    h.update(payload.encode("utf-8"))
    return h.hexdigest()


class FipsDeduplicator:
    """Thread-safe event deduplicator using FIPS-approved SHA hashes.

    Prevents duplicate events from flooding audit logs or alerting pipelines.
    Events are considered duplicates when their FIPS hash (computed over
    a canonical JSON representation) has already been seen within the
    configured ``ttl_s`` window.  Pass ``ttl_s=0`` (or ``ttl_s=None``) to
    keep seen hashes indefinitely.

    Example::

        dedup = FipsDeduplicator(ttl_s=300)  # 5-minute dedup window
        event = {"category": "memory", "action": "pressure_detected"}
        if dedup.is_new(event):
            append_audit_log("audit.jsonl", event)
    """

    def __init__(self, *, hash_algo: str = "sha256", ttl_s: float | int | None = 300) -> None:
        algo = hash_algo.strip().lower()
        if algo not in _FIPS_HASH_ALGOS:
            raise ValueError(
                f"Unsupported hash algorithm {hash_algo!r}; use one of {sorted(_FIPS_HASH_ALGOS)}"
            )
        self._algo = algo
        self._ttl: float | None = float(ttl_s) if ttl_s is not None and float(ttl_s) > 0 else None
        self._seen: dict[str, float] = {}  # hash -> monotonic timestamp of first sight
        self._lock = threading.Lock()

    def _canonical(self, event: dict[str, Any]) -> str:
        """Stable JSON representation for hashing (sorted keys, no whitespace)."""
        return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)

    def event_hash(self, event: dict[str, Any]) -> str:
        """Return the FIPS hash for ``event`` without recording it."""
        return fips_event_hash(self._canonical(event), hash_algo=self._algo)

    def is_new(self, event: dict[str, Any]) -> bool:
        """Return ``True`` and record ``event`` if it is new; ``False`` if duplicate."""
        digest = self.event_hash(event)
        now = time.monotonic()
        with self._lock:
            if self._ttl is not None:
                # Purge expired entries inline to prevent unbounded growth
                expired = [h for h, ts in self._seen.items() if (now - ts) >= self._ttl]
                for h in expired:
                    del self._seen[h]

            if digest in self._seen:
                return False
            self._seen[digest] = now
            return True

    def mark_seen(self, event: dict[str, Any]) -> None:
        """Explicitly mark ``event`` as seen without checking."""
        digest = self.event_hash(event)
        with self._lock:
            self._seen[digest] = time.monotonic()

    def reset(self) -> None:
        """Clear all seen hashes."""
        with self._lock:
            self._seen.clear()

    @property
    def seen_count(self) -> int:
        """Number of unique events currently tracked (before TTL expiry)."""
        with self._lock:
            return len(self._seen)


def append_audit_log(
    path: str,
    event: dict[str, Any],
    *,
    hash_algo: str = "sha256",
    deduplicator: "FipsDeduplicator" | None = None,
) -> dict[str, Any]:
    """Append an event to a newline-delimited JSON audit log.

    Records are chained by hash (`prev_hash` -> `hash`) to make tampering
    evident during downstream verification.
    """
    expanded = os.path.expanduser(path)
    os.makedirs(os.path.dirname(expanded) or ".", exist_ok=True)

    algo = hash_algo.strip().lower()
    if algo not in _FIPS_HASH_ALGOS:
        raise ValueError(
            f"Unsupported hash algorithm {hash_algo!r}; use one of {sorted(_FIPS_HASH_ALGOS)}"
        )

    ts = int(time.time())
    normalized_event = normalize_policy_violation_event(event)
    event_payload = json.dumps(normalized_event, sort_keys=True, separators=(",", ":"))
    event_hash = fips_event_hash(event_payload, hash_algo=algo)

    # Fast-path duplicate suppression before scanning/writing the chain file.
    if deduplicator is not None and not deduplicator.is_new(normalized_event):
        return {
            "ts": ts,
            "hash_algo": algo,
            "event": normalized_event,
            "event_hash": event_hash,
            "prev_hash": "",
            "hash": "",
            "skipped": True,
        }

    prev_hash = ""
    if os.path.exists(expanded):
        try:
            with open(expanded, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue

                    if str(row.get("hash_algo", algo)).strip().lower() != algo:
                        raise ValueError(
                            "Audit log contains mixed hash algorithms; "
                            f"found {row.get('hash_algo')} expected {algo}"
                        )

                    try:
                        prev_hash = str(row.get("hash", ""))
                    except Exception:
                        continue
        except OSError:
            prev_hash = ""
    chain_input = f"{prev_hash}\n{ts}\n{event_payload}".encode("utf-8")
    digest = hashlib.new(algo, chain_input).hexdigest()

    record: dict[str, Any] = {
        "ts": ts,
        "hash_algo": algo,
        "event": normalized_event,
        "event_hash": event_hash,
        "prev_hash": prev_hash,
        "hash": digest,
    }

    with open(expanded, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")

    return record


def audit_policy_taxonomy() -> dict[str, list[str]]:
    """Return allowed taxonomy values for policy-violation audit events."""
    return {
        "severity": sorted(_AUDIT_POLICY_SEVERITIES),
        "category": sorted(_AUDIT_POLICY_CATEGORIES),
        "action": sorted(_AUDIT_POLICY_ACTIONS),
    }


def normalize_policy_violation_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize policy-violation events to canonical taxonomy values.

    Normalization is applied when ``event_type`` resolves to
    ``policy_violation`` or when ``action`` resolves to ``policy_violation``.
    Other events are returned unchanged.
    """

    def _token(value: Any) -> str:
        raw = str(value).strip().lower()
        return raw.replace("-", "_").replace(" ", "_")

    category_aliases = {
        # memory
        "mem": "memory",
        "memory_pressure": "memory",
        "oom": "memory",
        # system
        "host": "system",
        "host_pressure": "system",
        # config
        "configuration": "config",
        "cfg": "config",
        # compliance
        "policy": "compliance",
        "governance": "compliance",
        "soc2": "compliance",
        "hipaa": "compliance",
        "gdpr": "compliance",
        "regulatory": "compliance",
        # incident
        "incident_response": "incident",
        "response": "incident",
        # access
        "access_control": "access",
        "access_review": "access",
        "privileged_access": "access",
        "authorization": "access",
        "authz": "access",
        # auth
        "authentication": "auth",
        "authn": "auth",
        "login": "auth",
        "credential": "auth",
        # integrity
        "hash_integrity": "integrity",
        "tamper": "integrity",
        "checksum": "integrity",
        # availability
        "uptime": "availability",
        "capacity": "availability",
        "sla": "availability",
        # network
        "networking": "network",
        "net": "network",
        "connection": "network",
        # storage
        "disk": "storage",
        "file": "storage",
        "filesystem": "storage",
        # pipeline
        "pipeline_lifecycle": "pipeline",
        "etl": "pipeline",
        "workflow": "pipeline",
        # scheduler
        "queue": "scheduler",
        "cron": "scheduler",
        "task": "scheduler",
        "job": "scheduler",
        # data_quality
        "data": "data_quality",
        "data_integrity": "data_quality",
        "validation": "data_quality",
        # resource
        "resources": "resource",
        "quota": "resource",
        "limit": "resource",
    }
    action_aliases = {
        # acknowledge
        "ack": "acknowledge",
        "acknowledged": "acknowledge",
        # recover
        "auto_recovery": "recover",
        "incident_response": "recover",
        "restart": "recover",
        # remediate
        "remediation": "remediate",
        "corrective_action": "remediate",
        "corrective_actions": "remediate",
        "fix": "remediate",
        # evict
        "evict_worker": "evict",
        "evict_cache": "evict",
        "cache_evict": "evict",
        # drain
        "drain_queue": "drain",
        "drain_workers": "drain",
        "flush": "drain",
        # suspend
        "suspend_process": "suspend",
        "pause": "suspend",
        "freeze": "suspend",
        # checkpoint
        "checkpoint_state": "checkpoint",
        "save_checkpoint": "checkpoint",
        "save_state": "checkpoint",
        # rollback
        "rollback_change": "rollback",
        "revert": "rollback",
        "undo": "rollback",
        # validate
        "validate_policy": "validate",
        "validate_config": "validate",
        "verify": "validate",
        # quarantine
        "quarantine_worker": "quarantine",
        "isolate": "quarantine",
        # alert
        "alert_oncall": "alert",
        "send_alert": "alert",
        "page": "alert",
        # rebalance
        "rebalance_load": "rebalance",
        "rebalance_workers": "rebalance",
    }

    out = dict(event)
    event_type = _token(out.get("event_type", ""))
    action_type = _token(out.get("action", ""))
    if event_type not in {"policy_violation", "policyviolation"} and action_type not in {
        "policy_violation",
        "policyviolation",
    }:
        return out

    out["event_type"] = "policy_violation"

    sev = _token(out.get("severity", "warning"))
    if sev not in _AUDIT_POLICY_SEVERITIES:
        sev = "warning"
    out["severity"] = sev

    category = _token(out.get("category", "memory"))
    category = category_aliases.get(category, category)
    if category not in _AUDIT_POLICY_CATEGORIES:
        category = "unknown"
    out["category"] = category

    action = _token(out.get("action", "observe"))
    action = action_aliases.get(action, action)
    if action not in _AUDIT_POLICY_ACTIONS:
        action = "custom"
    out["action"] = action

    if "policy_id" in out:
        out["policy_id"] = str(out.get("policy_id", "")).strip()

    return out


def verify_audit_log_chain(path: str) -> dict[str, Any]:
    """Verify hash-chain integrity for an audit log file.

    Returns verification metadata including status and first failing line.
    """
    expanded = os.path.expanduser(path)
    prev_hash = ""
    line_no = 0

    if not os.path.exists(expanded):
        return {"ok": False, "reason": "missing", "line": 0}

    with open(expanded, encoding="utf-8") as fh:
        for raw in fh:
            line_no += 1
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                return {"ok": False, "reason": "invalid-json", "line": line_no}

            algo = str(row.get("hash_algo", "sha256")).strip().lower()
            if algo not in _FIPS_HASH_ALGOS:
                return {"ok": False, "reason": "unsupported-algo", "line": line_no}

            row_prev = str(row.get("prev_hash", ""))
            if row_prev != prev_hash:
                return {"ok": False, "reason": "prev-hash-mismatch", "line": line_no}

            ts = int(row.get("ts", 0) or 0)
            event = row.get("event", {})
            event_payload = json.dumps(event, sort_keys=True, separators=(",", ":"))

            expected_event_hash = fips_event_hash(event_payload, hash_algo=algo)
            if str(row.get("event_hash", "")) != expected_event_hash:
                return {"ok": False, "reason": "event-hash-mismatch", "line": line_no}

            expected_chain = hashlib.new(
                algo, f"{prev_hash}\n{ts}\n{event_payload}".encode("utf-8")
            ).hexdigest()
            if str(row.get("hash", "")) != expected_chain:
                return {"ok": False, "reason": "chain-hash-mismatch", "line": line_no}

            prev_hash = expected_chain

    return {"ok": True, "line": line_no, "records": line_no, "last_hash": prev_hash}


def soc2_required_controls() -> dict[str, str]:
    """Return the default SOC2 control baseline tracked by runtime-guard."""

    return dict(_SOC2_RUNTIME_GUARD_CONTROLS)


def soc2_gap_assessment(
    control_state: dict[str, bool],
    *,
    required_controls: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Summarize SOC2 control coverage and missing controls.

    By default this evaluates runtime-guard's baseline controls (CC6.1, CC7.1,
    CC7.2). Callers can pass ``required_controls`` to override the baseline.
    """

    required = (
        dict(required_controls) if required_controls is not None else soc2_required_controls()
    )

    items: list[tuple[str, bool]] = []
    for key, value in control_state.items():
        items.append((str(key), bool(value)))

    provided: dict[str, bool] = {key: state for key, state in items}
    missing_required = [
        control_id
        for control_id in sorted(required.keys())
        if not bool(provided.get(control_id, False))
    ]
    unknown_controls = [
        control_id for control_id in sorted(provided.keys()) if control_id not in required
    ]

    total = len(items)
    covered = sum(1 for _, state in items if state)
    missing = [name for name, state in items if not state]
    score = (covered / total) if total else 0.0

    return {
        "total_controls": total,
        "covered_controls": covered,
        "missing_controls": missing,
        "missing_required_controls": missing_required,
        "unknown_controls": unknown_controls,
        "coverage_ratio": score,
        "status": "ready" if missing_required == [] else "gaps-found",
    }


def soc2_evidence_requirements(
    *,
    required_controls: dict[str, str] | None = None,
) -> dict[str, list[str]]:
    """Return evidence artifacts expected for SOC2 controls.

    If ``required_controls`` is provided, the returned map is scoped to those
    control IDs and omits unknown IDs.
    """

    requirements = {
        control_id: list(items) for control_id, items in _SOC2_CONTROL_EVIDENCE_REQUIREMENTS.items()
    }
    if required_controls is None:
        return requirements

    scoped: dict[str, list[str]] = {}
    for control_id in required_controls:
        if control_id in requirements:
            scoped[control_id] = list(requirements[control_id])
    return scoped


def soc2_readiness_report(
    control_state: dict[str, bool],
    *,
    evidence_state: dict[str, list[str] | tuple[str, ...] | set[str]] | None = None,
    required_controls: dict[str, str] | None = None,
    evidence_requirements: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Build a SOC2 readiness report with control and evidence coverage."""

    required = (
        dict(required_controls) if required_controls is not None else soc2_required_controls()
    )
    gap = soc2_gap_assessment(control_state, required_controls=required)
    expected = (
        dict(evidence_requirements)
        if evidence_requirements is not None
        else soc2_evidence_requirements(required_controls=required)
    )
    evidence_lookup = evidence_state or {}

    missing_evidence_by_control: dict[str, list[str]] = {}
    provided_evidence_count = 0
    expected_evidence_count = 0

    for control_id in sorted(required.keys()):
        if not bool(control_state.get(control_id, False)):
            continue

        required_items = list(expected.get(control_id, []))
        expected_evidence_count += len(required_items)
        provided_items = {
            str(item).strip()
            for item in evidence_lookup.get(control_id, [])
            if str(item).strip() != ""
        }
        provided_evidence_count += len([item for item in required_items if item in provided_items])
        missing_items = [item for item in required_items if item not in provided_items]
        if missing_items:
            missing_evidence_by_control[control_id] = missing_items

    missing_evidence_controls = sorted(missing_evidence_by_control.keys())
    evidence_ratio = (
        (provided_evidence_count / expected_evidence_count) if expected_evidence_count else 1.0
    )

    if gap["missing_required_controls"]:
        status = "gaps-found"
        maturity = "initial" if gap["coverage_ratio"] < 0.5 else "partial"
    elif missing_evidence_controls:
        status = "evidence-missing"
        maturity = "controls-implemented-evidence-pending"
    else:
        status = "ready"
        maturity = "audit-ready"

    return {
        **gap,
        "status": status,
        "maturity": maturity,
        "expected_evidence_count": expected_evidence_count,
        "provided_evidence_count": provided_evidence_count,
        "missing_evidence_controls": missing_evidence_controls,
        "missing_evidence_by_control": missing_evidence_by_control,
        "evidence_ratio": evidence_ratio,
    }


def build_adoption_scorecard(
    team_records: list[dict[str, Any]],
    *,
    stages: list[str] | None = None,
    success_stage: str = "production",
) -> dict[str, Any]:
    """Summarize multi-team adoption progress for rollout tracking."""

    stage_order = stages or [
        "discover",
        "pilot",
        "trial",
        "staging",
        "production",
        "expanded",
    ]
    stage_index = {name: idx for idx, name in enumerate(stage_order)}
    stage_aliases = {
        "discovery": "discover",
        "prod": "production",
    }
    success_norm = stage_aliases.get(str(success_stage).strip().lower(), str(success_stage).strip().lower())

    def _stage(value: Any) -> str:
        raw = str(value or "discover").strip().lower()
        return stage_aliases.get(raw, raw)

    team_count = len(team_records)
    stage_counts: dict[str, int] = {name: 0 for name in stage_order}
    stage_counts["unknown"] = 0
    missing_evidence_teams: list[str] = []

    reached_success = 0
    for row in team_records:
        team_name = str(row.get("team") or row.get("name") or "unknown-team")
        stage = _stage(row.get("stage"))

        if stage in stage_counts:
            stage_counts[stage] += 1
        else:
            stage_counts["unknown"] += 1

        if stage_index.get(stage, -1) >= stage_index.get(success_norm, len(stage_order)):
            reached_success += 1

        evidence = row.get("evidence", [])
        evidence_items = [str(item).strip() for item in evidence if str(item).strip() != ""]
        if stage in stage_index and stage != "discover" and len(evidence_items) == 0:
            missing_evidence_teams.append(team_name)

    adoption_ratio = (reached_success / team_count) if team_count else 0.0
    status = "on-track" if reached_success >= 5 else "in-progress"

    return {
        "total_teams": team_count,
        "reached_success_stage": reached_success,
        "success_stage": success_norm,
        "adoption_ratio": adoption_ratio,
        "stage_counts": stage_counts,
        "missing_evidence_teams": sorted(missing_evidence_teams),
        "status": status,
    }


def make_worker_report(
    guard: "RuntimeGuard",
    *,
    stage: str = "worker",
    worker_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a single worker report suitable for parent-process aggregation."""
    report = guard.check(stage=stage)
    snap = report.snapshot if report is not None else _read_snapshot()
    severity = "none"
    if report is not None:
        severity = "critical" if report.is_critical else "warning"

    out: dict[str, Any] = {
        "ts": int(time.time()),
        "pid": os.getpid(),
        "worker_id": worker_id or str(os.getpid()),
        "stage": stage,
        "pressure": report is not None,
        "severity": severity,
        "self_inflicted": bool(report.self_inflicted) if report is not None else False,
        "cause": report.cause if report is not None else "",
        "missing_mem_mb": report.missing_mem_mb if report is not None else 0,
        "swap_excess_pct": report.swap_excess_pct if report is not None else 0,
        "mem_available_mb": snap.mem_available_mb,
        "mem_total_mb": snap.mem_total_mb,
        "swap_used_pct": snap.swap_used_pct,
        "rss_mb": snap.rss_mb,
    }
    if metadata:
        out["metadata"] = metadata
    return out


def aggregate_worker_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate worker reports from a process pool or job queue."""
    total = len(reports)
    pressured = [r for r in reports if bool(r.get("pressure"))]
    critical = [r for r in pressured if str(r.get("severity", "")).lower() == "critical"]

    max_missing = 0
    max_swap = 0
    for r in reports:
        try:
            max_missing = max(max_missing, int(r.get("missing_mem_mb", 0) or 0))
        except (TypeError, ValueError):
            pass
        try:
            max_swap = max(max_swap, int(r.get("swap_used_pct", 0) or 0))
        except (TypeError, ValueError):
            pass

    worst_severity = "none"
    if critical:
        worst_severity = "critical"
    elif pressured:
        worst_severity = "warning"

    return {
        "total_workers": total,
        "pressured_workers": len(pressured),
        "critical_workers": len(critical),
        "any_pressure": bool(pressured),
        "worst_severity": worst_severity,
        "max_missing_mem_mb": max_missing,
        "max_swap_used_pct": max_swap,
        "workers": reports,
    }


def append_worker_report_jsonl(path: str, report: dict[str, Any]) -> dict[str, Any]:
    """Append a single worker report to a JSONL transport file.

    Creates parent directories when needed and writes one compact JSON object
    per line. Returns the written report dict.
    """
    expanded = os.path.expanduser(path)
    parent = os.path.dirname(expanded)
    if parent:
        os.makedirs(parent, exist_ok=True)

    row = dict(report)
    with open(expanded, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    return row


def load_worker_reports_jsonl(path: str) -> list[dict[str, Any]]:
    """Load worker reports from a JSONL transport file.

    Invalid JSON lines are skipped so one bad producer write does not block
    whole-pool aggregation.
    """
    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        return []

    rows: list[dict[str, Any]] = []
    with open(expanded, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line == "":
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(dict(row))
    return rows


def aggregate_worker_reports_jsonl(path: str) -> dict[str, Any]:
    """Aggregate worker reports directly from a JSONL transport file."""
    rows = load_worker_reports_jsonl(path)
    return aggregate_worker_reports(rows)


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


# ---------------------------------------------------------------------------
# M1-C01 — Polars scan budget enforcement
# ---------------------------------------------------------------------------


def install_polars_scan_budget(
    guard: "RuntimeGuard",
    *,
    module: Any | None = None,
    max_columns: int | None = None,
    warn_columns: int | None = None,
    max_scans: int | None = None,
    warn_scans: int | None = None,
    schema_attr: str = "schema",
) -> Callable[[], None]:
    """Install a query-plan budget check on Polars LazyFrame execution.

    Before each ``.collect()`` / ``.fetch()`` / sink call the wrapper:

    1. Inspects the LazyFrame's ``schema`` attribute (if available) to count
       projected columns.
    2. Inspects a ``_scan_count`` attribute (if present on the frame) to count
       pending data source scans.
    3. Emits a ``check_and_log`` warning when either metric exceeds the warn
       threshold, and raises ``RuntimeError`` when the hard cap is exceeded.

    Parameters
    ----------
    guard:
        The :class:`RuntimeGuard` instance to use for memory pressure checks.
    module:
        Polars module to patch.  Imported lazily if ``None``.
    max_columns:
        Hard cap on projected columns.  Raises ``RuntimeError`` if exceeded.
    warn_columns:
        Soft cap on projected columns.  Emits ``check_and_log`` and continues.
    max_scans:
        Hard cap on scan node count (``_scan_count`` attribute).
    warn_scans:
        Soft cap on scan node count.
    schema_attr:
        Attribute name on LazyFrame that holds the schema dict/object.
        Defaults to ``"schema"``; override for mock modules.

    Returns
    -------
    Callable[[], None]
        Restore function that removes the budget wrapper.
    """
    if module is None:
        try:
            import polars as module  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Polars is not installed. Install polars or pass module=<polars module>."
            ) from exc

    lazyframe_cls = getattr(module, "LazyFrame", None)
    if lazyframe_cls is None:
        raise RuntimeError("The provided module does not expose polars.LazyFrame.")

    candidate_methods = (
        "collect",
        "fetch",
        "collect_async",
        "sink_parquet",
        "sink_csv",
        "sink_ipc",
        "sink_ndjson",
    )
    original_methods: dict[str, Any] = {
        name: getattr(lazyframe_cls, name, None) for name in candidate_methods
    }

    # Idempotent: if already budget-wrapped, replace in-place.
    _BUDGET_ATTR = "_runtime_guard_budget_wrapped"

    def _check_budget(frame: Any) -> None:
        """Check column/scan budget and warn or raise."""
        schema = getattr(frame, schema_attr, None)
        if schema is not None:
            try:
                col_count = len(schema)
            except Exception:
                col_count = 0

            if max_columns is not None and col_count > max_columns:
                raise RuntimeError(
                    f"[runtime-guard] Polars LazyFrame column budget exceeded: "
                    f"{col_count} columns > max_columns={max_columns}. "
                    "Narrow your select() or projection before collecting."
                )
            if warn_columns is not None and col_count > warn_columns:
                guard.check_and_log(
                    stage=f"polars-budget:columns:{col_count}>{warn_columns}"
                )

        scan_count = getattr(frame, "_scan_count", None)
        if scan_count is not None:
            try:
                sc = int(scan_count)
            except Exception:
                sc = 0
            if max_scans is not None and sc > max_scans:
                raise RuntimeError(
                    f"[runtime-guard] Polars LazyFrame scan budget exceeded: "
                    f"{sc} scans > max_scans={max_scans}. "
                    "Reduce scan sources or use streaming."
                )
            if warn_scans is not None and sc > warn_scans:
                guard.check_and_log(stage=f"polars-budget:scans:{sc}>{warn_scans}")

    def _wrap_with_budget(name: str, fn: Any) -> Any:
        def _budgeted(self: Any, *args: Any, **kwargs: Any) -> Any:
            _check_budget(self)
            return fn(self, *args, **kwargs)

        setattr(_budgeted, _BUDGET_ATTR, True)
        setattr(_budgeted, "_runtime_guard_budget_original", fn)
        setattr(_budgeted, "_runtime_guard_budget_method", name)
        return _budgeted

    for name, fn in original_methods.items():
        if callable(fn):
            # Strip existing budget wrapper before re-applying so we don't nest.
            base_fn = getattr(fn, "_runtime_guard_budget_original", fn)
            setattr(lazyframe_cls, name, _wrap_with_budget(name, base_fn))

    def _restore() -> None:
        for name, fn in original_methods.items():
            if callable(fn):
                # Restore the pre-budget version.
                setattr(lazyframe_cls, name, fn)

    return _restore


# ---------------------------------------------------------------------------
# M1-C02 — Dask task-graph size guard
# ---------------------------------------------------------------------------


def install_dask_task_graph_guard(
    guard: "RuntimeGuard",
    *,
    module: Any | None = None,
    max_tasks: int | None = None,
    warn_tasks: int | None = None,
    task_count_fn: Callable[..., int] | None = None,
) -> Callable[[], None]:
    """Install a task-graph size check on Dask compute/persist entry points.

    Before each ``dask.compute()`` or ``dask.persist()`` call the wrapper:

    1. Estimates the total task count by summing ``len(obj.__dask_graph__())``
       across all positional arguments that implement the Dask graph protocol.
    2. If ``task_count_fn`` is provided, calls it with the positional arguments
       to obtain the count (useful for testing or custom schedulers).
    3. Emits ``check_and_log`` when count exceeds *warn_tasks*, raises
       ``RuntimeError`` when count exceeds *max_tasks*.

    Parameters
    ----------
    guard:
        The :class:`RuntimeGuard` instance.
    module:
        Dask module to patch.  Imported lazily if ``None``.
    max_tasks:
        Hard cap.  Raises ``RuntimeError`` if exceeded before scheduling.
    warn_tasks:
        Soft cap.  Emits ``check_and_log`` and continues.
    task_count_fn:
        Optional ``(*args) -> int`` override for counting tasks.  Receives the
        positional arguments passed to ``compute``/``persist``.

    Returns
    -------
    Callable[[], None]
        Restore function.
    """
    if module is None:
        try:
            import dask as module  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Dask is not installed. Install dask or pass module=<dask module>."
            ) from exc

    compute_fn = getattr(module, "compute", None)
    if compute_fn is None or not callable(compute_fn):
        raise RuntimeError("The provided module does not expose callable dask.compute.")

    base_mod = getattr(module, "base", None)
    original_compute = compute_fn
    original_base_compute = getattr(base_mod, "compute", None) if base_mod is not None else None
    original_base_persist = getattr(base_mod, "persist", None) if base_mod is not None else None

    _TGRAPH_ATTR = "_runtime_guard_tgraph_wrapped"

    def _count_tasks(*args: Any) -> int:
        if task_count_fn is not None:
            return task_count_fn(*args)
        total = 0
        for obj in args:
            graph_fn = getattr(obj, "__dask_graph__", None)
            if callable(graph_fn):
                try:
                    g = graph_fn()
                    total += len(g) if g is not None else 0
                except Exception:
                    pass
        return total

    def _check_graph(*args: Any, label: str = "dask-compute") -> None:
        count = _count_tasks(*args)
        if count == 0:
            return
        if max_tasks is not None and count > max_tasks:
            raise RuntimeError(
                f"[runtime-guard] Dask task-graph budget exceeded: "
                f"{count} tasks > max_tasks={max_tasks}. "
                "Reduce graph size, use dask.persist() with smaller partitions, "
                "or increase max_tasks."
            )
        if warn_tasks is not None and count > warn_tasks:
            guard.check_and_log(stage=f"{label}:tasks:{count}>{warn_tasks}")

    def _guarded_compute(*args: Any, **kwargs: Any) -> Any:
        _check_graph(*args, label="dask-compute")
        return original_compute(*args, **kwargs)

    setattr(_guarded_compute, _TGRAPH_ATTR, True)
    setattr(_guarded_compute, "_runtime_guard_tgraph_original", original_compute)
    setattr(module, "compute", _guarded_compute)

    if base_mod is not None and callable(original_base_compute):

        def _guarded_base_compute(*args: Any, **kwargs: Any) -> Any:
            _check_graph(*args, label="dask-base-compute")
            return original_base_compute(*args, **kwargs)

        setattr(_guarded_base_compute, _TGRAPH_ATTR, True)
        setattr(_guarded_base_compute, "_runtime_guard_tgraph_original", original_base_compute)
        setattr(base_mod, "compute", _guarded_base_compute)

    if base_mod is not None and callable(original_base_persist):

        def _guarded_base_persist(*args: Any, **kwargs: Any) -> Any:
            _check_graph(*args, label="dask-base-persist")
            return original_base_persist(*args, **kwargs)

        setattr(_guarded_base_persist, _TGRAPH_ATTR, True)
        setattr(_guarded_base_persist, "_runtime_guard_tgraph_original", original_base_persist)
        setattr(base_mod, "persist", _guarded_base_persist)

    def _restore() -> None:
        setattr(module, "compute", original_compute)
        if base_mod is not None and callable(original_base_compute):
            setattr(base_mod, "compute", original_base_compute)
        if base_mod is not None and callable(original_base_persist):
            setattr(base_mod, "persist", original_base_persist)

    return _restore


# ---------------------------------------------------------------------------
# M1-C04 — OpenTelemetry memory span exporter
# ---------------------------------------------------------------------------


def install_otel_memory_exporter(
    guard: "RuntimeGuard",
    *,
    tracer: Any | None = None,
    tracer_provider: Any | None = None,
    service_name: str = "runtime-guard",
    span_name_prefix: str = "rg.memory",
    include_rss: bool = True,
    include_swap: bool = True,
    include_available: bool = True,
) -> Callable[[], None]:
    """Install an OpenTelemetry span exporter that emits memory snapshots as spans.

    Wraps :meth:`RuntimeGuard.check_and_log` to also create an OTEL span for
    each check with memory attributes attached.  If ``opentelemetry`` is not
    installed, falls back to a no-op that still allows ``check_and_log`` to
    work normally.

    Parameters
    ----------
    guard:
        The :class:`RuntimeGuard` instance to instrument.
    tracer:
        Pre-built OTEL ``Tracer`` object.  If not provided, one is obtained
        from ``tracer_provider`` or the global ``TracerProvider``.
    tracer_provider:
        OTEL ``TracerProvider`` to use when ``tracer`` is ``None``.
    service_name:
        Service name to use when obtaining a tracer from the global provider.
    span_name_prefix:
        Prefix for span names.  Spans are named ``{span_name_prefix}.check``.
    include_rss:
        Attach ``rss_mb`` attribute to spans.
    include_swap:
        Attach ``swap_used_pct`` attribute to spans.
    include_available:
        Attach ``mem_available_mb`` attribute to spans.

    Returns
    -------
    Callable[[], None]
        Restore function that removes the OTEL wrapper.
    """
    _OTEL_ATTR = "_runtime_guard_otel_wrapped"

    original_check_and_log = guard.check_and_log

    # Attempt to resolve a tracer.  Fail gracefully if OTEL is not installed.
    _tracer: Any = None
    _otel_available = False
    if tracer is not None:
        _tracer = tracer
        _otel_available = True
    else:
        try:
            from opentelemetry import trace as _otel_trace  # type: ignore

            if tracer_provider is not None:
                _tracer = tracer_provider.get_tracer(service_name)
            else:
                _tracer = _otel_trace.get_tracer(service_name)
            _otel_available = True
        except ImportError:
            pass  # OTEL not installed; spans will be no-ops

    def _otel_check_and_log(stage: str = "") -> None:
        if not _otel_available or _tracer is None:
            original_check_and_log(stage=stage)
            return

        span_name = f"{span_name_prefix}.check"
        try:
            with _tracer.start_as_current_span(span_name) as span:
                if stage:
                    span.set_attribute("rg.stage", stage)
                if include_rss or include_swap or include_available:
                    try:
                        avail_mb, total_mb, swap_pct = guard.memory_snapshot_mb()
                        if include_available:
                            span.set_attribute("rg.mem_available_mb", avail_mb)
                        if include_swap:
                            span.set_attribute("rg.swap_used_pct", swap_pct)
                        if include_rss:
                            snap = _read_snapshot()
                            span.set_attribute("rg.rss_mb", snap.rss_mb)
                    except Exception:
                        pass
                original_check_and_log(stage=stage)
        except Exception:
            # If OTEL span creation fails, always fall back to original check.
            original_check_and_log(stage=stage)

    if getattr(original_check_and_log, _OTEL_ATTR, False):
        # Already wrapped — return a no-op restore.
        return lambda: None

    _had_instance_attr = "check_and_log" in vars(guard)

    setattr(_otel_check_and_log, _OTEL_ATTR, True)
    setattr(_otel_check_and_log, "_runtime_guard_otel_original", original_check_and_log)
    guard.check_and_log = _otel_check_and_log  # type: ignore[method-assign]

    def _restore() -> None:
        if _had_instance_attr:
            guard.check_and_log = original_check_and_log  # type: ignore[method-assign]
        else:
            try:
                del guard.__dict__["check_and_log"]
            except KeyError:
                pass

    return _restore


def subprocess_safe(
    label: str = "subprocess",
    *,
    min_mb: int = 500,
    env_prefix: str = "RUNTIME_GUARD",
) -> tuple[bool, str]:
    """Module-level convenience wrapper for :meth:`RuntimeGuard.subprocess_safe`.

    Check whether it is safe to launch a memory-hungry subprocess without
    needing to create a ``RuntimeGuard`` instance first.

    Parameters
    ----------
    label:
        Human-readable name of the subprocess (e.g. ``"Chrome"``).
    min_mb:
        Minimum available RAM in MB required to proceed.  Defaults to 500.
    env_prefix:
        RuntimeGuard env prefix for threshold overrides.  Defaults to
        ``RUNTIME_GUARD``; change to match your repo's prefix.

    Returns
    -------
    ``(True, "")`` when safe.  ``(False, reason)`` when pressure is high.

    Example
    -------
    ::

        from runtime_guard import subprocess_safe

        safe, reason = subprocess_safe("Chrome", min_mb=500)
        if not safe:
            raise RuntimeError(f"Skipping Chrome — {reason}")
    """
    return RuntimeGuard(env_prefix=env_prefix).subprocess_safe(label, min_mb=min_mb)


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


def _read_linux_memory_psi() -> dict[str, float]:
    """Read Linux memory PSI metrics from /proc/pressure/memory when present."""
    data = {
        "psi_some_avg10": 0.0,
        "psi_some_avg60": 0.0,
        "psi_full_avg10": 0.0,
        "psi_full_avg60": 0.0,
    }
    try:
        with open("/proc/pressure/memory", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                scope = parts[0]
                kv: dict[str, str] = {}
                for token in parts[1:]:
                    if "=" not in token:
                        continue
                    k, v = token.split("=", 1)
                    kv[k] = v
                if scope == "some":
                    data["psi_some_avg10"] = float(kv.get("avg10", "0") or 0)
                    data["psi_some_avg60"] = float(kv.get("avg60", "0") or 0)
                elif scope == "full":
                    data["psi_full_avg10"] = float(kv.get("avg10", "0") or 0)
                    data["psi_full_avg60"] = float(kv.get("avg60", "0") or 0)
    except OSError:
        return data
    except ValueError:
        return data
    return data


def _classify_wsl_crash_risk(metrics: dict[str, Any]) -> tuple[str, int, list[str], list[str]]:
    """Return (risk_level, score, likely_causes, prevention_actions)."""
    score = 0
    causes: list[str] = []
    prevention: list[str] = []

    guest_mem_available_mb = int(metrics.get("guest_mem_available_mb", 0) or 0)
    guest_swap_used_pct = int(metrics.get("guest_swap_used_pct", 0) or 0)
    psi_some_avg10 = float(metrics.get("psi_some_avg10", 0.0) or 0.0)
    psi_full_avg10 = float(metrics.get("psi_full_avg10", 0.0) or 0.0)
    host_vm_used_pct = int(metrics.get("host_vm_used_pct", 0) or 0)

    if guest_mem_available_mb < 1024:
        score += 2
        causes.append("guest available memory is below 1 GiB")
        prevention.append("reduce concurrent heavy processes in WSL and VS Code extension hosts")
    if guest_swap_used_pct >= 90:
        score += 2
        causes.append("guest swap usage is at or above 90%")
        prevention.append("increase .wslconfig swap and reduce memory spikes before heavy launches")
    if psi_full_avg10 >= 10:
        score += 2
        causes.append("guest full memory PSI avg10 is high (frequent stalls)")
        prevention.append("stagger memory-heavy tasks; avoid concurrent mypy/pylance/test bursts")
    if psi_some_avg10 >= 20:
        score += 1
        causes.append("guest some memory PSI avg10 indicates sustained contention")
        prevention.append("limit extension host count and long-running indexers during heavy jobs")
    if host_vm_used_pct >= 85:
        score += 1
        causes.append("host virtual memory usage is high")
        prevention.append("free host memory/pagefile pressure and verify Windows pagefile is system-managed")

    if score >= 5:
        level = "critical"
    elif score >= 3:
        level = "high"
    elif score >= 1:
        level = "moderate"
    else:
        level = "low"

    if not prevention:
        prevention.append("current pressure is low; keep WSL capped and monitor before heavy subprocess launches")

    return level, score, causes, prevention


def diagnose_wsl_crash() -> dict[str, Any]:
    """Collect host+guest diagnostics and classify WSL crash risk.

    Returns a dictionary suitable for JSON serialization and CI gating.
    """
    snap = _read_snapshot()
    psi = _read_linux_memory_psi() if sys.platform.startswith("linux") else {
        "psi_some_avg10": 0.0,
        "psi_some_avg60": 0.0,
        "psi_full_avg10": 0.0,
        "psi_full_avg60": 0.0,
    }

    metrics: dict[str, Any] = {
        "guest_mem_total_mb": snap.mem_total_mb,
        "guest_mem_available_mb": snap.mem_available_mb,
        "guest_swap_total_mb": snap.swap_total_mb,
        "guest_swap_free_mb": snap.swap_free_mb,
        "guest_swap_used_pct": snap.swap_used_pct,
        "host_mem_total_mb": snap.host_mem_total_mb,
        "host_mem_free_mb": snap.host_mem_available_mb,
        "host_vm_total_mb": snap.host_swap_total_mb,
        "host_vm_free_mb": snap.host_swap_free_mb,
        "host_vm_used_pct": snap.host_swap_used_pct,
        "drift_mem_total_mb": snap.drift_mem_total_mb,
        "drift_mem_available_mb": snap.drift_mem_available_mb,
        "drift_swap_used_pct": snap.drift_swap_used_pct,
    }
    metrics.update(psi)

    level, score, causes, prevention = _classify_wsl_crash_risk(metrics)
    metrics["risk_level"] = level
    metrics["risk_score"] = score
    metrics["likely_causes"] = causes
    metrics["prevention_actions"] = prevention
    return metrics


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


def make_sitecustomize_content(
    *,
    repo_name: str,
    stage: str = "repo-autostart",
    interval_s: float = 30.0,
    cooldown_s: float = 30.0,
    env_prefix: str = "RUNTIME_GUARD",
) -> str:
    """Return a ``sitecustomize.py`` string that auto-starts RuntimeGuard.

    This is intended for seeding repository-local Python startup behavior so
    RuntimeGuard begins background checks automatically when Python starts.
    Set ``<ENV_PREFIX>_AUTOSTART=0`` to disable without deleting the file.
    """
    lines: list[str] = [
        f'"""sitecustomize.py - RuntimeGuard autostart for {repo_name}.',
        "",
        "Auto-generated by runtime_guard.make_sitecustomize_content().",
        f"Disable with: {env_prefix}_AUTOSTART=0",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "import atexit",
        "import os",
        "",
        "try:",
        "    from runtime_guard import RuntimeGuard",
        "except Exception:",
        "    RuntimeGuard = None  # type: ignore[assignment]",
        "",
        f'_enabled = os.getenv("{env_prefix}_AUTOSTART", "1").strip().lower() not in {{"0", "false", "no", "off"}}',
        "_guard = None",
        "",
        "if RuntimeGuard is not None and _enabled:",
        "    try:",
        "        _guard = RuntimeGuard(",
        f"            env_prefix={env_prefix!r},",
        f"            log_tag={repo_name!r},",
        f"            cooldown_s={cooldown_s!r},",
        "        )",
        f"        _guard.start_background_check(interval_s={interval_s!r}, stage={stage!r})",
        "    except Exception:",
        "        _guard = None",
        "",
        "",
        "def _stop_guard() -> None:",
        "    if _guard is not None:",
        "        try:",
        "            _guard.stop_background_check()",
        "        except Exception:",
        "            pass",
        "",
        "",
        "atexit.register(_stop_guard)",
        "",
    ]
    return "\n".join(lines)


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
    --verify-audit-log Verify an audit log hash chain; exit 0 on success, 1 on failure.
    --audit-policy-taxonomy
                       Print JSON taxonomy catalog used for policy-violation normalization.
    --report           Full WSL2 system health report (same as wsl_system_report()).
    --generate-wslconfig [MEM_GB]
                       Print a recommended .wslconfig; optionally write it with
                       --write (respects existing file — merges, does not overwrite).
    --policy-file PATH Load threshold overrides from a JSON policy file.
    --policy-auto-reload
                       Re-read policy file when its mtime changes (effective with --check/default mode).
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
        "--verify-audit-log",
        metavar="PATH",
        help="Verify audit log chain integrity; exit 0 when valid, 1 when invalid.",
    )
    group.add_argument(
        "--audit-policy-taxonomy",
        action="store_true",
        help="Print the audit policy taxonomy JSON catalog and exit 0.",
    )
    group.add_argument(
        "--report",
        action="store_true",
        help="Print a full WSL2 / system health report.",
    )
    group.add_argument(
        "--diagnose-wsl-crash",
        action="store_true",
        help="Collect host+guest diagnostics and classify WSL crash risk.",
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
        "--policy-file",
        metavar="PATH",
        help="Load threshold policy overrides from JSON file.",
    )
    parser.add_argument(
        "--policy-auto-reload",
        action="store_true",
        help="Auto-reload --policy-file when modified (check/default mode).",
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
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output where applicable (e.g., --diagnose-wsl-crash).",
    )
    parser.add_argument(
        "--fail-on-risk",
        choices=["none", "high", "critical"],
        default="none",
        help="With --diagnose-wsl-crash, exit non-zero when risk meets threshold.",
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

    if args.diagnose_wsl_crash:
        diag = diagnose_wsl_crash()
        if args.json:
            print(json.dumps(diag, sort_keys=True))
        else:
            print(
                "[RuntimeGuard] WSL crash diagnosis "
                f"risk={diag['risk_level']} score={diag['risk_score']} "
                f"guest_mem_available={diag['guest_mem_available_mb']}MB "
                f"guest_swap_used={diag['guest_swap_used_pct']}%"
            )
            if diag.get("host_mem_total_mb"):
                print(
                    "  host: "
                    f"mem_free={diag['host_mem_free_mb']}MB "
                    f"vm_used={diag['host_vm_used_pct']}%"
                )
            if diag.get("likely_causes"):
                print("  likely causes:")
                for cause in diag["likely_causes"]:
                    print(f"    - {cause}")
            print("  prevention actions:")
            for action in diag["prevention_actions"]:
                print(f"    - {action}")

        if args.fail_on_risk == "critical":
            sys.exit(1 if diag["risk_level"] == "critical" else 0)
        if args.fail_on_risk == "high":
            sys.exit(1 if diag["risk_level"] in {"high", "critical"} else 0)
        sys.exit(0)

    if args.verify_audit_log:
        result = verify_audit_log_chain(args.verify_audit_log)
        if bool(result.get("ok")):
            records = int(result.get("records", 0) or 0)
            print(f"[RuntimeGuard] Audit chain OK ({records} record(s))")
            sys.exit(0)

        reason = str(result.get("reason", "unknown"))
        line = int(result.get("line", 0) or 0)
        print(
            f"[RuntimeGuard] Audit chain FAILED at line {line}: {reason}",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.audit_policy_taxonomy:
        taxonomy = audit_policy_taxonomy()
        print(json.dumps(taxonomy, indent=2, sort_keys=True))
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
        if args.policy_file:
            try:
                guard.load_policy_file(
                    args.policy_file,
                    auto_reload=bool(args.policy_auto_reload),
                )
            except (OSError, ValueError) as exc:
                print(f"[RuntimeGuard] Failed to load policy file: {exc}", file=sys.stderr)
                sys.exit(2)
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
