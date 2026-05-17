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
import inspect
import logging
import math
import os
import re
import subprocess
import sys
import threading
import time
import weakref
from collections.abc import Mapping
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
_POLARS_NATIVE_CALLBACK_KWARGS: tuple[str, ...] = (
    "post_opt_callback",
    "post_optimization_callback",
    "collect_callback",
)


def _infer_polars_callback_kwargs(fn: Any) -> tuple[str, ...]:
    """Infer callback kwarg names from a callable signature.

    Keeps a stable preference order for known Polars callback kwargs while
    accepting additional callback-like names (for version drift).
    """
    try:
        signature = inspect.signature(fn)
    except Exception:
        return ()

    callback_params: list[str] = []
    for name, param in signature.parameters.items():
        if param.kind not in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            continue
        if name in _POLARS_NATIVE_CALLBACK_KWARGS:
            callback_params.append(name)
            continue
        lowered = name.lower()
        if "callback" not in lowered:
            continue
        callback_params.append(name)

    if not callback_params:
        return ()
    # De-duplicate while preserving declared order in the function signature.
    return tuple(dict.fromkeys(callback_params).keys())
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
    # IDE-heavy WSL2 developer sessions (VS Code/Pylance/etc.)
    "wsl_dev": (256, 97, 128, 99, 10),
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
    """Sync/async context manager for phase-scoped RuntimeGuard checks.
    
    Supports advanced span-linking (C08) via child span creation and memory attributes.
    """

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
        self._phase_span: Any | None = None
        self._phase_span_ctx: Any | None = None
        self._span_context_entered: bool = False

    def __enter__(self) -> "_GuardPhaseContext":
        # Create a child span for the phase (advanced span-linking C08)
        if self._emit_phase_traces:
            self._create_phase_span()

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
        
        # Close the phase span with final memory snapshot (C08 advanced linking)
        if self._emit_phase_traces:
            self._close_phase_span(with_error=exc_type is not None)
        return False

    async def __aenter__(self) -> "_GuardPhaseContext":
        # Create a child span for the phase (advanced span-linking C08)
        if self._emit_phase_traces:
            self._create_phase_span()

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
        
        # Close the phase span with final memory snapshot (C08 advanced linking)
        if self._emit_phase_traces:
            self._close_phase_span(with_error=exc_type is not None)
        return False


    def _create_phase_span(self) -> None:
        """Create a child span for this phase (advanced span-linking C08)."""
        trace_mod = self._trace_module
        if trace_mod is None:
            try:
                from opentelemetry import trace as trace_mod  # type: ignore
            except Exception:
                return
        
        tracer_factory = getattr(trace_mod, "get_tracer", None)
        if not callable(tracer_factory):
            return
        
        try:
            tracer = tracer_factory(__name__)
            start_as_current = getattr(tracer, "start_as_current_span", None)
            if callable(start_as_current):
                span_name = f"runtime_guard.phase.{self._stage}"
                span_or_ctx = start_as_current(span_name)
                enter = getattr(span_or_ctx, "__enter__", None)
                if callable(enter):
                    self._phase_span_ctx = span_or_ctx
                    self._phase_span = enter()
                    self._span_context_entered = True
                else:
                    self._phase_span_ctx = None
                    self._phase_span = span_or_ctx
                    self._span_context_entered = True
        except Exception:
            pass

    def _close_phase_span(self, with_error: bool = False) -> None:
        """Close the phase span and add final memory snapshot (C08 advanced linking)."""
        if self._phase_span is None or not self._span_context_entered:
            return
        
        try:
            # Add final memory snapshot to span
            final_snap = _read_snapshot()
            set_attr = getattr(self._phase_span, "set_attribute", None)
            if callable(set_attr):
                set_attr("runtime_guard.final_mem_available_mb", final_snap.mem_available_mb)
                set_attr("runtime_guard.final_swap_used_pct", final_snap.swap_used_pct)
                set_attr("runtime_guard.final_rss_mb", final_snap.rss_mb)

            # Set final span status if error occurred
            if with_error:
                set_status = getattr(self._phase_span, "set_status", None)
                if callable(set_status):
                    try:
                        from opentelemetry.trace import Status, StatusCode
                        set_status(Status(StatusCode.ERROR, description="phase exited with exception"))
                    except Exception:
                        pass

            # Prefer context-manager close when available; otherwise end the span directly.
            exited_with_ctx = False
            if self._phase_span_ctx is not None:
                exit_fn = getattr(self._phase_span_ctx, "__exit__", None)
                if callable(exit_fn):
                    try:
                        exit_fn(None, None, None)
                        exited_with_ctx = True
                    except Exception:
                        exited_with_ctx = False

            if not exited_with_ctx:
                end = getattr(self._phase_span, "end", None)
                if callable(end):
                    end()
            self._phase_span = None
            self._phase_span_ctx = None
            self._span_context_entered = False
        except Exception:
            pass

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
        if not isinstance(env_prefix, str) or not env_prefix.strip():
            raise ValueError("env_prefix must be a non-empty string")
        prefix = env_prefix.strip().rstrip("_")
        if not prefix:
            raise ValueError("env_prefix must include at least one non-underscore character")
        if not isinstance(log_tag, str) or not log_tag.strip():
            raise ValueError("log_tag must be a non-empty string")
        if isinstance(cooldown_s, bool) or not isinstance(cooldown_s, (int, float)):
            raise ValueError("cooldown_s must be a non-negative finite number")
        cooldown_value = float(cooldown_s)
        if math.isnan(cooldown_value) or math.isinf(cooldown_value) or cooldown_value < 0:
            raise ValueError("cooldown_s must be a non-negative finite number")
        if hints is not None:
            if not isinstance(hints, list):
                raise ValueError("hints must be a list of strings when provided")
            if any(not isinstance(item, str) for item in hints):
                raise ValueError("hints must contain only strings")
        if not isinstance(show_top_procs, bool):
            raise ValueError("show_top_procs must be a boolean")

        self._prefix = prefix
        self._tag = log_tag.strip()
        self._cooldown_s = cooldown_value
        self._hints: list[str] = list(hints) if hints is not None else []
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
        policy_posture_raw = self._policy_overrides.get("posture", "")
        policy_posture_key = policy_posture_raw.strip().lower() if isinstance(policy_posture_raw, str) else ""
        posture_key = env_posture_key or policy_posture_key
        preset = _PRESETS.get(posture_key, (2048, 85, 1024, 95, 20))

        def _policy_int(key: str, default: int, *, minimum: int = 0, maximum: int | None = None) -> int:
            raw = self._policy_overrides.get(key, default)
            if not isinstance(raw, int) or isinstance(raw, bool):
                return default
            if raw < minimum:
                return default
            if maximum is not None and raw > maximum:
                return default
            return raw

        min_mem_mb = self._int_env(
            "MIN_MEM_AVAILABLE_MB",
            _policy_int("min_mem_available_mb", preset[0], minimum=0),
        )
        max_swap_pct = self._int_env(
            "MAX_SWAP_USED_PCT",
            _policy_int("max_swap_used_pct", preset[1], minimum=0, maximum=100),
        )
        critical_mem_mb = self._int_env(
            "CRITICAL_MEM_MB",
            _policy_int("critical_mem_mb", preset[2], minimum=0),
        )
        critical_swap_pct = self._int_env(
            "CRITICAL_SWAP_PCT",
            _policy_int("critical_swap_pct", preset[3], minimum=0, maximum=100),
        )
        self_inflicted_pct = self._int_env(
            "SELF_INFLICTED_PCT",
            _policy_int("self_inflicted_pct", preset[4], minimum=0, maximum=100),
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

    def _parse_csv_kb_field(row: dict[str, str], key: str) -> int:
        raw = row.get(key, "0")
        if not isinstance(raw, str):
            return 0
        text = raw.strip()
        if not text or not text.isdigit():
            return 0
        return int(text)

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
            snap.host_mem_total_mb = _parse_csv_kb_field(row, "TotalVisibleMemorySize") // 1024
            snap.host_mem_available_mb = _parse_csv_kb_field(row, "FreePhysicalMemory") // 1024
            swap_total_kb = _parse_csv_kb_field(row, "TotalVirtualMemorySize")
            swap_free_kb = _parse_csv_kb_field(row, "FreeVirtualMemory")
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

    def _parse_csv_kb_field(row: dict[str, str], key: str) -> int:
        raw = row.get(key, "0")
        if not isinstance(raw, str):
            return 0
        text = raw.strip()
        if not text or not text.isdigit():
            return 0
        return int(text)

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
            snap.mem_total_mb = _parse_csv_kb_field(row, "TotalVisibleMemorySize") // 1024
            snap.mem_available_mb = _parse_csv_kb_field(row, "FreePhysicalMemory") // 1024
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

    def _parse_non_negative_int(raw: str) -> int | None:
        text = raw.strip()
        if not text or not text.isdigit():
            return None
        return int(text)

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
                parsed = _parse_non_negative_int(v)
                if parsed is not None:
                    fields[k.strip()] = parsed
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
                parsed = _parse_non_negative_int(v)
                if parsed is not None:
                    snap.rss_mb = parsed // (1024 * 1024)
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


def _top_memory_process_details(n: int = 5) -> list[dict[str, Any]]:
    """Return structured details for the top *n* RSS consumers."""
    try:
        result = subprocess.run(
            ["ps", "axo", "pid,rss,args", "--no-headers", "--sort=-rss"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        rows: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                pid = int(parts[0])
                rss_mb = int(parts[1]) // 1024
            except ValueError:
                continue
            command = parts[2].strip()
            if len(command) > 220:
                command = command[:220] + "..."
            rows.append({"pid": pid, "rss_mb": rss_mb, "command": command})
            if len(rows) >= n:
                break
        return rows
    except Exception:
        return []


def _read_wsl_running_distros() -> dict[str, Any]:
    """Return the currently running WSL distros as seen from the host."""
    out: dict[str, Any] = {
        "wsl_running_distros": [],
        "wsl_running_distro_count": 0,
        "docker_desktop_running": False,
        "wsl_parse_warning_count": 0,
    }

    if not _is_wsl():
        return out

    try:
        raw = subprocess.check_output(
            ["cmd.exe", "/c", "cd /d C:\\ && wsl -l -v"],
            stderr=subprocess.DEVNULL,
            timeout=8,
            text=True,
        )
    except Exception:
        return out

    # cmd.exe / wsl.exe output can arrive as NUL-padded UTF-16-style text.
    # Normalize it before line-based parsing.
    raw = raw.replace("\x00", "")

    import re as _re

    running: list[dict[str, Any]] = []
    line_re = _re.compile(r"^\*?\s*(.*?)\s{2,}(Running|Stopped|Installing)\s+(\d+)\s*$")
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("name"):
            continue
        match = line_re.match(line)
        if not match:
            out["wsl_parse_warning_count"] = out["wsl_parse_warning_count"] + 1
            continue
        name, state, version = match.groups()
        if state != "Running":
            continue
        row = {"name": name.strip(), "state": state, "version": int(version)}
        running.append(row)

    out["wsl_running_distros"] = running
    out["wsl_running_distro_count"] = len(running)
    out["docker_desktop_running"] = any(
        isinstance(row.get("name"), str) and row.get("name", "").lower() == "docker-desktop"
        for row in running
    )
    return out


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


    # Dynamically discover all LazyFrame methods that look like execution or sink entry points.
    known_methods = {
        "collect", "fetch", "collect_async",
        "sink_parquet", "sink_csv", "sink_ipc", "sink_ndjson"
    }
    # Also match any method with 'sink' or 'collect' in the name, or with callback-like kwargs.
    dynamic_methods = set()
    for attr in dir(lazyframe_cls):
        if attr.startswith("__"):
            continue
        fn = getattr(lazyframe_cls, attr, None)
        if not callable(fn):
            continue
        if attr in known_methods or "sink" in attr or "collect" in attr:
            dynamic_methods.add(attr)
            continue
        # Check for callback-like kwargs
        try:
            sig = inspect.signature(fn)
            for pname, param in sig.parameters.items():
                if "callback" in pname.lower():
                    dynamic_methods.add(attr)
                    break
        except Exception:
            continue
    candidate_methods = sorted(dynamic_methods)
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
        def _canonical_callback_key(raw_key: Any) -> str:
            if not isinstance(raw_key, str):
                return ""
            return "".join(ch for ch in raw_key.lower() if ch.isalnum())

        signature: inspect.Signature | None = None
        accepts_var_kwargs = False
        accepted_keyword_param_names: set[str] = set()
        try:
            signature = inspect.signature(fn)
            for pname, param in signature.parameters.items():
                if param.kind is inspect.Parameter.VAR_KEYWORD:
                    accepts_var_kwargs = True
                if param.kind in (
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                ):
                    accepted_keyword_param_names.add(pname)
        except Exception:
            signature = None
        callback_kw_names: tuple[str, ...] = _infer_polars_callback_kwargs(fn)
        explicit_callback_kw_names: tuple[str, ...] = ()
        if signature is not None and callback_kw_names:
            explicit_callback_kw_names = tuple(
                pname
                for pname, param in signature.parameters.items()
                if pname in callback_kw_names
                and param.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                )
            )

        native_callback_stage = f"{stage}-native-callback"

        def _chain_native_callback(user_callback: Any | None = None) -> Callable[..., Any]:
            def _wrapped_callback(*cb_args: Any, **cb_kwargs: Any) -> Any:
                guard.check_and_log(stage=native_callback_stage)
                if callable(user_callback):
                    return user_callback(*cb_args, **cb_kwargs)
                return None

            return _wrapped_callback

        def _wrap_callback_value(value: Any) -> tuple[Any, bool]:
            if value is None or callable(value):
                return _chain_native_callback(value), True

            if isinstance(value, list):
                wrapped_items = []
                wrapped_any = False
                for item in value:
                    if item is None or callable(item):
                        wrapped_items.append(_chain_native_callback(item))
                        wrapped_any = True
                    else:
                        wrapped_items.append(item)
                if wrapped_any:
                    return wrapped_items, True
                return value, False

            if isinstance(value, tuple):
                wrapped_items = []
                wrapped_any = False
                for item in value:
                    if item is None or callable(item):
                        wrapped_items.append(_chain_native_callback(item))
                        wrapped_any = True
                    else:
                        wrapped_items.append(item)
                if wrapped_any:
                    return tuple(wrapped_items), True
                return value, False

            return value, False

        def _guarded(self: Any, *args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            positional_callback_alias_values: dict[str, Any] = {}
            if callback_kw_names:
                callback_kw_names_set = set(callback_kw_names)
                explicit_alias_map = {
                    _canonical_callback_key(callback_name): callback_name
                    for callback_name in callback_kw_names
                    if callback_name in accepted_keyword_param_names
                }
                explicit_positional_alias_map = {
                    _canonical_callback_key(callback_name): callback_name
                    for callback_name in explicit_callback_kw_names
                    if callback_name not in accepted_keyword_param_names
                }
                explicit_positional_callback_names = set(explicit_positional_alias_map.values())
                for kw_name in list(kwargs):
                    if kw_name in callback_kw_names:
                        if accepts_var_kwargs and kw_name in explicit_positional_callback_names:
                            # Positional-only callback params cannot be passed as kwargs; hydrate and
                            # remove canonical callback kwargs so binding/call paths stay deterministic.
                            positional_callback_alias_values[kw_name] = kwargs.pop(kw_name)
                        continue
                    if "callback" not in kw_name.lower():
                        continue
                    canonical_name = _canonical_callback_key(kw_name)
                    mapped_name = explicit_alias_map.get(canonical_name)
                    if mapped_name:
                        if mapped_name in kwargs:
                            kwargs.pop(kw_name, None)
                            continue
                        kwargs[mapped_name] = kwargs.pop(kw_name)
                        continue
                    positional_mapped_name = explicit_positional_alias_map.get(canonical_name)
                    if (
                        positional_mapped_name
                        and accepts_var_kwargs
                        and positional_mapped_name not in positional_callback_alias_values
                    ):
                        positional_callback_alias_values[positional_mapped_name] = kwargs.pop(kw_name)

                if signature is not None and not accepts_var_kwargs:
                    for kw_name in list(kwargs):
                        if "callback" not in kw_name.lower():
                            continue
                        if kw_name in callback_kw_names_set and kw_name in accepted_keyword_param_names:
                            continue
                        if kw_name in accepted_keyword_param_names:
                            continue
                        kwargs.pop(kw_name, None)

            callback_like_kwargs = tuple(
                kw_name for kw_name in kwargs if "callback" in kw_name.lower()
            )
            if callback_kw_names or callback_like_kwargs:
                if signature is not None and explicit_callback_kw_names:
                    try:
                        bound = signature.bind_partial(self, *args, **kwargs)
                    except TypeError:
                        bound = None
                    if bound is not None:
                        wrapped_any = False
                        saw_callback_arg = False
                        for kw_name in explicit_callback_kw_names:
                            if kw_name not in bound.arguments and kw_name in positional_callback_alias_values:
                                bound.arguments[kw_name] = positional_callback_alias_values[kw_name]
                            if kw_name in bound.arguments:
                                saw_callback_arg = True
                                user_callback = bound.arguments.get(kw_name)
                                wrapped_callback, wrapped_value = _wrap_callback_value(user_callback)
                                if wrapped_value:
                                    bound.arguments[kw_name] = wrapped_callback
                                    wrapped_any = True

                        bound_kwargs = dict(bound.kwargs)
                        for kw_name in callback_like_kwargs:
                            if kw_name in explicit_callback_kw_names:
                                continue
                            if kw_name in bound_kwargs:
                                saw_callback_arg = True
                                user_callback = bound_kwargs.get(kw_name)
                                wrapped_callback, wrapped_value = _wrap_callback_value(user_callback)
                                if wrapped_value:
                                    bound_kwargs[kw_name] = wrapped_callback
                                    wrapped_any = True

                        if not wrapped_any and not saw_callback_arg:
                            bound.arguments[explicit_callback_kw_names[0]] = _chain_native_callback()
                        return fn(*bound.args, **bound_kwargs)

                callback_candidates = list(callback_like_kwargs)
                for kw_name in callback_kw_names:
                    if kw_name not in callback_candidates:
                        callback_candidates.append(kw_name)

                wrapped_any = False
                saw_callback_arg = False
                for kw_name in callback_candidates:
                    if kw_name in kwargs:
                        saw_callback_arg = True
                        user_callback = kwargs.get(kw_name)
                        wrapped_callback, wrapped_value = _wrap_callback_value(user_callback)
                        if wrapped_value:
                            kwargs[kw_name] = wrapped_callback
                            wrapped_any = True

                if not wrapped_any and not saw_callback_arg and callback_candidates:
                    kwargs[callback_candidates[0]] = _chain_native_callback()
            return fn(self, *args, **kwargs)

        setattr(_guarded, "_runtime_guard_wrapped", True)
        setattr(_guarded, "_runtime_guard_original", fn)
        setattr(_guarded, "_runtime_guard_method", name)
        setattr(_guarded, "_runtime_guard_native_callback_supported", bool(callback_kw_names))
        setattr(_guarded, "_runtime_guard_native_callback_wrapped", bool(callback_kw_names))
        setattr(_guarded, "_runtime_guard_native_callback_kwargs", callback_kw_names)
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
    enable_scheduler_callbacks: bool = False,
    scheduler_stage_prefix: str = "dask",
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

    Parameters
    ----------
    enable_scheduler_callbacks:
        When True, attempts to wrap compute/persist calls in a
        ``dask.callbacks.Callback`` context from
        ``install_dask_scheduler_callbacks`` for deeper scheduler integration.
    scheduler_stage_prefix:
        Stage prefix for scheduler callback checks when
        ``enable_scheduler_callbacks`` is enabled.
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

    # Optionally guard new compute-like methods (e.g., submit) in future Dask versions
    extra_methods = []
    for attr in dir(module):
        if attr.startswith("__") or attr in ("compute", "persist"):
            continue
        fn = getattr(module, attr, None)
        if callable(fn) and ("compute" in attr or "submit" in attr):
            extra_methods.append(attr)

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

        original_extra_methods = {}
        for name in extra_methods:
            method = getattr(module, name, None)
            if callable(method) and getattr(method, "_runtime_guard_wrapped", False):
                method = getattr(method, "_runtime_guard_original", method)
            if callable(method):
                original_extra_methods[name] = method

        def _restore() -> None:
            setattr(module, "compute", original_compute)
            if callable(original_persist):
                setattr(module, "persist", original_persist)
            if base_mod is not None and callable(original_base_compute):
                setattr(base_mod, "compute", original_base_compute)
            if base_mod is not None and callable(original_base_persist):
                setattr(base_mod, "persist", original_base_persist)
            for name, fn in original_extra_methods.items():
                setattr(module, name, fn)

        return _restore

    original_compute = compute_fn
    original_persist = getattr(module, "persist", None)
    original_base_compute = base_compute_fn
    original_base_persist = base_persist_fn

    callback_api_available = False
    callback_context_factory: Callable[[], Any] | None = None
    if enable_scheduler_callbacks:
        callback_reporter = install_dask_scheduler_callbacks(
            guard,
            stage_prefix=scheduler_stage_prefix,
            module=module,
        )
        callback_api_available = bool(getattr(callback_reporter, "callback_api_available", False))
        maybe_factory = getattr(callback_reporter, "create_callback_context", None)
        if callable(maybe_factory):
            callback_context_factory = maybe_factory

    def _with_scheduler_context(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if not enable_scheduler_callbacks or callback_context_factory is None:
            return fn(*args, **kwargs)
        if not callback_api_available:
            return fn(*args, **kwargs)
        try:
            ctx = callback_context_factory()
        except Exception:
            return fn(*args, **kwargs)
        enter = getattr(ctx, "__enter__", None)
        exit_ = getattr(ctx, "__exit__", None)
        if not callable(enter) or not callable(exit_):
            return fn(*args, **kwargs)
        try:
            enter()
        except Exception:
            return fn(*args, **kwargs)

        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:
            suppress = False
            try:
                suppress = bool(exit_(type(exc), exc, exc.__traceback__))
            except Exception:
                suppress = False
            if suppress:
                return None
            raise

        try:
            exit_(None, None, None)
        except Exception:
            # Callback teardown should never block guarded execution.
            return result
        return result

    def _guarded_compute(*args: Any, **kwargs: Any) -> Any:
        guard.check_and_log(stage=stage)
        return _with_scheduler_context(original_compute, *args, **kwargs)

    setattr(_guarded_compute, "_runtime_guard_wrapped", True)
    setattr(_guarded_compute, "_runtime_guard_original", original_compute)
    setattr(_guarded_compute, "_runtime_guard_scheduler_callbacks_enabled", enable_scheduler_callbacks)
    setattr(_guarded_compute, "_runtime_guard_scheduler_callback_api_available", callback_api_available)
    setattr(module, "compute", _guarded_compute)

    if callable(original_persist):

        def _guarded_persist(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return _with_scheduler_context(original_persist, *args, **kwargs)

        setattr(_guarded_persist, "_runtime_guard_wrapped", True)
        setattr(_guarded_persist, "_runtime_guard_original", original_persist)
        setattr(_guarded_persist, "_runtime_guard_scheduler_callbacks_enabled", enable_scheduler_callbacks)
        setattr(_guarded_persist, "_runtime_guard_scheduler_callback_api_available", callback_api_available)
        setattr(module, "persist", _guarded_persist)

    if base_mod is not None and callable(original_base_compute):

        def _guarded_base_compute(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return _with_scheduler_context(original_base_compute, *args, **kwargs)

        setattr(_guarded_base_compute, "_runtime_guard_wrapped", True)
        setattr(_guarded_base_compute, "_runtime_guard_original", original_base_compute)
        setattr(_guarded_base_compute, "_runtime_guard_scheduler_callbacks_enabled", enable_scheduler_callbacks)
        setattr(_guarded_base_compute, "_runtime_guard_scheduler_callback_api_available", callback_api_available)
        setattr(base_mod, "compute", _guarded_base_compute)

    if base_mod is not None and callable(original_base_persist):

        def _guarded_base_persist(*args: Any, **kwargs: Any) -> Any:
            guard.check_and_log(stage=stage)
            return _with_scheduler_context(original_base_persist, *args, **kwargs)

        setattr(_guarded_base_persist, "_runtime_guard_wrapped", True)
        setattr(_guarded_base_persist, "_runtime_guard_original", original_base_persist)
        setattr(_guarded_base_persist, "_runtime_guard_scheduler_callbacks_enabled", enable_scheduler_callbacks)
        setattr(_guarded_base_persist, "_runtime_guard_scheduler_callback_api_available", callback_api_available)
        setattr(base_mod, "persist", _guarded_base_persist)

    # Guard extra compute-like methods
    original_extra_methods = {name: getattr(module, name) for name in extra_methods}
    for name in extra_methods:
        fn = getattr(module, name)

        def _make_guarded(method: Callable[..., Any], wrapped_stage: str = stage) -> Callable[..., Any]:
            def _guarded(*args: Any, **kwargs: Any) -> Any:
                guard.check_and_log(stage=wrapped_stage)
                return _with_scheduler_context(method, *args, **kwargs)

            setattr(_guarded, "_runtime_guard_wrapped", True)
            setattr(_guarded, "_runtime_guard_original", method)
            return _guarded

        guarded = _make_guarded(fn)
        setattr(module, name, guarded)

    def _restore() -> None:
        setattr(module, "compute", original_compute)
        if callable(original_persist):
            setattr(module, "persist", original_persist)
        if base_mod is not None and callable(original_base_compute):
            setattr(base_mod, "compute", original_base_compute)
        if base_mod is not None and callable(original_base_persist):
            setattr(base_mod, "persist", original_base_persist)
        for name, fn in original_extra_methods.items():
            setattr(module, name, fn)

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

    def _canonical_worker_alias_key(raw_key: Any) -> str:
        if isinstance(raw_key, (bytes, bytearray, memoryview)):
            try:
                raw_key = bytes(raw_key).decode("utf-8", errors="ignore")
            except Exception:
                return ""
        if not isinstance(raw_key, str):
            return ""
        return "".join(ch for ch in raw_key.lower() if ch.isalnum())

    def _find_worker_alias_in_mapping(mapping: Mapping[Any, Any]) -> Any:
        preferred_keys = {
            "workerid",
            "worker",
            "workeraddr",
            "workeraddress",
            "address",
        }
        try:
            items_iter = mapping.items()
        except Exception:
            return None
        try:
            for key, value in items_iter:
                if _canonical_worker_alias_key(key) in preferred_keys:
                    return value
        except Exception:
            return None
        return None

    def _extract_worker_alias_value(value: Any, *, _seen_ids: set[int] | None = None) -> Any:
        seen_ids = _seen_ids if _seen_ids is not None else set()

        def _safe_get_alias_attr(target: Any, attr: str) -> Any:
            try:
                return getattr(target, attr, None)
            except Exception:
                return None

        if isinstance(value, (list, tuple)):
            container_id = id(value)
            if container_id in seen_ids:
                return None
            seen_ids.add(container_id)
            for item in value:
                if isinstance(item, (Mapping, list, tuple)):
                    candidate = _extract_worker_alias_value(item, _seen_ids=seen_ids)
                else:
                    has_alias_attr = False
                    for attr in (
                        "worker_id",
                        "workerId",
                        "worker",
                        "worker_addr",
                        "workerAddr",
                        "worker_address",
                        "workerAddress",
                        "address",
                    ):
                        attr_value = _safe_get_alias_attr(item, attr)
                        if attr_value is not None and not callable(attr_value):
                            has_alias_attr = True
                            break
                    if not has_alias_attr:
                        continue
                    candidate = _extract_worker_alias_value(item, _seen_ids=seen_ids)
                if candidate is not None:
                    return candidate
            return None

        current = value
        seen: set[int] = set()

        for _ in range(5):
            if current is None:
                return None

            if isinstance(current, Mapping):
                next_value = _find_worker_alias_in_mapping(current)
                if next_value is None:
                    return None
                current = next_value
                continue

            next_value = None
            for attr in (
                "worker_id",
                "workerId",
                "worker",
                "worker_addr",
                "workerAddr",
                "worker_address",
                "workerAddress",
                "address",
            ):
                candidate = _safe_get_alias_attr(current, attr)
                if candidate is not None and not callable(candidate):
                    next_value = candidate
                    break

            if next_value is None:
                return current

            candidate_id = id(next_value)
            if candidate_id in seen or candidate_id in seen_ids:
                return None
            seen.add(candidate_id)
            seen_ids.add(candidate_id)
            current = next_value

        return current

    def _extract_worker_id(
        *,
        explicit_worker_id: Any = None,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
    ) -> Any:
        def _looks_like_worker_label(value: str) -> bool:
            lowered = value.lower()
            host_part, sep, port_part = lowered.rpartition(":")
            has_host_port_shape = bool(host_part) and sep == ":" and port_part.isdigit()
            return (
                "worker" in lowered
                or lowered.startswith("tcp://")
                or lowered.startswith("inproc://")
                or lowered.startswith("ipc://")
                or lowered.startswith("tls://")
                or lowered.startswith("ucx://")
                or has_host_port_shape
            )

        if explicit_worker_id is not None:
            return explicit_worker_id

        source = kwargs if isinstance(kwargs, dict) else {}
        source_candidate = _find_worker_alias_in_mapping(source)
        if source_candidate is not None:
            return _extract_worker_alias_value(source_candidate)

        for arg in args:
            if isinstance(arg, Mapping):
                arg_candidate = _find_worker_alias_in_mapping(arg)
                if arg_candidate is not None:
                    return _extract_worker_alias_value(arg_candidate)
                continue

            if isinstance(arg, (bytes, bytearray, memoryview)):
                try:
                    decoded_label = bytes(arg).decode("utf-8", errors="ignore").strip()
                except Exception:
                    decoded_label = ""
                if decoded_label and _looks_like_worker_label(decoded_label):
                    return decoded_label

            if isinstance(arg, str):
                candidate_label = arg.strip()
                if candidate_label and _looks_like_worker_label(candidate_label):
                    return candidate_label

            candidate = _extract_worker_alias_value(arg)
            if candidate is not None and candidate is not arg:
                return candidate
        return None

    def _normalize_worker_label(raw_worker_id: Any) -> str:
        if isinstance(raw_worker_id, (bytes, bytearray, memoryview)):
            try:
                decoded = bytes(raw_worker_id).decode("utf-8", errors="ignore").strip()
            except Exception:
                decoded = ""
            if decoded:
                return decoded
        if isinstance(raw_worker_id, str):
            normalized = raw_worker_id.strip()
            if normalized:
                return normalized
        return "unknown-worker"

    def _callback_start(
        key: str,
        *_: Any,
        worker_id: str | None = None,
        **_ignored_kwargs: Any,
    ) -> None:
        """Called before task execution (requires dask.callbacks.Callback.start)."""
        nonlocal callback_count
        callback_count += 1

        def _safe_report_field(report_obj: Any, field_name: str, default: Any) -> Any:
            try:
                return getattr(report_obj, field_name, default)
            except Exception:
                return default

        # Get current worker context if available
        worker_label = _normalize_worker_label(worker_id)
        stage = f"{stage_prefix}-task-{callback_count}"

        def _default_worker_row() -> dict[str, Any]:
            return {
                "worker_id": worker_label,
                "task_count": 0,
                "completed_tasks": 0,
                "pressure_events": 0,
                "healthy_events": 0,
                "snapshots": [],
            }

        def _ensure_mutable_worker_row() -> dict[str, Any]:
            worker_row = worker_snapshots.get(worker_label)
            if not isinstance(worker_row, dict):
                worker_row = _default_worker_row()
            elif type(worker_row) is not dict:
                try:
                    worker_row = dict(worker_row)
                except Exception:
                    worker_row = _default_worker_row()
            else:
                try:
                    worker_row.get("worker_id", worker_label)
                except Exception:
                    worker_row = _default_worker_row()
            worker_snapshots[worker_label] = worker_row
            return worker_row

        # Check memory before task
        report = guard.check_and_log(stage=stage)

        if enable_worker_reports:
            worker_row = _ensure_mutable_worker_row()

            def _safe_worker_row_get(name: str, default: Any) -> Any:
                try:
                    return worker_row.get(name, default)
                except Exception:
                    return default

            task_count = _safe_worker_row_get("task_count", 0)
            if not isinstance(task_count, int) or isinstance(task_count, bool) or task_count < 0:
                task_count = 0
            worker_row["task_count"] = task_count + 1
            if report is not None:
                pressure_events = _safe_worker_row_get("pressure_events", 0)
                if (
                    not isinstance(pressure_events, int)
                    or isinstance(pressure_events, bool)
                    or pressure_events < 0
                ):
                    pressure_events = 0
                worker_row["pressure_events"] = pressure_events + 1

                is_critical = _safe_report_field(report, "is_critical", False)
                if not isinstance(is_critical, bool):
                    is_critical = False

                cause = _safe_report_field(report, "cause", "unknown")
                if not isinstance(cause, str):
                    cause = "unknown"

                missing_mem_mb = _safe_report_field(report, "missing_mem_mb", 0)
                if (
                    not isinstance(missing_mem_mb, (int, float))
                    or isinstance(missing_mem_mb, bool)
                    or missing_mem_mb < 0
                ):
                    missing_mem_mb = 0

                snapshots = _safe_worker_row_get("snapshots", [])
                if not isinstance(snapshots, list):
                    snapshots = []
                    worker_row["snapshots"] = snapshots
                snapshot_entry = {
                    "key": str(key),
                    "timestamp": int(time.time()),
                    "severity": "critical" if is_critical else "warning",
                    "cause": cause,
                    "missing_mem_mb": missing_mem_mb,
                }
                try:
                    snapshots.append(snapshot_entry)
                except Exception:
                    try:
                        snapshots = list(snapshots)
                    except Exception:
                        snapshots = []
                    worker_row["snapshots"] = snapshots
                    snapshots.append(snapshot_entry)
            else:
                healthy_events = _safe_worker_row_get("healthy_events", 0)
                if (
                    not isinstance(healthy_events, int)
                    or isinstance(healthy_events, bool)
                    or healthy_events < 0
                ):
                    healthy_events = 0
                worker_row["healthy_events"] = healthy_events + 1

    def _callback_finish(
        key: str,
        value: Any,
        *_: Any,
        worker_id: str | None = None,
        **_ignored_kwargs: Any,
    ) -> None:
        """Called after task execution (requires dask.callbacks.Callback.finish)."""
        if not enable_worker_reports:
            return

        worker_label = _normalize_worker_label(worker_id)
        worker_row = worker_snapshots.get(worker_label)
        if not isinstance(worker_row, dict):
            worker_row = {
                "worker_id": worker_label,
                "task_count": 0,
                "completed_tasks": 0,
                "pressure_events": 0,
                "healthy_events": 0,
                "snapshots": [],
            }
        elif type(worker_row) is not dict:
            try:
                worker_row = dict(worker_row)
            except Exception:
                worker_row = {
                    "worker_id": worker_label,
                    "task_count": 0,
                    "completed_tasks": 0,
                    "pressure_events": 0,
                    "healthy_events": 0,
                    "snapshots": [],
                }
        else:
            try:
                worker_row.get("worker_id", worker_label)
            except Exception:
                worker_row = {
                    "worker_id": worker_label,
                    "task_count": 0,
                    "completed_tasks": 0,
                    "pressure_events": 0,
                    "healthy_events": 0,
                    "snapshots": [],
                }
        worker_snapshots[worker_label] = worker_row

        def _safe_worker_row_get(name: str, default: Any) -> Any:
            try:
                return worker_row.get(name, default)
            except Exception:
                return default

        completed_tasks = _safe_worker_row_get("completed_tasks", 0)
        if (
            not isinstance(completed_tasks, int)
            or isinstance(completed_tasks, bool)
            or completed_tasks < 0
        ):
            completed_tasks = 0
        worker_row["completed_tasks"] = completed_tasks + 1

    def _get_worker_report(worker_id: str | None = None) -> dict[str, Any]:
        """Retrieve memory report for a specific worker."""
        if worker_id is None:
            # Return aggregated view
            total_events = 0
            total_tasks = 0
            total_completed_tasks = 0
            total_healthy_events = 0
            parse_warning_count = 0

            def _safe_worker_row_get(worker_row: dict[str, Any], name: str, default: Any) -> Any:
                nonlocal parse_warning_count
                try:
                    return worker_row.get(name, default)
                except Exception:
                    parse_warning_count += 1
                    return default

            def _safe_counter(worker_row: dict[str, Any], name: str) -> int:
                nonlocal parse_warning_count
                value = _safe_worker_row_get(worker_row, name, 0)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    return value
                parse_warning_count += 1
                return 0

            def _sanitize_snapshots(raw_snapshots: Any) -> list[dict[str, Any]]:
                nonlocal parse_warning_count
                if not isinstance(raw_snapshots, list):
                    parse_warning_count += 1
                    return []

                def _safe_item_get(item: dict[str, Any], key: str, default: Any) -> Any:
                    nonlocal parse_warning_count
                    try:
                        return item.get(key, default)
                    except Exception:
                        parse_warning_count += 1
                        return default

                out: list[dict[str, Any]] = []
                for item in raw_snapshots:
                    safe_item = {
                        "key": "unknown-task",
                        "timestamp": 0,
                        "severity": "warning",
                        "cause": "unknown",
                        "missing_mem_mb": 0,
                    }
                    if not isinstance(item, dict):
                        parse_warning_count += 1
                        out.append(safe_item)
                        continue

                    key = _safe_item_get(item, "key", "unknown-task")
                    if isinstance(key, str) and key:
                        safe_item["key"] = key
                    else:
                        parse_warning_count += 1

                    timestamp = _safe_item_get(item, "timestamp", 0)
                    if isinstance(timestamp, int) and not isinstance(timestamp, bool) and timestamp >= 0:
                        safe_item["timestamp"] = timestamp
                    else:
                        parse_warning_count += 1

                    severity = _safe_item_get(item, "severity", "warning")
                    if isinstance(severity, str) and severity in ("critical", "warning"):
                        safe_item["severity"] = severity
                    else:
                        parse_warning_count += 1

                    cause = _safe_item_get(item, "cause", "unknown")
                    if isinstance(cause, str):
                        safe_item["cause"] = cause
                    else:
                        parse_warning_count += 1

                    missing_mem_mb = _safe_item_get(item, "missing_mem_mb", 0)
                    if (
                        isinstance(missing_mem_mb, (int, float))
                        and not isinstance(missing_mem_mb, bool)
                        and missing_mem_mb >= 0
                    ):
                        safe_item["missing_mem_mb"] = missing_mem_mb
                    else:
                        parse_warning_count += 1

                    out.append(safe_item)

                return out

            for worker_label, worker_row in worker_snapshots.items():
                if not isinstance(worker_label, str):
                    parse_warning_count += 1

                if not isinstance(worker_row, dict):
                    parse_warning_count += 1
                    safe_row = {
                        "worker_id": worker_label if isinstance(worker_label, str) else "unknown-worker",
                        "task_count": 0,
                        "completed_tasks": 0,
                        "pressure_events": 0,
                        "healthy_events": 0,
                        "snapshots": [],
                    }
                    worker_snapshots[worker_label] = safe_row
                    continue
                if type(worker_row) is not dict:
                    parse_warning_count += 1
                    try:
                        worker_row = dict(worker_row)
                    except Exception:
                        worker_row = {
                            "worker_id": worker_label if isinstance(worker_label, str) else "unknown-worker",
                            "task_count": 0,
                            "completed_tasks": 0,
                            "pressure_events": 0,
                            "healthy_events": 0,
                            "snapshots": [],
                        }
                    worker_snapshots[worker_label] = worker_row

                pressure_events = _safe_counter(worker_row, "pressure_events")
                task_count = _safe_counter(worker_row, "task_count")
                completed_tasks = _safe_counter(worker_row, "completed_tasks")
                healthy_events = _safe_counter(worker_row, "healthy_events")

                snapshots = _sanitize_snapshots(_safe_worker_row_get(worker_row, "snapshots", []))

                worker_row["worker_id"] = (
                    worker_label if isinstance(worker_label, str) else "unknown-worker"
                )
                worker_row["task_count"] = task_count
                worker_row["completed_tasks"] = completed_tasks
                worker_row["pressure_events"] = pressure_events
                worker_row["healthy_events"] = healthy_events
                worker_row["snapshots"] = snapshots

                total_events += pressure_events
                total_tasks += task_count
                total_completed_tasks += completed_tasks
                total_healthy_events += healthy_events
            return {
                "ok": True,
                "workers_monitored": len(worker_snapshots),
                "total_pressure_events": total_events,
                "total_tasks": total_tasks,
                "total_completed_tasks": total_completed_tasks,
                "total_healthy_events": total_healthy_events,
                "worker_details": worker_snapshots,
                "parse_warning_count": parse_warning_count,
            }

        worker_key = _normalize_worker_label(worker_id)
        worker_data = worker_snapshots.get(worker_key)
        if worker_data is None:
            return {
                "ok": True,
                "worker_id": worker_key,
                "pressure_events": 0,
                "task_count": 0,
                "completed_tasks": 0,
                "healthy_events": 0,
            }
        if not isinstance(worker_data, dict):
            return {
                "ok": True,
                "worker_id": worker_key,
                "task_count": 0,
                "completed_tasks": 0,
                "pressure_events": 0,
                "healthy_events": 0,
                "parse_warning_count": 1,
            }

        parse_warning_count = 0

        def _safe_worker_data_get(name: str, default: Any) -> Any:
            nonlocal parse_warning_count
            try:
                return worker_data.get(name, default)
            except Exception:
                parse_warning_count += 1
                return default

        def _safe_counter(name: str) -> int:
            nonlocal parse_warning_count
            value = _safe_worker_data_get(name, 0)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
            parse_warning_count += 1
            return 0

        def _sanitize_snapshots(raw_snapshots: Any) -> list[dict[str, Any]]:
            nonlocal parse_warning_count
            if not isinstance(raw_snapshots, list):
                parse_warning_count += 1
                return []

            def _safe_item_get(item: dict[str, Any], key: str, default: Any) -> Any:
                nonlocal parse_warning_count
                try:
                    return item.get(key, default)
                except Exception:
                    parse_warning_count += 1
                    return default

            out: list[dict[str, Any]] = []
            for item in raw_snapshots:
                safe_item = {
                    "key": "unknown-task",
                    "timestamp": 0,
                    "severity": "warning",
                    "cause": "unknown",
                    "missing_mem_mb": 0,
                }
                if not isinstance(item, dict):
                    parse_warning_count += 1
                    out.append(safe_item)
                    continue

                key = _safe_item_get(item, "key", "unknown-task")
                if isinstance(key, str) and key:
                    safe_item["key"] = key
                else:
                    parse_warning_count += 1

                timestamp = _safe_item_get(item, "timestamp", 0)
                if isinstance(timestamp, int) and not isinstance(timestamp, bool) and timestamp >= 0:
                    safe_item["timestamp"] = timestamp
                else:
                    parse_warning_count += 1

                severity = _safe_item_get(item, "severity", "warning")
                if isinstance(severity, str) and severity in ("critical", "warning"):
                    safe_item["severity"] = severity
                else:
                    parse_warning_count += 1

                cause = _safe_item_get(item, "cause", "unknown")
                if isinstance(cause, str):
                    safe_item["cause"] = cause
                else:
                    parse_warning_count += 1

                missing_mem_mb = _safe_item_get(item, "missing_mem_mb", 0)
                if (
                    isinstance(missing_mem_mb, (int, float))
                    and not isinstance(missing_mem_mb, bool)
                    and missing_mem_mb >= 0
                ):
                    safe_item["missing_mem_mb"] = missing_mem_mb
                else:
                    parse_warning_count += 1

                out.append(safe_item)

            return out

        snapshots = _sanitize_snapshots(_safe_worker_data_get("snapshots", []))

        return {
            "ok": True,
            "worker_id": worker_key,
            "task_count": _safe_counter("task_count"),
            "completed_tasks": _safe_counter("completed_tasks"),
            "pressure_events": _safe_counter("pressure_events"),
            "healthy_events": _safe_counter("healthy_events"),
            "snapshots": snapshots,
            "parse_warning_count": parse_warning_count,
        }

    # Create a callback object compatible with dask.callbacks.Callback
    class _SchedulerCallback:
        """Dask scheduler callback for memory monitoring."""

        _start = _callback_start
        _finish = _callback_finish

        @staticmethod
        def start(key: str, *args: Any, **kwargs: Any) -> None:
            worker_id = _extract_worker_id(args=args, kwargs=kwargs)
            _callback_start(key, *args, worker_id=worker_id)

        @staticmethod
        def finish(key: str, value: Any, *args: Any, **kwargs: Any) -> None:
            worker_id = _extract_worker_id(args=args, kwargs=kwargs)
            _callback_finish(key, value, *args, worker_id=worker_id)

    _SchedulerCallback.get_worker_report = staticmethod(_get_worker_report)  # type: ignore

    callback_api_available = False
    callback_context_cls: Any = _SchedulerCallback

    callbacks_mod = getattr(module, "callbacks", None) if module is not None else None
    callback_base = getattr(callbacks_mod, "Callback", None) if callbacks_mod is not None else None

    if isinstance(callback_base, type):
        callback_api_available = True

        class _RuntimeGuardDaskCallback(callback_base):
            def _pretask(self, key: str, *_args: Any, **kwargs: Any) -> None:
                worker_id = _extract_worker_id(args=_args, kwargs=kwargs)
                _callback_start(key, worker_id=worker_id)

            def _posttask(self, key: str, value: Any, *_args: Any, **kwargs: Any) -> None:
                worker_id = _extract_worker_id(args=_args, kwargs=kwargs)
                _callback_finish(key, value, worker_id=worker_id)

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
    scheduler_telemetry_counters_present = False

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

        # Validate scheduler telemetry report surface for machine-verifiable evidence.
        try:
            callback_reporter = install_dask_scheduler_callbacks(guard, module=dask_mod)
            callback_summary = callback_reporter()
            required_counter_fields = {
                "total_tasks",
                "total_completed_tasks",
                "total_healthy_events",
                "total_pressure_events",
            }
            scheduler_telemetry_counters_present = required_counter_fields.issubset(
                set(callback_summary.keys()) if isinstance(callback_summary, dict) else set()
            )
        except Exception:
            scheduler_telemetry_counters_present = False

        methods_wrapped = bool(getattr(compute_fn, "_runtime_guard_wrapped", False))
        scheduler_callbacks_wrapped = bool(
            getattr(compute_fn, "_runtime_guard_scheduler_callbacks_enabled", False)
        )
        scheduler_callback_context_available = bool(
            getattr(compute_fn, "_runtime_guard_scheduler_callback_api_available", False)
        )

        return {
            "ok": True,
            "dask_available": True,
            "methods_wrapped": methods_wrapped,
            "scheduler_callbacks_wrapped": scheduler_callbacks_wrapped,
            "scheduler_callback_context_available": scheduler_callback_context_available,
            "scheduler_telemetry_counters_present": scheduler_telemetry_counters_present,
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
            "scheduler_telemetry_counters_present": scheduler_telemetry_counters_present,
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

    if validation.get("scheduler_callback_context_available"):
        evidence_items.append("dask_scheduler_callback_context_available")

    if validation.get("scheduler_callbacks_wrapped"):
        evidence_items.append("dask_scheduler_callback_context_wrapped")

    if validation.get("scheduler_telemetry_counters_present"):
        evidence_items.append("dask_scheduler_telemetry_counters_present")

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
    parse_warning_count = 0

    def _strict_non_negative_counter(value: Any) -> tuple[int, bool]:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value, True
        return 0, False

    def _warn_parse() -> None:
        nonlocal parse_warning_count
        parse_warning_count += 1

    def _normalize_key(raw: Any, *, fallback: str) -> str:
        if isinstance(raw, (bytes, bytearray, memoryview)):
            try:
                decoded = bytes(raw).decode("utf-8", errors="ignore").strip()
            except Exception:
                decoded = ""
            if decoded:
                return decoded
        if isinstance(raw, str):
            value = raw.strip()
            if value:
                return value
        _warn_parse()
        return fallback

    config: dict[str, Any] = {
        "ok": True,
        "stage_prefix": stage_prefix,
        "check_on_entry": check_on_entry,
        "check_on_exit": check_on_exit,
        "method_decorator": None,
        "remote_wrapper": None,
        "get_actor_report": None,
        "reset_actor_report": None,
        "node_report": None,
        "reset_node_reports": None,
        "get_all_node_reports": None,
        "cluster_summary": None,
        "parse_warning_count": 0,
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
        pressure_detected: bool,
    ) -> None:
        node_key = _normalize_key(node_id, fallback="unknown-node")
        actor_key = _normalize_key(actor_id, fallback="unknown-actor")
        method_key = _normalize_key(method_name, fallback="unknown-method")

        def _default_node_row() -> dict[str, Any]:
            return {
                "node_id": node_key,
                "events": 0,
                "entry_checks": 0,
                "exit_checks": 0,
                "pressure_events": 0,
                "healthy_events": 0,
                "actors": {},
            }

        node_row = actor_event_state.get(node_key)
        if not isinstance(node_row, dict):
            if node_row is not None:
                _warn_parse()
            node_row = _default_node_row()
        elif type(node_row) is not dict:
            _warn_parse()
            try:
                node_row = dict(node_row)
            except Exception:
                node_row = _default_node_row()
        else:
            try:
                node_row.get("node_id", node_key)
            except Exception:
                _warn_parse()
                node_row = _default_node_row()
        actor_event_state[node_key] = node_row
        node_events, _ = _strict_non_negative_counter(node_row.get("events", 0))
        node_row["events"] = node_events + 1
        if event_type == "entry":
            node_entry_checks, _ = _strict_non_negative_counter(node_row.get("entry_checks", 0))
            node_row["entry_checks"] = node_entry_checks + 1
        elif event_type == "exit":
            node_exit_checks, _ = _strict_non_negative_counter(node_row.get("exit_checks", 0))
            node_row["exit_checks"] = node_exit_checks + 1
        if pressure_detected:
            node_pressure_events, _ = _strict_non_negative_counter(node_row.get("pressure_events", 0))
            node_row["pressure_events"] = node_pressure_events + 1
        else:
            node_healthy_events, _ = _strict_non_negative_counter(node_row.get("healthy_events", 0))
            node_row["healthy_events"] = node_healthy_events + 1

        actors = node_row.get("actors")
        if not isinstance(actors, dict):
            _warn_parse()
            actors = {}
            node_row["actors"] = actors

        try:
            actor_row = actors.get(actor_key)
        except Exception:
            _warn_parse()
            actors = {}
            node_row["actors"] = actors
            actor_row = None
        if not isinstance(actor_row, dict):
            if actor_row is not None:
                _warn_parse()
            actor_row = {
                "actor_id": actor_key,
                "events": 0,
                "entry_checks": 0,
                "exit_checks": 0,
                "pressure_events": 0,
                "healthy_events": 0,
                "methods": {},
            }
            actors[actor_key] = actor_row
        elif type(actor_row) is not dict:
            _warn_parse()
            try:
                actor_row = dict(actor_row)
            except Exception:
                actor_row = {
                    "actor_id": actor_key,
                    "events": 0,
                    "entry_checks": 0,
                    "exit_checks": 0,
                    "pressure_events": 0,
                    "healthy_events": 0,
                    "methods": {},
                }
            actors[actor_key] = actor_row
        else:
            try:
                actor_row.get("actor_id", actor_key)
            except Exception:
                _warn_parse()
                actor_row = {
                    "actor_id": actor_key,
                    "events": 0,
                    "entry_checks": 0,
                    "exit_checks": 0,
                    "pressure_events": 0,
                    "healthy_events": 0,
                    "methods": {},
                }
                actors[actor_key] = actor_row
        actor_events, _ = _strict_non_negative_counter(actor_row.get("events", 0))
        actor_row["events"] = actor_events + 1
        if event_type == "entry":
            actor_entry_checks, _ = _strict_non_negative_counter(actor_row.get("entry_checks", 0))
            actor_row["entry_checks"] = actor_entry_checks + 1
        elif event_type == "exit":
            actor_exit_checks, _ = _strict_non_negative_counter(actor_row.get("exit_checks", 0))
            actor_row["exit_checks"] = actor_exit_checks + 1
        if pressure_detected:
            actor_pressure_events, _ = _strict_non_negative_counter(actor_row.get("pressure_events", 0))
            actor_row["pressure_events"] = actor_pressure_events + 1
        else:
            actor_healthy_events, _ = _strict_non_negative_counter(actor_row.get("healthy_events", 0))
            actor_row["healthy_events"] = actor_healthy_events + 1

        methods = actor_row.get("methods")
        if not isinstance(methods, dict):
            _warn_parse()
            methods = {}
            actor_row["methods"] = methods
        elif type(methods) is not dict:
            _warn_parse()
            try:
                methods = dict(methods)
            except Exception:
                methods = {}
            actor_row["methods"] = methods
        try:
            raw_method_count = methods.get(method_key, 0)
        except Exception:
            _warn_parse()
            methods = {}
            actor_row["methods"] = methods
            raw_method_count = 0
        method_count, _ = _strict_non_negative_counter(raw_method_count)
        methods[method_key] = method_count + 1

    def _sanitize_actor_row_for_report(actor_row: dict[str, Any], actor_key: str) -> dict[str, Any]:
        safe_row: dict[str, Any] = {}

        def _safe_actor_row_get(key: str, default: Any) -> Any:
            try:
                return actor_row.get(key, default)
            except Exception:
                _warn_parse()
                return default

        safe_actor_id = _normalize_key(_safe_actor_row_get("actor_id", actor_key), fallback=actor_key)
        safe_row["actor_id"] = safe_actor_id

        for counter_name in (
            "events",
            "entry_checks",
            "exit_checks",
            "pressure_events",
            "healthy_events",
        ):
            raw_value = _safe_actor_row_get(counter_name, 0)
            counter_value, counter_ok = _strict_non_negative_counter(raw_value)
            if not counter_ok and raw_value not in (0,):
                _warn_parse()
            safe_row[counter_name] = counter_value

        methods = _safe_actor_row_get("methods", {})
        if not isinstance(methods, dict):
            if methods is not None:
                _warn_parse()
            methods = {}

        safe_methods: dict[str, int] = {}
        try:
            method_items = list(methods.items())
        except Exception:
            _warn_parse()
            method_items = []
        for raw_method_name, raw_method_count in method_items:
            if not isinstance(raw_method_name, str):
                _warn_parse()
                continue
            method_name = raw_method_name.strip()
            if not method_name:
                _warn_parse()
                continue
            method_count, method_ok = _strict_non_negative_counter(raw_method_count)
            if not method_ok and raw_method_count not in (0,):
                _warn_parse()
            safe_methods[method_name] = method_count

        safe_row["methods"] = safe_methods

        return safe_row

    def _sanitize_node_row_for_report(node_row: dict[str, Any], node_key: str) -> dict[str, Any]:
        safe_row: dict[str, Any] = {}

        def _safe_node_row_get(key: str, default: Any) -> Any:
            try:
                return node_row.get(key, default)
            except Exception:
                _warn_parse()
                return default

        safe_node_id = _normalize_key(_safe_node_row_get("node_id", node_key), fallback=node_key)
        safe_row["node_id"] = safe_node_id

        for counter_name in (
            "events",
            "entry_checks",
            "exit_checks",
            "pressure_events",
            "healthy_events",
        ):
            raw_value = _safe_node_row_get(counter_name, 0)
            counter_value, counter_ok = _strict_non_negative_counter(raw_value)
            if not counter_ok and raw_value not in (0,):
                _warn_parse()
            safe_row[counter_name] = counter_value

        actors = _safe_node_row_get("actors", {})
        if not isinstance(actors, dict):
            if actors is not None:
                _warn_parse()
            actors = {}

        safe_actors: dict[str, dict[str, Any]] = {}
        try:
            actor_items = list(actors.items())
        except Exception:
            _warn_parse()
            actor_items = []
        for raw_actor_id, raw_actor_row in actor_items:
            if not isinstance(raw_actor_id, str):
                _warn_parse()
                continue
            actor_key = raw_actor_id.strip()
            if not actor_key:
                _warn_parse()
                continue
            if not isinstance(raw_actor_row, dict):
                _warn_parse()
                continue
            safe_actors[actor_key] = _sanitize_actor_row_for_report(raw_actor_row, actor_key)

        safe_row["actors"] = safe_actors
        return safe_row

    def _get_actor_report(*, node_id: str | None = None, actor_id: str | None = None) -> dict[str, Any]:
        if node_id is None and actor_id is None:
            safe_nodes: dict[str, dict[str, Any]] = {}
            total_events = 0
            for node_key, row in actor_event_state.items():
                if not isinstance(row, dict):
                    _warn_parse()
                    continue
                safe_row = _sanitize_node_row_for_report(row, node_key)
                safe_nodes[node_key] = safe_row
                total_events += safe_row.get("events", 0)
            return {
                "ok": True,
                "nodes": safe_nodes,
                "nodes_monitored": len(actor_event_state),
                "total_events": total_events,
                "parse_warning_count": parse_warning_count,
            }

        if node_id is not None:
            node_key = _normalize_key(node_id, fallback="unknown-node")
            node_row = actor_event_state.get(node_key)
            if node_row is None:
                return {
                    "ok": True,
                    "node_id": node_key,
                    "events": 0,
                    "actors": {},
                    "parse_warning_count": parse_warning_count,
                }
            if not isinstance(node_row, dict):
                _warn_parse()
                return {
                    "ok": True,
                    "node_id": node_key,
                    "events": 0,
                    "actors": {},
                    "parse_warning_count": parse_warning_count,
                }
            if actor_id is None:
                safe_node_row = _sanitize_node_row_for_report(node_row, node_key)
                return {"ok": True, **safe_node_row, "parse_warning_count": parse_warning_count}
            actor_key = _normalize_key(actor_id, fallback="unknown-actor")
            try:
                actors = node_row.get("actors")
            except Exception:
                _warn_parse()
                actors = {}
            if not isinstance(actors, dict):
                _warn_parse()
                actors = {}
            try:
                actor_row = actors.get(actor_key)
            except Exception:
                _warn_parse()
                actor_row = None
            if actor_row is None:
                return {
                    "ok": True,
                    "node_id": node_key,
                    "actor_id": actor_key,
                    "events": 0,
                    "methods": {},
                    "parse_warning_count": parse_warning_count,
                }
            if not isinstance(actor_row, dict):
                _warn_parse()
                return {
                    "ok": True,
                    "node_id": node_key,
                    "actor_id": actor_key,
                    "events": 0,
                    "methods": {},
                    "parse_warning_count": parse_warning_count,
                }
            safe_actor_row = _sanitize_actor_row_for_report(actor_row, actor_key)
            return {
                "ok": True,
                "node_id": node_key,
                **safe_actor_row,
                "parse_warning_count": parse_warning_count,
            }

        actor_key = _normalize_key(actor_id, fallback="unknown-actor")
        for node_key, node_row in actor_event_state.items():
            if not isinstance(node_row, dict):
                _warn_parse()
                continue
            try:
                actors = node_row.get("actors")
            except Exception:
                _warn_parse()
                continue
            if not isinstance(actors, dict):
                _warn_parse()
                continue
            try:
                actor_row = actors.get(actor_key)
            except Exception:
                _warn_parse()
                continue
            if actor_row is not None:
                if not isinstance(actor_row, dict):
                    _warn_parse()
                    continue
                safe_actor_row = _sanitize_actor_row_for_report(actor_row, actor_key)
                return {
                    "ok": True,
                    "node_id": node_key,
                    **safe_actor_row,
                    "parse_warning_count": parse_warning_count,
                }

        return {
            "ok": True,
            "actor_id": actor_key,
            "events": 0,
            "methods": {},
            "parse_warning_count": parse_warning_count,
        }

    def _reset_actor_report() -> None:
        actor_event_state.clear()

    def _node_report(node_id: str) -> dict[str, Any]:
        return _get_actor_report(node_id=node_id)

    def _reset_node_reports() -> None:
        actor_event_state.clear()

    def _get_all_node_reports() -> dict[str, Any]:
        total_events = 0
        total_pressure_events = 0
        total_healthy_events = 0

        def _safe_row_get(row: dict[str, Any], key: str, default: Any) -> Any:
            try:
                return row.get(key, default)
            except Exception:
                _warn_parse()
                return default

        for node_id, row in actor_event_state.items():
            if not isinstance(node_id, str) or not node_id.strip():
                _warn_parse()
            if not isinstance(row, dict):
                _warn_parse()
                continue
            raw_events = _safe_row_get(row, "events", 0)
            events, events_ok = _strict_non_negative_counter(raw_events)
            if not events_ok and raw_events not in (0,):
                _warn_parse()
            total_events += events

            raw_pressure_events = _safe_row_get(row, "pressure_events", 0)
            pressure_events, pressure_ok = _strict_non_negative_counter(raw_pressure_events)
            if not pressure_ok and raw_pressure_events not in (0,):
                _warn_parse()
            total_pressure_events += pressure_events

            raw_healthy_events = _safe_row_get(row, "healthy_events", 0)
            healthy_events, healthy_ok = _strict_non_negative_counter(raw_healthy_events)
            if not healthy_ok and raw_healthy_events not in (0,):
                _warn_parse()
            total_healthy_events += healthy_events

        return {
            "ok": True,
            "nodes": actor_event_state,
            "nodes_monitored": len(actor_event_state),
            "total_events": total_events,
            "total_pressure_events": total_pressure_events,
            "total_healthy_events": total_healthy_events,
            "parse_warning_count": parse_warning_count,
        }

    def _cluster_summary() -> dict[str, Any]:
        total_events = 0
        total_actors = 0
        total_pressure_events = 0
        total_healthy_events = 0
        busiest_node = None
        busiest_events = -1
        busiest_actor = None
        busiest_actor_events = -1

        def _safe_row_get(row: dict[str, Any], key: str, default: Any) -> Any:
            try:
                return row.get(key, default)
            except Exception:
                _warn_parse()
                return default

        for raw_node_id, row in actor_event_state.items():
            if isinstance(raw_node_id, str):
                node_id = raw_node_id.strip()
                if not node_id:
                    _warn_parse()
                    node_id = "unknown-node"
            else:
                _warn_parse()
                node_id = "unknown-node"

            if not isinstance(row, dict):
                _warn_parse()
                continue
            raw_events = _safe_row_get(row, "events", 0)
            events, events_ok = _strict_non_negative_counter(raw_events)
            if not events_ok and raw_events not in (0,):
                _warn_parse()
            total_events += events
            raw_pressure_events = _safe_row_get(row, "pressure_events", 0)
            pressure_events, pressure_ok = _strict_non_negative_counter(raw_pressure_events)
            if not pressure_ok and raw_pressure_events not in (0,):
                _warn_parse()
            total_pressure_events += pressure_events
            raw_healthy_events = _safe_row_get(row, "healthy_events", 0)
            healthy_events, healthy_ok = _strict_non_negative_counter(raw_healthy_events)
            if not healthy_ok and raw_healthy_events not in (0,):
                _warn_parse()
            total_healthy_events += healthy_events
            if events > busiest_events:
                busiest_events = events
                busiest_node = node_id
            actors = _safe_row_get(row, "actors", {})
            if not isinstance(actors, dict):
                _warn_parse()
                actors = {}

            for raw_actor_id, actor_row in actors.items():
                if isinstance(raw_actor_id, str):
                    actor_id = raw_actor_id.strip()
                    if not actor_id:
                        _warn_parse()
                        continue
                else:
                    _warn_parse()
                    continue

                total_actors += 1
                if not isinstance(actor_row, dict):
                    _warn_parse()
                    continue
                raw_actor_events = _safe_row_get(actor_row, "events", 0)
                actor_events, actor_events_ok = _strict_non_negative_counter(raw_actor_events)
                if not actor_events_ok and raw_actor_events not in (0,):
                    _warn_parse()
                if actor_events > busiest_actor_events:
                    busiest_actor_events = actor_events
                    busiest_actor = actor_id
        return {
            "ok": True,
            "nodes_monitored": len(actor_event_state),
            "actors_monitored": total_actors,
            "total_events": total_events,
            "total_pressure_events": total_pressure_events,
            "total_healthy_events": total_healthy_events,
            "busiest_node": busiest_node,
            "busiest_node_events": max(busiest_events, 0),
            "busiest_actor": busiest_actor,
            "busiest_actor_events": max(busiest_actor_events, 0),
            "parse_warning_count": parse_warning_count,
        }

    def _method_decorator(method: Any) -> Any:
        """Decorator for actor methods to add memory monitoring."""

        def _wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            stage = f"{stage_prefix}::{method.__name__}"
            node_id = _normalize_key(
                getattr(self, "_runtime_guard_node_id", "unknown-node"),
                fallback="unknown-node",
            )
            actor_id = _normalize_key(
                getattr(self, "_runtime_guard_actor_id", f"{self.__class__.__name__}:{id(self)}"),
                fallback="unknown-actor",
            )
            if check_on_entry:
                report = guard.check_and_log(stage=f"{stage}:entry")
                _record_actor_event(
                    node_id=node_id,
                    actor_id=actor_id,
                    method_name=method.__name__,
                    event_type="entry",
                    pressure_detected=report is not None,
                )
            try:
                result = method(self, *args, **kwargs)
            finally:
                if check_on_exit:
                    report = guard.check_and_log(stage=f"{stage}:exit")
                    _record_actor_event(
                        node_id=node_id,
                        actor_id=actor_id,
                        method_name=method.__name__,
                        event_type="exit",
                        pressure_detected=report is not None,
                    )
            return result

        return _wrapper

    def _remote_wrapper(fn: Any) -> Any:
        """Wrapper for remote functions to add memory monitoring."""

        fn_name = getattr(fn, "__name__", None)
        if not isinstance(fn_name, str) or not fn_name:
            fn_name = getattr(type(fn), "__name__", "remote_fn")
            if not isinstance(fn_name, str) or not fn_name:
                fn_name = "remote_fn"

        def _canonical_id_key(raw_key: Any) -> str:
            if not isinstance(raw_key, str):
                return ""
            return "".join(ch for ch in raw_key.lower() if ch.isalnum())

        fn_signature: inspect.Signature | None = None
        accepts_var_kwargs = False
        accepts_node_id_kwarg = False
        accepts_actor_id_kwarg = False
        has_positional_only_node_id = False
        has_positional_only_actor_id = False
        try:
            fn_signature = inspect.signature(fn)
        except Exception:
            fn_signature = None
        if fn_signature is not None:
            for pname, param in fn_signature.parameters.items():
                if param.kind is inspect.Parameter.VAR_KEYWORD:
                    accepts_var_kwargs = True
                if pname == "node_id" and param.kind in (
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                ):
                    accepts_node_id_kwarg = True
                if pname == "node_id" and param.kind is inspect.Parameter.POSITIONAL_ONLY:
                    has_positional_only_node_id = True
                if pname == "actor_id" and param.kind in (
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                ):
                    accepts_actor_id_kwarg = True
                if pname == "actor_id" and param.kind is inspect.Parameter.POSITIONAL_ONLY:
                    has_positional_only_actor_id = True

        preserve_node_id = accepts_var_kwargs or accepts_node_id_kwarg
        preserve_actor_id = accepts_var_kwargs or accepts_actor_id_kwarg

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            call_kwargs = kwargs

            node_alias_keys: list[str] = []
            actor_alias_keys: list[str] = []
            for key in kwargs:
                if key == "node_id":
                    continue
                if _canonical_id_key(key) == "nodeid":
                    node_alias_keys.append(key)
                if key == "actor_id":
                    continue
                if _canonical_id_key(key) == "actorid":
                    actor_alias_keys.append(key)

            raw_node_id: Any | None = kwargs.get("node_id")
            if raw_node_id is None and node_alias_keys and has_positional_only_node_id:
                raw_node_id = kwargs.get(node_alias_keys[0])
            raw_actor_id: Any | None = kwargs.get("actor_id")
            if raw_actor_id is None and actor_alias_keys and has_positional_only_actor_id:
                raw_actor_id = kwargs.get(actor_alias_keys[0])

            if node_alias_keys:
                if call_kwargs is kwargs:
                    call_kwargs = dict(kwargs)
                if preserve_node_id and "node_id" not in call_kwargs:
                    call_kwargs["node_id"] = call_kwargs[node_alias_keys[0]]
                for alias_key in node_alias_keys:
                    call_kwargs.pop(alias_key, None)

            if actor_alias_keys:
                if call_kwargs is kwargs:
                    call_kwargs = dict(kwargs)
                if preserve_actor_id and "actor_id" not in call_kwargs:
                    call_kwargs["actor_id"] = call_kwargs[actor_alias_keys[0]]
                for alias_key in actor_alias_keys:
                    call_kwargs.pop(alias_key, None)

            stage = f"{stage_prefix}::{fn_name}"
            if raw_node_id is None:
                raw_node_id = call_kwargs.get("node_id", "remote-node")
            if raw_actor_id is None:
                raw_actor_id = call_kwargs.get("actor_id", f"remote::{fn_name}")
            if fn_signature is not None:
                try:
                    bound = fn_signature.bind_partial(*args, **call_kwargs)
                except TypeError:
                    bound = None
                if bound is not None:
                    raw_node_id = bound.arguments.get("node_id", raw_node_id)
                    raw_actor_id = bound.arguments.get("actor_id", raw_actor_id)

            node_id = _normalize_key(raw_node_id, fallback="remote-node")
            actor_id = _normalize_key(raw_actor_id, fallback="remote-actor")
            if not preserve_node_id and "node_id" in call_kwargs:
                if call_kwargs is kwargs:
                    call_kwargs = dict(kwargs)
                call_kwargs.pop("node_id", None)
            if not preserve_actor_id and "actor_id" in call_kwargs:
                if call_kwargs is kwargs:
                    call_kwargs = dict(kwargs)
                call_kwargs.pop("actor_id", None)
            if check_on_entry:
                report = guard.check_and_log(stage=f"{stage}:entry")
                _record_actor_event(
                    node_id=node_id,
                    actor_id=actor_id,
                        method_name=fn_name,
                    event_type="entry",
                    pressure_detected=report is not None,
                )
            try:
                result = fn(*args, **call_kwargs)
            finally:
                if check_on_exit:
                    report = guard.check_and_log(stage=f"{stage}:exit")
                    _record_actor_event(
                        node_id=node_id,
                        actor_id=actor_id,
                        method_name=fn_name,
                        event_type="exit",
                        pressure_detected=report is not None,
                    )
            return result

        return _wrapper

    config["method_decorator"] = _method_decorator
    config["remote_wrapper"] = _remote_wrapper
    config["get_actor_report"] = _get_actor_report
    config["reset_actor_report"] = _reset_actor_report
    config["node_report"] = _node_report
    config["reset_node_reports"] = _reset_node_reports
    config["get_all_node_reports"] = _get_all_node_reports
    config["cluster_summary"] = _cluster_summary
    config["parse_warning_count"] = parse_warning_count

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
    actor_monitoring_api_available = False
    actor_monitoring_keys_present = False
    actor_node_telemetry_api_available = False
    actor_cluster_summary_api_available = False
    actor_cluster_hotspot_fields_present = False
    actor_cluster_health_split_fields_present = False

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

        actor_cfg = enable_ray_actor_memory_monitoring(guard)
        required_actor_keys = {
            "method_decorator",
            "remote_wrapper",
            "get_actor_report",
            "reset_actor_report",
            "node_report",
            "reset_node_reports",
            "get_all_node_reports",
            "cluster_summary",
        }
        actor_monitoring_api_available = callable(enable_ray_actor_memory_monitoring)
        actor_monitoring_keys_present = required_actor_keys.issubset(set(actor_cfg.keys()))
        actor_node_telemetry_api_available = all(
            callable(actor_cfg.get(k))
            for k in ("node_report", "reset_node_reports", "get_all_node_reports")
        )
        actor_cluster_summary_api_available = callable(actor_cfg.get("cluster_summary"))
        if actor_cluster_summary_api_available:
            try:
                summary = actor_cfg["cluster_summary"]()
                required_hotspot_fields = {
                    "busiest_node",
                    "busiest_node_events",
                    "busiest_actor",
                    "busiest_actor_events",
                }
                required_health_split_fields = {
                    "total_pressure_events",
                    "total_healthy_events",
                }
                actor_cluster_hotspot_fields_present = required_hotspot_fields.issubset(
                    set(summary.keys()) if isinstance(summary, dict) else set()
                )
                actor_cluster_health_split_fields_present = required_health_split_fields.issubset(
                    set(summary.keys()) if isinstance(summary, dict) else set()
                )
            except Exception:
                actor_cluster_hotspot_fields_present = False
                actor_cluster_health_split_fields_present = False

        return {
            "ok": True,
            "ray_available": True,
            "methods_wrapped": methods_wrapped,
            "actor_monitoring_api_available": actor_monitoring_api_available,
            "actor_monitoring_keys_present": actor_monitoring_keys_present,
            "actor_node_telemetry_api_available": actor_node_telemetry_api_available,
            "actor_cluster_summary_api_available": actor_cluster_summary_api_available,
            "actor_cluster_hotspot_fields_present": actor_cluster_hotspot_fields_present,
            "actor_cluster_health_split_fields_present": actor_cluster_health_split_fields_present,
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
            "actor_monitoring_api_available": actor_monitoring_api_available,
            "actor_monitoring_keys_present": actor_monitoring_keys_present,
            "actor_node_telemetry_api_available": actor_node_telemetry_api_available,
            "actor_cluster_summary_api_available": actor_cluster_summary_api_available,
            "actor_cluster_hotspot_fields_present": actor_cluster_hotspot_fields_present,
            "actor_cluster_health_split_fields_present": actor_cluster_health_split_fields_present,
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

    if validation.get("actor_monitoring_api_available"):
        evidence_items.append("ray_actor_monitoring_api_available")

    if validation.get("actor_monitoring_keys_present"):
        evidence_items.append("ray_actor_node_telemetry_keys_available")

    if validation.get("actor_node_telemetry_api_available"):
        evidence_items.append("ray_actor_node_telemetry_api_available")

    if validation.get("actor_cluster_summary_api_available"):
        evidence_items.append("ray_actor_cluster_summary_api_available")

    if validation.get("actor_cluster_hotspot_fields_present"):
        evidence_items.append("ray_actor_cluster_hotspot_fields_present")

    if validation.get("actor_cluster_health_split_fields_present"):
        evidence_items.append("ray_actor_cluster_health_split_fields_present")

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
    scan_budget_api_available = False
    explain_plan_available = False
    native_callback_supported = False
    native_callback_wrapped = False
    native_callback_kwargs: list[str] = []

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
        explain_method = getattr(lazyframe_cls, "explain", None)

        scan_budget_api_available = callable(install_polars_scan_budget)
        explain_plan_available = callable(explain_method)
        native_callback_supported = bool(
            getattr(collect_method, "_runtime_guard_native_callback_supported", False)
        )
        native_callback_wrapped = bool(
            getattr(collect_method, "_runtime_guard_native_callback_wrapped", False)
        )
        native_callback_raw = getattr(collect_method, "_runtime_guard_native_callback_kwargs", ())
        if isinstance(native_callback_raw, tuple):
            native_callback_kwargs = [str(x) for x in native_callback_raw]

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
            "scan_budget_api_available": scan_budget_api_available,
            "explain_plan_available": explain_plan_available,
            "native_callback_supported": native_callback_supported,
            "native_callback_wrapped": native_callback_wrapped,
            "native_callback_kwargs": native_callback_kwargs,
            "wrapped_methods": wrapped_methods,
            "errors": errors,
        }
    except Exception as exc:  # pragma: no cover
        errors.append(f"Validation error: {exc}")
        return {
            "ok": False,
            "polars_available": polars_available,
            "methods_wrapped": methods_wrapped,
            "scan_budget_api_available": scan_budget_api_available,
            "explain_plan_available": explain_plan_available,
            "native_callback_supported": native_callback_supported,
            "native_callback_wrapped": native_callback_wrapped,
            "native_callback_kwargs": native_callback_kwargs,
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

    if validation.get("scan_budget_api_available"):
        evidence_items.append("polars_scan_budget_api_available")

    if validation.get("explain_plan_available"):
        evidence_items.append("polars_explain_plan_available")

    if validation.get("native_callback_supported"):
        evidence_items.append("polars_native_callback_supported")

    if validation.get("native_callback_wrapped"):
        evidence_items.append("polars_native_callback_wrapped")

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
        out: dict[str, str] = {}

        def _add_pair(key: Any, value: Any) -> None:
            if not isinstance(key, str) or not isinstance(value, str):
                return
            key_norm = key.strip().lower()
            if not key_norm:
                return
            out[key_norm] = value

        if isinstance(headers, dict):
            for k, v in headers.items():
                _add_pair(k, v)
            return out
        try:
            for k, v in headers:
                _add_pair(k, v)
        except (TypeError, ValueError):
            return {}
        return out

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
            from pydantic import BaseModel, ConfigDict, Field, ValidationError
        except ImportError:
            pass
        else:
            class _ConfigModel(BaseModel):
                model_config = ConfigDict(extra="forbid", strict=True)

                posture: str | None = None
                min_mem_available_mb: int | None = Field(default=None, ge=0)
                max_swap_used_pct: int | None = Field(default=None, ge=0, le=100)
                critical_mem_mb: int | None = Field(default=None, ge=0)
                critical_swap_pct: int | None = Field(default=None, ge=0, le=100)
                self_inflicted_pct: int | None = Field(default=None, ge=0, le=100)

            try:
                model = _ConfigModel(**config)
            except ValidationError as exc:
                raise ValueError(f"Invalid RuntimeGuard config: {exc}") from exc
            out = model.model_dump(exclude_none=True)
            posture = out.get("posture")
            if posture is not None and posture not in _PRESETS:
                raise ValueError(f"Invalid posture {posture!r}; expected one of {sorted(_PRESETS)}")
            return out

    out: dict[str, Any] = {}

    posture = config.get("posture")
    if posture is not None:
        if not isinstance(posture, str):
            raise ValueError("posture must be a string")
        posture_norm = posture.strip().lower()
        if posture_norm not in _PRESETS:
            raise ValueError(f"Invalid posture {posture!r}; expected one of {sorted(_PRESETS)}")
        out["posture"] = posture_norm

    def _coerce_int(name: str, *, minimum: int = 0, maximum: int | None = None) -> None:
        if name not in config:
            return
        value = config[name]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")
        ivalue = value
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

    def _as_bool(raw: str | None, default: bool) -> tuple[bool, bool]:
        if raw is None:
            return default, False
        value = raw.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True, False
        if value in {"0", "false", "no", "off"}:
            return False, False
        return default, True

    def _as_positive_int(raw: str | None) -> tuple[int | None, bool]:
        if raw is None:
            return None, False
        value = raw.strip()
        if value == "":
            return None, False
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None, True
        if parsed <= 0:
            return None, True
        return parsed, False

    def _as_positive_float(raw: str | None) -> tuple[float | None, bool]:
        if raw is None:
            return None, False
        value = raw.strip()
        if value == "":
            return None, False
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None, True
        if parsed <= 0:
            return None, True
        return parsed, False

    invalid_policy_fields: list[str] = []

    enabled, enabled_invalid = _as_bool(_env("SIGNAL_RECOVERY_ENABLE"), True)
    if enabled_invalid:
        enabled = False
        invalid_policy_fields.append("SIGNAL_RECOVERY_ENABLE")

    auto_intervene, auto_intervene_invalid = _as_bool(_env("SIGNAL_RECOVERY_AUTO_INTERVENE"), False)
    if auto_intervene_invalid:
        auto_intervene = False
        invalid_policy_fields.append("SIGNAL_RECOVERY_AUTO_INTERVENE")

    intervene_on = (_env("SIGNAL_RECOVERY_INTERVENE_ON", "critical") or "critical").strip().lower()
    if intervene_on not in {"critical", "any"}:
        intervene_on = "critical"
        invalid_policy_fields.append("SIGNAL_RECOVERY_INTERVENE_ON")

    chain_previous, chain_previous_invalid = _as_bool(_env("SIGNAL_RECOVERY_CHAIN_PREVIOUS"), False)
    if chain_previous_invalid:
        chain_previous = False
        invalid_policy_fields.append("SIGNAL_RECOVERY_CHAIN_PREVIOUS")

    stage_prefix = (_env("SIGNAL_RECOVERY_STAGE_PREFIX", "signal") or "signal").strip()
    if stage_prefix == "":
        stage_prefix = "signal"
        invalid_policy_fields.append("SIGNAL_RECOVERY_STAGE_PREFIX")

    kill_hogs_above_mb, kill_hogs_invalid = _as_positive_int(_env("SIGNAL_RECOVERY_KILL_HOGS_MB"))
    if kill_hogs_invalid:
        invalid_policy_fields.append("SIGNAL_RECOVERY_KILL_HOGS_MB")

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

    hash_algo_env = (_env("SIGNAL_RECOVERY_HASH_ALGO", "sha256") or "sha256").strip().lower()
    if hash_algo_env not in _FIPS_HASH_ALGOS:
        hash_algo_env = "sha256"
        invalid_policy_fields.append("SIGNAL_RECOVERY_HASH_ALGO")

    audit_dedup_ttl_s, ttl_invalid = _as_positive_float(_env("SIGNAL_RECOVERY_AUDIT_DEDUP_TTL_S"))
    if ttl_invalid:
        invalid_policy_fields.append("SIGNAL_RECOVERY_AUDIT_DEDUP_TTL_S")

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
        "invalid_policy_fields": invalid_policy_fields,
    }


def install_signal_recovery_from_policy(
    guard: "RuntimeGuard",
    *,
    env_prefix: str = "RUNTIME_GUARD",
    module: Any | None = None,
) -> Callable[[], None]:
    """Install signal recovery using environment-resolved policy settings."""
    policy = resolve_signal_recovery_policy(env_prefix=env_prefix, module=module)
    enabled_value = policy.get("enabled", True)
    if not isinstance(enabled_value, bool):
        enabled_value = False
    if not enabled_value:
        return lambda: None

    auto_intervene = policy.get("auto_intervene", False)
    if not isinstance(auto_intervene, bool):
        auto_intervene = False

    chain_previous = policy.get("chain_previous", False)
    if not isinstance(chain_previous, bool):
        chain_previous = False

    intervene_on = policy.get("intervene_on", "critical")
    if not isinstance(intervene_on, str):
        intervene_on = "critical"
    intervene_on = intervene_on.strip().lower()
    if intervene_on not in {"critical", "any"}:
        intervene_on = "critical"

    stage_prefix = policy.get("stage_prefix", "signal")
    if not isinstance(stage_prefix, str):
        stage_prefix = "signal"
    stage_prefix = stage_prefix.strip() or "signal"

    hash_algo = policy.get("hash_algo", "sha256")
    if not isinstance(hash_algo, str):
        hash_algo = "sha256"
    hash_algo = hash_algo.strip().lower()
    if hash_algo not in _FIPS_HASH_ALGOS:
        hash_algo = "sha256"

    ttl_s_raw = policy.get("audit_dedup_ttl_s")
    ttl_s: float | None = None
    if isinstance(ttl_s_raw, (int, float)):
        ttl_value = float(ttl_s_raw)
        if ttl_value > 0:
            ttl_s = ttl_value

    signals_raw = policy.get("signals_to_handle", [])
    signals_to_handle: list[int] = []
    if isinstance(signals_raw, list):
        for item in signals_raw:
            if isinstance(item, int) and item > 0:
                signals_to_handle.append(item)

    kill_hogs_above_mb = policy.get("kill_hogs_above_mb")
    if not isinstance(kill_hogs_above_mb, int) or kill_hogs_above_mb <= 0:
        kill_hogs_above_mb = None

    audit_log_path = policy.get("audit_log_path")
    if not isinstance(audit_log_path, str):
        audit_log_path = None
    audit_log_path = audit_log_path.strip() or None

    audit_deduplicator: FipsDeduplicator | None = None
    if audit_log_path:
        if ttl_s is not None:
            audit_deduplicator = FipsDeduplicator(
                hash_algo=hash_algo,
                ttl_s=ttl_s,
            )

    return attach_signal_recovery(
        guard,
        signals_to_handle=signals_to_handle,
        stage_prefix=stage_prefix,
        auto_intervene=auto_intervene,
        intervene_on=intervene_on,
        kill_hogs_above_mb=kill_hogs_above_mb,
        chain_previous=chain_previous,
        audit_log_path=audit_log_path,
        hash_algo=hash_algo,
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
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")
    if not isinstance(event, dict):
        raise ValueError("event must be a dictionary")
    if type(event) is not dict:
        raise ValueError("event must be a plain dictionary")

    expanded = os.path.expanduser(path)
    try:
        os.makedirs(os.path.dirname(expanded) or ".", exist_ok=True)
    except OSError as exc:
        raise ValueError("could not create audit log directory") from exc

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
                line_no = 0
                for line in fh:
                    line_no += 1
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception as exc:
                        raise ValueError(
                            f"Audit log contains invalid JSON row at line {line_no}"
                        ) from exc

                    if not isinstance(row, dict):
                        raise ValueError(
                            f"Audit log contains non-object row at line {line_no}"
                        )

                    row_algo_raw = row.get("hash_algo", algo)
                    if not isinstance(row_algo_raw, str):
                        raise ValueError(
                            "Audit log contains invalid hash_algo type; "
                            f"line {line_no} expected string"
                        )
                    if row_algo_raw.strip().lower() != algo:
                        raise ValueError(
                            "Audit log contains mixed hash algorithms; "
                            f"found {row.get('hash_algo')} expected {algo}"
                        )

                    row_hash_raw = row.get("hash", "")
                    if not isinstance(row_hash_raw, str):
                        raise ValueError(
                            "Audit log contains invalid hash type; "
                            f"line {line_no} expected string"
                        )
                    prev_hash = row_hash_raw
        except OSError as exc:
            raise ValueError("could not read audit log") from exc
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

    try:
        with open(expanded, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise ValueError("could not write audit log") from exc

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

    try:
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

                if not isinstance(row, dict):
                    return {"ok": False, "reason": "invalid-row-type", "line": line_no}

                algo_raw = row.get("hash_algo", "sha256")
                if not isinstance(algo_raw, str):
                    return {"ok": False, "reason": "invalid-hash-algo-type", "line": line_no}
                algo = algo_raw.strip().lower()
                if algo not in _FIPS_HASH_ALGOS:
                    return {"ok": False, "reason": "unsupported-algo", "line": line_no}

                row_prev_raw = row.get("prev_hash", "")
                if not isinstance(row_prev_raw, str):
                    return {"ok": False, "reason": "invalid-prev-hash-type", "line": line_no}
                row_prev = row_prev_raw
                if row_prev != prev_hash:
                    return {"ok": False, "reason": "prev-hash-mismatch", "line": line_no}

                ts_raw = row.get("ts", 0)
                if not isinstance(ts_raw, int) or isinstance(ts_raw, bool):
                    return {"ok": False, "reason": "invalid-ts-type", "line": line_no}
                ts = ts_raw
                event = row.get("event", {})
                event_payload = json.dumps(event, sort_keys=True, separators=(",", ":"))

                expected_event_hash = fips_event_hash(event_payload, hash_algo=algo)
                event_hash_raw = row.get("event_hash", "")
                if not isinstance(event_hash_raw, str):
                    return {"ok": False, "reason": "invalid-event-hash-type", "line": line_no}
                if event_hash_raw != expected_event_hash:
                    return {"ok": False, "reason": "event-hash-mismatch", "line": line_no}

                expected_chain = hashlib.new(
                    algo, f"{prev_hash}\n{ts}\n{event_payload}".encode("utf-8")
                ).hexdigest()
                chain_hash_raw = row.get("hash", "")
                if not isinstance(chain_hash_raw, str):
                    return {"ok": False, "reason": "invalid-hash-type", "line": line_no}
                if chain_hash_raw != expected_chain:
                    return {"ok": False, "reason": "chain-hash-mismatch", "line": line_no}

                prev_hash = expected_chain
    except OSError:
        return {"ok": False, "reason": "read-error", "line": 0}

    return {"ok": True, "line": line_no, "records": line_no, "last_hash": prev_hash}


def soc2_required_controls() -> dict[str, str]:
    """Return the default SOC2 control baseline tracked by runtime-guard."""

    return dict(_SOC2_RUNTIME_GUARD_CONTROLS)


def _soc2_normalize_control_state(
    control_state: Any,
) -> tuple[dict[str, bool], list[str]]:
    if not isinstance(control_state, dict):
        return {}, ["<root>"]

    normalized: dict[str, bool] = {}
    invalid_fields: list[str] = []

    for key, value in control_state.items():
        if not isinstance(key, str) or not key.strip():
            invalid_fields.append("<non-string-control-id>")
            continue
        control_id = key.strip()
        if isinstance(value, bool):
            normalized[control_id] = value
            continue
        normalized[control_id] = False
        invalid_fields.append(control_id)

    return normalized, sorted(set(invalid_fields))


def _soc2_normalize_evidence_items(raw: Any) -> tuple[set[str], bool]:
    if not isinstance(raw, (list, tuple, set)):
        return set(), False

    normalized: set[str] = set()
    valid = True
    for item in raw:
        if not isinstance(item, str):
            valid = False
            continue
        text = item.strip()
        if text:
            normalized.add(text)
    return normalized, valid


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
    normalized_control_state, invalid_control_state_fields = _soc2_normalize_control_state(control_state)

    items: list[tuple[str, bool]] = []
    for key, value in normalized_control_state.items():
        items.append((str(key), value))

    provided: dict[str, bool] = {key: state for key, state in items}
    missing_required = [
        control_id
        for control_id in sorted(required.keys())
        if not provided.get(control_id, False)
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
        "invalid_control_state_fields": invalid_control_state_fields,
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
    normalized_control_state, invalid_control_state_fields = _soc2_normalize_control_state(control_state)
    gap = soc2_gap_assessment(normalized_control_state, required_controls=required)
    expected = (
        dict(evidence_requirements)
        if evidence_requirements is not None
        else soc2_evidence_requirements(required_controls=required)
    )
    evidence_lookup: dict[str, list[str] | tuple[str, ...] | set[str]] = {}
    if evidence_state is None:
        evidence_lookup = {}
    elif isinstance(evidence_state, dict):
        evidence_lookup = evidence_state
    else:
        evidence_lookup = {}

    missing_evidence_by_control: dict[str, list[str]] = {}
    invalid_evidence_fields: list[str] = []
    if evidence_state is not None and not isinstance(evidence_state, dict):
        invalid_evidence_fields.append("<root>")
    provided_evidence_count = 0
    expected_evidence_count = 0

    for control_id in sorted(required.keys()):
        if not normalized_control_state.get(control_id, False):
            continue

        required_items = list(expected.get(control_id, []))
        expected_evidence_count += len(required_items)
        provided_items, evidence_ok = _soc2_normalize_evidence_items(
            evidence_lookup.get(control_id, [])
        )
        if not evidence_ok:
            invalid_evidence_fields.append(control_id)
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
        "invalid_control_state_fields": sorted(set(invalid_control_state_fields)),
        "invalid_evidence_fields": sorted(set(invalid_evidence_fields)),
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

    def _stage(value: Any) -> tuple[str, bool]:
        if not isinstance(value, str):
            return "unknown", False
        raw = value.strip().lower()
        if raw == "":
            raw = "discover"
        return stage_aliases.get(raw, raw), True

    def _evidence_items(value: Any) -> tuple[list[str], bool]:
        if value is None:
            return [], True
        if not isinstance(value, (list, tuple, set)):
            return [], False
        out: list[str] = []
        valid = True
        for item in value:
            if not isinstance(item, str):
                valid = False
                continue
            text = item.strip()
            if text:
                out.append(text)
        return out, valid

    team_count = len(team_records)
    stage_counts: dict[str, int] = {name: 0 for name in stage_order}
    stage_counts["unknown"] = 0
    missing_evidence_teams: list[str] = []
    invalid_stage_teams: list[str] = []
    invalid_evidence_teams: list[str] = []
    malformed_record_indexes: list[int] = []

    reached_success = 0
    for idx, row in enumerate(team_records):
        if not isinstance(row, dict):
            malformed_record_indexes.append(idx)
            continue

        team_raw = row.get("team") if row.get("team") is not None else row.get("name")
        team_name = str(team_raw).strip() if team_raw is not None else ""
        if team_name == "":
            team_name = f"unknown-team-{idx + 1}"

        stage, stage_ok = _stage(row.get("stage"))
        if not stage_ok:
            invalid_stage_teams.append(team_name)

        if stage in stage_counts:
            stage_counts[stage] += 1
        else:
            stage_counts["unknown"] += 1

        if stage_index.get(stage, -1) >= stage_index.get(success_norm, len(stage_order)):
            reached_success += 1

        evidence_items, evidence_ok = _evidence_items(row.get("evidence", []))
        if not evidence_ok:
            invalid_evidence_teams.append(team_name)
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
        "malformed_record_indexes": sorted(malformed_record_indexes),
        "invalid_stage_teams": sorted(invalid_stage_teams),
        "invalid_evidence_teams": sorted(invalid_evidence_teams),
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
    metadata_value: dict[str, Any] | None = None

    if not isinstance(stage, str):
        raise ValueError("stage must be a string")
    stage_value = stage.strip()
    if not stage_value:
        raise ValueError("stage must be a non-empty string")
    if worker_id is not None and not isinstance(worker_id, str):
        raise ValueError("worker_id must be a string when provided")
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be a dictionary when provided")
    if metadata is not None and type(metadata) is not dict:
        raise ValueError("metadata must be a plain dictionary when provided")
    if metadata is not None:
        metadata_value = dict(metadata)
        for metadata_key in metadata_value:
            if not isinstance(metadata_key, str) or not metadata_key.strip():
                raise ValueError("metadata keys must be non-empty strings")
        try:
            json.dumps(metadata_value, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "metadata must be JSON-serializable with finite numbers"
            ) from exc

    report = guard.check(stage=stage_value)
    snap = report.snapshot if report is not None else _read_snapshot()
    severity = "none"
    if report is not None:
        severity = "critical" if report.is_critical else "warning"

    worker_id_value = worker_id.strip() if isinstance(worker_id, str) else ""
    if not worker_id_value:
        worker_id_value = str(os.getpid())

    out: dict[str, Any] = {
        "ts": int(time.time()),
        "pid": os.getpid(),
        "worker_id": worker_id_value,
        "stage": stage_value,
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
    if metadata_value is not None:
        out["metadata"] = metadata_value
    return out


def aggregate_worker_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate worker reports from a process pool or job queue."""

    if not isinstance(reports, list):
        raise ValueError("reports must be a list")

    def _worker_identity(row: dict[str, Any], index: int) -> tuple[str, bool]:
        if "worker_id" not in row:
            return f"unknown-worker-{index + 1}", True
        worker_id = row.get("worker_id")
        if isinstance(worker_id, str):
            text = worker_id.strip()
            if text:
                return text, True
        return f"unknown-worker-{index + 1}", False

    def _strict_non_negative_int(value: Any) -> tuple[int, bool]:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value, True
        return 0, False

    total = len(reports)
    pressured: list[dict[str, Any]] = []
    critical: list[dict[str, Any]] = []
    invalid_pressure_workers: list[str] = []
    invalid_severity_workers: list[str] = []
    invalid_missing_mem_workers: list[str] = []
    invalid_swap_workers: list[str] = []
    invalid_worker_id_workers: list[str] = []
    malformed_worker_rows: list[str] = []
    parse_warning_count = 0

    typed_rows: list[dict[str, Any]] = []
    typed_rows_with_index: list[tuple[int, dict[str, Any]]] = []
    for index, row in enumerate(reports):
        if type(row) is dict:
            typed_rows.append(row)
            typed_rows_with_index.append((index, row))
            continue
        malformed_worker_rows.append(f"unknown-worker-{index + 1}")
        parse_warning_count += 1

    worker_context: list[tuple[dict[str, Any], str]] = []
    for report_index, row in typed_rows_with_index:
        worker_name, worker_id_ok = _worker_identity(row, report_index)
        worker_context.append((row, worker_name))
        if not worker_id_ok:
            invalid_worker_id_workers.append(worker_name)
            parse_warning_count += 1

    for row, worker_name in worker_context:

        pressure_raw = row.get("pressure", False)
        if isinstance(pressure_raw, bool):
            pressure = pressure_raw
        else:
            pressure = False
            invalid_pressure_workers.append(worker_name)
            parse_warning_count += 1

        severity_raw = row.get("severity", "")
        if isinstance(severity_raw, str):
            severity = severity_raw.strip().lower()
            if severity not in {"none", "warning", "critical"}:
                invalid_severity_workers.append(worker_name)
                severity = ""
                parse_warning_count += 1
        else:
            severity = ""
            invalid_severity_workers.append(worker_name)
            parse_warning_count += 1

        if pressure:
            pressured.append(row)
            if severity == "critical":
                critical.append(row)

    max_missing = 0
    max_swap = 0
    for r, worker_name in worker_context:
        missing_mem_mb, missing_mem_ok = _strict_non_negative_int(r.get("missing_mem_mb", 0))
        if missing_mem_ok:
            max_missing = max(max_missing, missing_mem_mb)
        else:
            invalid_missing_mem_workers.append(worker_name)
            parse_warning_count += 1

        swap_used_pct, swap_used_pct_ok = _strict_non_negative_int(r.get("swap_used_pct", 0))
        if swap_used_pct_ok:
            max_swap = max(max_swap, swap_used_pct)
        else:
            invalid_swap_workers.append(worker_name)
            parse_warning_count += 1

    worst_severity = "none"
    if critical:
        worst_severity = "critical"
    elif pressured:
        worst_severity = "warning"

    return {
        "total_workers": total,
        "typed_workers": len(typed_rows),
        "pressured_workers": len(pressured),
        "critical_workers": len(critical),
        "any_pressure": bool(pressured),
        "worst_severity": worst_severity,
        "max_missing_mem_mb": max_missing,
        "max_swap_used_pct": max_swap,
        "parse_warning_count": parse_warning_count,
        "malformed_worker_rows": sorted(set(malformed_worker_rows)),
        "invalid_pressure_workers": sorted(set(invalid_pressure_workers)),
        "invalid_severity_workers": sorted(set(invalid_severity_workers)),
        "invalid_missing_mem_workers": sorted(set(invalid_missing_mem_workers)),
        "invalid_swap_workers": sorted(set(invalid_swap_workers)),
        "invalid_worker_id_workers": sorted(set(invalid_worker_id_workers)),
        "workers": typed_rows,
    }


def append_worker_report_jsonl(path: str, report: dict[str, Any]) -> dict[str, Any]:
    """Append a single worker report to a JSONL transport file.

    Creates parent directories when needed and writes one compact JSON object
    per line. Returns the written report dict.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")
    if not isinstance(report, dict):
        raise ValueError("report must be a dictionary")
    if type(report) is not dict:
        raise ValueError("report must be a plain dictionary")

    expanded = os.path.expanduser(path)
    parent = os.path.dirname(expanded)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise ValueError("could not create report directory") from exc

    row = dict(report)
    try:
        payload = json.dumps(row, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("report must be JSON-serializable with finite numbers") from exc

    try:
        with open(expanded, "a", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    except OSError as exc:
        raise ValueError("could not write report jsonl") from exc
    return row


def _load_worker_reports_jsonl_with_stats(path: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Load worker reports from JSONL and return rows with parse statistics."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")

    def _contains_non_finite_number(value: Any) -> bool:
        if isinstance(value, float):
            return math.isnan(value) or math.isinf(value)
        if isinstance(value, dict):
            return any(_contains_non_finite_number(v) for v in value.values())
        if isinstance(value, list):
            return any(_contains_non_finite_number(v) for v in value)
        return False

    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        return [], {
            "jsonl_total_lines": 0,
            "jsonl_loaded_rows": 0,
            "jsonl_empty_lines": 0,
            "jsonl_invalid_json_lines": 0,
            "jsonl_non_object_lines": 0,
            "jsonl_non_finite_rows": 0,
            "jsonl_parse_warning_count": 0,
        }

    rows: list[dict[str, Any]] = []
    stats = {
        "jsonl_total_lines": 0,
        "jsonl_loaded_rows": 0,
        "jsonl_empty_lines": 0,
        "jsonl_invalid_json_lines": 0,
        "jsonl_non_object_lines": 0,
        "jsonl_non_finite_rows": 0,
        "jsonl_parse_warning_count": 0,
    }
    try:
        with open(expanded, encoding="utf-8") as fh:
            for raw in fh:
                stats["jsonl_total_lines"] += 1
                line = raw.strip()
                if line == "":
                    stats["jsonl_empty_lines"] += 1
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    stats["jsonl_invalid_json_lines"] += 1
                    stats["jsonl_parse_warning_count"] += 1
                    continue
                if isinstance(row, dict):
                    if _contains_non_finite_number(row):
                        stats["jsonl_non_finite_rows"] += 1
                        stats["jsonl_parse_warning_count"] += 1
                        continue
                    rows.append(dict(row))
                    stats["jsonl_loaded_rows"] += 1
                else:
                    stats["jsonl_non_object_lines"] += 1
                    stats["jsonl_parse_warning_count"] += 1
    except OSError as exc:
        raise ValueError("could not read report jsonl") from exc
    return rows, stats


def load_worker_reports_jsonl(path: str) -> list[dict[str, Any]]:
    """Load worker reports from a JSONL transport file.

    Invalid JSON or non-object lines are skipped so one bad producer write
    does not block whole-pool aggregation.
    """
    rows, _ = _load_worker_reports_jsonl_with_stats(path)
    return rows


def aggregate_worker_reports_jsonl(path: str) -> dict[str, Any]:
    """Aggregate worker reports directly from a JSONL transport file."""
    rows, stats = _load_worker_reports_jsonl_with_stats(path)
    out = aggregate_worker_reports(rows)
    out.update(stats)
    out["parse_warning_count"] = (
        out.get("parse_warning_count", 0) + stats.get("jsonl_parse_warning_count", 0)
    )
    return out


# ---------------------------------------------------------------------------
# Convenience factory for pytest conftest.py integration
# ---------------------------------------------------------------------------


def make_pytest_guard(
    *,
    repo_name: str,
    env_prefix: str | None = None,
    hints: list[str] | None = None,
    cooldown_s: float = 30.0,
    posture: str | None = None,
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
    posture:
        Optional threshold preset (``tight|relaxed|ci``) applied through
        ``<ENV_PREFIX>_POSTURE`` when that env var is not already set.
    """
    derived_prefix = (
        env_prefix
        if env_prefix is not None
        else repo_name.upper().replace(" ", "_").replace("-", "_") + "_GUARD"
    )

    if posture is not None:
        posture_cfg = validate_runtime_guard_config(
            {"posture": posture},
            use_pydantic=False,
        )
        env_key = f"{derived_prefix}_POSTURE"
        if not os.environ.get(env_key, "").strip():
            os.environ[env_key] = str(posture_cfg["posture"])

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
    if not isinstance(memory_gb, int) or isinstance(memory_gb, bool) or memory_gb < 1:
        raise ValueError("memory_gb must be a positive integer")
    if swap_gb is not None and (
        not isinstance(swap_gb, int) or isinstance(swap_gb, bool) or swap_gb < 0
    ):
        raise ValueError("swap_gb must be a non-negative integer when provided")
    if processors is not None and (
        not isinstance(processors, int) or isinstance(processors, bool) or processors < 1
    ):
        raise ValueError("processors must be a positive integer when provided")
    if output_path is not None and not isinstance(output_path, str):
        raise ValueError("output_path must be a string when provided")
    if not isinstance(dry_run, bool):
        raise ValueError("dry_run must be a boolean")

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
    scan_count_fn: Callable[[Any], int] | None = None,
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
    scan_count_fn:
        Optional ``(lazy_frame) -> int`` override used to derive scan count.
        When omitted, RuntimeGuard first checks ``_scan_count`` then falls
        back to parsing ``lazy_frame.explain()`` for native ``SCAN`` nodes.
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

        sc = 0
        if scan_count_fn is not None:
            try:
                sc = int(scan_count_fn(frame))
            except Exception:
                sc = 0
        else:
            scan_count = getattr(frame, "_scan_count", None)
            if scan_count is not None:
                try:
                    sc = int(scan_count)
                except Exception:
                    sc = 0
            elif callable(getattr(frame, "explain", None)):
                # Native Polars fallback: count SCAN nodes from explain output.
                try:
                    explain_out = str(frame.explain())
                    sc = sum(1 for line in explain_out.splitlines() if "SCAN" in line.upper())
                except Exception:
                    sc = 0

        if sc > 0:
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

    def _otel_check_and_log(stage: str = "") -> Any:
        if not _otel_available or _tracer is None:
            return original_check_and_log(stage=stage)

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
                return original_check_and_log(stage=stage)
        except Exception:
            # If OTEL span creation fails, always fall back to original check.
            return original_check_and_log(stage=stage)

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


def _read_linux_memory_psi() -> dict[str, Any]:
    """Read Linux memory PSI metrics from /proc/pressure/memory when present."""
    data: dict[str, Any] = {
        "psi_some_avg10": 0.0,
        "psi_some_avg60": 0.0,
        "psi_full_avg10": 0.0,
        "psi_full_avg60": 0.0,
        "psi_parse_error": False,
    }

    def _parse_avg(kv: dict[str, str], key: str) -> float:
        raw = kv.get(key)
        if not isinstance(raw, str) or not raw.strip():
            data["psi_parse_error"] = True
            return 0.0
        try:
            value = float(raw)
        except ValueError:
            data["psi_parse_error"] = True
            return 0.0
        if math.isnan(value) or math.isinf(value) or value < 0:
            data["psi_parse_error"] = True
            return 0.0
        return value

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
                        data["psi_parse_error"] = True
                        continue
                    k, v = token.split("=", 1)
                    kv[k] = v
                if scope == "some":
                    data["psi_some_avg10"] = _parse_avg(kv, "avg10")
                    data["psi_some_avg60"] = _parse_avg(kv, "avg60")
                elif scope == "full":
                    data["psi_full_avg10"] = _parse_avg(kv, "avg10")
                    data["psi_full_avg60"] = _parse_avg(kv, "avg60")
                elif scope:
                    data["psi_parse_error"] = True
    except OSError:
        return data
    return data


def _derive_guest_pressure_offender_hints(metrics: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Derive actionable causes/prevention hints from top guest RSS offenders."""
    causes: list[str] = []
    prevention: list[str] = []

    def _metric_int(name: str, default: int = 0) -> int:
        raw = metrics.get(name, default)
        if isinstance(raw, int) and not isinstance(raw, bool):
            return raw
        return default

    def _metric_float(name: str, default: float = 0.0) -> float:
        raw = metrics.get(name, default)
        if isinstance(raw, bool):
            return default
        if isinstance(raw, (int, float)):
            return float(raw)
        return default

    rows_raw = metrics.get("guest_top_memory_processes", [])
    if not isinstance(rows_raw, list):
        return causes, prevention

    rows: list[dict[str, Any]] = []
    for item in rows_raw:
        if isinstance(item, dict):
            rows.append(item)

    if not rows:
        return causes, prevention

    pressure_like = (
        _metric_int("guest_mem_available_mb", 0) < 2048
        or _metric_int("guest_swap_used_pct", 0) >= 70
        or _metric_float("psi_full_avg10", 0.0) >= 5
        or _metric_float("psi_some_avg10", 0.0) >= 10
    )
    if not pressure_like:
        return causes, prevention

    top_rows = rows[:3]
    offenders = []
    for row in top_rows:
        pid_raw = row.get("pid", 0)
        rss_raw = row.get("rss_mb", 0)
        if (
            not isinstance(pid_raw, int)
            or isinstance(pid_raw, bool)
            or pid_raw <= 0
            or not isinstance(rss_raw, int)
            or isinstance(rss_raw, bool)
            or rss_raw < 0
        ):
            continue
        pid = pid_raw
        rss_mb = rss_raw
        cmd_raw = row.get("command", "")
        if not isinstance(cmd_raw, str):
            continue
        cmd = cmd_raw.strip()
        if not cmd:
            continue
        if len(cmd) > 96:
            cmd = cmd[:96] + "..."
        offenders.append(f"pid={pid} rss={rss_mb}MB cmd={cmd}")

    if offenders:
        causes.append("top guest RSS offenders are consuming significant memory: " + "; ".join(offenders))

    commands = "\n".join(
        row.get("command", "").lower()
        for row in top_rows
        if isinstance(row.get("command", ""), str)
    )
    if "vscode-server" in commands or "extensionhost" in commands:
        prevention.append("close idle VS Code windows/workspaces to reduce extension host memory pressure")
    if "pylance" in commands or "server.bundle.js" in commands:
        prevention.append("reduce Pylance indexing scope (exclude large folders/workspaces) during heavy runs")
    if "tsserver" in commands or "typescript" in commands:
        prevention.append("restart idle TypeScript servers or reduce concurrent JS/TS workspaces during memory spikes")
    if "python" in commands:
        prevention.append("pause non-essential long-running Python jobs while memory pressure is elevated")

    return causes, prevention


def _derive_vscode_extension_pressure_hints(
    metrics: dict[str, Any],
) -> tuple[int, list[str], list[str]]:
    """Derive proactive hints for VS Code extension-host memory concentration.

    Returns (score_delta, causes, prevention_actions).
    """
    ext_rows_raw = metrics.get("guest_vscode_extension_rss", [])
    ext_rows: list[dict[str, Any]] = []
    if isinstance(ext_rows_raw, list):
        for item in ext_rows_raw:
            if isinstance(item, dict):
                ext_rows.append(item)

    def _row_rss_mb(row: dict[str, Any]) -> int | None:
        value = row.get("rss_mb", 0)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    if not ext_rows:
        return 0, [], []

    total_vscode_rss_mb = 0
    for row in ext_rows:
        rss_mb = _row_rss_mb(row)
        if rss_mb is None:
            continue
        total_vscode_rss_mb += rss_mb

    score_delta = 0
    if total_vscode_rss_mb >= 5000:
        score_delta = 2
    elif total_vscode_rss_mb >= 3000:
        score_delta = 1

    top_extension_labels: list[str] = []
    for row in ext_rows[:3]:
        name_raw = row.get("extension", "")
        name = name_raw.strip() if isinstance(name_raw, str) else ""
        if not name:
            continue
        rss_mb = _row_rss_mb(row)
        if rss_mb is None:
            continue
        top_extension_labels.append(f"{name} ({rss_mb} MB)")

    causes = [
        "VS Code extension hosts account for elevated guest RSS "
        f"(~{total_vscode_rss_mb} MB across top processes)"
    ]
    if top_extension_labels:
        causes.append("top extension memory consumers: " + ", ".join(top_extension_labels))

    prevention = [
        "reload VS Code window and disable high-RSS extensions not needed for the current task",
        "split large multi-root workspaces to reduce concurrent language-server indexing load",
    ]
    if top_extension_labels:
        top_extension_names: list[str] = []
        for row in ext_rows[:3]:
            ext_name = row.get("extension", "")
            if isinstance(ext_name, str) and ext_name:
                top_extension_names.append(ext_name)
        prevention.append(
            "review settings and indexing scope for top extensions: "
            + ", ".join(top_extension_names)
        )

    return score_delta, causes, prevention


def _summarize_vscode_extension_rss(rows_raw: Any, limit: int = 5) -> list[dict[str, Any]]:
    """Summarize VS Code extension RSS from guest top-process rows."""
    if not isinstance(rows_raw, list):
        return []
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        limit = 5

    extension_map: dict[str, dict[str, Any]] = {}

    for item in rows_raw:
        if not isinstance(item, dict):
            continue
        cmd_raw = item.get("command", "")
        if not isinstance(cmd_raw, str):
            continue
        cmd = cmd_raw
        cmd_lower = cmd.lower()
        if ".vscode-server" not in cmd_lower:
            continue

        ext_name: str | None = None
        match = re.search(r"/\.vscode-server/extensions/([^/\s]+)", cmd)
        if match:
            matched_name = match.group(1)
            ext_name = matched_name.strip() if isinstance(matched_name, str) else ""
            if ext_name:
                ext_name = re.sub(r"-(\d+(?:\.\d+){1,})$", "", ext_name)
        if not ext_name:
            if "extensionhost" in cmd_lower:
                ext_name = "vscode.extension-host"
            else:
                continue

        rss_raw = item.get("rss_mb", 0)
        pid_raw = item.get("pid", 0)
        if (
            not isinstance(rss_raw, int)
            or isinstance(rss_raw, bool)
            or rss_raw < 0
            or not isinstance(pid_raw, int)
            or isinstance(pid_raw, bool)
            or pid_raw <= 0
        ):
            continue
        rss_mb = rss_raw
        pid = pid_raw

        row = extension_map.get(ext_name)
        if row is None:
            row = {
                "extension": ext_name,
                "rss_mb": 0,
                "process_count": 0,
                "pids": [],
            }
            extension_map[ext_name] = row

        row["rss_mb"] = row["rss_mb"] + rss_mb
        row["process_count"] = row["process_count"] + 1
        row_pids = row.get("pids")
        if isinstance(row_pids, list):
            row_pids.append(pid)

    rows = list(extension_map.values())
    rows.sort(key=lambda r: r["rss_mb"] if isinstance(r.get("rss_mb"), int) else 0, reverse=True)
    return rows[:limit]


def _classify_wsl_crash_risk(metrics: dict[str, Any]) -> tuple[str, int, list[str], list[str]]:
    """Return (risk_level, score, likely_causes, prevention_actions)."""

    def _metric_int(name: str, default: int = 0) -> int:
        raw = metrics.get(name, default)
        if isinstance(raw, int) and not isinstance(raw, bool):
            return raw
        return default

    def _metric_float(name: str, default: float = 0.0) -> float:
        raw = metrics.get(name, default)
        if isinstance(raw, bool):
            return default
        if isinstance(raw, (int, float)):
            return float(raw)
        return default

    def _metric_bool(name: str, default: bool = False) -> bool:
        raw = metrics.get(name, default)
        if isinstance(raw, bool):
            return raw
        return default

    score = 0
    causes: list[str] = []
    prevention: list[str] = []

    guest_mem_available_mb = _metric_int("guest_mem_available_mb", 0)
    guest_swap_used_pct = _metric_int("guest_swap_used_pct", 0)
    psi_some_avg10 = _metric_float("psi_some_avg10", 0.0)
    psi_full_avg10 = _metric_float("psi_full_avg10", 0.0)
    psi_parse_error = _metric_bool("psi_parse_error", False)
    host_vm_used_pct = _metric_int("host_vm_used_pct", 0)
    host_error_event_count = _metric_int("host_error_event_count", 0)
    host_high_relevance_event_count = _metric_int("host_high_relevance_event_count", 0)
    running_distro_count = _metric_int("wsl_running_distro_count", 0)
    docker_desktop_running = _metric_bool("docker_desktop_running", False)

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
    if psi_parse_error:
        score += 2
        causes.append("guest memory PSI data could not be parsed reliably")
        prevention.append("treat missing/malformed PSI as high risk until pressure telemetry is healthy")
    if running_distro_count > 1 and (guest_mem_available_mb < 2048 or psi_full_avg10 >= 5 or guest_swap_used_pct >= 70):
        score += 1
        causes.append("multiple WSL distros are running concurrently during guest memory pressure")
        prevention.append("stop idle WSL distros before heavy IDE, training, or test workloads")
    if docker_desktop_running and (guest_mem_available_mb < 2048 or psi_full_avg10 >= 5 or guest_swap_used_pct >= 70):
        score += 1
        causes.append("docker-desktop is running alongside pressured WSL workloads")
        prevention.append("stop docker-desktop when it is not needed during heavy WSL sessions")
    if host_vm_used_pct >= 85:
        score += 1
        causes.append("host virtual memory usage is high")
        prevention.append("free host memory/pagefile pressure and verify Windows pagefile is system-managed")
    if host_high_relevance_event_count > 0:
        score += 1
        causes.append("host WSL/Hyper-V relevant warning or error events were detected")
        prevention.append("inspect recent Hyper-V/WSL-related events for VM resets or integration faults")
    elif host_error_event_count > 0:
        causes.append("host warning/error events were detected (low relevance to WSL)")
        prevention.append("review host events, but prioritize guest memory pressure signals first")

    offender_causes, offender_prevention = _derive_guest_pressure_offender_hints(metrics)
    causes.extend(offender_causes)
    prevention.extend(offender_prevention)

    vscode_score, vscode_causes, vscode_prevention = _derive_vscode_extension_pressure_hints(metrics)
    score += vscode_score
    causes.extend(vscode_causes)
    prevention.extend(vscode_prevention)

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


def _read_windows_wsl_event_hints(max_events: int = 6) -> dict[str, Any]:
    """Read recent host-side warning/error events relevant to WSL/Hyper-V.

    Returns a compact summary. Best-effort only; never raises.
    """
    out: dict[str, Any] = {
        "host_event_logs_checked": [
            "Microsoft-Windows-Hyper-V-Compute-Operational",
            "Microsoft-Windows-Hyper-V-Worker-Operational",
            "System",
        ],
        "host_error_event_count": 0,
        "host_high_relevance_event_count": 0,
        "host_event_parse_warning_count": 0,
        "host_error_events": [],
    }

    if not _is_wsl():
        return out

    try:
        raw = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "$logs=@('Microsoft-Windows-Hyper-V-Compute-Operational','Microsoft-Windows-Hyper-V-Worker-Operational','System');"
                "$rows=@();"
                "foreach($l in $logs){"
                "  try {"
                "    $ev=Get-WinEvent -LogName $l -MaxEvents 40 -ErrorAction Stop | "
                "      Where-Object { $_.LevelDisplayName -in @('Error','Critical','Warning') } | "
                "      Select-Object -First 4 TimeCreated,Id,LevelDisplayName,ProviderName,Message;"
                "    foreach($e in $ev){"
                "      $rows += [PSCustomObject]@{"
                "        LogName=$l;"
                "        TimeCreated=$e.TimeCreated;"
                "        Id=$e.Id;"
                "        Level=$e.LevelDisplayName;"
                "        Provider=$e.ProviderName;"
                "        Message=$e.Message"
                "      }"
                "    }"
                "  } catch {}"
                "}"
                "$rows | ConvertTo-Json -Depth 4 -Compress",
            ],
            stderr=subprocess.DEVNULL,
            timeout=10,
            text=True,
        )
    except Exception:
        return out

    raw = raw.strip()
    if not raw:
        return out

    try:
        parsed = json.loads(raw)
    except Exception:
        return out

    events: list[dict[str, Any]] = []
    if isinstance(parsed, dict):
        parsed = [parsed]
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                out["host_event_parse_warning_count"] = out["host_event_parse_warning_count"] + 1
                continue
            message_raw = item.get("Message", "")
            if "Message" in item and not isinstance(message_raw, str):
                out["host_event_parse_warning_count"] = out["host_event_parse_warning_count"] + 1
            msg = message_raw if isinstance(message_raw, str) else ""
            msg = msg.replace("\r", " ").replace("\n", " ").strip()
            if len(msg) > 220:
                msg = msg[:220] + "..."

            log_raw = item.get("LogName", "")
            if "LogName" in item and not isinstance(log_raw, str):
                out["host_event_parse_warning_count"] = out["host_event_parse_warning_count"] + 1
            log_name = log_raw if isinstance(log_raw, str) else ""

            time_raw = item.get("TimeCreated", "")
            if "TimeCreated" in item and not isinstance(time_raw, str):
                out["host_event_parse_warning_count"] = out["host_event_parse_warning_count"] + 1
            event_time = time_raw if isinstance(time_raw, str) else ""

            level_raw = item.get("Level", "")
            if "Level" in item and not isinstance(level_raw, str):
                out["host_event_parse_warning_count"] = out["host_event_parse_warning_count"] + 1
            level = level_raw if isinstance(level_raw, str) else ""

            provider_raw = item.get("Provider", "")
            if "Provider" in item and not isinstance(provider_raw, str):
                out["host_event_parse_warning_count"] = out["host_event_parse_warning_count"] + 1
            provider = provider_raw if isinstance(provider_raw, str) else ""

            event_id_raw = item.get("Id", 0)
            if "Id" in item and not (isinstance(event_id_raw, int) and not isinstance(event_id_raw, bool)):
                out["host_event_parse_warning_count"] = out["host_event_parse_warning_count"] + 1
            event_id = event_id_raw if isinstance(event_id_raw, int) and not isinstance(event_id_raw, bool) else 0

            events.append(
                {
                    "log": log_name,
                    "time": event_time,
                    "id": event_id,
                    "level": level,
                    "provider": provider,
                    "message": msg,
                }
            )

    def _event_relevance(ev: dict[str, Any]) -> str:
        log_raw = ev.get("log", "")
        provider_raw = ev.get("provider", "")
        message_raw = ev.get("message", "")

        log_name = log_raw.lower() if isinstance(log_raw, str) else ""
        provider = provider_raw.lower() if isinstance(provider_raw, str) else ""
        message = message_raw.lower() if isinstance(message_raw, str) else ""

        if "hyper-v" in log_name or "hyper-v" in provider:
            return "high"
        if "lxss" in provider or "wsl" in provider or "wsl" in message:
            return "high"
        if "vmcompute" in provider or "hcs" in provider:
            return "high"
        if "vmm" in provider or "virtual machine" in message:
            return "medium"
        return "low"

    for ev in events:
        ev["relevance"] = _event_relevance(ev)

    events.sort(
        key=lambda e: {
            "high": 0,
            "medium": 1,
            "low": 2,
        }.get(e.get("relevance", "low") if isinstance(e.get("relevance"), str) else "low", 3)
    )
    events = events[:max_events]

    high_count = sum(1 for e in events if e.get("relevance") == "high")
    out["host_error_events"] = events
    out["host_error_event_count"] = len(events)
    out["host_high_relevance_event_count"] = high_count
    return out


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
        "host_high_relevance_event_count": 0,
        "guest_top_memory_processes": _top_memory_process_details(8),
    }
    metrics["guest_vscode_extension_rss"] = _summarize_vscode_extension_rss(
        metrics.get("guest_top_memory_processes", []),
        limit=5,
    )
    metrics["guest_vscode_extension_total_rss_mb"] = sum(
        row.get("rss_mb", 0)
        for row in metrics.get("guest_vscode_extension_rss", [])
        if isinstance(row, dict)
        and isinstance(row.get("rss_mb"), int)
        and not isinstance(row.get("rss_mb"), bool)
        and row.get("rss_mb", 0) >= 0
    )
    metrics.update(psi)
    metrics.update(_read_wsl_running_distros())
    metrics.update(_read_windows_wsl_event_hints())

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
    posture: str | None = None,
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

    When ``posture`` is provided, the generated conftest will pass it through
    to ``make_pytest_guard(...)`` so threshold presets are applied via the
    same validated path as direct factory usage.
    """
    if not isinstance(repo_name, str) or not repo_name.strip():
        raise ValueError("repo_name must be a non-empty string")
    if hints is not None:
        if not isinstance(hints, list):
            raise ValueError("hints must be a list of strings when provided")
        if any(not isinstance(item, str) for item in hints):
            raise ValueError("hints must contain only strings")
    if not isinstance(skip_on_critical, bool):
        raise ValueError("skip_on_critical must be a boolean")
    if not isinstance(intervene_on_warning, bool):
        raise ValueError("intervene_on_warning must be a boolean")
    if kill_hogs_above_mb is not None and (
        not isinstance(kill_hogs_above_mb, int)
        or isinstance(kill_hogs_above_mb, bool)
        or kill_hogs_above_mb < 1
    ):
        raise ValueError("kill_hogs_above_mb must be a positive integer when provided")
    if posture is not None and not isinstance(posture, str):
        raise ValueError("posture must be a string when provided")

    hints_repr = repr(hints or [])
    kill_repr = repr(kill_hogs_above_mb)
    skip_repr = repr(skip_on_critical)
    intervene_repr = repr(intervene_on_warning)
    posture_repr = "None"
    if posture is not None:
        posture_cfg = validate_runtime_guard_config(
            {"posture": posture},
            use_pydantic=False,
        )
        posture_repr = repr(str(posture_cfg["posture"]))

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
        f"        posture={posture_repr},",
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
    posture: str | None = None,
) -> str:
    """Return a ``sitecustomize.py`` string that auto-starts RuntimeGuard.

    This is intended for seeding repository-local Python startup behavior so
    RuntimeGuard begins background checks automatically when Python starts.
    Set ``<ENV_PREFIX>_AUTOSTART=0`` to disable without deleting the file.
    """
    if not isinstance(repo_name, str) or not repo_name.strip():
        raise ValueError("repo_name must be a non-empty string")
    if not isinstance(stage, str) or not stage.strip():
        raise ValueError("stage must be a non-empty string")
    if isinstance(interval_s, bool) or not isinstance(interval_s, (int, float)):
        raise ValueError("interval_s must be a positive number")
    if isinstance(cooldown_s, bool) or not isinstance(cooldown_s, (int, float)):
        raise ValueError("cooldown_s must be a non-negative number")
    interval_val = float(interval_s)
    cooldown_val = float(cooldown_s)
    if math.isnan(interval_val) or math.isinf(interval_val) or interval_val <= 0:
        raise ValueError("interval_s must be a positive number")
    if math.isnan(cooldown_val) or math.isinf(cooldown_val) or cooldown_val < 0:
        raise ValueError("cooldown_s must be a non-negative number")
    if not isinstance(env_prefix, str) or not env_prefix.strip():
        raise ValueError("env_prefix must be a non-empty string")
    if posture is not None and not isinstance(posture, str):
        raise ValueError("posture must be a string when provided")

    posture_value: str | None = None
    if posture is not None:
        posture_cfg = validate_runtime_guard_config(
            {"posture": posture},
            use_pydantic=False,
        )
        posture_value = str(posture_cfg["posture"])

    posture_lines: list[str] = []
    if posture_value is not None:
        posture_lines = [
            f'        _posture_key = "{env_prefix}_POSTURE"',
            '        if not os.environ.get(_posture_key, "").strip():',
            f'            os.environ[_posture_key] = "{posture_value}"',
        ]

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
        *posture_lines,
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
    parser.add_argument(
        "--fail-on-extension-total-rss-mb",
        type=int,
        default=0,
        help=(
            "With --diagnose-wsl-crash, exit non-zero when summed RSS of "
            "guest_vscode_extension_rss meets/exceeds this threshold."
        ),
    )
    parser.add_argument(
        "--fail-on-extension-rss",
        action="append",
        default=[],
        metavar="EXTENSION=MB",
        help=(
            "With --diagnose-wsl-crash, exit non-zero when a named extension "
            "meets/exceeds MB threshold. May be repeated."
        ),
    )

    args = parser.parse_args()

    cli_errors: list[str] = []

    def _require_bool(field: str, option: str) -> None:
        value = getattr(args, field, None)
        if not isinstance(value, bool):
            cli_errors.append(f"{option} must be boolean")

    def _require_optional_string(field: str, option: str) -> None:
        value = getattr(args, field, None)
        if value is None:
            return
        if not isinstance(value, str):
            cli_errors.append(f"{option} must be a string when provided")

    _require_bool("snapshot", "--snapshot")
    _require_bool("check", "--check")
    _require_bool("audit_policy_taxonomy", "--audit-policy-taxonomy")
    _require_bool("report", "--report")
    _require_bool("diagnose_wsl_crash", "--diagnose-wsl-crash")
    _require_bool("policy_auto_reload", "--policy-auto-reload")
    _require_bool("version", "--version")
    _require_bool("json", "--json")

    _require_optional_string("verify_audit_log", "--verify-audit-log")
    _require_optional_string("write", "--write")
    _require_optional_string("policy_file", "--policy-file")

    posture_value = getattr(args, "posture", None)
    if posture_value is not None and not isinstance(posture_value, str):
        cli_errors.append("--posture must be a string when provided")

    stage_value = getattr(args, "stage", "")
    if not isinstance(stage_value, str):
        cli_errors.append("--stage must be a string")

    generate_wslconfig_value = getattr(args, "generate_wslconfig", None)
    if generate_wslconfig_value is not None and (
        not isinstance(generate_wslconfig_value, int)
        or isinstance(generate_wslconfig_value, bool)
    ):
        cli_errors.append("--generate-wslconfig must be an integer when provided")

    fail_on_risk_value = getattr(args, "fail_on_risk", "none")
    if not isinstance(fail_on_risk_value, str) or fail_on_risk_value not in {
        "none",
        "high",
        "critical",
    }:
        cli_errors.append("--fail-on-risk must be one of: none, high, critical")

    extension_total_rss_value = getattr(args, "fail_on_extension_total_rss_mb", 0)
    if (
        not isinstance(extension_total_rss_value, int)
        or isinstance(extension_total_rss_value, bool)
        or extension_total_rss_value < 0
    ):
        cli_errors.append("--fail-on-extension-total-rss-mb must be a non-negative integer")

    extension_specs = getattr(args, "fail_on_extension_rss", [])
    if not isinstance(extension_specs, list):
        cli_errors.append("--fail-on-extension-rss must be a list when provided")
    elif not all(isinstance(spec, str) for spec in extension_specs):
        cli_errors.append("--fail-on-extension-rss entries must be strings")

    if cli_errors:
        for row in sorted(set(cli_errors)):
            print(f"[RuntimeGuard] Invalid CLI argument state: {row}", file=sys.stderr)
        sys.exit(2)

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

        fail_reasons: list[str] = []

        if args.fail_on_risk == "critical" and diag["risk_level"] == "critical":
            fail_reasons.append("risk threshold met: critical")
        elif args.fail_on_risk == "high" and diag["risk_level"] in {"high", "critical"}:
            fail_reasons.append(f"risk threshold met: {diag['risk_level']}")

        ext_rows = [
            row
            for row in diag.get("guest_vscode_extension_rss", [])
            if isinstance(row, dict)
        ]
        ext_totals: dict[str, int] = {}
        for row in ext_rows:
            ext_name_raw = row.get("extension", "")
            ext_name = ext_name_raw.strip() if isinstance(ext_name_raw, str) else ""
            if not ext_name:
                continue

            rss_raw = row.get("rss_mb", 0)
            if not isinstance(rss_raw, int) or isinstance(rss_raw, bool) or rss_raw < 0:
                print(
                    "[RuntimeGuard] Invalid --diagnose-wsl-crash result: "
                    "guest_vscode_extension_rss[].rss_mb must be a non-negative integer",
                    file=sys.stderr,
                )
                sys.exit(2)

            ext_totals[ext_name] = rss_raw

        total_ext_rss_mb_raw = diag.get("guest_vscode_extension_total_rss_mb", 0)
        if not isinstance(total_ext_rss_mb_raw, int) or isinstance(total_ext_rss_mb_raw, bool) or total_ext_rss_mb_raw < 0:
            print(
                "[RuntimeGuard] Invalid --diagnose-wsl-crash result: "
                "guest_vscode_extension_total_rss_mb must be a non-negative integer",
                file=sys.stderr,
            )
            sys.exit(2)
        total_ext_rss_mb = total_ext_rss_mb_raw or sum(ext_totals.values())

        if args.fail_on_extension_total_rss_mb > 0 and total_ext_rss_mb >= args.fail_on_extension_total_rss_mb:
            fail_reasons.append(
                "extension total RSS threshold met: "
                f"{total_ext_rss_mb}MB >= {args.fail_on_extension_total_rss_mb}MB"
            )

        for spec in args.fail_on_extension_rss:
            if "=" not in spec:
                print(
                    "[RuntimeGuard] Invalid --fail-on-extension-rss spec "
                    f"'{spec}' (expected EXTENSION=MB)",
                    file=sys.stderr,
                )
                sys.exit(2)
            ext_name_raw, mb_raw = spec.split("=", 1)
            ext_name = ext_name_raw.strip()
            if not ext_name:
                print(
                    "[RuntimeGuard] Invalid --fail-on-extension-rss spec "
                    f"'{spec}' (empty extension name)",
                    file=sys.stderr,
                )
                sys.exit(2)
            try:
                threshold_mb = int(mb_raw)
            except ValueError:
                print(
                    "[RuntimeGuard] Invalid --fail-on-extension-rss spec "
                    f"'{spec}' (MB must be integer)",
                    file=sys.stderr,
                )
                sys.exit(2)
            if threshold_mb <= 0:
                print(
                    "[RuntimeGuard] Invalid --fail-on-extension-rss spec "
                    f"'{spec}' (MB must be > 0)",
                    file=sys.stderr,
                )
                sys.exit(2)
            rss_mb = ext_totals.get(ext_name, 0)
            if rss_mb >= threshold_mb:
                fail_reasons.append(
                    f"extension RSS threshold met: {ext_name} {rss_mb}MB >= {threshold_mb}MB"
                )

        if fail_reasons:
            for reason in fail_reasons:
                print(f"[RuntimeGuard] FAIL gate: {reason}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.verify_audit_log:
        result = verify_audit_log_chain(args.verify_audit_log)
        ok_value = result.get("ok")
        if not isinstance(ok_value, bool):
            print(
                "[RuntimeGuard] Invalid verify-audit-log result: 'ok' must be boolean",
                file=sys.stderr,
            )
            sys.exit(2)

        if ok_value:
            records_value = result.get("records", 0)
            if not isinstance(records_value, int) or isinstance(records_value, bool) or records_value < 0:
                print(
                    "[RuntimeGuard] Invalid verify-audit-log result: 'records' must be a non-negative integer",
                    file=sys.stderr,
                )
                sys.exit(2)
            records = records_value
            print(f"[RuntimeGuard] Audit chain OK ({records} record(s))")
            sys.exit(0)

        reason_value = result.get("reason", "unknown")
        if not isinstance(reason_value, str):
            print(
                "[RuntimeGuard] Invalid verify-audit-log result: 'reason' must be a string",
                file=sys.stderr,
            )
            sys.exit(2)
        reason = reason_value.strip() or "unknown"

        line_value = result.get("line", 0)
        if not isinstance(line_value, int) or isinstance(line_value, bool) or line_value < 0:
            print(
                "[RuntimeGuard] Invalid verify-audit-log result: 'line' must be a non-negative integer",
                file=sys.stderr,
            )
            sys.exit(2)
        line = line_value
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
                    auto_reload=args.policy_auto_reload,
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
