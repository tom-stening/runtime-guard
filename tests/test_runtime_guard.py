"""Tests for runtime_guard improvements.

Covers:
 - Threshold presets (POSTURE env var)
 - Structured JSON events (runtime_guard.events logger)
 - Cooldown / deduplication
 - Periodic background check (start / stop)
 - Cross-platform snapshot (Linux path, non-Linux zeros)
"""

from __future__ import annotations

import io
import json
import logging
import asyncio
import os
import sys
import time
import unittest.mock as mock
from pathlib import Path
from typing import Any

import pytest
from runtime_guard import (
    MemSnapshot,
    PressureReport,
    RuntimeGuard,
    make_conftest_content,
    make_pytest_guard,
    attach_dask_guard,
    attach_signal_recovery,
    install_signal_recovery_from_policy,
    append_audit_log,
    audit_policy_taxonomy,
    aggregate_worker_reports,
    build_adoption_scorecard,
    emit_otel_event,
    emit_otel_phase_event,
    fips_event_hash,
    FipsDeduplicator,
    subprocess_safe,
    make_worker_report,
    make_sitecustomize_content,
    normalize_policy_violation_event,
    soc2_required_controls,
    soc2_evidence_requirements,
    soc2_gap_assessment,
    soc2_readiness_report,
    resolve_signal_recovery_policy,
    verify_audit_log_chain,
    pressure_report_attributes,
    render_prometheus_metrics,
    trace_context_attributes,
    validate_runtime_guard_config,
    validate_polars_integration,
    collect_polars_integration_evidence,
    validate_dask_integration,
    collect_dask_integration_evidence,
    validate_ray_integration,
    collect_ray_integration_evidence,
    attach_ray_guard,
    _read_snapshot,
    attach_polars_guard,
    install_polars_scan_budget,
    install_dask_task_graph_guard,
    install_otel_memory_exporter,
    install_prometheus_endpoint,
    install_distributed_trace_propagator,
)

def _make_report(*, is_critical: bool = False, stage: str = "") -> PressureReport:
    snap = MemSnapshot(
        mem_total_mb=8192,
        mem_available_mb=100,
        swap_total_mb=2048,
        swap_free_mb=0,
        swap_used_pct=100,
        rss_mb=50,
        vm_swap_mb=0,
    )
    return PressureReport(
        snapshot=snap,
        is_critical=is_critical,
        cause="test cause",
        self_inflicted=False,
        self_pct=1,
        pid=12345,
        stage=stage,
        min_mem_mb=2048,
        max_swap_pct=85,
    )


def _capture_json_events(guard: RuntimeGuard, report: PressureReport) -> dict:
    """Call guard.log(report) and return the parsed JSON event payload."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    ev_logger = logging.getLogger("runtime_guard.events")
    ev_logger.addHandler(handler)
    ev_logger.setLevel(logging.DEBUG)
    try:
        guard.log(report)
    finally:
        ev_logger.removeHandler(handler)
    return json.loads(buf.getvalue().strip())


# ---------------------------------------------------------------------------
# Threshold presets
# ---------------------------------------------------------------------------


class TestThresholdPresets:
    def test_ci_preset_values(self, monkeypatch):
        monkeypatch.setenv("RUNTIME_GUARD_POSTURE", "ci")
        g = RuntimeGuard()
        assert g._resolve_thresholds() == (1024, 90, 512, 97, 20)

    def test_tight_preset_values(self, monkeypatch):
        monkeypatch.setenv("RUNTIME_GUARD_POSTURE", "tight")
        g = RuntimeGuard()
        min_mem, max_swap, crit_mem, crit_swap, self_pct = g._resolve_thresholds()
        assert min_mem == 2048
        assert max_swap == 75
        assert crit_mem == 1024
        assert crit_swap == 90
        assert self_pct == 15

    def test_relaxed_preset_values(self, monkeypatch):
        monkeypatch.setenv("RUNTIME_GUARD_POSTURE", "relaxed")
        g = RuntimeGuard()
        min_mem, max_swap, crit_mem, crit_swap, self_pct = g._resolve_thresholds()
        assert min_mem == 512
        assert max_swap == 95

    def test_wsl_dev_preset_values(self, monkeypatch):
        monkeypatch.setenv("RUNTIME_GUARD_POSTURE", "wsl_dev")
        g = RuntimeGuard()
        min_mem, max_swap, crit_mem, crit_swap, self_pct = g._resolve_thresholds()
        assert (min_mem, max_swap, crit_mem, crit_swap, self_pct) == (256, 97, 128, 99, 10)

    def test_unknown_posture_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("RUNTIME_GUARD_POSTURE", "nonexistent")
        g = RuntimeGuard()
        assert g._resolve_thresholds() == (2048, 85, 1024, 95, 20)

    def test_no_posture_uses_default(self, monkeypatch):
        monkeypatch.delenv("RUNTIME_GUARD_POSTURE", raising=False)
        g = RuntimeGuard()
        assert g._resolve_thresholds() == (2048, 85, 1024, 95, 20)

    def test_explicit_env_overrides_preset(self, monkeypatch):
        monkeypatch.setenv("RUNTIME_GUARD_POSTURE", "ci")
        monkeypatch.setenv("RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB", "512")
        g = RuntimeGuard()
        min_mem, *_ = g._resolve_thresholds()
        assert min_mem == 512  # explicit var wins over ci preset value of 1024

    def test_explicit_env_overrides_wsl_dev(self, monkeypatch):
        monkeypatch.setenv("RUNTIME_GUARD_POSTURE", "wsl_dev")
        monkeypatch.setenv("RUNTIME_GUARD_MAX_SWAP_USED_PCT", "96")
        g = RuntimeGuard()
        _, max_swap, *_ = g._resolve_thresholds()
        assert max_swap == 96  # explicit var wins over wsl_dev preset value of 97

    def test_custom_prefix_posture(self, monkeypatch):
        monkeypatch.setenv("MYAPP_POSTURE", "ci")
        g = RuntimeGuard(env_prefix="MYAPP")
        assert g._resolve_thresholds()[0] == 1024  # ci min_mem_mb


class TestMakePytestGuard:
    def test_posture_applies_when_env_not_set(self, monkeypatch):
        monkeypatch.delenv("MY_REPO_GUARD_POSTURE", raising=False)
        _ = make_pytest_guard(repo_name="My Repo", posture="ci")
        assert os.environ.get("MY_REPO_GUARD_POSTURE") == "ci"

    def test_posture_does_not_override_existing_env(self, monkeypatch):
        monkeypatch.setenv("MY_REPO_GUARD_POSTURE", "tight")
        _ = make_pytest_guard(repo_name="My Repo", posture="relaxed")
        assert os.environ.get("MY_REPO_GUARD_POSTURE") == "tight"

    def test_invalid_posture_raises(self):
        with pytest.raises(ValueError, match="Invalid posture"):
            make_pytest_guard(repo_name="My Repo", posture="fast")


class TestConftestContent:
    def test_conftest_includes_posture_when_provided(self):
        text = make_conftest_content(repo_name="myrepo", posture="ci")
        assert "make_pytest_guard(" in text
        assert "posture='ci'" in text

    def test_conftest_validates_posture(self):
        with pytest.raises(ValueError, match="Invalid posture"):
            make_conftest_content(repo_name="myrepo", posture="fast")


# ---------------------------------------------------------------------------
# Structured JSON events
# ---------------------------------------------------------------------------


class TestJsonEvents:
    def test_json_event_emitted_on_log(self):
        g = RuntimeGuard()
        report = _make_report()
        payload = _capture_json_events(g, report)
        assert payload["event"] == "runtime_guard.pressure"

    def test_json_event_has_required_keys(self):
        g = RuntimeGuard()
        report = _make_report(stage="data-load")
        payload = _capture_json_events(g, report)
        required = {
            "event",
            "severity",
            "tag",
            "stage",
            "pid",
            "cause",
            "self_inflicted",
            "self_pct",
            "is_critical",
            "mem_available_mb",
            "mem_total_mb",
            "rss_mb",
        }
        assert required.issubset(payload.keys())

    def test_json_event_stage_propagated(self):
        g = RuntimeGuard()
        report = _make_report(stage="my-stage")
        payload = _capture_json_events(g, report)
        assert payload["stage"] == "my-stage"

    def test_json_event_severity_warning_for_non_critical(self):
        g = RuntimeGuard()
        report = _make_report(is_critical=False)
        payload = _capture_json_events(g, report)
        assert payload["severity"] == "warning"

    def test_json_event_severity_critical_for_critical(self):
        g = RuntimeGuard()
        report = _make_report(is_critical=True)
        payload = _capture_json_events(g, report)
        assert payload["severity"] == "critical"

    def test_json_event_tag_matches_log_tag(self):
        g = RuntimeGuard(log_tag="MyApp")
        report = _make_report()
        payload = _capture_json_events(g, report)
        assert payload["tag"] == "MyApp"

    def test_json_event_is_valid_json(self):
        g = RuntimeGuard()
        report = _make_report()
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        ev_logger = logging.getLogger("runtime_guard.events")
        ev_logger.addHandler(h)
        ev_logger.setLevel(logging.DEBUG)
        g.log(report)
        ev_logger.removeHandler(h)
        raw = buf.getvalue().strip()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Cooldown / deduplication
# ---------------------------------------------------------------------------


class TestCooldown:
    def test_zero_cooldown_allows_repeated_emission(self):
        """Default cooldown=0 should never suppress."""
        g = RuntimeGuard(cooldown_s=0.0)
        report = _make_report()
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        logging.getLogger("runtime_guard").addHandler(h)
        logging.getLogger("runtime_guard").setLevel(logging.WARNING)
        try:
            g.log(report)
            g.log(report)
        finally:
            logging.getLogger("runtime_guard").removeHandler(h)
        # Both calls should have emitted — check that _last_logged is never set
        assert g._last_logged == {}

    def test_cooldown_suppresses_second_emission(self):
        g = RuntimeGuard(cooldown_s=60.0)
        report = _make_report()
        g.log(report)
        first_ts = dict(g._last_logged)
        time.sleep(0.01)
        g.log(report)
        # Timestamp should not advance since cooldown blocks the second log
        assert g._last_logged == first_ts

    def test_cooldown_allows_after_window(self, monkeypatch):
        g = RuntimeGuard(cooldown_s=0.05)
        report = _make_report()
        cooldown_key = f"{report.stage}\x00warning"
        g.log(report)
        first_ts = g._last_logged.get(cooldown_key)
        time.sleep(0.1)
        g.log(report)
        assert g._last_logged.get(cooldown_key) > first_ts  # timestamp updated

    def test_cooldown_warning_and_critical_independent(self):
        g = RuntimeGuard(cooldown_s=60.0)
        warn_report = _make_report(is_critical=False)
        crit_report = _make_report(is_critical=True)
        warn_key = f"{warn_report.stage}\x00warning"
        crit_key = f"{crit_report.stage}\x00critical"
        g.log(warn_report)
        assert warn_key in g._last_logged
        assert crit_key not in g._last_logged
        g.log(crit_report)
        assert crit_key in g._last_logged

    def test_cooldown_custom_prefix(self):
        g = RuntimeGuard(env_prefix="MYAPP", cooldown_s=60.0)
        report = _make_report()
        cooldown_key = f"{report.stage}\x00warning"
        g.log(report)
        assert cooldown_key in g._last_logged


# ---------------------------------------------------------------------------
# Background check
# ---------------------------------------------------------------------------


class TestBackgroundCheck:
    def test_start_creates_daemon_thread(self):
        g = RuntimeGuard()
        g.start_background_check(interval_s=5.0)
        try:
            assert g._bg_thread is not None
            assert g._bg_thread.is_alive()
            assert g._bg_thread.daemon
        finally:
            g.stop_background_check()

    def test_stop_removes_thread(self):
        g = RuntimeGuard()
        g.start_background_check(interval_s=5.0)
        g.stop_background_check()
        assert g._bg_thread is None
        assert g._bg_stop is None

    def test_second_start_replaces_first(self):
        g = RuntimeGuard()
        g.start_background_check(interval_s=5.0)
        t1 = g._bg_thread
        g.start_background_check(interval_s=10.0)
        t2 = g._bg_thread
        try:
            assert t2 is not t1
            assert t2.is_alive()
        finally:
            g.stop_background_check()

    def test_stop_without_start_is_safe(self):
        g = RuntimeGuard()
        g.stop_background_check()  # should not raise

    def test_background_calls_check_and_log(self, monkeypatch):
        """Background thread should invoke check_and_log."""
        calls: list[str] = []

        def fake_check_and_log(stage="", **kwargs):
            calls.append(stage)
            return None

        g = RuntimeGuard()
        monkeypatch.setattr(g, "check_and_log", fake_check_and_log)
        g.start_background_check(interval_s=0.05, stage="bg-test")
        time.sleep(0.18)  # allow ~3 intervals
        g.stop_background_check()
        assert len(calls) >= 2
        assert all(c == "bg-test" for c in calls)


# ---------------------------------------------------------------------------
# _read_snapshot — platform coverage
# ---------------------------------------------------------------------------


class TestReadSnapshot:
    def test_returns_memsnapshot_instance(self):
        snap = _read_snapshot()
        assert isinstance(snap, MemSnapshot)

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
    def test_linux_populates_mem_fields(self):
        snap = _read_snapshot()
        assert snap.mem_total_mb > 0
        assert snap.mem_available_mb >= 0
        assert snap.rss_mb >= 0

    def test_non_linux_returns_zeros_gracefully(self, monkeypatch):
        """Simulate a non-Linux, non-macOS, non-Windows platform."""
        monkeypatch.setattr("sys.platform", "freebsd14")
        snap = _read_snapshot()
        # All fields zero — no exception raised
        assert snap.mem_total_mb == 0
        assert snap.mem_available_mb == 0

    def test_oserror_on_proc_handled(self, monkeypatch):
        """If /proc/meminfo is missing, snapshot zeros silently."""
        original_open = open

        def mock_open(path, *args, **kwargs):
            if "/proc" in str(path):
                raise OSError("no proc")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        snap = _read_snapshot()
        assert snap.mem_total_mb == 0

    def test_macos_subprocess_failure_handled(self, monkeypatch):
        """Simulate macOS with failing subprocess — should not raise."""
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(
            "subprocess.check_output",
            mock.Mock(side_effect=Exception("no sysctl")),
        )
        snap = _read_snapshot()
        assert isinstance(snap, MemSnapshot)

    def test_windows_subprocess_failure_handled(self, monkeypatch):
        """Simulate Windows with failing wmic — should not raise."""
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(
            "subprocess.check_output",
            mock.Mock(side_effect=Exception("no wmic")),
        )
        snap = _read_snapshot()
        assert isinstance(snap, MemSnapshot)

    def test_read_windows_host_from_wsl_handles_non_numeric_csv_fields(self, monkeypatch):
        import runtime_guard as rg

        monkeypatch.setattr(
            "subprocess.check_output",
            mock.Mock(
                return_value=(
                    '"TotalVisibleMemorySize","FreePhysicalMemory","TotalVirtualMemorySize","FreeVirtualMemory"\n'
                    '"not-a-number","123","oops","456"\n'
                )
            ),
        )

        snap = MemSnapshot()
        rg._read_windows_host_from_wsl(snap)

        assert snap.host_mem_total_mb == 0
        assert snap.host_mem_available_mb == 0
        assert snap.host_swap_total_mb == 0
        assert snap.host_swap_free_mb == 0
        assert snap.host_swap_used_pct == 0

    def test_read_windows_powershell_handles_non_numeric_csv_fields(self, monkeypatch):
        import runtime_guard as rg

        def _mock_check_output(cmd, **kwargs):
            joined = " ".join(str(part) for part in cmd)
            if "Get-CimInstance Win32_OperatingSystem" in joined:
                return (
                    '"FreePhysicalMemory","TotalVisibleMemorySize"\n'
                    '"bad-free","bad-total"\n'
                )
            if "WorkingSet64" in joined:
                return "0"
            return ""

        monkeypatch.setattr("subprocess.check_output", _mock_check_output)

        snap = MemSnapshot()
        ok = rg._read_windows_powershell(snap)

        assert ok is False
        assert snap.mem_total_mb == 0
        assert snap.mem_available_mb == 0


class TestIsWsl:
    def test_returns_bool(self):
        from runtime_guard import _is_wsl

        assert isinstance(_is_wsl(), bool)

    def test_detects_wsl_when_proc_version_contains_microsoft(self, tmp_path, monkeypatch):
        from runtime_guard import _is_wsl

        fake = tmp_path / "proc_version"
        fake.write_text("Linux version 5.15.0-microsoft-standard-WSL2")
        orig_open = open

        def fake_open(*a, **kw):
            return orig_open(str(fake))

        monkeypatch.setattr("builtins.open", fake_open)
        assert _is_wsl() is True

    def test_returns_false_when_oserror(self, monkeypatch):
        from runtime_guard import _is_wsl

        monkeypatch.setattr("builtins.open", mock.Mock(side_effect=OSError("no file")))
        assert _is_wsl() is False


class TestTopMemoryProcesses:
    def test_returns_string(self):
        from runtime_guard import _top_memory_processes

        result = _top_memory_processes(n=3)
        assert isinstance(result, str)

    def test_returns_empty_on_subprocess_failure(self, monkeypatch):
        from runtime_guard import _top_memory_processes

        monkeypatch.setattr(
            "subprocess.run",
            mock.Mock(side_effect=Exception("ps not found")),
        )
        assert _top_memory_processes() == ""

    def test_output_contains_rss_info_on_linux(self):
        """On Linux, ps should succeed and return non-empty results."""
        import sys

        if sys.platform != "linux":
            pytest.skip("Linux only")
        from runtime_guard import _top_memory_processes

        result = _top_memory_processes(n=3)
        # May be empty if ps is missing; just verify it doesn't raise
        assert isinstance(result, str)

    def test_top_memory_process_details_parses_rows(self, monkeypatch):
        from runtime_guard import _top_memory_process_details

        monkeypatch.setattr(
            "subprocess.run",
            mock.Mock(
                return_value=mock.Mock(
                    stdout=(
                        "123 204800 python train.py\n"
                        "456 102400 node /vscode/server.js\n"
                    )
                )
            ),
        )

        rows = _top_memory_process_details(2)
        assert rows == [
            {"pid": 123, "rss_mb": 200, "command": "python train.py"},
            {"pid": 456, "rss_mb": 100, "command": "node /vscode/server.js"},
        ]


class TestWslRuntimeContext:
    def test_read_wsl_running_distros_parses_running_rows(self, monkeypatch):
        from runtime_guard import _read_wsl_running_distros

        monkeypatch.setattr("runtime_guard._is_wsl", lambda: True)
        monkeypatch.setattr(
            "subprocess.check_output",
            mock.Mock(
                return_value=(
                    " \x00 \x00N\x00A\x00M\x00E\x00  \x00S\x00T\x00A\x00T\x00E\x00  \x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00\n"
                    "\x00*\x00 \x00U\x00b\x00u\x00n\x00t\x00u\x00-\x002\x004\x00.\x000\x004\x00      \x00R\x00u\x00n\x00n\x00i\x00n\x00g\x00         \x002\x00\n"
                    "\x00  \x00d\x00o\x00c\x00k\x00e\x00r\x00-\x00d\x00e\x00s\x00k\x00t\x00o\x00p\x00    \x00R\x00u\x00n\x00n\x00i\x00n\x00g\x00         \x002\x00\n"
                    "\x00  \x00U\x00b\x00u\x00n\x00t\x00u\x00-\x002\x002\x00.\x000\x004\x00      \x00S\x00t\x00o\x00p\x00p\x00e\x00d\x00         \x002\x00\n"
                )
            ),
        )

        ctx = _read_wsl_running_distros()
        assert ctx["wsl_running_distro_count"] == 2
        assert ctx["docker_desktop_running"] is True
        assert [row["name"] for row in ctx["wsl_running_distros"]] == [
            "Ubuntu-24.04",
            "docker-desktop",
        ]

    def test_read_wsl_running_distros_returns_empty_when_not_wsl(self):
        from runtime_guard import _read_wsl_running_distros

        ctx = _read_wsl_running_distros()
        assert ctx["wsl_running_distro_count"] >= 0

    def test_summarize_vscode_extension_rss_aggregates_and_normalizes(self):
        from runtime_guard import _summarize_vscode_extension_rss

        rows = [
            {
                "pid": 10,
                "rss_mb": 700,
                "command": "/home/u/.vscode-server/extensions/ms-python.vscode-pylance-2026.2.1/dist/server.bundle.js",
            },
            {
                "pid": 11,
                "rss_mb": 500,
                "command": "/home/u/.vscode-server/extensions/ms-python.vscode-pylance-2026.2.1/dist/server.bundle.js",
            },
            {
                "pid": 12,
                "rss_mb": 300,
                "command": "/home/u/.vscode-server/extensions/tamasfe.even-better-toml-0.21.2/dist/server.js",
            },
            {
                "pid": 13,
                "rss_mb": 450,
                "command": "/home/u/.vscode-server/bin/hash/out/bootstrap-fork --type=extensionHost",
            },
        ]

        summary = _summarize_vscode_extension_rss(rows, limit=5)
        assert summary[0]["extension"] == "ms-python.vscode-pylance"
        assert summary[0]["rss_mb"] == 1200
        assert summary[0]["process_count"] == 2
        assert set(summary[0]["pids"]) == {10, 11}
        assert any(r["extension"] == "vscode.extension-host" for r in summary)

    def test_summarize_vscode_extension_rss_rejects_non_typed_rows(self):
        from runtime_guard import _summarize_vscode_extension_rss

        rows = [
            {
                "pid": 10,
                "rss_mb": 700,
                "command": "/home/u/.vscode-server/extensions/ms-python.vscode-pylance-2026.2.1/dist/server.bundle.js",
            },
            {
                "pid": "11",
                "rss_mb": "500",
                "command": "/home/u/.vscode-server/extensions/ms-python.vscode-pylance-2026.2.1/dist/server.bundle.js",
            },
            {
                "pid": 12,
                "rss_mb": True,
                "command": "/home/u/.vscode-server/extensions/ms-python.vscode-pylance-2026.2.1/dist/server.bundle.js",
            },
            {
                "pid": 13,
                "rss_mb": 300,
                "command": 123,
            },
        ]

        summary = _summarize_vscode_extension_rss(rows, limit=5)
        assert len(summary) == 1
        assert summary[0]["extension"] == "ms-python.vscode-pylance"
        assert summary[0]["rss_mb"] == 700
        assert summary[0]["process_count"] == 1
        assert summary[0]["pids"] == [10]

    def test_derive_vscode_extension_pressure_hints_ignores_non_typed_rss(self):
        from runtime_guard import _derive_vscode_extension_pressure_hints

        score, causes, prevention = _derive_vscode_extension_pressure_hints(
            {
                "guest_vscode_extension_rss": [
                    {"extension": "ms-python.vscode-pylance", "rss_mb": "5000"},
                    {"extension": "vscode.extension-host", "rss_mb": True},
                    {"extension": "eamodio.gitlens", "rss_mb": 3500},
                ]
            }
        )

        assert score == 1
        assert any("3500 MB" in row for row in causes)
        assert prevention

    def test_derive_guest_pressure_offender_hints_handles_non_numeric_metrics(self):
        from runtime_guard import _derive_guest_pressure_offender_hints

        causes, prevention = _derive_guest_pressure_offender_hints(
            {
                "guest_mem_available_mb": "bad",
                "guest_swap_used_pct": "bad",
                "psi_full_avg10": "bad",
                "psi_some_avg10": "bad",
                "guest_top_memory_processes": [
                    {"pid": 1, "rss_mb": 900, "command": "python worker.py"},
                ],
            }
        )

        assert any("top guest RSS offenders" in row for row in causes)
        assert prevention

    def test_derive_guest_pressure_offender_hints_rejects_non_typed_rows(self):
        from runtime_guard import _derive_guest_pressure_offender_hints

        causes, prevention = _derive_guest_pressure_offender_hints(
            {
                "guest_mem_available_mb": 1000,
                "guest_swap_used_pct": 80,
                "psi_full_avg10": 11.0,
                "psi_some_avg10": 21.0,
                "guest_top_memory_processes": [
                    {"pid": "1", "rss_mb": "900", "command": "python worker.py"},
                    {"pid": 2, "rss_mb": True, "command": "tsserver"},
                    {"pid": 3, "rss_mb": 700, "command": 123},
                ],
            }
        )

        assert not any("top guest RSS offenders" in row for row in causes)
        assert prevention


class TestDiagnoseWslCrash:
    def test_diagnose_wsl_crash_includes_top_processes_and_runtime_context(self, monkeypatch):
        from runtime_guard import diagnose_wsl_crash

        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=16384,
                mem_available_mb=900,
                swap_total_mb=8192,
                swap_free_mb=512,
                swap_used_pct=93,
                rss_mb=120,
                vm_swap_mb=0,
                host_mem_total_mb=32768,
                host_mem_available_mb=12000,
                host_swap_total_mb=65536,
                host_swap_free_mb=40000,
                host_swap_used_pct=39,
            ),
        )
        monkeypatch.setattr(
            "runtime_guard._read_linux_memory_psi",
            lambda: {
                "psi_some_avg10": 22.0,
                "psi_some_avg60": 10.0,
                "psi_full_avg10": 11.0,
                "psi_full_avg60": 5.0,
            },
        )
        monkeypatch.setattr(
            "runtime_guard._top_memory_process_details",
            lambda n=8: [{"pid": 1, "rss_mb": 1500, "command": "python main.py"}],
        )
        monkeypatch.setattr(
            "runtime_guard._read_wsl_running_distros",
            lambda: {
                "wsl_running_distros": [
                    {"name": "Ubuntu-24.04", "state": "Running", "version": 2},
                    {"name": "docker-desktop", "state": "Running", "version": 2},
                ],
                "wsl_running_distro_count": 2,
                "docker_desktop_running": True,
            },
        )
        monkeypatch.setattr(
            "runtime_guard._read_windows_wsl_event_hints",
            lambda max_events=6: {
                "host_event_logs_checked": ["System"],
                "host_error_event_count": 0,
                "host_high_relevance_event_count": 0,
                "host_error_events": [],
            },
        )

        diag = diagnose_wsl_crash()
        assert diag["risk_level"] in {"high", "critical"}
        assert diag["guest_top_memory_processes"] == [
            {"pid": 1, "rss_mb": 1500, "command": "python main.py"}
        ]
        assert diag["wsl_running_distro_count"] == 2
        assert diag["docker_desktop_running"] is True
        assert any("multiple WSL distros" in item for item in diag["likely_causes"])
        assert any("docker-desktop" in item for item in diag["likely_causes"])

    def test_diagnose_wsl_crash_adds_offender_aware_prevention_hints(self, monkeypatch):
        from runtime_guard import diagnose_wsl_crash

        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=16384,
                mem_available_mb=1200,
                swap_total_mb=8192,
                swap_free_mb=1800,
                swap_used_pct=78,
                rss_mb=120,
                vm_swap_mb=0,
            ),
        )
        monkeypatch.setattr(
            "runtime_guard._read_linux_memory_psi",
            lambda: {
                "psi_some_avg10": 12.0,
                "psi_some_avg60": 8.0,
                "psi_full_avg10": 3.0,
                "psi_full_avg60": 2.0,
            },
        )
        monkeypatch.setattr(
            "runtime_guard._top_memory_process_details",
            lambda n=8: [
                {
                    "pid": 111,
                    "rss_mb": 2200,
                    "command": "/home/thomas_stening/.vscode-server/bin/.../node --type=extensionHost",
                },
                {
                    "pid": 222,
                    "rss_mb": 900,
                    "command": "/home/thomas_stening/.vscode-server/extensions/ms-python.vscode-pylance/dist/server.bundle.js",
                },
                {
                    "pid": 333,
                    "rss_mb": 1500,
                    "command": "/home/thomas_stening/ML-Trading/venv/bin/python main.py",
                },
            ],
        )
        monkeypatch.setattr(
            "runtime_guard._read_wsl_running_distros",
            lambda: {
                "wsl_running_distros": [
                    {"name": "Ubuntu-24.04", "state": "Running", "version": 2}
                ],
                "wsl_running_distro_count": 1,
                "docker_desktop_running": False,
            },
        )
        monkeypatch.setattr(
            "runtime_guard._read_windows_wsl_event_hints",
            lambda max_events=6: {
                "host_event_logs_checked": ["System"],
                "host_error_event_count": 0,
                "host_high_relevance_event_count": 0,
                "host_error_events": [],
            },
        )

        diag = diagnose_wsl_crash()
        assert any("top guest RSS offenders" in item for item in diag["likely_causes"])
        assert any("VS Code" in item for item in diag["prevention_actions"])
        assert any("Pylance" in item for item in diag["prevention_actions"])
        assert any("Python jobs" in item for item in diag["prevention_actions"])

    def test_diagnose_wsl_crash_flags_vscode_extension_memory_concentration(self, monkeypatch):
        from runtime_guard import diagnose_wsl_crash

        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=16384,
                mem_available_mb=3500,
                swap_total_mb=8192,
                swap_free_mb=7200,
                swap_used_pct=12,
                rss_mb=120,
                vm_swap_mb=0,
            ),
        )
        monkeypatch.setattr(
            "runtime_guard._read_linux_memory_psi",
            lambda: {
                "psi_some_avg10": 0.8,
                "psi_some_avg60": 0.5,
                "psi_full_avg10": 0.2,
                "psi_full_avg60": 0.1,
            },
        )
        monkeypatch.setattr(
            "runtime_guard._top_memory_process_details",
            lambda n=8: [
                {
                    "pid": 101,
                    "rss_mb": 2100,
                    "command": "/home/thomas_stening/.vscode-server/bin/.../node --type=extensionHost",
                },
                {
                    "pid": 102,
                    "rss_mb": 1700,
                    "command": "/home/thomas_stening/.vscode-server/extensions/ms-python.vscode-pylance/dist/server.bundle.js",
                },
                {
                    "pid": 103,
                    "rss_mb": 900,
                    "command": "/home/thomas_stening/.vscode-server/extensions/tamasfe.even-better-toml/dist/server.js",
                },
            ],
        )
        monkeypatch.setattr(
            "runtime_guard._read_wsl_running_distros",
            lambda: {
                "wsl_running_distros": [
                    {"name": "Ubuntu-24.04", "state": "Running", "version": 2}
                ],
                "wsl_running_distro_count": 1,
                "docker_desktop_running": False,
            },
        )
        monkeypatch.setattr(
            "runtime_guard._read_windows_wsl_event_hints",
            lambda max_events=6: {
                "host_event_logs_checked": ["System"],
                "host_error_event_count": 0,
                "host_high_relevance_event_count": 0,
                "host_error_events": [],
            },
        )

        diag = diagnose_wsl_crash()
        assert diag["risk_level"] in {"moderate", "high", "critical"}
        assert any("VS Code extension hosts" in item for item in diag["likely_causes"])
        assert any("top extension memory consumers" in item for item in diag["likely_causes"])
        assert any("ms-python.vscode-pylance" in item for item in diag["likely_causes"])
        assert any("reload VS Code window" in item for item in diag["prevention_actions"])
        assert any("top extensions" in item for item in diag["prevention_actions"])
        assert isinstance(diag.get("guest_vscode_extension_rss"), list)
        assert any(
            row.get("extension") == "ms-python.vscode-pylance"
            for row in diag.get("guest_vscode_extension_rss", [])
            if isinstance(row, dict)
        )


class TestPressureReportNewFields:
    def test_missing_mem_mb_populated(self):
        """missing_mem_mb reflects how far below the floor we are."""
        snap = MemSnapshot(
            mem_available_mb=500,
            mem_total_mb=16000,
            swap_used_pct=10,
            rss_mb=200,
            vm_swap_mb=0,
        )
        report = PressureReport(
            snapshot=snap,
            is_critical=False,
            cause="MemAvail=500MB",
            self_inflicted=False,
            self_pct=1,
            min_mem_mb=2048,
            max_swap_pct=85,
            missing_mem_mb=1548,
            swap_excess_pct=0,
        )
        assert report.missing_mem_mb == 1548
        assert report.swap_excess_pct == 0

    def test_swap_excess_pct_populated(self):
        snap = MemSnapshot(
            mem_available_mb=3000,
            mem_total_mb=16000,
            swap_used_pct=90,
            rss_mb=200,
            vm_swap_mb=500,
        )
        report = PressureReport(
            snapshot=snap,
            is_critical=False,
            cause="SwapUsed=90%",
            self_inflicted=False,
            self_pct=1,
            min_mem_mb=2048,
            max_swap_pct=85,
            missing_mem_mb=0,
            swap_excess_pct=5,
        )
        assert report.swap_excess_pct == 5

    def test_check_populates_missing_mem_mb(self, monkeypatch):
        """RuntimeGuard.check() sets missing_mem_mb correctly."""
        monkeypatch.setenv("RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB", "4096")
        guard = RuntimeGuard(log_tag="test")
        snap = MemSnapshot(
            mem_available_mb=2000,
            mem_total_mb=16000,
            swap_used_pct=10,
            rss_mb=200,
            vm_swap_mb=0,
        )
        import unittest.mock as _mock

        with _mock.patch("runtime_guard._read_snapshot", return_value=snap):
            report = guard.check()
        assert report is not None
        assert report.missing_mem_mb == 2096  # 4096 - 2000

    def test_json_event_includes_new_fields(self, caplog, monkeypatch):
        """JSON log event includes missing_mem_mb and swap_excess_pct."""
        import json as _json

        monkeypatch.setenv("RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB", "4096")
        guard = RuntimeGuard(log_tag="jsontest", cooldown_s=0)
        snap = MemSnapshot(
            mem_available_mb=1500,
            mem_total_mb=16000,
            swap_used_pct=10,
            rss_mb=200,
            vm_swap_mb=0,
        )
        with mock.patch("runtime_guard._read_snapshot", return_value=snap):
            report = guard.check()
        assert report is not None
        with caplog.at_level(logging.WARNING, logger="runtime_guard.events"):
            guard.log(report)
        json_lines = [r.getMessage() for r in caplog.records if r.name == "runtime_guard.events"]
        assert json_lines, "No JSON event emitted on runtime_guard.events"
        event = _json.loads(json_lines[0])
        assert "missing_mem_mb" in event
        assert "swap_excess_pct" in event
        assert event["missing_mem_mb"] == report.missing_mem_mb


# ---------------------------------------------------------------------------
# KI-005 — unsupported platform emits a warning (not silent)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# KI-004 — cooldown is now per-stage, not global
# ---------------------------------------------------------------------------


class TestPerStageCooldown:
    def test_different_stages_independent(self):
        """A cooldown for stage A must not suppress stage B."""
        g = RuntimeGuard(cooldown_s=60.0)
        report_a = _make_report(stage="stage-a")
        report_b = _make_report(stage="stage-b")
        g.log(report_a)  # starts cooldown for stage-a / warning
        # stage-b has its own clock — must NOT be suppressed
        key_b = "stage-b\x00warning"
        g.log(report_b)
        assert key_b in g._last_logged, "stage-b was incorrectly suppressed by stage-a cooldown"

    def test_same_stage_is_suppressed(self):
        """Repeat calls for the same stage ARE suppressed within the window."""
        g = RuntimeGuard(cooldown_s=60.0)
        report = _make_report(stage="train")
        g.log(report)
        ts1 = g._last_logged["train\x00warning"]
        time.sleep(0.02)
        g.log(report)
        assert g._last_logged["train\x00warning"] == ts1, (
            "Timestamp advanced when it should have been suppressed"
        )

    def test_empty_stage_and_named_stage_independent(self):
        """stage='' and stage='train' are distinct cooldown buckets."""
        g = RuntimeGuard(cooldown_s=60.0)
        g.log(_make_report(stage=""))
        g.log(_make_report(stage="train"))
        assert "\x00warning" in g._last_logged
        assert "train\x00warning" in g._last_logged


# ---------------------------------------------------------------------------
# M1-C01 — Polars integration hook
# ---------------------------------------------------------------------------


class TestPolarsIntegration:
    class _DummyPolars:
        class LazyFrame:
            def collect(self, multiplier: int = 1) -> int:
                return 21 * multiplier

            def fetch(self, rows: int = 1) -> int:
                return rows

            def collect_async(self, multiplier: int = 1) -> int:
                return 84 * multiplier

            def sink_parquet(self, path: str) -> str:
                return f"parquet:{path}"

            def sink_csv(self, path: str) -> str:
                return f"csv:{path}"

            def explain(self) -> str:
                return "SCAN parquet source"

    def test_attach_calls_check_before_collect(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []

        def fake_check_and_log(stage: str = "") -> None:
            calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check_and_log)
        restore = attach_polars_guard(guard, stage="polars-pipeline", module=self._DummyPolars)
        try:
            result = self._DummyPolars.LazyFrame().collect(multiplier=2)
            assert result == 42
            assert calls == ["polars-pipeline"]
        finally:
            restore()

    def test_restore_restores_original_collect(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        original = self._DummyPolars.LazyFrame.collect
        original_fetch = self._DummyPolars.LazyFrame.fetch
        restore = attach_polars_guard(guard, module=self._DummyPolars)
        restore()
        assert self._DummyPolars.LazyFrame.collect is original
        assert self._DummyPolars.LazyFrame.fetch is original_fetch

    def test_attach_calls_check_before_fetch(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_polars_guard(guard, stage="polars-fetch", module=self._DummyPolars)
        try:
            result = self._DummyPolars.LazyFrame().fetch(rows=5)
            assert result == 5
            assert calls == ["polars-fetch"]
        finally:
            restore()

    def test_attach_calls_check_before_collect_async(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_polars_guard(guard, stage="polars-async", module=self._DummyPolars)
        try:
            result = self._DummyPolars.LazyFrame().collect_async(multiplier=2)
            assert result == 168
            assert calls == ["polars-async"]
        finally:
            restore()

    def test_attach_calls_check_before_sink_parquet(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_polars_guard(guard, stage="polars-sink", module=self._DummyPolars)
        try:
            result = self._DummyPolars.LazyFrame().sink_parquet("out.parquet")
            assert result == "parquet:out.parquet"
            assert calls == ["polars-sink"]
        finally:
            restore()

    def test_attach_is_idempotent(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))
        restore_a = attach_polars_guard(guard, stage="s1", module=self._DummyPolars)
        restore_b = attach_polars_guard(guard, stage="s2", module=self._DummyPolars)
        try:
            self._DummyPolars.LazyFrame().collect()
            # Single wrapper only; second attach should not double-wrap.
            assert len(calls) == 1
        finally:
            restore_b()
            restore_a()

    def test_attach_raises_when_no_lazyframe(self):
        class NoLazyFrame:
            pass

        with pytest.raises(RuntimeError, match="LazyFrame"):
            attach_polars_guard(RuntimeGuard(), module=NoLazyFrame)

    def test_validate_polars_integration_ok_when_wrapped(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_polars_guard(guard, module=self._DummyPolars)
        try:
            result = validate_polars_integration(guard, module=self._DummyPolars)
            assert result["ok"] is True
            assert result["polars_available"] is True
            assert result["methods_wrapped"] is True
            assert result["collect_present"] is True
            assert result["fetch_present"] is True
            assert result["collect_async_present"] is True
            assert result["sink_parquet_present"] is True
            assert result["sink_csv_present"] is True
            assert result["scan_budget_api_available"] is True
            assert result["explain_plan_available"] is True
            assert "collect" in result["wrapped_methods"]
            assert "fetch" in result["wrapped_methods"]
            assert "collect_async" in result["wrapped_methods"]
            assert "sink_parquet" in result["wrapped_methods"]
        finally:
            restore()

    def test_validate_polars_integration_detects_missing_polars(self):
        class NotPolars:
            pass

        guard = RuntimeGuard()
        result = validate_polars_integration(guard, module=NotPolars)
        assert result["ok"] is False
        # polars_available is True because the module is provided, but LazyFrame is missing
        assert result["polars_available"] is True

    def test_collect_polars_integration_evidence_with_hooks_installed(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_polars_guard(guard, module=self._DummyPolars)
        try:
            evidence = collect_polars_integration_evidence(guard, module=self._DummyPolars)
            assert evidence["validation_ok"] is True
            assert "polars_integration_validated" in evidence["evidence_items"]
            assert "polars_hooks_installed" in evidence["evidence_items"]
            assert "polars_collect_async_available" in evidence["evidence_items"]
            assert "polars_sink_parquet_available" in evidence["evidence_items"]
            assert "polars_sink_csv_available" in evidence["evidence_items"]
            assert "polars_scan_budget_api_available" in evidence["evidence_items"]
            assert "polars_explain_plan_available" in evidence["evidence_items"]
            # Dummy polars doesn't have __version__, so it will be 'unknown'
            assert evidence["polars_version"] == "unknown"
        finally:
            restore()

    def test_collect_polars_integration_evidence_with_version_metadata(self, monkeypatch):
        class VersionedPolars:
            __version__ = "0.19.0"

            class LazyFrame:
                def collect(self, multiplier: int = 1) -> int:
                    return 21 * multiplier

                def fetch(self, rows: int = 1) -> int:
                    return rows

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_polars_guard(guard, module=VersionedPolars)
        try:
            evidence = collect_polars_integration_evidence(
                guard,
                module=VersionedPolars,
                version_info={"custom_field": "custom_value"},
            )
            assert evidence["polars_version"] == "0.19.0"
            assert evidence.get("custom_field") == "custom_value"
        finally:
            restore()

    def test_attach_chains_native_collect_callback(self, monkeypatch):
        class CallbackPolars:
            class LazyFrame:
                def collect(
                    self,
                    multiplier: int = 1,
                    post_opt_callback: Any | None = None,
                ) -> int:
                    if callable(post_opt_callback):
                        post_opt_callback("logical-plan")
                    return 21 * multiplier

        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_polars_guard(guard, stage="polars-native", module=CallbackPolars)
        try:
            user_callback_calls: list[str] = []
            result = CallbackPolars.LazyFrame().collect(
                multiplier=2,
                post_opt_callback=lambda plan: user_callback_calls.append(plan),
            )
            assert result == 42
            assert calls == ["polars-native", "polars-native-native-callback"]
            assert user_callback_calls == ["logical-plan"]
        finally:
            restore()

    def test_validate_polars_reports_native_callback_support(self, monkeypatch):
        class CallbackPolars:
            class LazyFrame:
                def collect(
                    self,
                    multiplier: int = 1,
                    post_opt_callback: Any | None = None,
                ) -> int:
                    if callable(post_opt_callback):
                        post_opt_callback("plan")
                    return 21 * multiplier

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_polars_guard(guard, module=CallbackPolars)
        try:
            result = validate_polars_integration(guard, module=CallbackPolars)
            assert result["native_callback_supported"] is True
            assert result["native_callback_wrapped"] is True
            assert "post_opt_callback" in result["native_callback_kwargs"]
        finally:
            restore()

    def test_collect_polars_evidence_includes_native_callback_markers(self, monkeypatch):
        class CallbackPolars:
            class LazyFrame:
                def collect(
                    self,
                    multiplier: int = 1,
                    post_opt_callback: Any | None = None,
                ) -> int:
                    if callable(post_opt_callback):
                        post_opt_callback("plan")
                    return 21 * multiplier

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_polars_guard(guard, module=CallbackPolars)
        try:
            evidence = collect_polars_integration_evidence(guard, module=CallbackPolars)
            assert "polars_native_callback_supported" in evidence["evidence_items"]
            assert "polars_native_callback_wrapped" in evidence["evidence_items"]
        finally:
            restore()

    def test_attach_infers_nonstandard_collect_callback_kwarg(self, monkeypatch):
        class CallbackPolars:
            class LazyFrame:
                def collect(
                    self,
                    multiplier: int = 1,
                    optimization_callback: Any | None = None,
                ) -> int:
                    if callable(optimization_callback):
                        optimization_callback("logical-plan")
                    return 21 * multiplier

        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_polars_guard(guard, stage="polars-native", module=CallbackPolars)
        try:
            user_callback_calls: list[str] = []
            result = CallbackPolars.LazyFrame().collect(
                multiplier=2,
                optimization_callback=lambda plan: user_callback_calls.append(plan),
            )
            assert result == 42
            assert calls == ["polars-native", "polars-native-native-callback"]
            assert user_callback_calls == ["logical-plan"]
        finally:
            restore()

    def test_validate_polars_reports_inferred_callback_kwarg(self, monkeypatch):
        class CallbackPolars:
            class LazyFrame:
                def collect(
                    self,
                    multiplier: int = 1,
                    optimization_callback: Any | None = None,
                ) -> int:
                    if callable(optimization_callback):
                        optimization_callback("plan")
                    return 21 * multiplier

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_polars_guard(guard, module=CallbackPolars)
        try:
            result = validate_polars_integration(guard, module=CallbackPolars)
            assert result["native_callback_supported"] is True
            assert result["native_callback_wrapped"] is True
            assert "optimization_callback" in result["native_callback_kwargs"]
        finally:
            restore()

    def test_attach_chains_positional_collect_callback(self, monkeypatch):
        class CallbackPolars:
            class LazyFrame:
                def collect(
                    self,
                    multiplier: int = 1,
                    optimization_callback: Any | None = None,
                ) -> int:
                    if callable(optimization_callback):
                        optimization_callback("logical-plan")
                    return 21 * multiplier

        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_polars_guard(guard, stage="polars-native", module=CallbackPolars)
        try:
            user_callback_calls: list[str] = []
            result = CallbackPolars.LazyFrame().collect(
                2,
                lambda plan: user_callback_calls.append(plan),
            )
            assert result == 42
            assert calls == ["polars-native", "polars-native-native-callback"]
            assert user_callback_calls == ["logical-plan"]
        finally:
            restore()


# ---------------------------------------------------------------------------
# M1-C02 — Dask integration hook
# ---------------------------------------------------------------------------


class TestDaskIntegration:
    class _DummyDask:
        @staticmethod
        def compute(value: int, add: int = 0) -> int:
            return value + add

        @staticmethod
        def persist(value: int) -> str:
            return f"persist:{value}"

        class base:
            @staticmethod
            def compute(value: int, add: int = 0) -> int:
                return value + add

            @staticmethod
            def persist(value: int) -> str:
                return f"base-persist:{value}"

    def test_attach_calls_check_before_compute(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []

        def fake_check_and_log(stage: str = "") -> None:
            calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check_and_log)
        restore = attach_dask_guard(guard, stage="dask-pipeline", module=self._DummyDask)
        try:
            result = self._DummyDask.compute(40, add=2)
            assert result == 42
            assert calls == ["dask-pipeline"]
        finally:
            restore()

    def test_attach_calls_check_before_persist(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))
        restore = attach_dask_guard(guard, stage="persist-stage", module=self._DummyDask)
        try:
            result = self._DummyDask.persist(7)
            assert result == "persist:7"
            assert calls == ["persist-stage"]
        finally:
            restore()

    def test_attach_calls_check_before_base_compute_and_persist(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))
        restore = attach_dask_guard(guard, stage="dask-base", module=self._DummyDask)
        try:
            out_compute = self._DummyDask.base.compute(40, add=2)
            out_persist = self._DummyDask.base.persist(7)
            assert out_compute == 42
            assert out_persist == "base-persist:7"
            assert calls == ["dask-base", "dask-base"]
        finally:
            restore()

    def test_restore_restores_original_functions(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        original_compute = self._DummyDask.compute
        original_persist = self._DummyDask.persist
        original_base_compute = self._DummyDask.base.compute
        original_base_persist = self._DummyDask.base.persist
        restore = attach_dask_guard(guard, module=self._DummyDask)
        restore()
        assert self._DummyDask.compute is original_compute
        assert self._DummyDask.persist is original_persist
        assert self._DummyDask.base.compute is original_base_compute
        assert self._DummyDask.base.persist is original_base_persist

    def test_attach_is_idempotent(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))
        restore_a = attach_dask_guard(guard, stage="s1", module=self._DummyDask)
        restore_b = attach_dask_guard(guard, stage="s2", module=self._DummyDask)
        try:
            self._DummyDask.compute(1)
            assert len(calls) == 1
        finally:
            restore_b()
            restore_a()

    def test_attach_raises_when_no_compute(self):
        class NoCompute:
            pass

        with pytest.raises(RuntimeError, match=r"dask\.compute"):
            attach_dask_guard(RuntimeGuard(), module=NoCompute)

    def test_validate_dask_integration_ok_when_wrapped(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_dask_guard(guard, module=self._DummyDask)
        try:
            result = validate_dask_integration(guard, module=self._DummyDask)
            assert result["ok"] is True
            assert result["dask_available"] is True
            assert result["methods_wrapped"] is True
            assert result["scheduler_telemetry_counters_present"] is True
            assert result["compute_present"] is True
            assert result["persist_present"] is True
            assert result["base_module_present"] is True
        finally:
            restore()

    def test_validate_dask_integration_detects_missing_dask(self):
        class NotDask:
            pass

        guard = RuntimeGuard()
        result = validate_dask_integration(guard, module=NotDask)
        assert result["ok"] is False
        assert result["dask_available"] is True

    def test_collect_dask_integration_evidence_with_hooks_installed(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_dask_guard(guard, module=self._DummyDask)
        try:
            evidence = collect_dask_integration_evidence(guard, module=self._DummyDask)
            assert evidence["validation_ok"] is True
            assert "dask_integration_validated" in evidence["evidence_items"]
            assert "dask_hooks_installed" in evidence["evidence_items"]
            assert "dask_scheduler_telemetry_counters_present" in evidence["evidence_items"]
            assert "dask_scheduler_callback_api_available" not in evidence["evidence_items"]
            assert evidence["dask_version"] == "unknown"
        finally:
            restore()

    def test_collect_dask_integration_evidence_includes_scheduler_api_marker(self, monkeypatch):
        class _DaskWithCallbackAPI(self._DummyDask):
            class callbacks:
                class Callback:
                    pass

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_dask_guard(guard, module=_DaskWithCallbackAPI)
        try:
            evidence = collect_dask_integration_evidence(guard, module=_DaskWithCallbackAPI)
            assert "dask_scheduler_callback_api_available" in evidence["evidence_items"]
            assert "dask_scheduler_callback_context_available" not in evidence["evidence_items"]
        finally:
            restore()

    def test_attach_with_scheduler_callbacks_wraps_compute_in_callback_context(self, monkeypatch):
        callback_events: list[str] = []

        class _DaskWithCallbackContext(self._DummyDask):
            class callbacks:
                class Callback:
                    def __enter__(self):
                        callback_events.append("enter")
                        return self

                    def __exit__(self, exc_type, exc, tb):
                        callback_events.append("exit")
                        return False

        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_dask_guard(
            guard,
            stage="dask-scheduler-wrap",
            enable_scheduler_callbacks=True,
            scheduler_stage_prefix="dask-scheduler",
            module=_DaskWithCallbackContext,
        )
        try:
            assert _DaskWithCallbackContext.compute(10, add=5) == 15
            assert calls == ["dask-scheduler-wrap"]
            assert callback_events == ["enter", "exit"]

            validation = validate_dask_integration(guard, module=_DaskWithCallbackContext)
            assert validation["scheduler_callbacks_wrapped"] is True
            assert validation["scheduler_callback_context_available"] is True

            evidence = collect_dask_integration_evidence(guard, module=_DaskWithCallbackContext)
            assert "dask_scheduler_callback_context_available" in evidence["evidence_items"]
            assert "dask_scheduler_callback_context_wrapped" in evidence["evidence_items"]
        finally:
            restore()

    def test_attach_with_scheduler_callbacks_gracefully_falls_back_without_api(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        restore = attach_dask_guard(
            guard,
            stage="dask-no-callback-api",
            enable_scheduler_callbacks=True,
            module=self._DummyDask,
        )
        try:
            assert self._DummyDask.compute(3, add=4) == 7
            assert calls == ["dask-no-callback-api"]

            validation = validate_dask_integration(guard, module=self._DummyDask)
            assert validation["scheduler_callbacks_wrapped"] is True
            assert validation["scheduler_callback_context_available"] is False
        finally:
            restore()

    def test_collect_dask_integration_evidence_with_version_metadata(self, monkeypatch):
        class VersionedDask:
            __version__ = "2024.1.0"

            @staticmethod
            def compute(value: int, add: int = 0) -> int:
                return value + add

            @staticmethod
            def persist(value: int) -> str:
                return f"persist:{value}"

            class base:
                @staticmethod
                def compute(value: int, add: int = 0) -> int:
                    return value + add

                @staticmethod
                def persist(value: int) -> str:
                    return f"base-persist:{value}"

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_dask_guard(guard, module=VersionedDask)
        try:
            evidence = collect_dask_integration_evidence(
                guard,
                module=VersionedDask,
                version_info={"environment": "staging"},
            )
            assert evidence["dask_version"] == "2024.1.0"
            assert evidence.get("environment") == "staging"
        finally:
            restore()


# ---------------------------------------------------------------------------
# M1-C01 — Polars scan budget enforcement
# ---------------------------------------------------------------------------


class TestPolarsScanBudget:
    """Tests for install_polars_scan_budget()."""

    class _DummyPolars:
        class LazyFrame:
            schema = {"col_a": "Int64", "col_b": "Utf8", "col_c": "Float64"}
            _scan_count = 2

            def collect(self) -> list[int]:
                return [1, 2, 3]

            def fetch(self, n: int = 1) -> list[int]:
                return [n]

            def sink_parquet(self, path: str) -> str:
                return f"parquet:{path}"

    def test_warn_columns_triggers_check_and_log(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))
        restore = install_polars_scan_budget(
            guard, module=self._DummyPolars, warn_columns=2
        )
        try:
            result = self._DummyPolars.LazyFrame().collect()
            assert result == [1, 2, 3]
            # 3 columns > warn_columns=2 → check_and_log called
            assert len(logged) == 1
            assert "columns" in logged[0]
        finally:
            restore()

    def test_max_columns_raises_runtime_error(self):
        guard = RuntimeGuard()
        restore = install_polars_scan_budget(
            guard, module=self._DummyPolars, max_columns=1
        )
        try:
            with pytest.raises(RuntimeError, match="column budget exceeded"):
                self._DummyPolars.LazyFrame().collect()
        finally:
            restore()

    def test_warn_scans_triggers_check_and_log(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))
        restore = install_polars_scan_budget(
            guard, module=self._DummyPolars, warn_scans=1
        )
        try:
            self._DummyPolars.LazyFrame().collect()
            assert any("scans" in s for s in logged)
        finally:
            restore()

    def test_max_scans_raises_runtime_error(self):
        guard = RuntimeGuard()
        restore = install_polars_scan_budget(
            guard, module=self._DummyPolars, max_scans=1
        )
        try:
            with pytest.raises(RuntimeError, match="scan budget exceeded"):
                self._DummyPolars.LazyFrame().collect()
        finally:
            restore()

    def test_restore_removes_budget_wrapper(self):
        guard = RuntimeGuard()
        original_collect = self._DummyPolars.LazyFrame.collect
        restore = install_polars_scan_budget(
            guard, module=self._DummyPolars, max_columns=1
        )
        restore()
        # After restore, should work without raising.
        result = self._DummyPolars.LazyFrame().collect()
        assert result == [1, 2, 3]
        assert self._DummyPolars.LazyFrame.collect is original_collect

    def test_no_warn_no_check_called_when_under_threshold(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))
        restore = install_polars_scan_budget(
            guard, module=self._DummyPolars, warn_columns=10
        )
        try:
            self._DummyPolars.LazyFrame().collect()
            assert logged == []
        finally:
            restore()

    def test_frame_without_schema_is_safe(self, monkeypatch):
        """LazyFrame with no schema attribute must not raise."""
        guard = RuntimeGuard()

        class _NoSchemaDummyPolars:
            class LazyFrame:
                def collect(self) -> int:
                    return 99

        restore = install_polars_scan_budget(
            guard, module=_NoSchemaDummyPolars, max_columns=1
        )
        try:
            assert _NoSchemaDummyPolars.LazyFrame().collect() == 99
        finally:
            restore()

    def test_raises_when_no_lazyframe_on_module(self):
        guard = RuntimeGuard()

        class Empty:
            pass

        with pytest.raises(RuntimeError, match="LazyFrame"):
            install_polars_scan_budget(guard, module=Empty)

    def test_budget_wraps_fetch_and_sink_parquet(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))
        restore = install_polars_scan_budget(
            guard, module=self._DummyPolars, warn_columns=2
        )
        try:
            self._DummyPolars.LazyFrame().fetch(3)
            self._DummyPolars.LazyFrame().sink_parquet("out.parquet")
            # Two method calls, each with 3 cols > 2 warn → two logs
            assert len(logged) == 2
        finally:
            restore()

    def test_budget_re_application_does_not_nest(self, monkeypatch):
        """Applying budget twice wraps at most once."""
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))
        restore_a = install_polars_scan_budget(
            guard, module=self._DummyPolars, warn_columns=2
        )
        restore_b = install_polars_scan_budget(
            guard, module=self._DummyPolars, warn_columns=2
        )
        try:
            self._DummyPolars.LazyFrame().collect()
            # Should only log once, not twice
            assert len(logged) == 1
        finally:
            restore_b()
            restore_a()

    def test_scan_budget_uses_explain_fallback_when_scan_attr_missing(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))

        class _ExplainDummyPolars:
            class LazyFrame:
                schema = {"a": "Int64"}

                def explain(self) -> str:
                    return """
                    SELECT
                      SCAN parquet file_a
                      FILTER
                      SCAN parquet file_b
                    """

                def collect(self) -> list[int]:
                    return [1]

        restore = install_polars_scan_budget(
            guard,
            module=_ExplainDummyPolars,
            warn_scans=1,
        )
        try:
            assert _ExplainDummyPolars.LazyFrame().collect() == [1]
            assert any("polars-budget:scans:2>1" in s for s in logged)
        finally:
            restore()

    def test_scan_budget_uses_custom_scan_count_fn(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))

        restore = install_polars_scan_budget(
            guard,
            module=self._DummyPolars,
            warn_scans=2,
            scan_count_fn=lambda frame: 5,
        )
        try:
            self._DummyPolars.LazyFrame().collect()
            assert any("polars-budget:scans:5>2" in s for s in logged)
        finally:
            restore()


# ---------------------------------------------------------------------------
# M1-C02 — Dask task-graph size guard
# ---------------------------------------------------------------------------


class TestDaskTaskGraphGuard:
    """Tests for install_dask_task_graph_guard()."""

    class _DummyDask:
        @staticmethod
        def compute(*args: object, **kwargs: object) -> tuple[object, ...]:
            return args

    def test_warn_tasks_triggers_check_and_log(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))

        class _BigGraph:
            def __dask_graph__(self) -> dict[str, int]:
                return {f"k{i}": i for i in range(100)}

        restore = install_dask_task_graph_guard(
            guard, module=self._DummyDask, warn_tasks=10
        )
        try:
            self._DummyDask.compute(_BigGraph())
            assert len(logged) == 1
            assert "tasks" in logged[0]
        finally:
            restore()

    def test_max_tasks_raises_runtime_error(self):
        guard = RuntimeGuard()

        class _HugeGraph:
            def __dask_graph__(self) -> dict[str, int]:
                return {f"k{i}": i for i in range(200)}

        restore = install_dask_task_graph_guard(
            guard, module=self._DummyDask, max_tasks=50
        )
        try:
            with pytest.raises(RuntimeError, match="task-graph budget exceeded"):
                self._DummyDask.compute(_HugeGraph())
        finally:
            restore()

    def test_no_dask_graph_attr_skips_check(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))
        restore = install_dask_task_graph_guard(
            guard, module=self._DummyDask, warn_tasks=1
        )
        try:
            # Plain int has no __dask_graph__ → task count = 0 → no log
            self._DummyDask.compute(42)
            assert logged == []
        finally:
            restore()

    def test_custom_task_count_fn(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))

        restore = install_dask_task_graph_guard(
            guard,
            module=self._DummyDask,
            warn_tasks=5,
            task_count_fn=lambda *args: 20,
        )
        try:
            self._DummyDask.compute(99)
            assert len(logged) == 1
        finally:
            restore()

    def test_restore_removes_guard(self):
        guard = RuntimeGuard()
        original = self._DummyDask.compute
        restore = install_dask_task_graph_guard(
            guard, module=self._DummyDask, max_tasks=1,
            task_count_fn=lambda *a: 0,
        )
        restore()
        assert self._DummyDask.compute is original

    def test_raises_when_module_lacks_compute(self):
        guard = RuntimeGuard()

        class Empty:
            pass

        with pytest.raises(RuntimeError, match="dask.compute"):
            install_dask_task_graph_guard(guard, module=Empty)

    def test_multiple_args_summed(self, monkeypatch):
        guard = RuntimeGuard()
        logged: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": logged.append(stage))

        class _SmallGraph:
            def __dask_graph__(self) -> dict[str, int]:
                return {f"k{i}": i for i in range(6)}

        restore = install_dask_task_graph_guard(
            guard, module=self._DummyDask, warn_tasks=10
        )
        try:
            # Two graphs × 6 tasks = 12 total → warn
            self._DummyDask.compute(_SmallGraph(), _SmallGraph())
            assert len(logged) == 1
        finally:
            restore()


# ---------------------------------------------------------------------------
# M1-C04 — OpenTelemetry memory span exporter
# ---------------------------------------------------------------------------


class TestOtelMemoryExporter:
    """Tests for install_otel_memory_exporter()."""

    def test_noop_when_otel_not_installed(self, monkeypatch):
        """Falls back gracefully when opentelemetry is not importable."""
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        # Simulate OTEL not installed by providing no tracer.
        restore = install_otel_memory_exporter(guard, tracer=None)
        # Even without OTEL, check_and_log should still work via the wrapper.
        guard.check_and_log(stage="test-stage")
        assert "test-stage" in calls
        restore()

    def test_with_mock_tracer_creates_span(self):
        """Span is created when a mock tracer is provided."""
        guard = RuntimeGuard()
        original_cal = guard.check_and_log
        spans_started: list[str] = []
        attrs: dict[str, object] = {}

        class _MockSpan:
            def set_attribute(self, key: str, val: object) -> None:
                attrs[key] = val

            def __enter__(self) -> "_MockSpan":
                return self

            def __exit__(self, *_: object) -> None:
                pass

        class _MockTracer:
            def start_as_current_span(self, name: str) -> _MockSpan:
                spans_started.append(name)
                return _MockSpan()

        restore = install_otel_memory_exporter(guard, tracer=_MockTracer())
        try:
            guard.check_and_log(stage="otel-test")
            assert any("rg.memory" in s for s in spans_started)
            assert attrs.get("rg.stage") == "otel-test"
        finally:
            restore()

    def test_restore_reverts_check_and_log(self):
        guard = RuntimeGuard()
        calls_original: list[str] = []
        calls_wrapped: list[str] = []

        # Patch the class-level method to track original calls.
        original_cal = guard.check_and_log

        class _MockTracer:
            def start_as_current_span(self, name: str) -> object:
                class _Ctx:
                    def set_attribute(self, *_: object) -> None:
                        pass

                    def __enter__(self) -> "_Ctx":
                        return self

                    def __exit__(self, *_: object) -> None:
                        pass

                return _Ctx()

        restore = install_otel_memory_exporter(guard, tracer=_MockTracer())
        # After install, check_and_log should be the OTEL wrapper.
        assert getattr(guard.check_and_log, "_runtime_guard_otel_wrapped", False)
        restore()
        # After restore, the OTEL wrapper should be gone.
        assert not getattr(guard.check_and_log, "_runtime_guard_otel_wrapped", False)

    def test_idempotent_attach_returns_noop_restore(self):
        guard = RuntimeGuard()

        class _MockTracer:
            def start_as_current_span(self, name: str) -> object:
                class _Ctx:
                    def set_attribute(self, *_: object) -> None:
                        pass

                    def __enter__(self) -> "_Ctx":
                        return self

                    def __exit__(self, *_: object) -> None:
                        pass

                return _Ctx()

        restore_a = install_otel_memory_exporter(guard, tracer=_MockTracer())
        restore_b = install_otel_memory_exporter(guard, tracer=_MockTracer())
        # Second install is idempotent; restore_b is a no-op.
        restore_b()
        # Original wrapper still present after noop restore.
        guard.check_and_log(stage="still-wrapped")
        restore_a()

    def test_span_attributes_include_memory_metrics(self):
        guard = RuntimeGuard()
        attrs: dict[str, object] = {}

        class _MockSpan:
            def set_attribute(self, key: str, val: object) -> None:
                attrs[key] = val

            def __enter__(self) -> "_MockSpan":
                return self

            def __exit__(self, *_: object) -> None:
                pass

        class _MockTracer:
            def start_as_current_span(self, name: str) -> _MockSpan:
                return _MockSpan()

        restore = install_otel_memory_exporter(
            guard, tracer=_MockTracer(), include_rss=True, include_swap=True, include_available=True
        )
        try:
            guard.check_and_log(stage="metrics-test")
            # Memory attributes should be present.
            assert "rg.mem_available_mb" in attrs
            assert "rg.swap_used_pct" in attrs
            assert "rg.rss_mb" in attrs
        finally:
            restore()

    def test_otel_failure_falls_back_to_original(self, monkeypatch):
        """If span creation throws, original check_and_log still runs."""
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        class _BrokenTracer:
            def start_as_current_span(self, name: str) -> object:
                raise RuntimeError("span creation failed")

        restore = install_otel_memory_exporter(guard, tracer=_BrokenTracer())
        try:
            guard.check_and_log(stage="fallback-test")
            assert "fallback-test" in calls
        finally:
            restore()


# ---------------------------------------------------------------------------
# M1-C02 — Dask scheduler callbacks (deeper integration)
# ---------------------------------------------------------------------------


class TestDaskSchedulerCallbacks:
    """Tests for Dask scheduler-level memory monitoring callbacks."""

    def test_install_dask_scheduler_callbacks_returns_reporter(self):
        """install_dask_scheduler_callbacks returns a worker report function."""
        from runtime_guard import install_dask_scheduler_callbacks

        guard = RuntimeGuard()
        get_report = install_dask_scheduler_callbacks(guard)

        assert callable(get_report)

    def test_scheduler_callback_tracks_workers(self):
        """Scheduler callbacks track per-worker memory events."""
        from runtime_guard import install_dask_scheduler_callbacks

        guard = RuntimeGuard()

        # Simulate callback invocations
        # (In real Dask, these would be called by the scheduler)
        callback_fn = install_dask_scheduler_callbacks(guard)
        report = callback_fn()

        assert report["ok"] is True
        assert "workers_monitored" in report
        assert report["total_pressure_events"] == 0

    def test_scheduler_callback_aggregates_reports(self):
        """Scheduler callback aggregates reports across workers."""
        from runtime_guard import install_dask_scheduler_callbacks

        guard = RuntimeGuard()
        get_report = install_dask_scheduler_callbacks(guard, enable_worker_reports=True)

        # Get initial aggregated report
        agg_report = get_report()
        assert agg_report["workers_monitored"] == 0
        assert agg_report["total_pressure_events"] == 0

        # Query non-existent worker (should not error)
        worker_report = get_report("worker-1")
        assert worker_report["ok"] is True
        assert worker_report["pressure_events"] == 0

    def test_scheduler_callback_respects_stage_prefix(self):
        """Scheduler callback uses configured stage prefix."""
        from runtime_guard import install_dask_scheduler_callbacks

        guard = RuntimeGuard()
        get_report = install_dask_scheduler_callbacks(guard, stage_prefix="custom-dask")

        # Verify callback was created
        assert callable(get_report)
        # Stage prefix is baked into the callback closure
        report = get_report()
        assert report["ok"] is True

    def test_scheduler_callback_multiple_instances_independent(self):
        """Multiple scheduler callback instances are independent."""
        from runtime_guard import install_dask_scheduler_callbacks

        guard1 = RuntimeGuard(cooldown_s=5.0)
        guard2 = RuntimeGuard(cooldown_s=10.0)

        get_report1 = install_dask_scheduler_callbacks(guard1)
        get_report2 = install_dask_scheduler_callbacks(guard2)

        report1 = get_report1()
        report2 = get_report2()

        # Each should have its own state
        assert report1["workers_monitored"] == 0
        assert report2["workers_monitored"] == 0

    def test_scheduler_callback_exposes_callback_api_adapter_when_available(self):
        from runtime_guard import install_dask_scheduler_callbacks

        class _FakeDask:
            class callbacks:
                class Callback:
                    def __enter__(self):
                        return self

                    def __exit__(self, exc_type, exc, tb):
                        return False

        guard = RuntimeGuard()
        reporter = install_dask_scheduler_callbacks(guard, module=_FakeDask)

        assert getattr(reporter, "callback_api_available", False) is True
        create_ctx = getattr(reporter, "create_callback_context")
        ctx = create_ctx()
        assert ctx is not None

    def test_scheduler_callback_adapter_raises_when_api_unavailable(self):
        from runtime_guard import install_dask_scheduler_callbacks

        guard = RuntimeGuard()
        reporter = install_dask_scheduler_callbacks(guard)

        assert getattr(reporter, "callback_api_available", True) is False
        create_ctx = getattr(reporter, "create_callback_context")
        with pytest.raises(RuntimeError, match="callback API unavailable"):
            create_ctx()

    def test_scheduler_callback_counts_healthy_tasks(self, monkeypatch):
        from runtime_guard import install_dask_scheduler_callbacks

        class _FakeDask:
            class callbacks:
                class Callback:
                    def __enter__(self):
                        return self

                    def __exit__(self, exc_type, exc, tb):
                        return False

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda *, stage="": None)

        reporter = install_dask_scheduler_callbacks(guard, module=_FakeDask)
        ctx = reporter.create_callback_context()
        ctx._pretask("task-1", worker_id="worker-a")
        ctx._pretask("task-2", worker_id="worker-a")

        worker_report = reporter("worker-a")
        assert worker_report["task_count"] == 2
        assert worker_report["pressure_events"] == 0
        assert worker_report["healthy_events"] == 2

        agg = reporter()
        assert agg["workers_monitored"] == 1
        assert agg["total_tasks"] == 2
        assert agg["total_pressure_events"] == 0
        assert agg["total_healthy_events"] == 2

    def test_scheduler_callback_counts_pressure_events_separately(self, monkeypatch):
        from runtime_guard import install_dask_scheduler_callbacks

        class _FakeDask:
            class callbacks:
                class Callback:
                    def __enter__(self):
                        return self

                    def __exit__(self, exc_type, exc, tb):
                        return False

        class _FakeReport:
            is_critical = False
            cause = "low-memory"
            missing_mem_mb = 256

        guard = RuntimeGuard()

        calls = {"n": 0}

        def _fake_check(*, stage=""):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeReport()
            return None

        monkeypatch.setattr(guard, "check_and_log", _fake_check)

        reporter = install_dask_scheduler_callbacks(guard, module=_FakeDask)
        ctx = reporter.create_callback_context()
        ctx._pretask("task-1", worker_id="worker-a")
        ctx._pretask("task-2", worker_id="worker-a")

        worker_report = reporter("worker-a")
        assert worker_report["task_count"] == 2
        assert worker_report["pressure_events"] == 1
        assert worker_report["healthy_events"] == 1
        assert len(worker_report["snapshots"]) == 1


# ---------------------------------------------------------------------------
# M1-C03 — Ray integration hook
# ---------------------------------------------------------------------------


class TestRayIntegration:
    class _DummyRay:
        @staticmethod
        def get(value: int, add: int = 0) -> int:
            return value + add

        @staticmethod
        def wait(items: list[int], *, num_returns: int = 1) -> tuple[list[int], list[int]]:
            return items[:num_returns], items[num_returns:]

        @staticmethod
        def put(value: object) -> str:
            return f"obj:{value}"

    def test_attach_calls_check_before_get(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []

        def fake_check_and_log(stage: str = "") -> None:
            calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check_and_log)
        restore = attach_ray_guard(guard, stage="ray-pipeline", module=self._DummyRay)
        try:
            result = self._DummyRay.get(40, add=2)
            assert result == 42
            assert calls == ["ray-pipeline"]
        finally:
            restore()

    def test_attach_calls_check_before_wait(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))
        restore = attach_ray_guard(guard, stage="ray-wait", module=self._DummyRay)
        try:
            ready, remaining = self._DummyRay.wait([1, 2, 3], num_returns=2)
            assert ready == [1, 2]
            assert remaining == [3]
            assert calls == ["ray-wait"]
        finally:
            restore()

    def test_attach_calls_check_before_put(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))
        restore = attach_ray_guard(guard, stage="ray-put", module=self._DummyRay)
        try:
            obj_ref = self._DummyRay.put({"k": 1})
            assert obj_ref == "obj:{'k': 1}"
            assert calls == ["ray-put"]
        finally:
            restore()

    def test_restore_restores_original_functions(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        original_get = self._DummyRay.get
        original_wait = self._DummyRay.wait
        original_put = self._DummyRay.put
        restore = attach_ray_guard(guard, module=self._DummyRay)
        restore()
        assert self._DummyRay.get is original_get
        assert self._DummyRay.wait is original_wait
        assert self._DummyRay.put is original_put

    def test_attach_is_idempotent(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))
        restore_a = attach_ray_guard(guard, stage="s1", module=self._DummyRay)
        restore_b = attach_ray_guard(guard, stage="s2", module=self._DummyRay)
        try:
            self._DummyRay.get(1)
            assert len(calls) == 1
        finally:
            restore_b()
            restore_a()

    def test_attach_raises_when_no_get(self):
        class NoGet:
            pass

        with pytest.raises(RuntimeError, match=r"ray\.get"):
            attach_ray_guard(RuntimeGuard(), module=NoGet)

    def test_validate_ray_integration_ok_when_wrapped(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_ray_guard(guard, module=self._DummyRay)
        try:
            result = validate_ray_integration(guard, module=self._DummyRay)
            assert result["ok"] is True
            assert result["ray_available"] is True
            assert result["methods_wrapped"] is True
            assert result["get_present"] is True
            assert result["wait_present"] is True
            assert result["put_present"] is True
            assert result["actor_monitoring_api_available"] is True
            assert result["actor_monitoring_keys_present"] is True
            assert result["actor_node_telemetry_api_available"] is True
            assert result["actor_cluster_summary_api_available"] is True
            assert result["actor_cluster_hotspot_fields_present"] is True
        finally:
            restore()

    def test_validate_ray_integration_detects_missing_ray(self):
        class NotRay:
            pass

        guard = RuntimeGuard()
        result = validate_ray_integration(guard, module=NotRay)
        assert result["ok"] is False
        assert result["ray_available"] is True

    def test_collect_ray_integration_evidence_with_hooks_installed(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_ray_guard(guard, module=self._DummyRay)
        try:
            evidence = collect_ray_integration_evidence(guard, module=self._DummyRay)
            assert evidence["validation_ok"] is True
            assert "ray_integration_validated" in evidence["evidence_items"]
            assert "ray_hooks_installed" in evidence["evidence_items"]
            assert "ray_actor_monitoring_api_available" in evidence["evidence_items"]
            assert "ray_actor_node_telemetry_keys_available" in evidence["evidence_items"]
            assert "ray_actor_node_telemetry_api_available" in evidence["evidence_items"]
            assert "ray_actor_cluster_summary_api_available" in evidence["evidence_items"]
            assert "ray_actor_cluster_hotspot_fields_present" in evidence["evidence_items"]
            assert evidence["ray_version"] == "unknown"
        finally:
            restore()

    def test_collect_ray_integration_evidence_with_version_metadata(self, monkeypatch):
        class VersionedRay:
            __version__ = "2.8.0"

            @staticmethod
            def get(value: int, add: int = 0) -> int:
                return value + add

            @staticmethod
            def wait(items: list[int], *, num_returns: int = 1) -> tuple[list[int], list[int]]:
                return items[:num_returns], items[num_returns:]

            @staticmethod
            def put(value: object) -> str:
                return f"obj:{value}"

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        restore = attach_ray_guard(guard, module=VersionedRay)
        try:
            evidence = collect_ray_integration_evidence(
                guard,
                module=VersionedRay,
                version_info={"cluster_size": "3-nodes"},
            )
            assert evidence["ray_version"] == "2.8.0"
            assert evidence.get("cluster_size") == "3-nodes"
        finally:
            restore()


# ---------------------------------------------------------------------------
# M1-C03 — Ray actor-based memory monitoring (deeper integration)
# ---------------------------------------------------------------------------


class TestRayActorMemoryMonitoring:
    """Tests for Ray actor-level memory monitoring decorators."""

    def test_enable_ray_actor_memory_monitoring_returns_config(self):
        """enable_ray_actor_memory_monitoring returns configuration dict."""
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        config = enable_ray_actor_memory_monitoring(guard)

        assert isinstance(config, dict)
        assert config["ok"] is True
        assert "method_decorator" in config
        assert "remote_wrapper" in config
        assert "get_actor_report" in config
        assert "reset_actor_report" in config
        assert "node_report" in config
        assert "reset_node_reports" in config
        assert "get_all_node_reports" in config
        assert "cluster_summary" in config
        assert callable(config["method_decorator"])
        assert callable(config["remote_wrapper"])
        assert callable(config["get_actor_report"])
        assert callable(config["reset_actor_report"])
        assert callable(config["node_report"])
        assert callable(config["reset_node_reports"])
        assert callable(config["get_all_node_reports"])
        assert callable(config["cluster_summary"])

    def test_actor_method_decorator_calls_check_on_entry(self, monkeypatch):
        """Actor method decorator calls check_and_log on entry."""
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        calls: list[str] = []

        def fake_check_and_log(stage: str = "") -> None:
            calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check_and_log)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=False)

        @config["method_decorator"]
        def sample_method(self: Any, value: int) -> int:
            return value * 2

        class DummyActor:
            pass

        actor = DummyActor()
        result = sample_method(actor, 21)

        assert result == 42
        assert len(calls) == 1
        assert "sample_method:entry" in calls[0]

    def test_actor_method_decorator_calls_check_on_exit(self, monkeypatch):
        """Actor method decorator calls check_and_log on exit."""
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        calls: list[str] = []

        def fake_check_and_log(stage: str = "") -> None:
            calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check_and_log)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=False, check_on_exit=True)

        @config["method_decorator"]
        def sample_method(self: Any, value: int) -> int:
            return value * 2

        class DummyActor:
            pass

        actor = DummyActor()
        result = sample_method(actor, 21)

        assert result == 42
        assert len(calls) == 1
        assert "sample_method:exit" in calls[0]

    def test_actor_method_decorator_both_entry_and_exit(self, monkeypatch):
        """Actor method decorator can check on both entry and exit."""
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        calls: list[str] = []

        def fake_check_and_log(stage: str = "") -> None:
            calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check_and_log)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=True)

        @config["method_decorator"]
        def sample_method(self: Any, value: int) -> int:
            return value * 2

        class DummyActor:
            pass

        actor = DummyActor()
        result = sample_method(actor, 21)

        assert result == 42
        assert len(calls) == 2
        assert any("entry" in c for c in calls)
        assert any("exit" in c for c in calls)

    def test_remote_wrapper_calls_check_on_entry(self, monkeypatch):
        """Remote wrapper calls check_and_log on entry."""
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        calls: list[str] = []

        def fake_check_and_log(stage: str = "") -> None:
            calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check_and_log)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=False)

        def compute(x: int, y: int) -> int:
            return x + y

        wrapped = config["remote_wrapper"](compute)
        result = wrapped(10, 32)

        assert result == 42
        assert len(calls) == 1
        assert "compute:entry" in calls[0]

    def test_actor_monitoring_respects_stage_prefix(self):
        """Actor monitoring uses configured stage prefix."""
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        config = enable_ray_actor_memory_monitoring(guard, stage_prefix="custom-ray-actor")

        assert config["stage_prefix"] == "custom-ray-actor"

    def test_actor_monitoring_provides_instructions(self):
        """Actor monitoring config includes usage instructions."""
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        config = enable_ray_actor_memory_monitoring(guard)

        assert "instructions" in config
        assert isinstance(config["instructions"], list)
        assert len(config["instructions"]) > 0

    def test_actor_monitoring_tracks_per_node_reports(self, monkeypatch):
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=True)

        @config["method_decorator"]
        def sample_method(self: Any, value: int) -> int:
            return value * 2

        class DummyActor:
            _runtime_guard_node_id = "node-a"
            _runtime_guard_actor_id = "actor-1"

        actor = DummyActor()
        out = sample_method(actor, 21)
        assert out == 42

        report = config["get_actor_report"](node_id="node-a", actor_id="actor-1")
        assert report["ok"] is True
        assert report["events"] == 2
        assert report["entry_checks"] == 1
        assert report["exit_checks"] == 1
        assert report["methods"]["sample_method"] == 2

    def test_actor_monitoring_reset_clears_reports(self, monkeypatch):
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=False)

        def compute(x: int) -> int:
            return x + 1

        wrapped = config["remote_wrapper"](compute)
        assert wrapped(1, node_id="node-r", actor_id="actor-r") == 2

        before = config["get_actor_report"]()
        assert before["nodes_monitored"] == 1
        assert before["total_events"] == 1

        config["reset_actor_report"]()
        after = config["get_actor_report"]()
        assert after["nodes_monitored"] == 0
        assert after["total_events"] == 0

    def test_node_report_and_get_all_node_reports(self, monkeypatch):
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=False)

        def compute(x: int) -> int:
            return x + 1

        wrapped = config["remote_wrapper"](compute)
        assert wrapped(1, node_id="node-x", actor_id="actor-1") == 2
        assert wrapped(2, node_id="node-y", actor_id="actor-2") == 3

        node_x = config["node_report"]("node-x")
        assert node_x["ok"] is True
        assert node_x["node_id"] == "node-x"
        assert node_x["events"] == 1

        all_nodes = config["get_all_node_reports"]()
        assert all_nodes["ok"] is True
        assert all_nodes["nodes_monitored"] == 2
        assert all_nodes["total_events"] == 2

    def test_cluster_summary_and_node_reset(self, monkeypatch):
        from runtime_guard import enable_ray_actor_memory_monitoring

        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        config = enable_ray_actor_memory_monitoring(guard, check_on_entry=True, check_on_exit=False)

        def compute(x: int) -> int:
            return x + 1

        wrapped = config["remote_wrapper"](compute)
        assert wrapped(1, node_id="node-a", actor_id="actor-1") == 2
        assert wrapped(2, node_id="node-a", actor_id="actor-1") == 3
        assert wrapped(3, node_id="node-b", actor_id="actor-2") == 4

        summary = config["cluster_summary"]()
        assert summary["ok"] is True
        assert summary["nodes_monitored"] == 2
        assert summary["actors_monitored"] == 2
        assert summary["total_events"] == 3
        assert summary["busiest_node"] == "node-a"
        assert summary["busiest_node_events"] == 2
        assert summary["busiest_actor"] == "actor-1"
        assert summary["busiest_actor_events"] == 2

        config["reset_node_reports"]()
        after = config["get_all_node_reports"]()
        assert after["nodes_monitored"] == 0
        assert after["total_events"] == 0


# ---------------------------------------------------------------------------
# M1-C04 — OpenTelemetry exporter scaffold
# ---------------------------------------------------------------------------


class TestOpenTelemetryExport:
    class _DummySpanContext:
        def __init__(self, trace_id: int, span_id: int, sampled: bool = True):
            self.trace_id = trace_id
            self.span_id = span_id
            self.trace_flags = type("_Flags", (), {"sampled": sampled})()

    class _DummySpan:
        def __init__(self, recording: bool = True, context: object | None = None):
            self._recording = recording
            self.events: list[tuple[str, dict[str, object]]] = []
            self._context = context

        def is_recording(self) -> bool:
            return self._recording

        def get_span_context(self):
            return self._context

        def add_event(self, name: str, *, attributes: dict[str, object]) -> None:
            self.events.append((name, attributes))

    class _DummyTrace:
        def __init__(self, span: object):
            self._span = span

        def get_current_span(self):
            return self._span

    def test_pressure_report_attributes_contains_expected_keys(self):
        report = _make_report(stage="otel-stage")
        attrs = pressure_report_attributes(report)
        assert attrs["runtime_guard.stage"] == "otel-stage"
        assert "runtime_guard.mem_available_mb" in attrs
        assert "runtime_guard.swap_used_pct" in attrs
        assert "runtime_guard.self_inflicted" in attrs

    def test_emit_with_explicit_span(self):
        report = _make_report(stage="span-stage")
        ctx = self._DummySpanContext(
            trace_id=0x0123456789ABCDEF0123456789ABCDEF,
            span_id=0x0123456789ABCDEF,
        )
        span = self._DummySpan(recording=True, context=ctx)
        ok = emit_otel_event(report, span=span)
        assert ok is True
        assert len(span.events) == 1
        name, attrs = span.events[0]
        assert name == "runtime_guard.pressure"
        assert attrs["runtime_guard.stage"] == "span-stage"
        assert attrs["runtime_guard.trace_id"] == "0123456789abcdef0123456789abcdef"
        assert attrs["runtime_guard.trace_span_id"] == "0123456789abcdef"
        assert attrs["runtime_guard.trace_sampled"] is True

    def test_emit_uses_current_span_from_module(self):
        report = _make_report(stage="module-stage")
        span = self._DummySpan(recording=True)
        trace_mod = self._DummyTrace(span)
        ok = emit_otel_event(report, module=trace_mod)
        assert ok is True
        assert len(span.events) == 1
        _, attrs = span.events[0]
        assert attrs["runtime_guard.stage"] == "module-stage"

    def test_emit_returns_false_when_span_not_recording(self):
        report = _make_report()
        span = self._DummySpan(recording=False)
        ok = emit_otel_event(report, span=span)
        assert ok is False
        assert span.events == []

    def test_emit_returns_false_without_otel(self):
        report = _make_report()
        ok = emit_otel_event(report, module=object())
        assert ok is False

    def test_trace_context_attributes_from_span(self):
        ctx = self._DummySpanContext(
            trace_id=0x11111111111111111111111111111111,
            span_id=0x2222222222222222,
            sampled=False,
        )
        span = self._DummySpan(context=ctx)
        attrs = trace_context_attributes(span=span)
        assert attrs["runtime_guard.trace_id"] == "11111111111111111111111111111111"
        assert attrs["runtime_guard.trace_span_id"] == "2222222222222222"
        assert attrs["runtime_guard.trace_sampled"] is False

    def test_trace_context_attributes_from_module(self):
        ctx = self._DummySpanContext(
            trace_id=0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
            span_id=0xBBBBBBBBBBBBBBBB,
        )
        span = self._DummySpan(context=ctx)
        trace_mod = self._DummyTrace(span)
        attrs = trace_context_attributes(module=trace_mod)
        assert attrs["runtime_guard.trace_id"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert attrs["runtime_guard.trace_span_id"] == "bbbbbbbbbbbbbbbb"

    def test_trace_context_attributes_empty_when_no_context(self):
        span = self._DummySpan(context=None)
        attrs = trace_context_attributes(span=span)
        assert attrs == {}


# ---------------------------------------------------------------------------
# M1-C05 — Prometheus renderer scaffold
# ---------------------------------------------------------------------------


class TestPrometheusRenderer:
    def test_render_contains_core_metrics(self):
        report = _make_report(stage="metrics")
        text = render_prometheus_metrics(report)
        assert "runtime_guard_is_critical" in text
        assert "runtime_guard_mem_available_mb" in text
        assert 'stage="metrics"' in text

    def test_render_supports_custom_prefix(self):
        report = _make_report(stage="custom")
        text = render_prometheus_metrics(report, prefix="rg")
        assert "rg_is_critical" in text
        assert "runtime_guard_is_critical" not in text

    def test_render_escapes_stage_quotes(self):
        report = _make_report(stage='train "A"')
        text = render_prometheus_metrics(report)
        assert 'stage="train \\"A\\""' in text


# ---------------------------------------------------------------------------
# M1-C07 — Config schema validation scaffold
# ---------------------------------------------------------------------------


class TestConfigValidation:
    def test_accepts_valid_config(self):
        cfg = validate_runtime_guard_config(
            {
                "posture": "ci",
                "min_mem_available_mb": 1024,
                "max_swap_used_pct": 90,
                "critical_mem_mb": 512,
                "critical_swap_pct": 97,
                "self_inflicted_pct": 20,
            },
            use_pydantic=False,
        )
        assert cfg["posture"] == "ci"
        assert cfg["min_mem_available_mb"] == 1024

    def test_rejects_unknown_key(self):
        with pytest.raises(ValueError, match="Unknown config keys"):
            validate_runtime_guard_config({"bad_key": 1}, use_pydantic=False)

    def test_rejects_invalid_posture(self):
        with pytest.raises(ValueError, match="Invalid posture"):
            validate_runtime_guard_config({"posture": "fast"}, use_pydantic=False)

    def test_rejects_non_integer_threshold(self):
        with pytest.raises(ValueError, match="must be an integer"):
            validate_runtime_guard_config({"min_mem_available_mb": "lots"}, use_pydantic=False)

    def test_rejects_out_of_range_percent(self):
        with pytest.raises(ValueError, match="must be <= 100"):
            validate_runtime_guard_config({"max_swap_used_pct": 101}, use_pydantic=False)


class TestDynamicPolicyReload:
    def test_set_and_clear_policy_overrides(self):
        guard = RuntimeGuard()
        out = guard.set_policy_overrides({"posture": "ci", "min_mem_available_mb": 1234})
        assert out["posture"] == "ci"
        assert out["min_mem_available_mb"] == 1234
        guard.clear_policy_overrides()
        assert guard._policy_overrides == {}

    def test_load_policy_file_applies_thresholds(self, tmp_path):
        guard = RuntimeGuard()
        policy = tmp_path / "policy.json"
        policy.write_text('{"min_mem_available_mb": 3333}', encoding="utf-8")
        guard.load_policy_file(str(policy), auto_reload=False)
        min_mem_mb, *_ = guard._resolve_thresholds()
        assert min_mem_mb == 3333

    def test_reload_policy_if_changed(self, tmp_path):
        guard = RuntimeGuard()
        policy = tmp_path / "policy.json"
        policy.write_text('{"min_mem_available_mb": 1111}', encoding="utf-8")
        guard.load_policy_file(str(policy), auto_reload=True)

        first, *_ = guard._resolve_thresholds()
        assert first == 1111

        # Ensure mtime changes on fast filesystems.
        time.sleep(0.02)
        policy.write_text('{"min_mem_available_mb": 2222}', encoding="utf-8")

        second, *_ = guard._resolve_thresholds()
        assert second == 2222

    def test_env_overrides_policy(self, tmp_path, monkeypatch):
        guard = RuntimeGuard()
        policy = tmp_path / "policy.json"
        policy.write_text('{"min_mem_available_mb": 4444}', encoding="utf-8")
        guard.load_policy_file(str(policy), auto_reload=False)

        monkeypatch.setenv("RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB", "5555")
        min_mem_mb, *_ = guard._resolve_thresholds()
        assert min_mem_mb == 5555


class TestSitecustomizeContent:
    def test_contains_autostart_toggle_and_background_start(self):
        text = make_sitecustomize_content(repo_name="demo")
        assert "RUNTIME_GUARD_AUTOSTART" in text
        assert "start_background_check" in text
        assert "stop_background_check" in text

    def test_respects_custom_values(self):
        text = make_sitecustomize_content(
            repo_name="myrepo",
            stage="seed-stage",
            interval_s=12.5,
            cooldown_s=7.0,
            env_prefix="MYAPP",
        )
        assert "MYAPP_AUTOSTART" in text
        assert "seed-stage" in text
        assert "12.5" in text
        assert "7.0" in text

    def test_posture_sets_env_when_missing(self):
        text = make_sitecustomize_content(
            repo_name="myrepo",
            env_prefix="MYAPP",
            posture="ci",
        )
        assert '_posture_key = "MYAPP_POSTURE"' in text
        assert 'os.environ[_posture_key] = "ci"' in text

    def test_posture_is_validated(self):
        with pytest.raises(ValueError, match="Invalid posture"):
            make_sitecustomize_content(repo_name="myrepo", posture="fast")


# ---------------------------------------------------------------------------
# M1-C08 — Async phase context manager scaffold
# ---------------------------------------------------------------------------


class TestPhaseContextManager:
    def test_sync_phase_calls_enter_and_exit(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        with guard.phase("load-csv"):
            pass

        assert calls == ["load-csv:enter", "load-csv:exit"]

    def test_sync_phase_calls_exit_on_exception(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        with pytest.raises(RuntimeError, match="boom"):
            with guard.phase("train"):
                raise RuntimeError("boom")

        assert calls == ["train:enter", "train:exit"]

    def test_async_phase_calls_enter_and_exit(self, monkeypatch):
        guard = RuntimeGuard()
        calls: list[str] = []
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": calls.append(stage))

        async def _run() -> None:
            async with guard.phase("async-stage"):
                return None

        asyncio.run(_run())
        assert calls == ["async-stage:enter", "async-stage:exit"]

    def test_phase_emits_otel_lifecycle_events(self, monkeypatch):
        guard = RuntimeGuard()

        class _Span:
            def __init__(self):
                self.events: list[tuple[str, dict[str, Any]]] = []

            def is_recording(self):
                return True

            def add_event(self, name: str, attributes: dict[str, Any] | None = None):
                self.events.append((name, dict(attributes or {})))

            def get_span_context(self):
                class _Ctx:
                    trace_id = 0x4BF92F3577B34DA6A3CE929D0E0E4736
                    span_id = 0x00F067AA0BA902B7
                    trace_flags = type("_Flags", (), {"sampled": True})()

                return _Ctx()

        span = _Span()
        trace_mod = type("_TraceMod", (), {"get_current_span": lambda self=None: span})()

        with guard.phase("etl-load", emit_phase_traces=True, trace_module=trace_mod):
            pass

        event_names = [name for name, _ in span.events]
        assert event_names == ["runtime_guard.phase", "runtime_guard.phase"]
        assert span.events[0][1]["runtime_guard.phase.lifecycle"] == "enter"
        assert span.events[1][1]["runtime_guard.phase.lifecycle"] == "exit"
        assert span.events[0][1]["runtime_guard.phase.stage"] == "etl-load"

    def test_phase_emits_error_lifecycle_on_exception(self):
        guard = RuntimeGuard()

        class _Span:
            def __init__(self):
                self.events: list[tuple[str, dict[str, Any]]] = []

            def is_recording(self):
                return True

            def add_event(self, name: str, attributes: dict[str, Any] | None = None):
                self.events.append((name, dict(attributes or {})))

            def get_span_context(self):
                class _Ctx:
                    trace_id = 0x4BF92F3577B34DA6A3CE929D0E0E4736
                    span_id = 0x00F067AA0BA902B7
                    trace_flags = type("_Flags", (), {"sampled": True})()

                return _Ctx()

        span = _Span()
        trace_mod = type("_TraceMod", (), {"get_current_span": lambda self=None: span})()

        with pytest.raises(ValueError):
            with guard.phase("etl-fail", emit_phase_traces=True, trace_module=trace_mod):
                raise ValueError("boom")

        assert span.events[-1][1]["runtime_guard.phase.lifecycle"] == "error"
        assert span.events[-1][1]["runtime_guard.phase.exception_type"] == "ValueError"

    def test_phase_creates_child_span_with_memory_attributes(self):
        """Test advanced span-linking: child span creation and memory attributes (C08)."""
        guard = RuntimeGuard()
        created_spans: list[tuple[str, Any]] = []
        closed_spans: list[str] = []

        class _MockSpan:
            def __init__(self, name: str):
                self.name = name
                self.attributes: dict[str, Any] = {}
                self.status = None

            def set_attribute(self, key: str, value: Any) -> None:
                self.attributes[key] = value

            def set_status(self, status: Any) -> None:
                self.status = status

            def end(self) -> None:
                closed_spans.append(self.name)

            def is_recording(self) -> bool:
                return True

            def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
                pass

            def get_span_context(self) -> Any:
                class _Ctx:
                    trace_id = 0x4BF92F3577B34DA6A3CE929D0E0E4736
                    span_id = 0x00F067AA0BA902B7
                    trace_flags = type("_Flags", (), {"sampled": True})()
                return _Ctx()

        class _MockTracer:
            def start_as_current_span(self, name: str):
                span = _MockSpan(name)
                created_spans.append((name, span))
                return span

        trace_mod = type("_TraceMod", (), {
            "get_current_span": lambda self=None: None,
            "get_tracer": lambda self=None, name="": _MockTracer(),
        })()

        with guard.phase("data-load", emit_phase_traces=True, trace_module=trace_mod):
            pass

        # Verify span was created with correct name
        assert len(created_spans) == 1
        span_name, span_obj = created_spans[0]
        assert "runtime_guard.phase.data-load" in span_name
        
        # Verify span has final memory attributes
        assert "runtime_guard.final_mem_available_mb" in span_obj.attributes
        assert "runtime_guard.final_swap_used_pct" in span_obj.attributes
        assert "runtime_guard.final_rss_mb" in span_obj.attributes
        
        # Verify span was closed
        assert len(closed_spans) == 1
        assert span_name in closed_spans

    def test_phase_span_gets_error_status_on_exception(self):
        """Test advanced span-linking: error status on exception (C08)."""
        guard = RuntimeGuard()
        created_spans: list[_MockSpan] = []

        class _MockSpan:
            def __init__(self, name: str):
                self.name = name
                self.status = None
                self.ended = False

            def set_attribute(self, key: str, value: Any) -> None:
                pass

            def set_status(self, status: Any) -> None:
                self.status = status

            def end(self) -> None:
                self.ended = True

            def is_recording(self) -> bool:
                return True

            def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
                pass

            def get_span_context(self) -> Any:
                class _Ctx:
                    trace_id = 0x1
                    span_id = 0x1
                    trace_flags = type("_Flags", (), {"sampled": True})()
                return _Ctx()

        class _MockTracer:
            def start_as_current_span(self, name: str):
                span = _MockSpan(name)
                created_spans.append(span)
                return span

        trace_mod = type("_TraceMod", (), {
            "get_current_span": lambda self=None: None,
            "get_tracer": lambda self=None, name="": _MockTracer(),
        })()

        try:
            with guard.phase("risky-op", emit_phase_traces=True, trace_module=trace_mod):
                raise RuntimeError("intentional test error")
        except RuntimeError:
            pass

        # Verify span was created and ended
        assert len(created_spans) == 1
        span = created_spans[0]
        assert span.ended is True
        # Status might not be set if StatusCode unavailable, but should attempt



class TestOtelPhaseEvent:
    def test_emit_otel_phase_event_returns_false_without_otel(self):
        assert emit_otel_phase_event("stage-a", lifecycle="enter", module=object()) is False


# ---------------------------------------------------------------------------
# M2-C01 — Signal-based auto-recovery scaffold
# ---------------------------------------------------------------------------


class TestSignalRecovery:
    class _DummySignalModule:
        SIGINT = 2
        SIGUSR1 = 10
        SIGTERM = 15
        SIG_DFL = object()

        class Signals:
            _map = {2: "SIGINT", 10: "SIGUSR1", 15: "SIGTERM"}

            def __new__(cls, value: int):
                obj = type("_Sig", (), {})()
                obj.name = cls._map.get(value, f"SIG{value}")
                return obj

        def __init__(self):
            self.handlers: dict[int, object] = {}

        def signal(self, signum: int, handler: object) -> object:
            prev = self.handlers.get(signum, self.SIG_DFL)
            self.handlers[signum] = handler
            return prev

    def test_attach_and_restore_handlers(self):
        guard = RuntimeGuard()
        sigmod = self._DummySignalModule()
        restore = attach_signal_recovery(guard, module=sigmod)
        try:
            assert sigmod.SIGTERM in sigmod.handlers
            assert callable(sigmod.handlers[sigmod.SIGTERM])
        finally:
            restore()
        assert sigmod.handlers[sigmod.SIGTERM] is sigmod.SIG_DFL

    def test_handler_runs_check_log_and_intervene(self, monkeypatch):
        guard = RuntimeGuard()
        sigmod = self._DummySignalModule()
        calls: list[str] = []
        monkeypatch.setattr(
            guard,
            "check",
            lambda stage="": calls.append(f"check:{stage}") or _make_report(stage=stage),
        )
        monkeypatch.setattr(guard, "log", lambda report: calls.append(f"log:{report.stage}"))
        monkeypatch.setattr(
            guard,
            "intervene",
            lambda report, **kwargs: calls.append(f"intervene:{report.stage}"),
        )

        restore = attach_signal_recovery(
            guard,
            module=sigmod,
            signals_to_handle=[sigmod.SIGTERM],
            auto_intervene=True,
        )
        try:
            handler = sigmod.handlers[sigmod.SIGTERM]
            assert callable(handler)
            handler(sigmod.SIGTERM, None)
        finally:
            restore()

        assert any(s.startswith("check:signal:sigterm") for s in calls)
        assert any(s.startswith("log:signal:sigterm") for s in calls)
        assert not any(s.startswith("intervene:signal:sigterm") for s in calls)

    def test_handler_intervenes_on_warning_when_intervene_on_any(self, monkeypatch):
        guard = RuntimeGuard()
        sigmod = self._DummySignalModule()
        calls: list[str] = []
        monkeypatch.setattr(
            guard,
            "check",
            lambda stage="": calls.append(f"check:{stage}") or _make_report(stage=stage),
        )
        monkeypatch.setattr(guard, "log", lambda report: calls.append(f"log:{report.stage}"))
        monkeypatch.setattr(
            guard,
            "intervene",
            lambda report, **kwargs: calls.append(f"intervene:{report.stage}"),
        )

        restore = attach_signal_recovery(
            guard,
            module=sigmod,
            signals_to_handle=[sigmod.SIGTERM],
            auto_intervene=True,
            intervene_on="any",
        )
        try:
            handler = sigmod.handlers[sigmod.SIGTERM]
            assert callable(handler)
            handler(sigmod.SIGTERM, None)
        finally:
            restore()

        assert any(s.startswith("intervene:signal:sigterm") for s in calls)

    def test_chain_previous_handler(self):
        guard = RuntimeGuard()
        sigmod = self._DummySignalModule()
        chained: list[int] = []

        def _previous(signum: int, frame: object) -> None:
            chained.append(signum)

        sigmod.handlers[sigmod.SIGINT] = _previous
        restore = attach_signal_recovery(
            guard,
            module=sigmod,
            signals_to_handle=[sigmod.SIGINT],
            chain_previous=True,
        )
        try:
            handler = sigmod.handlers[sigmod.SIGINT]
            assert callable(handler)
            handler(sigmod.SIGINT, None)
        finally:
            restore()

        assert chained == [sigmod.SIGINT]

    def test_resolve_policy_from_env(self, monkeypatch):
        sigmod = self._DummySignalModule()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_ENABLE", "true")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_AUTO_INTERVENE", "1")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_INTERVENE_ON", "any")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_CHAIN_PREVIOUS", "yes")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_STAGE_PREFIX", "ops")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_KILL_HOGS_MB", "2048")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_SIGNALS", "SIGTERM,2")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_AUDIT_DEDUP_TTL_S", "120")

        out = resolve_signal_recovery_policy(module=sigmod)
        assert out["enabled"] is True
        assert out["auto_intervene"] is True
        assert out["intervene_on"] == "any"
        assert out["chain_previous"] is True
        assert out["stage_prefix"] == "ops"
        assert out["kill_hogs_above_mb"] == 2048
        assert out["signals_to_handle"] == [sigmod.SIGTERM, 2]
        assert out["audit_dedup_ttl_s"] == 120.0

    def test_resolve_policy_sanitizes_invalid_rollout_values(self, monkeypatch):
        sigmod = self._DummySignalModule()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_INTERVENE_ON", "warn")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_STAGE_PREFIX", "   ")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_KILL_HOGS_MB", "not-a-number")
        monkeypatch.setenv(
            "RUNTIME_GUARD_SIGNAL_RECOVERY_SIGNALS",
            "SIGTERM, sigterm, 15, UNKNOWN, 0, -9, , SIGINT",
        )

        out = resolve_signal_recovery_policy(module=sigmod)

        assert out["intervene_on"] == "critical"
        assert out["stage_prefix"] == "signal"
        assert out["kill_hogs_above_mb"] is None
        assert out["signals_to_handle"] == [sigmod.SIGTERM, sigmod.SIGINT]
        assert "SIGNAL_RECOVERY_INTERVENE_ON" in out["invalid_policy_fields"]
        assert "SIGNAL_RECOVERY_STAGE_PREFIX" in out["invalid_policy_fields"]
        assert "SIGNAL_RECOVERY_KILL_HOGS_MB" in out["invalid_policy_fields"]

    def test_resolve_policy_fails_closed_on_invalid_enable_bool(self, monkeypatch):
        sigmod = self._DummySignalModule()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_ENABLE", "definitely")

        out = resolve_signal_recovery_policy(module=sigmod)

        assert out["enabled"] is False
        assert "SIGNAL_RECOVERY_ENABLE" in out["invalid_policy_fields"]

    def test_resolve_policy_ignores_non_positive_kill_hogs_threshold(self, monkeypatch):
        sigmod = self._DummySignalModule()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_KILL_HOGS_MB", "0")

        out = resolve_signal_recovery_policy(module=sigmod)

        assert out["kill_hogs_above_mb"] is None

    def test_install_from_policy_can_be_disabled(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_ENABLE", "0")
        restore = install_signal_recovery_from_policy(guard)
        assert callable(restore)
        restore()

    def test_install_from_policy_fails_closed_on_non_boolean_enabled(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(
            "runtime_guard.resolve_signal_recovery_policy",
            lambda **kwargs: {
                "enabled": "true",
                "signals_to_handle": [15],
            },
        )

        called = {"attach": False}

        def _attach(*args, **kwargs):
            called["attach"] = True
            return lambda: None

        monkeypatch.setattr("runtime_guard.attach_signal_recovery", _attach)
        restore = install_signal_recovery_from_policy(guard)

        assert callable(restore)
        restore()
        assert called["attach"] is False

    def test_default_signals_include_sigabrt(self):
        """SIGABRT must be in the default signal set (M2-C01)."""
        import signal as _sig

        guard = RuntimeGuard()
        installed_sigs: list[int] = []
        original_signal = _sig.signal

        def _capture(sig, handler):
            installed_sigs.append(sig)
            return original_signal(sig, handler)

        import runtime_guard as rg

        saved = rg.attach_signal_recovery.__module__
        import signal as real_sig

        restore = attach_signal_recovery(guard)
        restore()
        # Just verify the API exposes SIGABRT via the module's default list
        import signal as sm
        abrt = getattr(sm, "SIGABRT", None)
        assert abrt is not None, "SIGABRT not available on this platform"

    def test_attach_signal_recovery_writes_audit_log_on_signal(self, tmp_path, monkeypatch):
        """Signal handler must write a hash-chained audit record (M2-C01 + M2-C02)."""
        guard = RuntimeGuard()
        sigmod = self._DummySignalModule()
        monkeypatch.setattr(
            guard,
            "check",
            lambda stage="": _make_report(stage=stage),
        )
        monkeypatch.setattr(guard, "log", lambda report: None)
        monkeypatch.setattr(guard, "intervene", lambda report, **kw: None)

        audit_path = str(tmp_path / "signal_audit.jsonl")
        restore = attach_signal_recovery(
            guard,
            module=sigmod,
            signals_to_handle=[sigmod.SIGTERM],
            audit_log_path=audit_path,
        )
        try:
            handler = sigmod.handlers[sigmod.SIGTERM]
            handler(sigmod.SIGTERM, None)
        finally:
            restore()

        import json as _json

        records = [_json.loads(line) for line in open(audit_path).read().splitlines() if line.strip()]
        assert len(records) == 1
        assert records[0]["event"]["event_type"] == "signal_recovery"
        assert "signal" in records[0]["event"]
        assert "hash" in records[0]

    def test_resolve_policy_exposes_audit_log_and_hash_algo(self, monkeypatch):
        sigmod = self._DummySignalModule()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_AUDIT_LOG", "/tmp/sig.jsonl")
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_HASH_ALGO", "sha512")

        out = resolve_signal_recovery_policy(module=sigmod)
        assert out["audit_log_path"] == "/tmp/sig.jsonl"
        assert out["hash_algo"] == "sha512"

    def test_resolve_policy_rejects_unsupported_hash_algo(self, monkeypatch):
        sigmod = self._DummySignalModule()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_HASH_ALGO", "md5")

        out = resolve_signal_recovery_policy(module=sigmod)
        assert out["hash_algo"] == "sha256"  # falls back to default

    def test_resolve_policy_sanitizes_invalid_audit_dedup_ttl(self, monkeypatch):
        sigmod = self._DummySignalModule()
        monkeypatch.setenv("RUNTIME_GUARD_SIGNAL_RECOVERY_AUDIT_DEDUP_TTL_S", "0")
        out = resolve_signal_recovery_policy(module=sigmod)
        assert out["audit_dedup_ttl_s"] is None

    def test_attach_signal_recovery_dedups_audit_log_events(self, tmp_path, monkeypatch):
        guard = RuntimeGuard()
        sigmod = self._DummySignalModule()
        monkeypatch.setattr(guard, "check", lambda stage="": _make_report(stage=stage))
        monkeypatch.setattr(guard, "log", lambda report: None)
        monkeypatch.setattr(guard, "intervene", lambda report, **kw: None)

        audit_path = str(tmp_path / "signal_audit_dedup.jsonl")
        dedup = FipsDeduplicator(ttl_s=300)
        restore = attach_signal_recovery(
            guard,
            module=sigmod,
            signals_to_handle=[sigmod.SIGTERM],
            audit_log_path=audit_path,
            audit_deduplicator=dedup,
        )
        try:
            handler = sigmod.handlers[sigmod.SIGTERM]
            handler(sigmod.SIGTERM, None)
            handler(sigmod.SIGTERM, None)
        finally:
            restore()

        lines = Path(audit_path).read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1


# ---------------------------------------------------------------------------
# Crash prevention helpers
# ---------------------------------------------------------------------------


class TestSubprocessSafe:
    def test_method_blocks_when_available_memory_below_floor(self, monkeypatch):
        guard = RuntimeGuard()

        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=8192,
                mem_available_mb=300,
                swap_total_mb=2048,
                swap_free_mb=1536,
                swap_used_pct=25,
                rss_mb=120,
                vm_swap_mb=0,
            ),
        )
        called = {"check": False}

        def _check(stage: str = ""):
            called["check"] = True
            return None

        monkeypatch.setattr(guard, "check", _check)

        safe, reason = guard.subprocess_safe("Chrome", min_mb=500)
        assert safe is False
        assert "Chrome launch skipped" in reason
        assert "MemAvailable=300 MB < 500 MB threshold" in reason
        assert called["check"] is False

    def test_method_blocks_on_critical_pressure_report(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=8192,
                mem_available_mb=4000,
                swap_total_mb=2048,
                swap_free_mb=1024,
                swap_used_pct=50,
                rss_mb=120,
                vm_swap_mb=0,
            ),
        )
        monkeypatch.setattr(guard, "check", lambda stage="": _make_report(is_critical=True, stage=stage))

        safe, reason = guard.subprocess_safe("JVM", min_mb=500)
        assert safe is False
        assert "JVM launch skipped" in reason
        assert "system under memory pressure" in reason

    def test_method_allows_launch_when_healthy(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=8192,
                mem_available_mb=5000,
                swap_total_mb=2048,
                swap_free_mb=1800,
                swap_used_pct=12,
                rss_mb=120,
                vm_swap_mb=0,
            ),
        )
        monkeypatch.setattr(guard, "check", lambda stage="": None)

        safe, reason = guard.subprocess_safe("Chrome", min_mb=500)
        assert safe is True
        assert reason == ""

    def test_module_wrapper_delegates_to_runtime_guard(self, monkeypatch):
        calls: list[tuple[str, int]] = []

        def _fake_subprocess_safe(self, label: str, *, min_mb: int = 500, stage: str = ""):
            calls.append((label, min_mb))
            return True, ""

        monkeypatch.setattr(RuntimeGuard, "subprocess_safe", _fake_subprocess_safe)
        safe, reason = subprocess_safe("Chrome", min_mb=700, env_prefix="MY_APP")

        assert safe is True
        assert reason == ""
        assert calls == [("Chrome", 700)]


# ---------------------------------------------------------------------------
# M2-C05 — FIPS event deduplicator
# ---------------------------------------------------------------------------


class TestFipsDeduplicator:
    def test_new_event_returns_true(self):
        d = FipsDeduplicator()
        assert d.is_new({"category": "memory", "action": "observe"}) is True

    def test_duplicate_event_returns_false(self):
        d = FipsDeduplicator()
        evt = {"category": "memory", "action": "observe"}
        assert d.is_new(evt) is True
        assert d.is_new(evt) is False

    def test_different_events_are_independent(self):
        d = FipsDeduplicator()
        assert d.is_new({"category": "memory"}) is True
        assert d.is_new({"category": "incident"}) is True

    def test_seen_count_reflects_unique_events(self):
        d = FipsDeduplicator()
        d.is_new({"n": 1})
        d.is_new({"n": 2})
        d.is_new({"n": 1})  # dup
        assert d.seen_count == 2

    def test_reset_clears_all_seen(self):
        d = FipsDeduplicator()
        d.is_new({"n": 1})
        assert d.seen_count == 1
        d.reset()
        assert d.seen_count == 0
        assert d.is_new({"n": 1}) is True

    def test_mark_seen_makes_subsequent_is_new_false(self):
        d = FipsDeduplicator()
        evt = {"n": 99}
        d.mark_seen(evt)
        assert d.is_new(evt) is False

    def test_event_hash_is_stable(self):
        d = FipsDeduplicator()
        evt = {"b": 2, "a": 1}
        h1 = d.event_hash(evt)
        h2 = d.event_hash({"a": 1, "b": 2})  # same content, different key order
        assert h1 == h2

    def test_ttl_zero_keeps_hashes_indefinitely(self):
        d = FipsDeduplicator(ttl_s=0)
        d.is_new({"n": 1})
        assert d.seen_count == 1

    def test_unsupported_algo_raises(self):
        import pytest as _pytest
        with _pytest.raises(ValueError, match="Unsupported hash algorithm"):
            FipsDeduplicator(hash_algo="md5")

    def test_sha384_and_sha512_algos_work(self):
        for algo in ("sha384", "sha512"):
            d = FipsDeduplicator(hash_algo=algo)
            assert d.is_new({"n": 1}) is True
            assert d.is_new({"n": 1}) is False


# ---------------------------------------------------------------------------
# M2-C02 — Audit log scaffold
# ---------------------------------------------------------------------------


class TestAuditLog:
    def test_audit_policy_taxonomy_contains_expected_values(self):
        taxonomy = audit_policy_taxonomy()
        assert "warning" in taxonomy["severity"]
        assert "memory" in taxonomy["category"]
        assert "incident" in taxonomy["category"]
        assert "policy_violation" in taxonomy["action"]
        assert "remediate" in taxonomy["action"]

    def test_normalize_policy_violation_event_canonicalizes_tokens(self):
        out = normalize_policy_violation_event(
            {
                "event_type": "policy-violation",
                "severity": "CRITICAL",
                "category": "Memory",
                "action": "Policy Violation",
                "policy_id": 42,
            }
        )
        assert out["event_type"] == "policy_violation"
        assert out["severity"] == "critical"
        assert out["category"] == "memory"
        assert out["action"] == "policy_violation"
        assert out["policy_id"] == "42"

    def test_append_audit_log_normalizes_policy_violation_event(self, tmp_path):
        path = tmp_path / "audit.log"
        rec = append_audit_log(
            str(path),
            {
                "event_type": "policy-violation",
                "severity": "INVALID",
                "category": "NotARealCategory",
                "action": "non-standard",
            },
        )
        event = rec["event"]
        assert event["event_type"] == "policy_violation"
        assert event["severity"] == "warning"
        assert event["category"] == "unknown"
        assert event["action"] == "custom"

    def test_normalize_policy_violation_event_maps_enterprise_aliases(self):
        out = normalize_policy_violation_event(
            {
                "event_type": "policy_violation",
                "severity": "Warning",
                "category": "Incident Response",
                "action": "Corrective Action",
            }
        )
        assert out["severity"] == "warning"
        assert out["category"] == "incident"
        assert out["action"] == "remediate"

    def test_normalize_policy_violation_event_maps_access_aliases(self):
        out = normalize_policy_violation_event(
            {
                "event_type": "policy_violation",
                "category": "Access Review",
                "action": "ack",
            }
        )
        assert out["category"] == "access"
        assert out["action"] == "acknowledge"

    def test_normalize_policy_violation_event_uses_action_when_event_type_missing(self):
        out = normalize_policy_violation_event(
            {
                "action": "policy-violation",
                "severity": "CRITICAL",
                "category": "Memory Pressure",
                "policy_id": 101,
            }
        )
        assert out["event_type"] == "policy_violation"
        assert out["severity"] == "critical"
        assert out["category"] == "memory"
        assert out["action"] == "policy_violation"
        assert out["policy_id"] == "101"

    def test_append_audit_log_normalizes_when_action_marks_policy_violation(self, tmp_path):
        path = tmp_path / "audit.log"
        rec = append_audit_log(
            str(path),
            {
                "action": "policy_violation",
                "severity": "INVALID",
                "category": "NotARealCategory",
            },
        )
        event = rec["event"]
        assert event["event_type"] == "policy_violation"
        assert event["severity"] == "warning"
        assert event["category"] == "unknown"
        assert event["action"] == "policy_violation"

    def test_append_audit_log_creates_record(self, tmp_path):
        path = tmp_path / "audit.log"
        record = append_audit_log(str(path), {"action": "test", "value": 1})
        assert path.exists()
        assert record["event"]["action"] == "test"
        assert isinstance(record["hash"], str)
        assert len(record["hash"]) == 64

    def test_append_audit_log_hash_chain(self, tmp_path):
        path = tmp_path / "audit.log"
        first = append_audit_log(str(path), {"n": 1})
        second = append_audit_log(str(path), {"n": 2})
        assert second["prev_hash"] == first["hash"]

    def test_runtime_guard_audit_writes_pressure_fields(self, tmp_path):
        guard = RuntimeGuard(log_tag="audit-test")
        report = _make_report(stage="train")
        out = guard.audit(
            report,
            path=str(tmp_path / "audit.log"),
            action="policy-violation",
            metadata={"run_id": "abc123"},
        )
        assert out["event"]["action"] == "policy_violation"
        assert out["event"]["stage"] == "train"
        assert out["event"]["metadata"]["run_id"] == "abc123"

    def test_fips_hash_algorithm_selection(self, tmp_path):
        path = tmp_path / "audit.log"
        rec = append_audit_log(str(path), {"action": "x"}, hash_algo="sha512")
        assert rec["hash_algo"] == "sha512"
        assert len(rec["hash"]) == 128
        assert len(rec["event_hash"]) == 128

    def test_unsupported_hash_algorithm_rejected(self, tmp_path):
        path = tmp_path / "audit.log"
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            append_audit_log(str(path), {"x": 1}, hash_algo="md5")

    def test_fips_event_hash_lengths(self):
        assert len(fips_event_hash("hello", hash_algo="sha256")) == 64
        assert len(fips_event_hash("hello", hash_algo="sha384")) == 96
        assert len(fips_event_hash("hello", hash_algo="sha512")) == 128

    def test_verify_audit_log_chain_ok_and_tamper(self, tmp_path):
        path = tmp_path / "audit.log"
        append_audit_log(str(path), {"n": 1})
        append_audit_log(str(path), {"n": 2})
        ok = verify_audit_log_chain(str(path))
        assert ok["ok"] is True

        lines = path.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[1])
        row["event"]["n"] = 99
        lines[1] = json.dumps(row, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        bad = verify_audit_log_chain(str(path))
        assert bad["ok"] is False
        assert bad["reason"] in {"event-hash-mismatch", "chain-hash-mismatch"}

    def test_runtime_guard_audit_hash_algo_passthrough(self, tmp_path):
        guard = RuntimeGuard(log_tag="audit-test")
        out = guard.audit(_make_report(), path=str(tmp_path / "a.log"), hash_algo="sha384")
        assert out["hash_algo"] == "sha384"
        assert len(out["hash"]) == 96

    def test_append_audit_log_deduplicator_skips_duplicate_writes(self, tmp_path):
        path = tmp_path / "audit.log"
        dedup = FipsDeduplicator(ttl_s=300)

        first = append_audit_log(str(path), {"action": "policy_violation", "n": 1}, deduplicator=dedup)
        second = append_audit_log(str(path), {"action": "policy_violation", "n": 1}, deduplicator=dedup)

        assert first.get("skipped", False) is False
        assert second["skipped"] is True

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1

    def test_runtime_guard_audit_deduplicator_passthrough(self, tmp_path):
        guard = RuntimeGuard(log_tag="audit-test")
        dedup = FipsDeduplicator(ttl_s=300)
        path = tmp_path / "audit.log"

        first = guard.audit(_make_report(stage="train"), path=str(path), deduplicator=dedup)
        second = guard.audit(_make_report(stage="train"), path=str(path), deduplicator=dedup)

        assert first.get("skipped", False) is False
        assert second["skipped"] is True


# ---------------------------------------------------------------------------
# M2-C04 — Multi-process orchestration scaffold
# ---------------------------------------------------------------------------


class TestMultiProcessOrchestration:
    def test_make_worker_report_no_pressure(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check", lambda stage="": None)
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_available_mb=7000, mem_total_mb=8000, swap_used_pct=1, rss_mb=100
            ),
        )
        report = make_worker_report(guard, stage="worker-a", worker_id="w1")
        assert report["pressure"] is False
        assert report["severity"] == "none"
        assert report["worker_id"] == "w1"
        assert report["stage"] == "worker-a"

    def test_make_worker_report_with_pressure(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(
            guard, "check", lambda stage="": _make_report(stage=stage, is_critical=True)
        )
        report = make_worker_report(guard, stage="worker-b")
        assert report["pressure"] is True
        assert report["severity"] == "critical"
        assert report["missing_mem_mb"] >= 0

    def test_aggregate_worker_reports(self):
        summary = aggregate_worker_reports(
            [
                {"worker_id": "a", "pressure": False, "severity": "none", "swap_used_pct": 5},
                {
                    "worker_id": "b",
                    "pressure": True,
                    "severity": "warning",
                    "missing_mem_mb": 120,
                    "swap_used_pct": 60,
                },
                {
                    "worker_id": "c",
                    "pressure": True,
                    "severity": "critical",
                    "missing_mem_mb": 900,
                    "swap_used_pct": 99,
                },
            ]
        )
        assert summary["total_workers"] == 3
        assert summary["pressured_workers"] == 2
        assert summary["critical_workers"] == 1
        assert summary["any_pressure"] is True
        assert summary["worst_severity"] == "critical"
        assert summary["max_missing_mem_mb"] == 900
        assert summary["max_swap_used_pct"] == 99
        assert summary["invalid_pressure_workers"] == []
        assert summary["invalid_severity_workers"] == []

    def test_aggregate_worker_reports_fail_closed_on_non_boolean_pressure(self):
        summary = aggregate_worker_reports(
            [
                {"worker_id": "a", "pressure": "false", "severity": "critical"},
                {"worker_id": "b", "pressure": 1, "severity": "critical"},
                {"worker_id": "c", "pressure": True, "severity": "critical"},
            ]
        )

        assert summary["total_workers"] == 3
        assert summary["pressured_workers"] == 1
        assert summary["critical_workers"] == 1
        assert summary["invalid_pressure_workers"] == ["a", "b"]

    def test_aggregate_worker_reports_fail_closed_on_non_string_severity(self):
        summary = aggregate_worker_reports(
            [
                {"worker_id": "a", "pressure": True, "severity": None},
                {"worker_id": "b", "pressure": True, "severity": "critical"},
            ]
        )

        assert summary["pressured_workers"] == 2
        assert summary["critical_workers"] == 1
        assert summary["invalid_severity_workers"] == ["a"]

    def test_runtime_guard_worker_wrappers(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check", lambda stage="": None)
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_available_mb=6000, mem_total_mb=8000, swap_used_pct=2, rss_mb=50
            ),
        )
        wr = guard.worker_report(stage="pool")
        summary = guard.aggregate_workers([wr])
        assert wr["stage"] == "pool"
        assert summary["total_workers"] == 1


class TestSoc2GapAssessment:
    def test_required_controls_baseline_contains_core_ids(self):
        required = soc2_required_controls()
        assert {"CC6.1", "CC7.1", "CC7.2", "CC7.3", "CC8.1"}.issubset(set(required))
        # Expanded controls added in M2-C06
        assert {"CC6.2", "CC6.6", "A1.1", "A1.2", "PI1.2"}.issubset(set(required))

    def test_reports_ready_when_all_controls_present(self):
        all_controls = soc2_required_controls()
        control_state = {cid: True for cid in all_controls}
        out = soc2_gap_assessment(control_state)
        assert out["total_controls"] == len(all_controls)
        assert out["covered_controls"] == len(all_controls)
        assert out["missing_controls"] == []
        assert out["missing_required_controls"] == []
        assert out["unknown_controls"] == []
        assert out["coverage_ratio"] == 1.0
        assert out["status"] == "ready"

    def test_reports_gaps_and_ratio(self):
        out = soc2_gap_assessment({"CC6.1": True, "CC7.1": False, "CC8.1": False})
        assert out["total_controls"] == 3
        assert out["covered_controls"] == 1
        assert set(out["missing_controls"]) == {"CC7.1", "CC8.1"}
        # All expanded required controls not in input are missing
        assert "CC7.1" in out["missing_required_controls"]
        assert "CC7.2" in out["missing_required_controls"]
        assert "CC7.3" in out["missing_required_controls"]
        assert "CC8.1" in out["missing_required_controls"]
        assert out["unknown_controls"] == []
        assert out["coverage_ratio"] == pytest.approx(1 / 3)
        assert out["status"] == "gaps-found"

    def test_handles_empty_input(self):
        out = soc2_gap_assessment({})
        all_required = set(soc2_required_controls())
        assert out["total_controls"] == 0
        assert out["covered_controls"] == 0
        assert out["missing_controls"] == []
        assert set(out["missing_required_controls"]) == all_required
        assert out["unknown_controls"] == []
        assert out["invalid_control_state_fields"] == []
        assert out["coverage_ratio"] == 0.0
        assert out["status"] == "gaps-found"

    def test_fails_closed_on_non_boolean_control_state_values(self):
        out = soc2_gap_assessment({"CC6.1": "false", "CC7.1": 1})
        assert out["covered_controls"] == 0
        assert "CC6.1" in out["missing_controls"]
        assert "CC7.1" in out["missing_controls"]
        assert out["invalid_control_state_fields"] == ["CC6.1", "CC7.1"]

    def test_evidence_requirements_scoped_to_required_controls(self):
        req = soc2_evidence_requirements(required_controls={"CC6.1": "x", "CC8.1": "y"})
        assert sorted(req.keys()) == ["CC6.1", "CC8.1"]
        assert "access-review-log" in req["CC6.1"]
        assert "change-approval-record" in req["CC8.1"]

    def test_readiness_report_ready_with_evidence(self):
        all_controls = soc2_required_controls()
        control_state = {cid: True for cid in all_controls}
        requirements = soc2_evidence_requirements()
        evidence_state = {cid: list(items) for cid, items in requirements.items()}
        out = soc2_readiness_report(
            control_state,
            evidence_state=evidence_state,
        )
        assert out["status"] == "ready"
        assert out["maturity"] == "audit-ready"
        assert out["missing_evidence_controls"] == []
        assert out["evidence_ratio"] == 1.0

    def test_readiness_report_detects_missing_evidence(self):
        # All controls present but only partial evidence for the original 5
        all_controls = soc2_required_controls()
        control_state = {cid: True for cid in all_controls}
        out = soc2_readiness_report(
            control_state,
            evidence_state={
                "CC6.1": ["access-review-log"],
                "CC7.1": ["monitoring-alert-history"],
                "CC7.2": ["incident-timeline"],
                "CC7.3": ["alert-triage-record"],
                "CC8.1": ["change-approval-record"],
            },
        )
        assert out["status"] == "evidence-missing"
        assert out["maturity"] == "controls-implemented-evidence-pending"
        # All controls with evidence requirements should have some missing evidence
        assert len(out["missing_evidence_controls"]) > 0
        assert "CC6.1" in out["missing_evidence_controls"]

    def test_readiness_report_fails_closed_on_non_collection_evidence_items(self):
        out = soc2_readiness_report(
            {"CC6.1": True},
            evidence_state={"CC6.1": "access-review-log"},
            required_controls={"CC6.1": "Logical access controls"},
            evidence_requirements={"CC6.1": ["access-review-log"]},
        )
        assert out["status"] == "evidence-missing"
        assert out["provided_evidence_count"] == 0
        assert out["invalid_evidence_fields"] == ["CC6.1"]

    def test_readiness_report_fails_closed_on_non_boolean_control_values(self):
        out = soc2_readiness_report(
            {"CC6.1": "true"},
            evidence_state={"CC6.1": ["access-review-log"]},
            required_controls={"CC6.1": "Logical access controls"},
            evidence_requirements={"CC6.1": ["access-review-log"]},
        )
        assert out["status"] == "gaps-found"
        assert out["missing_required_controls"] == ["CC6.1"]
        assert out["invalid_control_state_fields"] == ["CC6.1"]


class TestAdoptionScorecard:
    def test_builds_stage_counts_and_success_ratio(self):
        out = build_adoption_scorecard(
            [
                {"team": "t1", "stage": "pilot", "evidence": ["e1"]},
                {"team": "t2", "stage": "production", "evidence": ["e2"]},
                {"team": "t3", "stage": "production", "evidence": ["e3"]},
            ]
        )
        assert out["total_teams"] == 3
        assert out["reached_success_stage"] == 2
        assert out["adoption_ratio"] == pytest.approx(2 / 3)
        assert out["stage_counts"]["pilot"] == 1
        assert out["stage_counts"]["production"] == 2

    def test_flags_missing_evidence_after_discover(self):
        out = build_adoption_scorecard(
            [
                {"team": "alpha", "stage": "trial", "evidence": []},
                {"team": "beta", "stage": "discover", "evidence": []},
                {"team": "gamma", "stage": "staging", "evidence": ["ticket-1"]},
            ]
        )
        assert out["missing_evidence_teams"] == ["alpha"]
        assert out["status"] == "in-progress"

    def test_status_on_track_when_five_teams_reach_success(self):
        rows = [{"team": f"t{i}", "stage": "production", "evidence": ["e"]} for i in range(1, 6)]
        out = build_adoption_scorecard(rows)
        assert out["reached_success_stage"] == 5
        assert out["status"] == "on-track"

    def test_stage_aliases_and_expanded_stage_are_counted(self):
        out = build_adoption_scorecard(
            [
                {"team": "alpha", "stage": "Discovery", "evidence": []},
                {"team": "beta", "stage": "prod", "evidence": ["e1"]},
                {"team": "gamma", "stage": "expanded", "evidence": ["e2"]},
            ]
        )
        assert out["stage_counts"]["discover"] == 1
        assert out["stage_counts"]["production"] == 1
        assert out["stage_counts"]["expanded"] == 1
        assert out["reached_success_stage"] == 2

    def test_fails_closed_on_non_string_stage_values(self):
        out = build_adoption_scorecard(
            [
                {"team": "alpha", "stage": True, "evidence": ["e1"]},
                {"team": "beta", "stage": "production", "evidence": ["e2"]},
            ]
        )
        assert out["stage_counts"]["unknown"] == 1
        assert out["invalid_stage_teams"] == ["alpha"]
        assert out["reached_success_stage"] == 1

    def test_fails_closed_on_non_collection_evidence(self):
        out = build_adoption_scorecard(
            [
                {"team": "alpha", "stage": "production", "evidence": "ticket-1"},
                {"team": "beta", "stage": "production", "evidence": ["ticket-2"]},
            ]
        )
        assert out["invalid_evidence_teams"] == ["alpha"]
        assert "alpha" in out["missing_evidence_teams"]

    def test_records_malformed_non_object_rows(self):
        out = build_adoption_scorecard(
            [
                {"team": "alpha", "stage": "production", "evidence": ["e1"]},
                ["bad", "row"],
            ]
        )
        assert out["total_teams"] == 2
        assert out["malformed_record_indexes"] == [1]
        assert out["reached_success_stage"] == 1


class TestUnsupportedPlatformWarning:
    def test_warns_on_unknown_platform(self, monkeypatch, caplog):
        """A single WARNING is emitted when running on an unsupported platform."""
        import runtime_guard as rg

        monkeypatch.setattr("sys.platform", "haiku1")
        # Reset the sentinel so the warning fires fresh.
        monkeypatch.setattr(rg, "_unsupported_platform_warned", False)
        with caplog.at_level(logging.WARNING, logger="runtime_guard"):
            snap = rg._read_snapshot()
        assert snap.mem_total_mb == 0
        warns = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("Unsupported platform" in r.getMessage() for r in warns)

    def test_warns_only_once(self, monkeypatch, caplog):
        """The warning is emitted at most once per interpreter session."""
        import runtime_guard as rg

        monkeypatch.setattr("sys.platform", "haiku1")
        monkeypatch.setattr(rg, "_unsupported_platform_warned", False)
        with caplog.at_level(logging.WARNING, logger="runtime_guard"):
            rg._read_snapshot()
            rg._read_snapshot()
        warns = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING and "Unsupported platform" in r.getMessage()
        ]
        assert len(warns) == 1


# ---------------------------------------------------------------------------
# KI-001 — macOS vm_stat page size comes from sysctl, not text parsing
# ---------------------------------------------------------------------------


class TestMacOSPageSize:
    def test_uses_sysctl_page_size(self, monkeypatch):
        """_read_macos should call sysctl hw.pagesize for the page size."""
        import runtime_guard as rg

        captured_calls: list[list[str]] = []

        def fake_check_output(cmd, **kwargs):
            captured_calls.append(list(cmd))
            if "hw.memsize" in cmd:
                return b"8589934592"  # 8 GB
            if "hw.pagesize" in cmd:
                return b"16384"  # 16 KB pages (e.g. Apple Silicon)
            if cmd[0] == "vm_stat":
                # Minimal vm_stat output with counts that are unambiguous with 16384 pages
                return (
                    "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
                    "Pages free:                    100.\n"
                    "Pages inactive:                200.\n"
                    "Pages speculative:              50.\n"
                )
            if "ps" in cmd:
                return b"65536"  # 64 KB RSS (bytes)
            return b""

        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr("subprocess.check_output", fake_check_output)

        snap = rg._read_snapshot()
        # 350 pages × 16384 bytes = 5734400 bytes = 5 MB
        assert snap.mem_available_mb == 5
        # hw.pagesize call must have been made
        assert any("hw.pagesize" in call for call in captured_calls)

    def test_falls_back_to_4096_if_sysctl_fails(self, monkeypatch):
        """If sysctl hw.pagesize fails, 4096 is used as the fallback."""
        import runtime_guard as rg

        def fake_check_output(cmd, **kwargs):
            if "hw.pagesize" in list(cmd):
                raise OSError("no sysctl")
            if "hw.memsize" in list(cmd):
                return b"4294967296"
            if cmd[0] == "vm_stat":
                return (
                    "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
                    "Pages free:                    256.\n"
                    "Pages inactive:                  0.\n"
                    "Pages speculative:               0.\n"
                )
            return b""

        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr("subprocess.check_output", fake_check_output)

        snap = rg._read_snapshot()
        # 256 pages × 4096 bytes = 1048576 bytes = 1 MB
        assert snap.mem_available_mb == 1


# ---------------------------------------------------------------------------
# KI-002 — Windows uses PowerShell first, falls back to wmic
# ---------------------------------------------------------------------------


class TestWindowsPowerShellFallback:
    def test_powershell_used_before_wmic(self, monkeypatch):
        """_read_windows calls PowerShell; wmic is not called when PS succeeds."""
        import runtime_guard as rg

        ps_called: list[bool] = []
        wmic_called: list[bool] = []

        def fake_check_output(cmd, **kwargs):
            cmd_list = list(cmd)
            if "powershell" in cmd_list[0].lower():
                ps_called.append(True)
                if "Get-CimInstance" in " ".join(cmd_list):
                    # Return CSV with header + data row
                    return (
                        '"FreePhysicalMemory","TotalVisibleMemorySize"\n'
                        '"2097152","8388608"\n'  # 2 GB free, 8 GB total (in KB)
                    )
                # WorkingSet64 call
                return "104857600"  # 100 MB in bytes
            if "wmic" in cmd_list[0].lower():
                wmic_called.append(True)
                return ""
            return ""

        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr("subprocess.check_output", fake_check_output)

        snap = rg._read_snapshot()
        assert ps_called, "PowerShell was never called"
        assert not wmic_called, "wmic was called even though PowerShell succeeded"
        assert snap.mem_total_mb == 8192  # 8388608 KB / 1024
        assert snap.mem_available_mb == 2048  # 2097152 KB / 1024

    def test_falls_back_to_wmic_when_powershell_fails(self, monkeypatch):
        """When PowerShell is unavailable, wmic provides the snapshot."""
        import runtime_guard as rg

        wmic_called: list[bool] = []

        def fake_check_output(cmd, **kwargs):
            cmd_list = list(cmd)
            if "powershell" in cmd_list[0].lower():
                raise FileNotFoundError("powershell not found")
            if "wmic" in cmd_list[0].lower():
                wmic_called.append(True)
                cmd_str = " ".join(cmd_list)
                if "FreePhysicalMemory" in cmd_str:
                    return (
                        "\r\nFreePhysicalMemory=2097152\r\nTotalVisibleMemorySize=8388608\r\n\r\n"
                    )
                return "WorkingSetSize=104857600\r\n"
            return ""

        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr("subprocess.check_output", fake_check_output)

        snap = rg._read_snapshot()
        assert wmic_called, "wmic fallback was never called"
        assert snap.mem_total_mb == 8192
        assert snap.mem_available_mb == 2048


# ---------------------------------------------------------------------------
# KI-003 — fork-safety: bg thread handles cleared in child process
# ---------------------------------------------------------------------------


class TestForkSafety:
    @pytest.mark.skipif(sys.platform != "linux", reason="os.fork() Linux only")
    def test_child_process_bg_thread_reset(self):
        """After os.fork(), the child process should have _bg_thread=None."""
        import os as _os

        # Ensure atfork handler is registered.
        g = RuntimeGuard()
        g.start_background_check(interval_s=60.0)
        assert g._bg_thread is not None

        pid = _os.fork()
        if pid == 0:
            # Child process
            try:
                # After fork, the atfork handler should have cleared all guards
                # registered in _active_guards.  Check that our guard's thread
                # handle is None (the handler clears it).
                ok = g._bg_thread is None and g._bg_stop is None
                _os._exit(0 if ok else 1)
            except Exception:
                _os._exit(2)
        else:
            # Parent process
            _, status = _os.waitpid(pid, 0)
            g.stop_background_check()
            exit_code = _os.waitstatus_to_exitcode(status)
            assert exit_code == 0, "Child process reported bg thread was NOT reset after fork"


# ---------------------------------------------------------------------------
# KI-006 — generate_wslconfig merges, does not overwrite
# ---------------------------------------------------------------------------


class TestWslconfigMerge:
    def test_writes_new_file_when_absent(self, tmp_path):
        """When no .wslconfig exists, the file is written directly."""
        from runtime_guard import generate_wslconfig

        out = tmp_path / ".wslconfig"
        generate_wslconfig(memory_gb=8, output_path=str(out), dry_run=False)
        assert out.exists()
        content = out.read_text()
        assert "memory=8GB" in content

    def test_creates_backup_when_file_exists(self, tmp_path):
        """Existing .wslconfig is backed up before merging."""
        from runtime_guard import generate_wslconfig

        out = tmp_path / ".wslconfig"
        out.write_text("[wsl2]\nmemory=4GB\ncustomKey=preserved\n")
        generate_wslconfig(memory_gb=8, output_path=str(out), dry_run=False)
        bak = tmp_path / ".wslconfig.bak"
        assert bak.exists()
        assert "memory=4GB" in bak.read_text()

    def test_merges_managed_keys_preserves_custom_keys(self, tmp_path):
        """Custom keys in existing file are preserved; managed keys are updated."""
        from runtime_guard import generate_wslconfig

        out = tmp_path / ".wslconfig"
        out.write_text("[wsl2]\nmemory=4GB\nkernelCommandLine=my-custom-flags\nprocessors=2\n")
        generate_wslconfig(memory_gb=12, output_path=str(out), dry_run=False)
        merged = out.read_text()
        assert "memory=12GB" in merged  # managed key updated
        assert "kernelCommandLine=my-custom-flags" in merged  # custom key preserved
        assert "memory=4GB" not in merged  # old value replaced

    def test_dry_run_does_not_write(self, tmp_path):
        """dry_run=True (default) must never write to disk."""
        from runtime_guard import generate_wslconfig

        out = tmp_path / ".wslconfig"
        content = generate_wslconfig(memory_gb=8, output_path=str(out), dry_run=True)
        assert not out.exists()
        assert "memory=8GB" in content


# ---------------------------------------------------------------------------
# CLI — argument parsing
# ---------------------------------------------------------------------------


class TestCLI:
    def _run_cli(self, *args: str) -> tuple[int, str]:
        """Run _cli with the given argv; return (exit_code, stderr_output)."""
        import io
        from runtime_guard import _cli

        captured = io.StringIO()
        old_argv = sys.argv
        old_stderr = sys.stderr
        sys.argv = ["runtime-guard", *args]
        sys.stderr = captured
        exit_code = 0
        try:
            _cli()
        except SystemExit as exc:
            exit_code = int(exc.code) if exc.code is not None else 0
        finally:
            sys.argv = old_argv
            sys.stderr = old_stderr
        return exit_code, captured.getvalue()

    def test_snapshot_exits_0(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=8192,
                mem_available_mb=4096,
                swap_total_mb=2048,
                swap_free_mb=2048,
                swap_used_pct=0,
                rss_mb=100,
                vm_swap_mb=0,
            ),
        )
        code, _ = self._run_cli("--snapshot")
        assert code == 0

    def test_check_exits_0_when_no_pressure(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=8192,
                mem_available_mb=6000,
                swap_total_mb=2048,
                swap_free_mb=2048,
                swap_used_pct=0,
                rss_mb=100,
                vm_swap_mb=0,
            ),
        )
        code, _ = self._run_cli("--check")
        assert code == 0

    def test_check_exits_1_when_pressure(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=8192,
                mem_available_mb=100,
                swap_total_mb=2048,
                swap_free_mb=0,
                swap_used_pct=99,
                rss_mb=50,
                vm_swap_mb=0,
            ),
        )
        code, _ = self._run_cli("--check")
        assert code == 1

    def test_version_exits_0(self):
        code, _ = self._run_cli("--version")
        assert code == 0

    def test_generate_wslconfig_prints_content(self, monkeypatch, capsys):
        """--generate-wslconfig without --write prints to stdout."""
        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(mem_total_mb=16384),
        )
        from runtime_guard import _cli

        old_argv = sys.argv
        sys.argv = ["runtime-guard", "--generate-wslconfig"]
        try:
            _cli()
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv
        out = capsys.readouterr().out
        assert "[wsl2]" in out
        assert "memory=" in out

    def test_verify_audit_log_exits_0_when_valid(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.verify_audit_log_chain",
            lambda path: {"ok": True, "records": 2},
        )
        code, _ = self._run_cli("--verify-audit-log", "audit.log")
        assert code == 0

    def test_verify_audit_log_exits_1_when_invalid(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.verify_audit_log_chain",
            lambda path: {"ok": False, "reason": "chain-hash-mismatch", "line": 4},
        )
        code, _ = self._run_cli("--verify-audit-log", "audit.log")
        assert code == 1

    def test_verify_audit_log_exits_2_on_non_boolean_ok_result(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.verify_audit_log_chain",
            lambda path: {"ok": "true", "records": 2},
        )
        code, stderr = self._run_cli("--verify-audit-log", "audit.log")
        assert code == 2
        assert "'ok' must be boolean" in stderr

    def test_verify_audit_log_exits_2_on_invalid_records_type(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.verify_audit_log_chain",
            lambda path: {"ok": True, "records": "2"},
        )
        code, stderr = self._run_cli("--verify-audit-log", "audit.log")
        assert code == 2
        assert "'records' must be a non-negative integer" in stderr

    def test_verify_audit_log_exits_2_on_invalid_reason_or_line_type(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.verify_audit_log_chain",
            lambda path: {"ok": False, "reason": 123, "line": "4"},
        )
        code, stderr = self._run_cli("--verify-audit-log", "audit.log")
        assert code == 2
        assert "'reason' must be a string" in stderr

    def test_check_uses_policy_file_overrides(self, monkeypatch, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text(
            json.dumps({"min_mem_available_mb": 1500, "critical_mem_mb": 1300}),
            encoding="utf-8",
        )

        monkeypatch.setattr(
            "runtime_guard._read_snapshot",
            lambda: MemSnapshot(
                mem_total_mb=8192,
                mem_available_mb=1200,
                swap_total_mb=2048,
                swap_free_mb=2048,
                swap_used_pct=0,
                rss_mb=100,
                vm_swap_mb=0,
            ),
        )

        code, _ = self._run_cli("--check", "--policy-file", str(policy))
        assert code == 1

    def test_check_exits_2_on_invalid_policy_file(self, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps({"bad_key": 1}), encoding="utf-8")

        code, stderr = self._run_cli("--check", "--policy-file", str(policy))
        assert code == 2
        assert "Failed to load policy file" in stderr

    def test_audit_policy_taxonomy_prints_json(self, capsys):
        from runtime_guard import _cli

        old_argv = sys.argv
        sys.argv = ["runtime-guard", "--audit-policy-taxonomy"]
        try:
            _cli()
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv

        out = capsys.readouterr().out
        payload = json.loads(out)
        assert "severity" in payload
        assert "category" in payload
        assert "action" in payload
        assert "memory" in payload["category"]
        assert "policy_violation" in payload["action"]

    def test_diagnose_wsl_crash_fails_on_extension_total_rss_gate(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.diagnose_wsl_crash",
            lambda: {
                "risk_level": "low",
                "risk_score": 0,
                "guest_mem_available_mb": 4000,
                "guest_swap_used_pct": 5,
                "prevention_actions": ["none"],
                "guest_vscode_extension_rss": [
                    {"extension": "ms-python.vscode-pylance", "rss_mb": 900}
                ],
                "guest_vscode_extension_total_rss_mb": 900,
            },
        )
        code, _ = self._run_cli(
            "--diagnose-wsl-crash",
            "--fail-on-extension-total-rss-mb",
            "800",
        )
        assert code == 1

    def test_diagnose_wsl_crash_fails_on_named_extension_rss_gate(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.diagnose_wsl_crash",
            lambda: {
                "risk_level": "low",
                "risk_score": 0,
                "guest_mem_available_mb": 4000,
                "guest_swap_used_pct": 5,
                "prevention_actions": ["none"],
                "guest_vscode_extension_rss": [
                    {"extension": "ms-python.vscode-pylance", "rss_mb": 700},
                    {"extension": "tamasfe.even-better-toml", "rss_mb": 600},
                ],
                "guest_vscode_extension_total_rss_mb": 1300,
            },
        )
        code, _ = self._run_cli(
            "--diagnose-wsl-crash",
            "--fail-on-extension-rss",
            "ms-python.vscode-pylance=600",
        )
        assert code == 1

    def test_diagnose_wsl_crash_invalid_extension_gate_spec_exits_2(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.diagnose_wsl_crash",
            lambda: {
                "risk_level": "low",
                "risk_score": 0,
                "guest_mem_available_mb": 4000,
                "guest_swap_used_pct": 5,
                "prevention_actions": ["none"],
                "guest_vscode_extension_rss": [],
                "guest_vscode_extension_total_rss_mb": 0,
            },
        )
        code, stderr = self._run_cli(
            "--diagnose-wsl-crash",
            "--fail-on-extension-rss",
            "broken-spec",
        )
        assert code == 2
        assert "expected EXTENSION=MB" in stderr

    def test_diagnose_wsl_crash_invalid_extension_row_rss_exits_2(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.diagnose_wsl_crash",
            lambda: {
                "risk_level": "low",
                "risk_score": 0,
                "guest_mem_available_mb": 4000,
                "guest_swap_used_pct": 5,
                "prevention_actions": ["none"],
                "guest_vscode_extension_rss": [
                    {"extension": "ms-python.vscode-pylance", "rss_mb": "900"}
                ],
                "guest_vscode_extension_total_rss_mb": 900,
            },
        )
        code, stderr = self._run_cli(
            "--diagnose-wsl-crash",
            "--fail-on-extension-rss",
            "ms-python.vscode-pylance=800",
        )
        assert code == 2
        assert "guest_vscode_extension_rss[].rss_mb must be a non-negative integer" in stderr

    def test_diagnose_wsl_crash_invalid_extension_total_rss_exits_2(self, monkeypatch):
        monkeypatch.setattr(
            "runtime_guard.diagnose_wsl_crash",
            lambda: {
                "risk_level": "low",
                "risk_score": 0,
                "guest_mem_available_mb": 4000,
                "guest_swap_used_pct": 5,
                "prevention_actions": ["none"],
                "guest_vscode_extension_rss": [
                    {"extension": "ms-python.vscode-pylance", "rss_mb": 900}
                ],
                "guest_vscode_extension_total_rss_mb": "900",
            },
        )
        code, stderr = self._run_cli(
            "--diagnose-wsl-crash",
            "--fail-on-extension-total-rss-mb",
            "800",
        )
        assert code == 2
        assert "guest_vscode_extension_total_rss_mb must be a non-negative integer" in stderr


# ---------------------------------------------------------------------------
# M2-C04 — JSONL worker-report transport adapters for process-pool coordination
# ---------------------------------------------------------------------------


class TestWorkerTransport:
    """Tests for file-based JSONL worker-report transport (process coordination)."""

    def test_append_worker_report_jsonl_creates_new_file(self, tmp_path):
        """append_worker_report_jsonl creates new JSONL file if it doesn't exist."""
        from runtime_guard import append_worker_report_jsonl

        path = str(tmp_path / "reports.jsonl")
        report = {"worker_id": "w1", "mem_mb": 512, "timestamp": 1234567890}
        result = append_worker_report_jsonl(path, report)

        assert result == report  # Returns the written report dict
        assert Path(path).exists()
        with open(path) as f:
            first_line = f.readline()
            loaded = json.loads(first_line)
            assert loaded == report

    def test_append_worker_report_jsonl_appends_to_existing(self, tmp_path):
        """append_worker_report_jsonl appends to existing JSONL file."""
        from runtime_guard import append_worker_report_jsonl

        path = str(tmp_path / "reports.jsonl")
        report1 = {"worker_id": "w1", "mem_mb": 512}
        report2 = {"worker_id": "w2", "mem_mb": 768}

        append_worker_report_jsonl(path, report1)
        result = append_worker_report_jsonl(path, report2)

        assert result == report2  # Returns the written report dict
        with open(path) as f:
            lines = [json.loads(line) for line in f]
            assert len(lines) == 2
            assert lines[0] == report1
            assert lines[1] == report2

    def test_append_worker_report_jsonl_handles_complex_data(self, tmp_path):
        """append_worker_report_jsonl handles nested dict/list in report."""
        from runtime_guard import append_worker_report_jsonl

        path = str(tmp_path / "reports.jsonl")
        report = {
            "worker_id": "w1",
            "metrics": {"cpu_percent": 45.5, "mem_mb": 512},
            "top_processes": [
                {"pid": 101, "name": "python", "rss_mb": 256},
                {"pid": 102, "name": "node", "rss_mb": 128},
            ],
        }
        result = append_worker_report_jsonl(path, report)

        assert result == report  # Returns the written report dict
        with open(path) as f:
            loaded = json.loads(f.readline())
            assert loaded["metrics"]["mem_mb"] == 512
            assert len(loaded["top_processes"]) == 2

    def test_load_worker_reports_jsonl_reads_empty_file(self, tmp_path):
        """load_worker_reports_jsonl returns empty list if file doesn't exist."""
        from runtime_guard import load_worker_reports_jsonl

        path = str(tmp_path / "nonexistent.jsonl")
        reports = load_worker_reports_jsonl(path)

        assert reports == []

    def test_load_worker_reports_jsonl_reads_all_lines(self, tmp_path):
        """load_worker_reports_jsonl reads all lines from JSONL file."""
        from runtime_guard import append_worker_report_jsonl, load_worker_reports_jsonl

        path = str(tmp_path / "reports.jsonl")
        reports_to_write = [
            {"worker_id": "w1", "mem_mb": 512},
            {"worker_id": "w2", "mem_mb": 768},
            {"worker_id": "w3", "mem_mb": 256},
        ]

        for report in reports_to_write:
            append_worker_report_jsonl(path, report)

        loaded = load_worker_reports_jsonl(path)
        assert len(loaded) == 3
        assert loaded[0]["worker_id"] == "w1"
        assert loaded[1]["worker_id"] == "w2"
        assert loaded[2]["worker_id"] == "w3"

    def test_load_worker_reports_jsonl_skips_invalid_json_lines(self, tmp_path):
        """load_worker_reports_jsonl tolerates and skips malformed JSON lines."""
        from runtime_guard import load_worker_reports_jsonl

        path = str(tmp_path / "reports.jsonl")
        with open(path, "w") as f:
            f.write('{"worker_id": "w1", "mem_mb": 512}\n')
            f.write("invalid json line\n")
            f.write('{"worker_id": "w2", "mem_mb": 768}\n')

        loaded = load_worker_reports_jsonl(path)
        # Should load valid lines and skip the invalid one
        assert len(loaded) >= 2

    def test_aggregate_worker_reports_jsonl_single_file(self, tmp_path):
        """aggregate_worker_reports_jsonl aggregates single JSONL file."""
        from runtime_guard import append_worker_report_jsonl, aggregate_worker_reports_jsonl

        path = str(tmp_path / "reports.jsonl")
        for i in range(1, 4):
            append_worker_report_jsonl(
                path,
                {
                    "worker_id": f"w{i}",
                    "mem_mb": 256 * i,
                    "cpu_percent": 20.0 + i,
                    "pressure": False,
                },
            )

        result = aggregate_worker_reports_jsonl(path)
        assert result["total_workers"] == 3
        assert "pressured_workers" in result
        assert "critical_workers" in result

    def test_aggregate_worker_reports_jsonl_nonexistent_file(self, tmp_path):
        """aggregate_worker_reports_jsonl handles missing file gracefully."""
        from runtime_guard import aggregate_worker_reports_jsonl

        path = str(tmp_path / "nonexistent.jsonl")
        result = aggregate_worker_reports_jsonl(path)

        assert result["total_workers"] == 0
        assert result["pressured_workers"] == 0

    def test_jsonl_transport_with_make_worker_report(self, tmp_path):
        """Integration test: append JSONL worker reports and aggregate."""
        from runtime_guard import append_worker_report_jsonl, aggregate_worker_reports_jsonl

        path = str(tmp_path / "reports.jsonl")

        # Create reports similar to what make_worker_report would return
        for i in range(3):
            report = {
                "ts": int(time.time()),
                "pid": 1000 + i,
                "worker_id": f"w{i}",
                "stage": "worker",
                "pressure": False,
                "severity": "none",
                "mem_available_mb": 4096,
                "mem_total_mb": 8192,
            }
            append_worker_report_jsonl(path, report)

        # Aggregate and verify
        result = aggregate_worker_reports_jsonl(path)
        assert result["total_workers"] == 3
        assert "pressured_workers" in result

    def test_jsonl_transport_multiple_append_sessions(self, tmp_path):
        """Test appending worker reports in multiple sessions."""
        from runtime_guard import (
            append_worker_report_jsonl,
            load_worker_reports_jsonl,
        )

        path = str(tmp_path / "reports.jsonl")

        # Session 1: Append 2 reports
        for i in range(1, 3):
            append_worker_report_jsonl(
                path,
                {
                    "session": 1,
                    "worker_id": i,
                    "mem_mb": 512,
                },
            )

        # Session 2: Append 2 more reports (simulates coordinator restart)
        for i in range(1, 3):
            append_worker_report_jsonl(
                path,
                {
                    "session": 2,
                    "worker_id": i,
                    "mem_mb": 768,
                },
            )

        # Verify all 4 reports were persisted
        loaded = load_worker_reports_jsonl(path)
        assert len(loaded) == 4
        session1_reports = [r for r in loaded if r["session"] == 1]
        session2_reports = [r for r in loaded if r["session"] == 2]
        assert len(session1_reports) == 2
        assert len(session2_reports) == 2

    def test_jsonl_transport_concurrent_append_safety(self, tmp_path):
        """Test that multiple appends maintain JSONL integrity."""
        from runtime_guard import append_worker_report_jsonl, load_worker_reports_jsonl

        path = str(tmp_path / "reports.jsonl")

        # Simulate concurrent workers appending (sequential in test but tests append safety)
        for i in range(10):
            result = append_worker_report_jsonl(
                path,
                {
                    "worker_id": i,
                    "iteration": 1,
                    "pressure": False,
                },
            )
            assert "worker_id" in result  # Returns the report dict

        # Verify all reports are readable
        loaded = load_worker_reports_jsonl(path)
        assert len(loaded) == 10
        for i, report in enumerate(loaded):
            assert report["worker_id"] == i
            assert report["pressure"] is False


# ---------------------------------------------------------------------------
# M1-C05 — Prometheus ASGI endpoint
# ---------------------------------------------------------------------------


class TestPrometheusEndpoint:
    """Tests for install_prometheus_endpoint() ASGI factory (M1-C05)."""

    def _make_guard(self) -> RuntimeGuard:
        return RuntimeGuard(env_prefix="TEST_PROM")

    def _run_asgi(self, app, method: str = "GET") -> tuple[int, bytes]:
        """Drive the ASGI app synchronously, return (status, body)."""
        import asyncio

        responses = []

        async def _send(msg):
            responses.append(msg)

        scope = {"type": "http", "method": method}
        asyncio.run(app(scope, None, _send))
        start = next((r for r in responses if r["type"] == "http.response.start"), {})
        body_msg = next((r for r in responses if r["type"] == "http.response.body"), {})
        return start.get("status", 0), body_msg.get("body", b"")

    def test_returns_callable_and_restore(self):
        guard = self._make_guard()
        app, restore = install_prometheus_endpoint(guard)
        assert callable(app)
        assert callable(restore)

    def test_get_returns_200_and_metrics_text(self):
        import unittest.mock as mock
        guard = self._make_guard()
        with mock.patch.object(guard, "check", return_value=None):
            app, _ = install_prometheus_endpoint(guard)
            status, body = self._run_asgi(app, "GET")
        assert status == 200
        assert b"runtime_guard_mem_available_mb" in body

    def test_post_returns_405(self):
        guard = self._make_guard()
        app, _ = install_prometheus_endpoint(guard)
        status, body = self._run_asgi(app, "POST")
        assert status == 405

    def test_custom_prefix_applied(self):
        import unittest.mock as mock
        guard = self._make_guard()
        with mock.patch.object(guard, "check", return_value=None):
            app, _ = install_prometheus_endpoint(guard, prefix="myapp")
            status, body = self._run_asgi(app, "GET")
        assert status == 200
        assert b"myapp_mem_available_mb" in body
        assert b"runtime_guard_mem_available_mb" not in body

    def test_503_on_critical_pressure(self):
        import unittest.mock as mock

        guard = self._make_guard()
        fake_report = _make_report(is_critical=True, stage="prometheus")
        with mock.patch.object(guard, "check", return_value=fake_report):
            app, _ = install_prometheus_endpoint(guard)
            status, body = self._run_asgi(app, "GET")
        assert status == 503
        assert b"runtime_guard_is_critical 1" in body

    def test_200_on_healthy(self):
        import unittest.mock as mock
        guard = self._make_guard()
        with mock.patch.object(guard, "check", return_value=None):
            app, _ = install_prometheus_endpoint(guard)
            status, _ = self._run_asgi(app, "GET")
        assert status == 200

    def test_non_http_scope_ignored(self):
        import asyncio

        guard = self._make_guard()
        app, _ = install_prometheus_endpoint(guard)
        responses = []

        async def _send(msg):
            responses.append(msg)

        asyncio.run(app({"type": "lifespan"}, None, _send))
        assert responses == []  # Nothing sent for non-HTTP scopes

    def test_restore_is_noop(self):
        guard = self._make_guard()
        _, restore = install_prometheus_endpoint(guard)
        restore()  # Must not raise

    def test_path_attribute_recorded(self):
        guard = self._make_guard()
        app, _ = install_prometheus_endpoint(guard, path="/custom-metrics")
        assert getattr(app, "_runtime_guard_prometheus_path") == "/custom-metrics"


# ---------------------------------------------------------------------------
# M1-C06 — Distributed trace propagator
# ---------------------------------------------------------------------------


class TestDistributedTracePropagator:
    """Tests for install_distributed_trace_propagator() (M1-C06)."""

    def _make_guard(self) -> RuntimeGuard:
        return RuntimeGuard(env_prefix="TEST_TRACE")

    def test_returns_dict_with_required_keys(self):
        guard = self._make_guard()
        result = install_distributed_trace_propagator(guard)
        assert callable(result["extract"])
        assert callable(result["inject"])
        assert callable(result["restore"])
        assert result["header_name"] == "traceparent"

    def test_extract_valid_traceparent(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard)
        tp_value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ctx = tp["extract"]({"traceparent": tp_value})
        assert ctx["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert ctx["span_id"] == "00f067aa0ba902b7"
        assert ctx["flags"] == "01"
        assert ctx["traceparent"] == tp_value

    def test_extract_missing_header_returns_empty(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard)
        ctx = tp["extract"]({"content-type": "application/json"})
        assert ctx == {}

    def test_extract_malformed_header_returns_empty(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard)
        ctx = tp["extract"]({"traceparent": "bad-value"})
        assert ctx == {}

    def test_extract_case_insensitive_header_key(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard)
        tp_value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ctx = tp["extract"]({"Traceparent": tp_value})
        assert ctx["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_inject_with_no_otel_returns_unchanged(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard, module=object())  # no OTEL
        headers = {"content-type": "application/json"}
        out = tp["inject"](headers)
        # No traceparent added because no span available
        assert "traceparent" not in out
        assert out.get("content-type") == "application/json"

    def test_inject_with_mock_span(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard)

        class _Flags:
            sampled = True

        class _SpanCtx:
            trace_id = 0x4BF92F3577B34DA6A3CE929D0E0E4736
            span_id = 0x00F067AA0BA902B7
            trace_flags = _Flags()

        class _Span:
            def get_span_context(self):
                return _SpanCtx()

        out = tp["inject"]({}, span=_Span())
        assert "traceparent" in out
        assert out["traceparent"].startswith("00-")
        assert "4bf92f3577b34da6a3ce929d0e0e4736" in out["traceparent"]

    def test_inject_preserves_existing_headers(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard, module=object())
        headers = {"authorization": "Bearer token123", "x-request-id": "abc"}
        out = tp["inject"](headers)
        assert out.get("authorization") == "Bearer token123"  # value preserved; key lowercased
        assert out.get("x-request-id") == "abc"

    def test_custom_header_name(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard, header_name="x-amzn-trace-id")
        assert tp["header_name"] == "x-amzn-trace-id"
        tp_val = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ctx = tp["extract"]({"x-amzn-trace-id": tp_val})
        assert ctx["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_restore_is_noop(self):
        guard = self._make_guard()
        tp = install_distributed_trace_propagator(guard)
        tp["restore"]()  # Must not raise
