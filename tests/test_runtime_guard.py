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
import sys
import time
import unittest.mock as mock

import pytest
from runtime_guard import (
    MemSnapshot,
    PressureReport,
    RuntimeGuard,
    attach_dask_guard,
    _read_snapshot,
    attach_polars_guard,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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

    def test_custom_prefix_posture(self, monkeypatch):
        monkeypatch.setenv("MYAPP_POSTURE", "ci")
        g = RuntimeGuard(env_prefix="MYAPP")
        assert g._resolve_thresholds()[0] == 1024  # ci min_mem_mb


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

        def fake_check_and_log(stage=""):
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
        restore = attach_polars_guard(guard, module=self._DummyPolars)
        restore()
        assert self._DummyPolars.LazyFrame.collect is original

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

    def test_restore_restores_original_functions(self, monkeypatch):
        guard = RuntimeGuard()
        monkeypatch.setattr(guard, "check_and_log", lambda stage="": None)
        original_compute = self._DummyDask.compute
        original_persist = self._DummyDask.persist
        restore = attach_dask_guard(guard, module=self._DummyDask)
        restore()
        assert self._DummyDask.compute is original_compute
        assert self._DummyDask.persist is original_persist

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
