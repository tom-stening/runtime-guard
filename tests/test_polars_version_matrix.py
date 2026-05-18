"""Polars version-matrix regression tests for callback signature drift coverage.

This test module verifies that runtime-guard Polars integration handles
callback signature drift across multiple Polars versions (0.20, 0.32, 1.0, 1.1+).
"""

from __future__ import annotations

from typing import Any, Callable

import pytest

from runtime_guard import RuntimeGuard, attach_polars_guard


class PolarsVersionMocks:
    """Mock Polars implementations for different versions."""

    @staticmethod
    def make_polars_0_20() -> type:
        """Polars 0.20 with callback_when_finished parameter."""

        class Polars_0_20:
            __version__ = "0.20.15"

            class LazyFrame:
                def collect(self, *, callback_when_finished: Callable | None = None) -> dict:
                    if callback_when_finished:
                        callback_when_finished({"stage": "collect"})
                    return {"data": [1, 2, 3]}

        return Polars_0_20

    @staticmethod
    def make_polars_0_32() -> type:
        """Polars 0.32 with camelCase callback variant."""

        class Polars_0_32:
            __version__ = "0.32.5"

            class LazyFrame:
                def collect(
                    self,
                    *,
                    callback_when_finished: Callable | None = None,
                    callbackWhenFinished: Callable | None = None,
                ) -> dict:
                    cb = callback_when_finished or callbackWhenFinished
                    if cb:
                        cb({"stage": "collect"})
                    return {"data": [1, 2, 3]}

        return Polars_0_32

    @staticmethod
    def make_polars_1_0() -> type:
        """Polars 1.0 with post_opt_callback naming."""

        class Polars_1_0:
            __version__ = "1.0.0"

            class LazyFrame:
                def collect(
                    self,
                    *,
                    post_opt_callback: Callable | None = None,
                    postOptCallback: Callable | None = None,
                    # legacy support
                    callback_when_finished: Callable | None = None,
                ) -> dict:
                    cb = (
                        post_opt_callback
                        or postOptCallback
                        or callback_when_finished
                    )
                    if cb:
                        cb({"stage": "collect"})
                    return {"data": [1, 2, 3]}

        return Polars_1_0

    @staticmethod
    def make_polars_1_1() -> type:
        """Polars 1.1 with simplified callback API."""

        class Polars_1_1:
            __version__ = "1.1.0"

            class LazyFrame:
                def collect(
                    self,
                    *,
                    post_opt_callback: Callable | None = None,
                ) -> dict:
                    if post_opt_callback:
                        post_opt_callback({"stage": "collect"})
                    return {"data": [1, 2, 3]}

        return Polars_1_1


POLARS_VERSIONS = [
    ("0.20", PolarsVersionMocks.make_polars_0_20()),
    ("0.32", PolarsVersionMocks.make_polars_0_32()),
    ("1.0", PolarsVersionMocks.make_polars_1_0()),
    ("1.1", PolarsVersionMocks.make_polars_1_1()),
]


class TestPolarsVersionMatrix:
    """Test Polars integration across version drift scenarios."""

    @pytest.mark.parametrize("version_str,polars_module", POLARS_VERSIONS)
    def test_guard_wraps_collect_across_versions(self, version_str: str, polars_module: type, monkeypatch) -> None:
        """Verify that attach_polars_guard wraps collect() across all Polars versions."""
        guard = RuntimeGuard()
        check_calls: list[str] = []

        def fake_check(stage: str = "") -> None:
            check_calls.append(stage)

        monkeypatch.setattr(guard, "check_and_log", fake_check)

        # Attach guard to this version
        restore = attach_polars_guard(guard, stage=f"polars-v{version_str}", module=polars_module)

        try:
            # Create and collect
            frame = polars_module.LazyFrame()
            result = frame.collect()

            # Guard wrapper should have been called
            assert f"polars-v{version_str}" in check_calls, (
                f"Guard not wrapped in Polars {version_str}. Calls: {check_calls}"
            )

            # Result should be unchanged
            assert result == {"data": [1, 2, 3]}
        finally:
            restore()

    @pytest.mark.parametrize("version_str,polars_module", POLARS_VERSIONS)
    def test_version_detection(self, version_str: str, polars_module: type) -> None:
        """Verify version is correctly detected for each Polars version."""
        guard = RuntimeGuard()
        restore = attach_polars_guard(guard, stage="version-test", module=polars_module)

        try:
            from runtime_guard import collect_polars_integration_evidence

            evidence = collect_polars_integration_evidence(
                guard, stage="version-test", module=polars_module
            )

            detected_version = evidence.get("polars_version", "unknown")
            assert detected_version != "unknown", f"Version not detected for Polars {version_str}"
        finally:
            restore()

    def test_multiple_versions_dont_interfere(self, monkeypatch) -> None:
        """Attaching guards to different version mocks shouldn't cause issues."""
        polars_0_20 = PolarsVersionMocks.make_polars_0_20()
        polars_1_0 = PolarsVersionMocks.make_polars_1_0()

        guard_a = RuntimeGuard()
        guard_b = RuntimeGuard()

        calls_a: list[str] = []
        calls_b: list[str] = []


        def track_a(stage: str = "") -> None:
            calls_a.append(stage)

        def track_b(stage: str = "") -> None:
            calls_b.append(stage)

        monkeypatch.setattr(guard_a, "check_and_log", track_a)
        monkeypatch.setattr(guard_b, "check_and_log", track_b)

        restore_a = attach_polars_guard(guard_a, stage="v0.20", module=polars_0_20)
        restore_b = attach_polars_guard(guard_b, stage="v1.0", module=polars_1_0)

        try:
            frame_a = polars_0_20.LazyFrame()
            frame_b = polars_1_0.LazyFrame()

            frame_a.collect()
            frame_b.collect()

            assert "v0.20" in calls_a
            assert "v1.0" in calls_b
        finally:
            restore_a()
            restore_b()

    def test_collect_still_works_with_unsupported_signature(self) -> None:
        """If callback signature is unsupported, collect should still work."""

        class IncompatiblePolars:
            __version__ = "9.9.9"

            class LazyFrame:
                def collect(self, *, unknown_param: bool = True) -> dict:
                    return {"data": [1, 2, 3]}

        guard = RuntimeGuard()
        restore = attach_polars_guard(guard, module=IncompatiblePolars)

        try:
            frame = IncompatiblePolars.LazyFrame()
            result = frame.collect()
            # Even if wrapper can't inject callback, collect should work
            assert result == {"data": [1, 2, 3]}
        finally:
            restore()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
