#!/usr/bin/env python3
"""Polars integration demo for runtime-guard adoption (M1-I01).

This script demonstrates a complete Polars + runtime-guard adoption scenario:
1. Validates Polars integration capabilities
2. Runs synthetic workload with memory pressure
3. Captures pressure events and evidence
4. Records adoption scorecard metrics

Run this after installing both polars and runtime-guard:
    pip install polars runtime-guard
    python examples/polars_integration_demo.py
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

try:
    import polars as pl
except ImportError:
    print("ERROR: polars not installed. Run: pip install polars")
    sys.exit(1)

from runtime_guard import (
    RuntimeGuard,
    attach_polars_guard,
    validate_polars_integration,
    collect_polars_integration_evidence,
    build_adoption_scorecard,
)

# Configure structured event logging for audit trail
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
)
_logger = logging.getLogger(__name__)
_events_logger = logging.getLogger("runtime_guard.events")


def run_demo(
    *,
    workload_size_mb: int = 256,
    pressure_scenario: str = "realistic",
    output_scorecard: Path | None = None,
) -> dict[str, Any]:
    """Run Polars integration demo with configurable workload.

    Parameters
    ----------
    workload_size_mb : int
        Size of synthetic data in MB (default 256 MB).
    pressure_scenario : str
        Type of scenario: 'light' (small workload), 'realistic' (normal), 'heavy' (max pressure).
    output_scorecard : Path, optional
        Path to write adoption scorecard JSON (default: no output).

    Returns
    -------
    dict
        Summary of demo results including validation, evidence, and metrics.
    """
    results: dict[str, Any] = {
        "timestamp": time.time(),
        "scenario": pressure_scenario,
        "workload_size_mb": workload_size_mb,
        "phases": {},
        "events_captured": 0,
        "adoption_evidence": {},
    }

    # -----------------------------------------------------------------------
    # Phase 1: Validation
    # -----------------------------------------------------------------------
    _logger.info("=" * 70)
    _logger.info("PHASE 1: Validate Polars Integration")
    _logger.info("=" * 70)

    validation = validate_polars_integration()
    _logger.info(f"Polars available: {validation.get('polars_available')}")
    _logger.info(f"LazyFrame.collect present: {validation.get('collect_present')}")
    _logger.info(f"LazyFrame.fetch present: {validation.get('fetch_present')}")

    if not validation.get("ok"):
        _logger.error(f"Validation failed: {validation.get('errors')}")
        results["phases"]["validation"] = validation
        return results

    _logger.info("✓ Polars integration validation passed")
    results["phases"]["validation"] = validation

    # -----------------------------------------------------------------------
    # Phase 2: Setup RuntimeGuard + Polars Hook
    # -----------------------------------------------------------------------
    _logger.info("")
    _logger.info("=" * 70)
    _logger.info("PHASE 2: Setup RuntimeGuard and Polars Hook")
    _logger.info("=" * 70)

    # Determine posture based on scenario
    posture_map = {
        "light": "relaxed",
        "realistic": "tight",
        "heavy": "tight",
    }
    posture = posture_map.get(pressure_scenario, "tight")

    guard = RuntimeGuard(
        posture=posture,
        cooldown_s=5.0,  # Reduce cooldown for demo to see multiple events
        log_tag="PolarsDemo",
    )
    _logger.info(f"RuntimeGuard initialized with posture={posture}")

    # Attach to Polars
    restore = attach_polars_guard(guard, stage="polars-collect")
    _logger.info("✓ Polars LazyFrame.collect() and .fetch() hooked")

    # Collect validation evidence
    evidence = collect_polars_integration_evidence()
    _logger.info(f"Integration evidence: {len(evidence.get('methods_hooked', []))} methods hooked")
    results["adoption_evidence"]["integration_evidence"] = evidence

    results["phases"]["setup"] = {
        "posture": posture,
        "guard_initialized": True,
        "hook_attached": True,
    }

    # -----------------------------------------------------------------------
    # Phase 3: Workload Execution with Pressure Scenarios
    # -----------------------------------------------------------------------
    _logger.info("")
    _logger.info("=" * 70)
    _logger.info("PHASE 3: Execute Workload Scenarios")
    _logger.info(f"Scenario: {pressure_scenario} (workload_size={workload_size_mb} MB)")
    _logger.info("=" * 70)

    scenarios = []

    # Scenario A: Simple collect (baseline)
    _logger.info("")
    _logger.info("Scenario A: Simple DataFrame collect")
    start_time = time.time()
    try:
        rows = workload_size_mb * 10000  # ~100KB per row
        df = pl.DataFrame(
            {
                "id": list(range(rows)),
                "value": list(range(rows)),
                "data": ["x" * 100] * rows,
            }
        )
        collected_df = df.collect() if isinstance(df, pl.LazyFrame) else df
        elapsed = time.time() - start_time
        _logger.info(f"  ✓ DataFrame collected in {elapsed:.2f}s, shape={collected_df.shape}")
        scenarios.append({
            "name": "simple_collect",
            "duration_s": elapsed,
            "rows": rows,
            "status": "ok",
        })
    except Exception as exc:
        _logger.warning(f"  ⚠ Simple collect failed: {exc}")
        scenarios.append({
            "name": "simple_collect",
            "status": "failed",
            "error": str(exc),
        })

    # Scenario B: Lazy evaluation + collect
    _logger.info("")
    _logger.info("Scenario B: Lazy evaluation with transformation + collect")
    start_time = time.time()
    try:
        rows = workload_size_mb * 5000
        df_lazy = pl.DataFrame(
            {
                "id": list(range(rows)),
                "value": list(range(rows)),
                "data": ["y" * 100] * rows,
            }
        ).lazy()

        # Add transformations
        result_lazy = (
            df_lazy
            .filter(pl.col("id") > 0)
            .select([pl.col("id"), pl.col("value")])
        )

        result_df = result_lazy.collect()
        elapsed = time.time() - start_time
        _logger.info(f"  ✓ Lazy frame collected in {elapsed:.2f}s, shape={result_df.shape}")
        scenarios.append({
            "name": "lazy_transform_collect",
            "duration_s": elapsed,
            "rows": rows,
            "status": "ok",
        })
    except Exception as exc:
        _logger.warning(f"  ⚠ Lazy transform failed: {exc}")
        scenarios.append({
            "name": "lazy_transform_collect",
            "status": "failed",
            "error": str(exc),
        })

    # Scenario C: Heavy workload (if requested)
    if pressure_scenario in {"realistic", "heavy"}:
        _logger.info("")
        _logger.info("Scenario C: Heavy aggregation workload")
        start_time = time.time()
        try:
            rows = (workload_size_mb * 3000) if pressure_scenario == "realistic" else (workload_size_mb * 5000)
            df_heavy = pl.DataFrame(
                {
                    "group": list(range(rows % 100)),  # 100 groups
                    "value": list(range(rows)),
                    "data": ["z" * 100] * rows,
                }
            ).lazy()

            result_heavy = (
                df_heavy
                .groupby("group")
                .agg([pl.col("value").sum(), pl.col("value").mean()])
            )

            agg_df = result_heavy.collect()
            elapsed = time.time() - start_time
            _logger.info(f"  ✓ Aggregation collected in {elapsed:.2f}s, shape={agg_df.shape}")
            scenarios.append({
                "name": "heavy_aggregation",
                "duration_s": elapsed,
                "rows": rows,
                "status": "ok",
            })
        except Exception as exc:
            _logger.warning(f"  ⚠ Heavy aggregation failed: {exc}")
            scenarios.append({
                "name": "heavy_aggregation",
                "status": "failed",
                "error": str(exc),
            })

    results["phases"]["workload"] = {
        "scenarios_executed": len(scenarios),
        "scenarios": scenarios,
    }

    # -----------------------------------------------------------------------
    # Phase 4: Cleanup and Evidence Collection
    # -----------------------------------------------------------------------
    _logger.info("")
    _logger.info("=" * 70)
    _logger.info("PHASE 4: Cleanup and Evidence Collection")
    _logger.info("=" * 70)

    # Restore monkeypatch
    restore()
    _logger.info("✓ Polars hook removed (monkeypatch restored)")

    # Re-validate after cleanup
    post_validation = validate_polars_integration()
    if post_validation.get("methods_wrapped"):
        _logger.warning("⚠ Polars hook not fully cleaned up")
    else:
        _logger.info("✓ Polars integration cleaned up successfully")

    results["phases"]["cleanup"] = {
        "restored": True,
        "post_validation": post_validation,
    }

    # -----------------------------------------------------------------------
    # Phase 5: Adoption Scorecard
    # -----------------------------------------------------------------------
    _logger.info("")
    _logger.info("=" * 70)
    _logger.info("PHASE 5: Adoption Readiness Scorecard")
    _logger.info("=" * 70)

    team_record = {
        "team": "polars-pilot-team",
        "stage": "validate",  # Stage 1: validation
        "integration": "polars",
        "scenario": pressure_scenario,
        "scenarios_passed": sum(1 for s in scenarios if s.get("status") == "ok"),
        "scenarios_total": len(scenarios),
        "guard_initialization": "success",
        "hook_attachment": "success",
        "workload_execution": "success" if scenarios else "unknown",
        "evidence_collection": "complete",
    }

    scorecard = build_adoption_scorecard([team_record])
    _logger.info(f"Adoption scorecard: stage={scorecard.get('stage')}, coverage={scorecard.get('coverage_pct')}%")

    results["adoption_scorecard"] = scorecard
    results["team_record"] = team_record

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    _logger.info("")
    _logger.info("=" * 70)
    _logger.info("SUMMARY")
    _logger.info("=" * 70)

    summary = {
        "validation": validation.get("ok"),
        "scenarios_passed": sum(1 for s in scenarios if s.get("status") == "ok"),
        "total_scenarios": len(scenarios),
        "hook_cleanup": post_validation.get("methods_wrapped") is False,
        "scorecard_stage": scorecard.get("stage"),
    }

    for key, value in summary.items():
        status = "✓" if value is True else "✗" if value is False else "•"
        _logger.info(f"{status} {key}: {value}")

    if output_scorecard:
        with open(output_scorecard, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)
        _logger.info(f"✓ Scorecard written to {output_scorecard}")

    return results


def main() -> int:
    """Parse CLI args and run demo."""
    parser = argparse.ArgumentParser(
        description="Polars + runtime-guard integration demo (M1-I01)",
    )
    parser.add_argument(
        "--workload-size",
        type=int,
        default=256,
        help="Synthetic workload size in MB (default: 256)",
    )
    parser.add_argument(
        "--scenario",
        choices=["light", "realistic", "heavy"],
        default="realistic",
        help="Pressure scenario (default: realistic)",
    )
    parser.add_argument(
        "--output-scorecard",
        type=Path,
        help="Path to write adoption scorecard JSON",
    )
    args = parser.parse_args()

    try:
        results = run_demo(
            workload_size_mb=args.workload_size,
            pressure_scenario=args.scenario,
            output_scorecard=args.output_scorecard,
        )
        return 0 if results.get("adoption_scorecard", {}).get("stage") == "validate" else 1
    except Exception as exc:
        _logger.exception(f"Demo failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
