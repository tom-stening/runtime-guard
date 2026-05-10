#!/usr/bin/env python3
"""Example: ML training pipeline with runtime-guard memory monitoring."""

import json
import logging
import os
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)

from runtime_guard import RuntimeGuard


def generate_synthetic_data(rows: int = 100_000) -> dict:
    """Generate synthetic training data."""
    print(f"[Data] Generating {rows:,} rows...")
    data = {
        "features": [i * 1.5 for i in range(rows)],
        "target": [i % 2 for i in range(rows)],
        "timestamp": [time.time() - (rows - i) * 0.1 for i in range(rows)],
    }
    return data


def train_model(guard: RuntimeGuard, data: dict, epochs: int = 3) -> dict:
    """Train a mock model."""
    print(f"[Model] Starting training for {epochs} epochs...")
    guard.start_background_check(interval_s=1.0)
    results = {"epochs": epochs, "samples": len(data["features"]), "losses": []}
    try:
        for epoch in range(1, epochs + 1):
            loss = 0.5 / epoch
            results["losses"].append(loss)
            print(f"  Epoch {epoch}/{epochs}: loss={loss:.4f}")
            time.sleep(0.5)
        print("[Model] Training complete.")
        return results
    finally:
        guard.stop_background_check()


def main():
    """Main pipeline entry point."""
    env_posture = os.environ.get("RUNTIME_GUARD_POSTURE", "relaxed")
    print(f"[Pipeline] Starting ML training demo with RUNTIME_GUARD_POSTURE={env_posture}\n")
    
    print("=" * 70)
    print("STAGE 1: Pre-flight check (before data load)")
    print("=" * 70)
    
    guard = RuntimeGuard(
        env_prefix="RUNTIME_GUARD",
        log_tag="MLPipeline",
        cooldown_s=5.0,
        hints=[
            "Reduce batch size: --batch-size 256",
            "Use fewer samples: --max-samples 50000",
            "Run with monitoring: RUNTIME_GUARD_POSTURE=tight",
        ],
    )
    
    try:
        report = guard.preflight_check(abort_on_critical=True, auto_intervene=True)
        if report is None:
            print("[✓] Preflight check passed: memory is healthy\n")
        else:
            print("[!] Memory pressure detected, but intervention attempted.\n")
    except MemoryError as e:
        print(f"[✗] Critical memory pressure: {e}\n")
        sys.exit(1)
    
    print("=" * 70)
    print("STAGE 2: Data loading and snapshot")
    print("=" * 70)
    
    data = generate_synthetic_data(rows=100_000)
    guard.check_and_log(stage="after-data-load")
    mem_total, mem_available, rss_mb = guard.memory_snapshot_mb()
    print(f"[Memory] Total: {mem_total}MB, Available: {mem_available}MB, Process RSS: {rss_mb}MB\n")
    
    print("=" * 70)
    print("STAGE 3: Training with background monitoring")
    print("=" * 70)
    print("[Background] Continuous memory checks active during training...\n")
    
    train_results = train_model(guard, data, epochs=3)
    
    print("\n" + "=" * 70)
    print("STAGE 4: Post-training snapshot")
    print("=" * 70)
    
    guard.check_and_log(stage="after-training")
    
    summary = {
        "pipeline": "ml_pipeline_demo",
        "data_rows": len(data["features"]),
        "training_epochs": train_results["epochs"],
        "final_loss": train_results["losses"][-1] if train_results["losses"] else None,
        "runtime_guard_posture": env_posture,
        "status": "success",
    }
    
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(json.dumps(summary, indent=2))
    print("\n[✓] Pipeline completed successfully!")
    print("\nKey observations:")
    print("  1. Memory snapshots show current system state before/after operations.")
    print("  2. Background monitoring detected memory issues (if any) during training.")
    print("  3. All events emitted to 'runtime_guard.events' logger for aggregation.")
    print("  4. If pressure detected, reports include:")
    print("     - Is it self-inflicted (this process) or host pressure?")
    print("     - How many MB below the safety threshold?")
    print("     - Top memory-consuming processes on the host.")


if __name__ == "__main__":
    main()
