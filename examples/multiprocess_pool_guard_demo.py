"""
Demo: Multi-process orchestration with runtime-guard

Each worker writes a memory pressure report to a shared JSONL file.
The parent aggregates all reports and prints a summary.

Run with:
    python examples/multiprocess_pool_guard_demo.py
"""
import multiprocessing as mp
import os
import time
from runtime_guard import RuntimeGuard, make_worker_report, append_worker_report_jsonl, aggregate_worker_reports_jsonl

REPORT_PATH = "/tmp/worker_guard_reports.jsonl"


def worker_main(worker_id: int):
    guard = RuntimeGuard()
    # Simulate work
    time.sleep(0.1 * worker_id)
    # Write a worker report
    report = make_worker_report(guard, stage="worker", worker_id=str(worker_id))
    append_worker_report_jsonl(REPORT_PATH, report)
    print(f"[Worker {worker_id}] Reported: pressure={report['pressure']} severity={report['severity']}")


def main():
    if os.path.exists(REPORT_PATH):
        os.remove(REPORT_PATH)
    pool = mp.Pool(4)
    pool.map(worker_main, range(4))
    pool.close()
    pool.join()

    # Parent aggregates all worker reports
    summary = aggregate_worker_reports_jsonl(REPORT_PATH)
    print("\n=== Aggregated Worker Pressure Summary ===")
    print(f"Total workers: {summary['total_workers']}")
    print(f"Pressured workers: {summary['pressured_workers']}")
    print(f"Critical workers: {summary['critical_workers']}")
    print(f"Worst severity: {summary['worst_severity']}")
    for w in summary['workers']:
        print(f"  Worker {w['worker_id']}: pressure={w['pressure']} severity={w['severity']} mem={w['mem_available_mb']}MB")


if __name__ == "__main__":
    main()
