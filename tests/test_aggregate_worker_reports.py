from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "aggregate_worker_reports.py"
    spec = importlib.util.spec_from_file_location("aggregate_worker_reports", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fail_on_critical_returns_2_for_non_integer_summary_value(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {"critical_workers": "1", "any_pressure": False},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-critical"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.critical_workers must be a non-negative integer" in captured.err


def test_fail_on_pressure_returns_2_for_non_boolean_summary_value(
    monkeypatch, capsys
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {"critical_workers": 0, "any_pressure": "false"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-pressure"],
    )

    code = module.main()
    captured = capsys.readouterr()

    assert code == 2
    assert "summary.any_pressure must be boolean" in captured.err


def test_fail_on_pressure_returns_1_for_true_boolean(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "aggregate_worker_reports_jsonl",
        lambda _path: {"critical_workers": 0, "any_pressure": True},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["aggregate_worker_reports.py", "--input", "dummy.jsonl", "--fail-on-pressure"],
    )

    assert module.main() == 1
