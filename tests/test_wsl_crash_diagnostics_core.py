from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import pytest
import runtime_guard as rg


def test_diagnose_wsl_crash_includes_risk_and_metrics(monkeypatch: pytest.MonkeyPatch):
    snap = rg.MemSnapshot(
        mem_total_mb=16000,
        mem_available_mb=800,
        swap_total_mb=12000,
        swap_free_mb=500,
        swap_used_pct=95,
        host_mem_total_mb=64000,
        host_mem_available_mb=24000,
        host_swap_total_mb=100000,
        host_swap_free_mb=45000,
        host_swap_used_pct=55,
        drift_mem_total_mb=-48000,
        drift_mem_available_mb=-23200,
        drift_swap_used_pct=40,
    )
    monkeypatch.setattr(rg, "_read_snapshot", lambda: snap)
    monkeypatch.setattr(
        rg,
        "_read_linux_memory_psi",
        lambda: {
            "psi_some_avg10": 25.0,
            "psi_some_avg60": 10.0,
            "psi_full_avg10": 12.0,
            "psi_full_avg60": 5.0,
        },
    )

    out = rg.diagnose_wsl_crash()

    assert out["guest_mem_available_mb"] == 800
    assert out["host_mem_total_mb"] == 64000
    assert out["risk_level"] in {"high", "critical"}
    assert out["risk_score"] >= 3
    assert out["likely_causes"]
    assert out["prevention_actions"]


def test_cli_diagnose_wsl_crash_json(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        rg,
        "diagnose_wsl_crash",
        lambda: {
            "risk_level": "low",
            "risk_score": 0,
            "guest_mem_available_mb": 5000,
            "guest_swap_used_pct": 10,
            "prevention_actions": ["ok"],
        },
    )
    monkeypatch.setattr(
        "sys.argv",
        ["runtime-guard", "--diagnose-wsl-crash", "--json", "--fail-on-risk", "high"],
    )

    buf = io.StringIO()
    with redirect_stdout(buf), pytest.raises(SystemExit) as ex:
        rg._cli()

    assert ex.value.code == 0
    payload = json.loads(buf.getvalue())
    assert payload["risk_level"] == "low"


def test_cli_diagnose_wsl_crash_fail_on_high(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        rg,
        "diagnose_wsl_crash",
        lambda: {
            "risk_level": "critical",
            "risk_score": 6,
            "guest_mem_available_mb": 700,
            "guest_swap_used_pct": 95,
            "prevention_actions": ["reduce load"],
        },
    )
    monkeypatch.setattr(
        "sys.argv",
        ["runtime-guard", "--diagnose-wsl-crash", "--fail-on-risk", "high"],
    )

    with pytest.raises(SystemExit) as ex:
        rg._cli()

    assert ex.value.code == 1
