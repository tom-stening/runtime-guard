from __future__ import annotations

import importlib.util
import pathlib


_SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "wsl_preflight.py"
_SPEC = importlib.util.spec_from_file_location("wsl_preflight", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
wsl_preflight = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(wsl_preflight)


def test_parse_psi_memory_handles_valid_content(tmp_path):
    psi = tmp_path / "memory"
    psi.write_text(
        "some avg10=12.34 avg60=5.00 avg300=1.0 total=100\n"
        "full avg10=3.21 avg60=1.23 avg300=0.1 total=50\n",
        encoding="utf-8",
    )

    out = wsl_preflight._parse_psi_memory(str(psi))

    assert out["some_avg10"] == 12.34
    assert out["some_avg60"] == 5.0
    assert out["full_avg10"] == 3.21
    assert out["full_avg60"] == 1.23


def test_classify_wsl_risk_marks_critical_for_combined_pressure():
    level, score, causes, actions = wsl_preflight._classify_wsl_risk(
        {
            "guest_mem_available_mb": 700,
            "guest_swap_used_pct": 95,
            "psi_some_avg10": 25.0,
            "psi_full_avg10": 12.0,
            "host_vm_used_pct": 80,
        }
    )

    assert level == "critical"
    assert score >= 5
    assert causes
    assert actions


def test_classify_wsl_risk_low_when_metrics_are_healthy():
    level, score, causes, actions = wsl_preflight._classify_wsl_risk(
        {
            "guest_mem_available_mb": 6000,
            "guest_swap_used_pct": 20,
            "psi_some_avg10": 0.5,
            "psi_full_avg10": 0.0,
            "host_vm_used_pct": 40,
        }
    )

    assert level == "low"
    assert score == 0
    assert causes == []
    assert actions
