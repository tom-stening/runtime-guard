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
    monkeypatch.setattr(
        rg,
        "_read_windows_wsl_event_hints",
        lambda: {
            "host_event_logs_checked": ["System"],
            "host_error_event_count": 1,
            "host_high_relevance_event_count": 0,
            "host_error_events": [
                {
                    "log": "System",
                    "id": 1,
                    "level": "Warning",
                    "provider": "TestProvider",
                    "message": "sample",
                    "relevance": "low",
                    "time": "2026-05-11T00:00:00",
                }
            ],
        },
    )

    out = rg.diagnose_wsl_crash()

    assert out["guest_mem_available_mb"] == 800
    assert out["host_mem_total_mb"] == 64000
    assert out["host_error_event_count"] == 1
    assert out["host_high_relevance_event_count"] == 0
    assert out["host_error_events"]
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


def test_classify_wsl_risk_includes_host_event_signal():
    level, score, causes, actions = rg._classify_wsl_crash_risk(
        {
            "guest_mem_available_mb": 5000,
            "guest_swap_used_pct": 20,
            "psi_some_avg10": 0.0,
            "psi_full_avg10": 0.0,
            "host_vm_used_pct": 40,
            "host_error_event_count": 2,
            "host_high_relevance_event_count": 1,
        }
    )

    assert level in {"moderate", "high", "critical"}
    assert score >= 1
    assert any("host WSL/Hyper-V relevant" in c for c in causes)
    assert any("Hyper-V/WSL-related events" in a for a in actions)


def test_classify_wsl_risk_keeps_low_relevance_host_events_informational_only():
    level, score, causes, actions = rg._classify_wsl_crash_risk(
        {
            "guest_mem_available_mb": 5000,
            "guest_swap_used_pct": 20,
            "psi_some_avg10": 0.0,
            "psi_full_avg10": 0.0,
            "host_vm_used_pct": 40,
            "host_error_event_count": 3,
            "host_high_relevance_event_count": 0,
        }
    )

    assert level == "low"
    assert score == 0
    assert any("low relevance" in c for c in causes)
    assert any("prioritize guest memory pressure" in a for a in actions)


def test_read_windows_wsl_event_hints_handles_malformed_event_types(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(rg, "_is_wsl", lambda: True)
    monkeypatch.setattr(
        "subprocess.check_output",
        lambda *args, **kwargs: json.dumps(
            [
                {
                    "LogName": "System",
                    "TimeCreated": "2026-05-11T00:00:00",
                    "Id": 42,
                    "Level": "Warning",
                    "Provider": "LxssManager",
                    "Message": "WSL service warning",
                },
                {
                    "LogName": 101,
                    "TimeCreated": 999,
                    "Id": "not-int",
                    "Level": ["Warning"],
                    "Provider": {"name": "broken"},
                    "Message": {"text": "bad"},
                },
            ]
        ),
    )

    out = rg._read_windows_wsl_event_hints(max_events=5)
    assert out["host_error_event_count"] == 2
    assert out["host_high_relevance_event_count"] >= 1
    assert out["host_error_events"][0]["id"] == 42
    assert out["host_error_events"][1]["id"] == 0
    assert out["host_error_events"][1]["log"] == ""
    assert out["host_error_events"][1]["provider"] == ""
    assert out["host_error_events"][1]["message"] == ""


def test_diagnose_wsl_crash_ignores_non_typed_extension_rss_in_total(
    monkeypatch: pytest.MonkeyPatch,
):
    snap = rg.MemSnapshot(
        mem_total_mb=16000,
        mem_available_mb=7000,
        swap_total_mb=12000,
        swap_free_mb=11000,
        swap_used_pct=8,
        host_mem_total_mb=64000,
        host_mem_available_mb=32000,
        host_swap_total_mb=100000,
        host_swap_free_mb=85000,
        host_swap_used_pct=15,
        drift_mem_total_mb=-48000,
        drift_mem_available_mb=-25000,
        drift_swap_used_pct=7,
    )
    monkeypatch.setattr(rg, "_read_snapshot", lambda: snap)
    monkeypatch.setattr(
        rg,
        "_read_linux_memory_psi",
        lambda: {
            "psi_some_avg10": 0.0,
            "psi_some_avg60": 0.0,
            "psi_full_avg10": 0.0,
            "psi_full_avg60": 0.0,
        },
    )
    monkeypatch.setattr(
        rg,
        "_top_memory_process_details",
        lambda n=8: [],
    )
    monkeypatch.setattr(
        rg,
        "_summarize_vscode_extension_rss",
        lambda rows, limit=5: [
            {"extension": "good.one", "rss_mb": 1200},
            {"extension": "bad.string", "rss_mb": "1300"},
            {"extension": "bad.bool", "rss_mb": True},
            {"extension": "bad.neg", "rss_mb": -5},
        ],
    )
    monkeypatch.setattr(
        rg,
        "_read_wsl_running_distros",
        lambda: {
            "wsl_running_distros": [],
            "wsl_running_distro_count": 0,
            "docker_desktop_running": False,
        },
    )
    monkeypatch.setattr(
        rg,
        "_read_windows_wsl_event_hints",
        lambda max_events=6: {
            "host_event_logs_checked": ["System"],
            "host_error_event_count": 0,
            "host_high_relevance_event_count": 0,
            "host_error_events": [],
        },
    )

    out = rg.diagnose_wsl_crash()
    assert out["guest_vscode_extension_total_rss_mb"] == 1200


def test_classify_wsl_risk_does_not_coerce_non_boolean_docker_flag():
    level, score, _causes, _actions = rg._classify_wsl_crash_risk(
        {
            "guest_mem_available_mb": 1500,
            "guest_swap_used_pct": 20,
            "psi_some_avg10": 0.0,
            "psi_full_avg10": 0.0,
            "host_vm_used_pct": 40,
            "host_error_event_count": 0,
            "host_high_relevance_event_count": 0,
            "wsl_running_distro_count": 1,
            "docker_desktop_running": "false",
        }
    )

    assert level == "low"
    assert score == 0


def test_classify_wsl_risk_handles_non_numeric_metrics_without_crashing():
    level, score, causes, actions = rg._classify_wsl_crash_risk(
        {
            "guest_mem_available_mb": "not-a-number",
            "guest_swap_used_pct": "n/a",
            "psi_some_avg10": "bad",
            "psi_full_avg10": "bad",
            "host_vm_used_pct": "bad",
            "host_error_event_count": "bad",
            "host_high_relevance_event_count": "bad",
            "wsl_running_distro_count": "bad",
            "docker_desktop_running": None,
        }
    )

    assert level in {"moderate", "high", "critical"}
    assert score >= 1
    assert any("below 1 GiB" in c for c in causes)
    assert actions
