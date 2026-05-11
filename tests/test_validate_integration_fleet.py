from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "validate_integration_fleet.py"
    spec = importlib.util.spec_from_file_location("validate_integration_fleet", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_extract_last_json_object_handles_prefixed_lines():
    module = _load_module()
    text = "warn one\nwarn two\n{\"ok\": true, \"value\": 3}\n"
    payload = module._extract_last_json_object(text)
    assert payload == {"ok": True, "value": 3}


def test_required_checks_for_each_component():
    module = _load_module()

    polars_ok, polars_errors = module._required_checks_for(
        "polars", {"scan_budget_api": {"available": True}}
    )
    assert polars_ok is True
    assert polars_errors == []

    dask_ok, dask_errors = module._required_checks_for(
        "dask",
        {
            "task_graph_guard_api": {"available": True},
            "scheduler_callback_api": {"available": True},
        },
    )
    assert dask_ok is True
    assert dask_errors == []

    ray_ok, ray_errors = module._required_checks_for(
        "ray", {"actor_monitoring_api": {"available": True}}
    )
    assert ray_ok is True
    assert ray_errors == []


def test_risk_level_rules():
    module = _load_module()

    low = module._risk_level(
        [
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
        ]
    )
    assert low == "low"

    high = module._risk_level(
        [
            {"healthy": False, "api_importable": False, "required_checks_ok": True},
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
        ]
    )
    assert high == "high"

    medium = module._risk_level(
        [
            {"healthy": False, "api_importable": True, "required_checks_ok": True},
            {"healthy": True, "api_importable": True, "required_checks_ok": True},
        ]
    )
    assert medium == "medium"


def test_component_from_payload_marks_healthy_with_required_checks():
    module = _load_module()
    comp = module._component_from_payload(
        "dask",
        {
            "ok": True,
            "api_importable": True,
            "task_graph_guard_api": {"available": True},
            "scheduler_callback_api": {"available": True},
            "errors": ["runtime warning"],
        },
        source="report",
        command=None,
        exit_code=0,
        hard_errors=[],
        warnings=["stderr warning"],
    )
    assert comp["healthy"] is True
    assert comp["source"] == "report"
    assert comp["errors"] == []
    assert "stderr warning" in comp["warnings"]
    assert "runtime warning" in comp["warnings"]


def test_component_from_report_invalid_file(tmp_path: Path):
    module = _load_module()
    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")

    comp = module._component_from_report("ray", bad)
    assert comp["healthy"] is False
    assert comp["source"] == "report"
    assert comp["exit_code"] == 1
    assert any("unable to read report" in err for err in comp["errors"])
