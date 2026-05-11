import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = REPO_ROOT / "examples" / "grafana" / "runtime_guard_dashboard.json"
SAMPLE_METRICS_PATH = REPO_ROOT / "examples" / "grafana" / "sample_metrics.prom"


def test_grafana_dashboard_is_valid_json_and_has_panels() -> None:
    dashboard = json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))
    assert dashboard["title"] == "Runtime Guard Memory Overview"
    assert dashboard["uid"] == "runtime-guard-memory-overview"
    assert isinstance(dashboard.get("panels"), list)
    assert len(dashboard["panels"]) >= 5


def test_sample_metrics_contains_runtime_guard_series() -> None:
    metrics_text = SAMPLE_METRICS_PATH.read_text(encoding="utf-8")
    assert "runtime_guard_mem_available_mb" in metrics_text
    assert "runtime_guard_host_mem_available_mb" in metrics_text
    assert "runtime_guard_drift_mem_available_mb" in metrics_text
