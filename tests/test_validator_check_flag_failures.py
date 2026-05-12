from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_script(module_name: str, filename: str):
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / filename
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validate_polars_fails_when_budget_check_unavailable(monkeypatch):
    module = _load_script("validate_polars_integration", "validate_polars_integration.py")
    monkeypatch.setattr(
        module,
        "_check_budget_api",
        lambda: {"available": False, "errors": ["budget check unavailable"]},
    )
    monkeypatch.setattr(module.sys, "argv", ["validate_polars_integration.py", "--check-budget-api", "--json"])
    assert module.main() == 1


def test_validate_dask_fails_when_scheduler_check_unavailable(monkeypatch):
    module = _load_script("validate_dask_integration", "validate_dask_integration.py")
    monkeypatch.setattr(
        module,
        "_check_scheduler_api",
        lambda: {"available": False, "errors": ["scheduler check unavailable"]},
    )
    monkeypatch.setattr(module.sys, "argv", ["validate_dask_integration.py", "--check-scheduler-api", "--json"])
    assert module.main() == 1


def test_validate_ray_fails_when_actor_check_unavailable(monkeypatch):
    module = _load_script("validate_ray_integration", "validate_ray_integration.py")
    monkeypatch.setattr(
        module,
        "_check_actor_api",
        lambda: {"available": False, "errors": ["actor check unavailable"]},
    )
    monkeypatch.setattr(module.sys, "argv", ["validate_ray_integration.py", "--check-actor-api", "--json"])
    assert module.main() == 1


def test_validate_polars_json_emits_provenance_and_run_id(monkeypatch, capsys):
    module = _load_script("validate_polars_integration", "validate_polars_integration.py")
    monkeypatch.setattr(
        module.sys,
        "argv",
        ["validate_polars_integration.py", "--json", "--run-id", "ci-polars"],
    )
    assert module.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_id"] == "ci-polars"
    assert payload["provenance"]["run_id"] == "ci-polars"
    assert payload["provenance"]["artifact_sha256"]
    assert payload["provenance"]["signature"]["signed_field"] == "artifact_sha256"
    assert (
        payload["provenance"]["signature"]["signed_value"]
        == payload["provenance"]["artifact_sha256"]
    )


def test_validate_dask_json_emits_provenance_and_run_id(monkeypatch, capsys):
    module = _load_script("validate_dask_integration", "validate_dask_integration.py")
    monkeypatch.setattr(
        module.sys,
        "argv",
        ["validate_dask_integration.py", "--json", "--run-id", "ci-dask"],
    )
    assert module.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_id"] == "ci-dask"
    assert payload["provenance"]["run_id"] == "ci-dask"
    assert payload["provenance"]["artifact_sha256"]
    assert payload["provenance"]["signature"]["signed_field"] == "artifact_sha256"
    assert (
        payload["provenance"]["signature"]["signed_value"]
        == payload["provenance"]["artifact_sha256"]
    )


def test_validate_ray_json_emits_provenance_and_run_id(monkeypatch, capsys):
    module = _load_script("validate_ray_integration", "validate_ray_integration.py")
    monkeypatch.setattr(
        module.sys,
        "argv",
        ["validate_ray_integration.py", "--json", "--run-id", "ci-ray"],
    )
    assert module.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_id"] == "ci-ray"
    assert payload["provenance"]["run_id"] == "ci-ray"
    assert payload["provenance"]["artifact_sha256"]
    assert payload["provenance"]["signature"]["signed_field"] == "artifact_sha256"
    assert (
        payload["provenance"]["signature"]["signed_value"]
        == payload["provenance"]["artifact_sha256"]
    )
