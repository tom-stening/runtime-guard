from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


def _run_script(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    script = Path("scripts/enforce_runtime_guard_all_repos.py").resolve()
    return subprocess.run(
        [
            sys.executable,
            str(script),
            "--root",
            str(tmp_path),
            "--report-path",
            str(tmp_path / "report.json"),
            *args,
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def _load_module():
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "enforce_runtime_guard_all_repos.py"
    spec = importlib.util.spec_from_file_location("enforce_runtime_guard_all_repos", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_enforcement_creates_sitecustomize_for_python_repo(tmp_path: Path) -> None:
    py_repo = tmp_path / "py-repo"
    py_repo.mkdir(parents=True)
    (py_repo / ".git").mkdir()
    (py_repo / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    result = _run_script(tmp_path)
    assert result.returncode == 0, result.stderr

    sitecustomize = py_repo / "sitecustomize.py"
    assert sitecustomize.exists()
    content = sitecustomize.read_text(encoding="utf-8")
    assert "RuntimeGuard autostart" in content

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["python_repos"] == 1
    assert report["summary"]["enforced"] == 1


def test_existing_non_runtime_guard_sitecustomize_is_not_overwritten(tmp_path: Path) -> None:
    py_repo = tmp_path / "py-repo"
    py_repo.mkdir(parents=True)
    (py_repo / ".git").mkdir()
    (py_repo / "setup.py").write_text("print('x')\n", encoding="utf-8")
    (py_repo / "sitecustomize.py").write_text("print('custom')\n", encoding="utf-8")

    result = _run_script(tmp_path)
    assert result.returncode == 0, result.stderr

    content = (py_repo / "sitecustomize.py").read_text(encoding="utf-8")
    assert content == "print('custom')\n"

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["blocked_existing_sitecustomize"] == 1


def test_dry_run_reports_candidates_without_writing(tmp_path: Path) -> None:
    py_repo = tmp_path / "py-repo"
    py_repo.mkdir(parents=True)
    (py_repo / ".git").mkdir()
    (py_repo / "Pipfile").write_text("[packages]\n", encoding="utf-8")

    result = _run_script(tmp_path, "--dry-run")
    assert result.returncode == 0, result.stderr

    assert not (py_repo / "sitecustomize.py").exists()
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["dry_run_candidates"] == 1


def test_enforce_all_repos_writes_sitecustomize_for_non_python_repo(tmp_path: Path) -> None:
    repo = tmp_path / "docs-repo"
    repo.mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "README.md").write_text("hello\n", encoding="utf-8")

    result = _run_script(tmp_path, "--enforce-all-repos")
    assert result.returncode == 0, result.stderr

    sitecustomize = repo / "sitecustomize.py"
    assert sitecustomize.exists()
    content = sitecustomize.read_text(encoding="utf-8")
    assert "RuntimeGuard autostart" in content

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["watcher_only_candidates"] == 0


def test_run_id_override_is_written_to_enforcement_payload(tmp_path: Path) -> None:
    repo = tmp_path / "py-repo"
    repo.mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    result = _run_script(tmp_path, "--run-id", "ci-run-xyz")
    assert result.returncode == 0, result.stderr

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report.get("run_id") == "ci-run-xyz"
    assert report.get("summary", {}).get("run_id") == "ci-run-xyz"
    provenance = report.get("provenance", {})
    assert provenance.get("tool") == "enforce_runtime_guard_all_repos"
    assert provenance.get("run_id") == "ci-run-xyz"
    assert str(provenance.get("generated_at_utc", "")).endswith("Z")
    assert provenance.get("inputs", {}).get("args_digest")
    assert provenance.get("artifact_sha256")
    signature = provenance.get("signature", {})
    assert signature.get("mode") in {"unsigned", "detached"}
    assert signature.get("signed_field") == "artifact_sha256"


def test_non_string_run_id_generates_uuid_in_enforcement_payload(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "py-repo"
    repo.mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    module = _load_module()

    class _Args:
        root = str(tmp_path)
        report_path = str(tmp_path / "report.json")
        stage = "repo-autostart"
        interval_s = 30.0
        cooldown_s = 30.0
        env_prefix = "RUNTIME_GUARD"
        posture = "wsl_dev"
        enforce_all_repos = False
        force_runtime_guard_sitecustomize = False
        run_id = 123
        dry_run = False

    monkeypatch.setattr(module, "_parse_args", lambda: _Args())

    result_code = module.main()
    assert result_code == 0

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    run_id = report.get("run_id")
    assert isinstance(run_id, str)
    assert run_id
    assert run_id != "123"
    assert report.get("summary", {}).get("run_id") == run_id
    assert report.get("provenance", {}).get("run_id") == run_id


def test_validate_cli_configuration_rejects_non_boolean_flags() -> None:
    module = _load_module()

    class _Args:
        root = "/tmp/workspace"
        report_path = "reports/repo_guard_enforcement.json"
        stage = "repo-autostart"
        interval_s = 30.0
        cooldown_s = 30.0
        env_prefix = "RUNTIME_GUARD"
        posture = "wsl_dev"
        enforce_all_repos = "true"  # type: ignore[assignment]
        force_runtime_guard_sitecustomize = 1  # type: ignore[assignment]
        run_id = ""
        dry_run = "false"  # type: ignore[assignment]

    errors = module._validate_cli_configuration(_Args())
    assert any("--enforce-all-repos flag must be boolean" in row for row in errors)
    assert any(
        "--force-runtime-guard-sitecustomize flag must be boolean" in row
        for row in errors
    )
    assert any("--dry-run flag must be boolean" in row for row in errors)


def test_validate_cli_configuration_rejects_invalid_interval_and_cooldown_types() -> None:
    module = _load_module()

    class _Args:
        root = "/tmp/workspace"
        report_path = "reports/repo_guard_enforcement.json"
        stage = "repo-autostart"
        interval_s = "30"  # type: ignore[assignment]
        cooldown_s = -1
        env_prefix = "RUNTIME_GUARD"
        posture = "wsl_dev"
        enforce_all_repos = False
        force_runtime_guard_sitecustomize = False
        run_id = ""
        dry_run = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--interval-s must be a non-negative number" in row for row in errors)
    assert any("--cooldown-s must be a non-negative number" in row for row in errors)


def test_validate_cli_configuration_rejects_non_string_root_and_report_path() -> None:
    module = _load_module()

    class _Args:
        root = 101  # type: ignore[assignment]
        report_path = None  # type: ignore[assignment]
        stage = "repo-autostart"
        interval_s = 30.0
        cooldown_s = 30.0
        env_prefix = "RUNTIME_GUARD"
        posture = "wsl_dev"
        enforce_all_repos = False
        force_runtime_guard_sitecustomize = False
        run_id = ""
        dry_run = False

    errors = module._validate_cli_configuration(_Args())
    assert any("--root must be a non-empty string" in row for row in errors)
    assert any("--report-path must be a non-empty string" in row for row in errors)


def test_extract_signature_artifact_sha256_rejects_non_string() -> None:
    module = _load_module()
    value, ok = module._extract_signature_artifact_sha256({"artifact_sha256": 123})
    assert value == ""
    assert ok is False


def test_extract_signature_artifact_sha256_accepts_string() -> None:
    module = _load_module()
    value, ok = module._extract_signature_artifact_sha256({"artifact_sha256": "abc"})
    assert value == "abc"
    assert ok is True


def test_main_rejects_non_string_artifact_sha256_for_signature(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = tmp_path / "py-repo"
    repo.mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    module = _load_module()

    class _Args:
        root = str(tmp_path)
        report_path = str(tmp_path / "report.json")
        stage = "repo-autostart"
        interval_s = 30.0
        cooldown_s = 30.0
        env_prefix = "RUNTIME_GUARD"
        posture = "wsl_dev"
        enforce_all_repos = False
        force_runtime_guard_sitecustomize = False
        run_id = "run-1"
        dry_run = False

    original_stamp = module._stamp_artifact_sha256

    def _bad_stamp(payload):
        original_stamp(payload)
        prov = payload.get("provenance")
        if isinstance(prov, dict):
            prov["artifact_sha256"] = 123

    monkeypatch.setattr(module, "_parse_args", lambda: _Args())
    monkeypatch.setattr(module, "_stamp_artifact_sha256", _bad_stamp)

    code = module.main()
    captured = capsys.readouterr()
    assert code == 2
    assert "error: provenance.artifact_sha256 must be a string" in captured.err
