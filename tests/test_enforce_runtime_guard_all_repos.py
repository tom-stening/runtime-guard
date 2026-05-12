from __future__ import annotations

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
