#!/usr/bin/env python3
"""Generate a fleet runtime report for RuntimeGuard coverage across repos.

This script reads the JSON output from enforce_runtime_guard_all_repos.py and
adds runtime visibility signals:
- whether each repo is currently active in /proc (cwd-based)
- aggregate enforcement and activity summary
- optional integration summary from validate_integration_fleet.py
- optional WSL crash diagnosis snapshot
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from runtime_guard import diagnose_wsl_crash


_ENFORCED_STATES = {"enforced", "already_enforced"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build fleet runtime report for RuntimeGuard.")
    parser.add_argument(
        "--enforcement-report",
        default="reports/repo_guard_enforcement.json",
        help="Path to enforcement JSON report produced by enforce_runtime_guard_all_repos.py",
    )
    parser.add_argument(
        "--output",
        default="reports/repo_guard_runtime_status.json",
        help="Path for generated runtime status JSON",
    )
    parser.add_argument(
        "--no-proc-scan",
        action="store_true",
        help="Skip /proc activity scan (useful for deterministic tests).",
    )
    parser.add_argument(
        "--integration-report",
        default="reports/integration_fleet_status.json",
        help=(
            "Optional path to integration fleet report from "
            "validate_integration_fleet.py"
        ),
    )
    parser.add_argument(
        "--include-wsl-diagnosis",
        action="store_true",
        help="Include diagnose_wsl_crash() payload in report.",
    )
    parser.add_argument(
        "--fail-on-unenforced",
        action="store_true",
        help="Exit 1 when any repositories are unenforced.",
    )
    parser.add_argument(
        "--fail-on-integration-unhealthy",
        action="store_true",
        help="Exit 1 when integration_overall_healthy is false in integration report.",
    )
    parser.add_argument(
        "--fail-on-wsl-risk",
        choices=["moderate", "high", "critical"],
        help="Exit 1 when WSL risk level is at or above this threshold (requires --include-wsl-diagnosis).",
    )
    parser.add_argument(
        "--fail-on-extension-total-rss-mb",
        type=int,
        default=0,
        help=(
            "Exit 1 when wsl_diagnosis.guest_vscode_extension_total_rss_mb "
            "meets/exceeds this threshold (requires --include-wsl-diagnosis)."
        ),
    )
    parser.add_argument(
        "--fail-on-extension-rss",
        action="append",
        default=[],
        metavar="EXTENSION=MB",
        help=(
            "Exit 1 when a named extension in wsl_diagnosis.guest_vscode_extension_rss "
            "meets/exceeds MB threshold. May be repeated."
        ),
    )
    parser.add_argument(
        "--run-id",
        default="",
        help="Optional external run identifier for cross-system correlation.",
    )
    parser.add_argument(
        "--fail-on-run-id-mismatch",
        action="store_true",
        help=(
            "Exit 1 when source artifact run_id values do not match the selected run_id. "
            "Missing source run_id values are also treated as mismatch."
        ),
    )
    return parser.parse_args()


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    if not isinstance(parsed, dict):
        return None, "report payload must be a JSON object"
    return parsed, None


def _cwd_in_repo(cwd: str, repo_path: str) -> bool:
    try:
        common = os.path.commonpath([cwd, repo_path])
    except ValueError:
        return False
    return common == repo_path


def _scan_repo_activity(repo_paths: list[str]) -> dict[str, int]:
    counts = {p: 0 for p in repo_paths}
    if not sys_platform_linux_proc_available():
        return counts

    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        cwd_link = os.path.join(entry.path, "cwd")
        try:
            cwd = os.readlink(cwd_link)
        except OSError:
            continue
        for repo_path in repo_paths:
            if _cwd_in_repo(cwd, repo_path):
                counts[repo_path] += 1
    return counts


def sys_platform_linux_proc_available() -> bool:
    return os.name == "posix" and os.path.isdir("/proc")


def _normalize_run_id(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return ""


def _strict_bool(value: Any) -> tuple[bool, bool]:
    if isinstance(value, bool):
        return value, True
    return False, False


def _strict_non_negative_int(value: Any) -> tuple[int, bool]:
    if isinstance(value, bool):
        return 0, False
    if isinstance(value, int) and value >= 0:
        return value, True
    return 0, False


def _strict_non_empty_string(value: Any, default: str) -> tuple[str, bool]:
    if isinstance(value, str) and value.strip():
        return value.strip(), True
    return default, False


def _build_recommendations(
    summary: dict[str, Any],
    *,
    include_wsl_diagnosis: bool,
    wsl_diag: dict[str, Any] | None,
) -> list[str]:
    recommendations: list[str] = []

    if not bool(summary.get("fully_enforced", False)):
        recommendations.append(
            "Run enforce_runtime_guard_all_repos.py with --enforce-all-repos to close guard coverage gaps."
        )

    integration_healthy = summary.get("integration_overall_healthy")
    if integration_healthy is False:
        recommendations.append(
            "Run validate_integration_fleet.py --json --require-healthy and fix unhealthy component checks."
        )

    if include_wsl_diagnosis and isinstance(wsl_diag, dict):
        wsl_risk = str(summary.get("wsl_risk_level", "unknown"))
        if wsl_risk in {"moderate", "high", "critical"}:
            recommendations.append(
                "WSL risk is elevated; reduce concurrent heavy processes and rerun runtime-guard --diagnose-wsl-crash --json."
            )

        if bool(summary.get("wsl_docker_desktop_running", False)):
            recommendations.append(
                "Stop docker-desktop when not needed during heavy WSL IDE/test/training sessions."
            )

        top_cmd = str(summary.get("wsl_top_process_command", "")).lower()
        if "vscode-server" in top_cmd or "extensionhost" in top_cmd:
            recommendations.append(
                "Close idle VS Code windows/workspaces to reduce extension host memory pressure."
            )
        if "pylance" in top_cmd:
            recommendations.append(
                "Reduce Pylance indexing scope (exclude large directories) during heavy workload windows."
            )
        if "python" in top_cmd:
            recommendations.append(
                "Pause non-essential long-running Python jobs while memory pressure is elevated."
            )

        for action in wsl_diag.get("prevention_actions", [])[:3]:
            text = str(action).strip()
            if text:
                recommendations.append(text)

    def _norm(text: str) -> str:
        out = text.strip().lower()
        if out.endswith("."):
            out = out[:-1]
        out = " ".join(out.split())
        return out

    def _signature(text: str) -> str:
        normalized = _norm(text)
        if "docker-desktop" in normalized:
            return "sig:docker-desktop"
        if "vscode" in normalized or "extension host" in normalized:
            return "sig:vscode-extension-host"
        if "pylance" in normalized:
            return "sig:pylance"
        if "python jobs" in normalized or "python job" in normalized:
            return "sig:python-jobs"
        if "wsl risk is elevated" in normalized:
            return "sig:wsl-risk"
        if "enforce_runtime_guard_all_repos.py" in normalized:
            return "sig:enforcement-gap"
        if "validate_integration_fleet.py" in normalized:
            return "sig:integration-health"
        return "txt:" + normalized

    deduped: list[str] = []
    seen: set[str] = set()
    for row in recommendations:
        sig = _signature(row)
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(row)

    if not deduped:
        deduped.append("Fleet status is healthy; keep periodic enforcement and runtime reporting enabled.")

    return deduped


def _risk_rank(level: str) -> int:
    table = {"low": 0, "moderate": 1, "high": 2, "critical": 3}
    return table.get(level.strip().lower(), -1)


def _parse_extension_rss_specs(specs: list[str]) -> dict[str, int]:
    parsed: dict[str, int] = {}
    for spec in specs:
        if "=" not in spec:
            raise ValueError(f"invalid --fail-on-extension-rss spec '{spec}' (expected EXTENSION=MB)")
        ext_raw, mb_raw = spec.split("=", 1)
        ext_name = ext_raw.strip()
        if not ext_name:
            raise ValueError(f"invalid --fail-on-extension-rss spec '{spec}' (empty extension name)")
        try:
            threshold_mb = int(mb_raw)
        except ValueError as exc:
            raise ValueError(
                f"invalid --fail-on-extension-rss spec '{spec}' (MB must be integer)"
            ) from exc
        if threshold_mb <= 0:
            raise ValueError(
                f"invalid --fail-on-extension-rss spec '{spec}' (MB must be > 0)"
            )
        parsed[ext_name] = threshold_mb
    return parsed


def _build_failed_gate(
    *,
    gate: str,
    run_id: str,
    evaluated_at_utc: str,
    actual: Any,
    threshold: Any,
    reason: str,
    extension: str | None = None,
) -> dict[str, Any]:
    gate_id = gate
    if extension:
        gate_id = f"{gate}:{extension}"

    payload: dict[str, Any] = {
        "gate": gate,
        "gate_id": gate_id,
        "run_id": run_id,
        "evaluated_at_utc": evaluated_at_utc,
        "actual": actual,
        "threshold": threshold,
        "reason": reason,
    }
    if extension:
        payload["extension"] = extension
    return payload


def _compute_overall_runtime_healthy(summary: dict[str, Any]) -> bool:
    if not bool(summary.get("fully_enforced", False)):
        return False

    integration_healthy = summary.get("integration_overall_healthy")
    if integration_healthy is False:
        return False

    wsl_level = str(summary.get("wsl_risk_level", "low")).lower()
    if _risk_rank(wsl_level) >= _risk_rank("high"):
        return False

    return True


def _extract_run_id(payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return ""
    root = payload.get("run_id")
    if isinstance(root, str) and root.strip():
        return root.strip()
    summary = payload.get("summary")
    if isinstance(summary, dict):
        nested = summary.get("run_id")
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return ""


def _safe_git_commit(repo_root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    commit = proc.stdout.strip()
    return commit or "unknown"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stamp_artifact_sha256(payload: dict[str, Any]) -> None:
    prov = payload.get("provenance")
    if not isinstance(prov, dict):
        return
    canonical_payload = json.loads(json.dumps(payload, sort_keys=True))
    canonical_prov = canonical_payload.get("provenance")
    if isinstance(canonical_prov, dict):
        canonical_prov.pop("artifact_sha256", None)
        canonical_prov.pop("signature", None)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    prov["artifact_sha256"] = _sha256_text(canonical)


def _build_signature_envelope(artifact_sha256: str) -> dict[str, str]:
    key_id = str(os.getenv("RUNTIME_GUARD_ARTIFACT_KEY_ID", "")).strip()
    algorithm = str(os.getenv("RUNTIME_GUARD_ARTIFACT_SIGNATURE_ALGORITHM", "")).strip()
    signature = str(os.getenv("RUNTIME_GUARD_ARTIFACT_SIGNATURE", "")).strip()
    mode = "detached" if signature else "unsigned"
    return {
        "mode": mode,
        "signed_field": "artifact_sha256",
        "signed_value": artifact_sha256,
        "algorithm": algorithm,
        "key_id": key_id,
        "signature": signature,
    }


def _build_payload(
    enforcement: dict[str, Any],
    *,
    include_proc_scan: bool,
    include_wsl_diagnosis: bool,
    integration_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    repos = list(enforcement.get("repos", []))
    repo_paths = [str(r.get("repo_path", "")) for r in repos]

    activity_counts = _scan_repo_activity(repo_paths) if include_proc_scan else {p: 0 for p in repo_paths}

    runtime_repos: list[dict[str, Any]] = []
    for repo in repos:
        repo_path = str(repo.get("repo_path", ""))
        status = str(repo.get("status", ""))
        pid_count = int(activity_counts.get(repo_path, 0))
        runtime_repos.append(
            {
                **repo,
                "is_enforced": status in _ENFORCED_STATES,
                "active_pid_count": pid_count,
                "is_active": pid_count > 0,
            }
        )

    enforced_count = sum(1 for r in runtime_repos if r["is_enforced"])
    active_count = sum(1 for r in runtime_repos if r["is_active"])

    parse_warnings: list[str] = []

    summary: dict[str, Any] = {
        "total_repos": len(runtime_repos),
        "enforced_repos": enforced_count,
        "unenforced_repos": len(runtime_repos) - enforced_count,
        "active_repos": active_count,
        "fully_enforced": enforced_count == len(runtime_repos),
        "proc_scan_enabled": include_proc_scan,
    }

    if isinstance(integration_report, dict):
        integ_summary = integration_report.get("summary", {})
        if isinstance(integ_summary, dict):
            overall_healthy, overall_ok = _strict_bool(
                integ_summary.get("overall_healthy", False)
            )
            summary["integration_overall_healthy"] = overall_healthy
            if not overall_ok:
                parse_warnings.append("integration.summary.overall_healthy must be boolean")

            risk_level, risk_ok = _strict_non_empty_string(
                integ_summary.get("risk_level", "unknown"),
                "unknown",
            )
            summary["integration_risk_level"] = risk_level
            if not risk_ok:
                parse_warnings.append("integration.summary.risk_level must be non-empty string")

            components_total, total_ok = _strict_non_negative_int(
                integ_summary.get("components_total", 0)
            )
            summary["integration_components_total"] = components_total
            if not total_ok:
                parse_warnings.append(
                    "integration.summary.components_total must be a non-negative integer"
                )

            components_healthy, healthy_ok = _strict_non_negative_int(
                integ_summary.get("components_healthy", 0)
            )
            summary["integration_components_healthy"] = components_healthy
            if not healthy_ok:
                parse_warnings.append(
                    "integration.summary.components_healthy must be a non-negative integer"
                )
        execution_mode, execution_ok = _strict_non_empty_string(
            integration_report.get("execution_mode", "unknown"),
            "unknown",
        )
        summary["integration_execution_mode"] = execution_mode
        if not execution_ok:
            parse_warnings.append("integration.execution_mode must be non-empty string")
        pressure_meta = integration_report.get("pressure_fallback", {})
        if isinstance(pressure_meta, dict):
            pressure_enabled, pressure_enabled_ok = _strict_bool(
                pressure_meta.get("enabled", False)
            )
            summary["integration_pressure_fallback_enabled"] = pressure_enabled
            if not pressure_enabled_ok:
                parse_warnings.append("integration.pressure_fallback.enabled must be boolean")

            pressure_detected, pressure_detected_ok = _strict_bool(
                pressure_meta.get("pressure_detected", False)
            )
            summary["integration_pressure_detected"] = pressure_detected
            if not pressure_detected_ok:
                parse_warnings.append(
                    "integration.pressure_fallback.pressure_detected must be boolean"
                )

    wsl_diag: dict[str, Any] | None = None

    payload: dict[str, Any] = {
        "source_enforcement_report": enforcement,
        "summary": summary,
        "repos": runtime_repos,
    }

    if include_wsl_diagnosis:
        raw_wsl_diag = diagnose_wsl_crash()
        if isinstance(raw_wsl_diag, dict):
            wsl_diag = raw_wsl_diag
        else:
            wsl_diag = {}
            parse_warnings.append("wsl_diagnosis payload must be an object")
        payload["wsl_diagnosis"] = wsl_diag
        risk_level, risk_ok = _strict_non_empty_string(wsl_diag.get("risk_level", "unknown"), "unknown")
        summary["wsl_risk_level"] = risk_level
        if not risk_ok:
            parse_warnings.append("wsl_diagnosis.risk_level must be non-empty string")

        risk_score, risk_score_ok = _strict_non_negative_int(wsl_diag.get("risk_score", 0))
        summary["wsl_risk_score"] = risk_score
        if not risk_score_ok:
            parse_warnings.append("wsl_diagnosis.risk_score must be a non-negative integer")

        distro_count, distro_count_ok = _strict_non_negative_int(
            wsl_diag.get("wsl_running_distro_count", 0)
        )
        summary["wsl_running_distro_count"] = distro_count
        if not distro_count_ok:
            parse_warnings.append(
                "wsl_diagnosis.wsl_running_distro_count must be a non-negative integer"
            )

        docker_running, docker_ok = _strict_bool(
            wsl_diag.get("docker_desktop_running", False)
        )
        summary["wsl_docker_desktop_running"] = docker_running
        if not docker_ok:
            parse_warnings.append("wsl_diagnosis.docker_desktop_running must be boolean")

        extension_total, extension_total_ok = _strict_non_negative_int(
            wsl_diag.get("guest_vscode_extension_total_rss_mb", 0)
        )
        summary["wsl_vscode_extension_total_rss_mb"] = extension_total
        if not extension_total_ok:
            parse_warnings.append(
                "wsl_diagnosis.guest_vscode_extension_total_rss_mb must be a non-negative integer"
            )
        top_rows = wsl_diag.get("guest_top_memory_processes", [])
        if isinstance(top_rows, list) and top_rows:
            first = top_rows[0]
            if isinstance(first, dict):
                top_pid, top_pid_ok = _strict_non_negative_int(first.get("pid", 0))
                summary["wsl_top_process_pid"] = top_pid
                if not top_pid_ok:
                    parse_warnings.append(
                        "wsl_diagnosis.guest_top_memory_processes[0].pid must be a non-negative integer"
                    )

                top_rss, top_rss_ok = _strict_non_negative_int(first.get("rss_mb", 0))
                summary["wsl_top_process_rss_mb"] = top_rss
                if not top_rss_ok:
                    parse_warnings.append(
                        "wsl_diagnosis.guest_top_memory_processes[0].rss_mb must be a non-negative integer"
                    )

                top_cmd, top_cmd_ok = _strict_non_empty_string(first.get("command", ""), "")
                summary["wsl_top_process_command"] = top_cmd
                if not top_cmd_ok:
                    parse_warnings.append(
                        "wsl_diagnosis.guest_top_memory_processes[0].command must be a string"
                    )

    if parse_warnings:
        summary["parse_warnings"] = parse_warnings

    payload["recommendations"] = _build_recommendations(
        summary,
        include_wsl_diagnosis=include_wsl_diagnosis,
        wsl_diag=wsl_diag,
    )
    summary["recommendation_count"] = len(payload["recommendations"])
    summary["overall_runtime_healthy"] = _compute_overall_runtime_healthy(summary)

    if isinstance(integration_report, dict):
        payload["integration_status"] = integration_report

    return payload


def main() -> int:
    args = _parse_args()

    enforcement_path = Path(args.enforcement_report)
    if not enforcement_path.is_absolute():
        enforcement_path = Path.cwd() / enforcement_path
    if not enforcement_path.exists():
        raise SystemExit(f"error: enforcement report not found: {enforcement_path}")

    enforcement, enforcement_error = _load_json(enforcement_path)
    if enforcement_error is not None or not isinstance(enforcement, dict):
        print(
            f"error: unable to read enforcement report {enforcement_path}: {enforcement_error or 'unknown error'}",
            file=sys.stderr,
        )
        return 2

    integration_payload: dict[str, Any] | None = None
    integration_parse_warning = ""
    integration_path = Path(args.integration_report)
    if not integration_path.is_absolute():
        integration_path = Path.cwd() / integration_path
    if integration_path.exists():
        loaded, integration_error = _load_json(integration_path)
        if isinstance(loaded, dict):
            integration_payload = loaded
        elif integration_error:
            integration_parse_warning = (
                f"unable to read integration report {integration_path}: {integration_error}"
            )

    payload = _build_payload(
        enforcement,
        include_proc_scan=not args.no_proc_scan,
        include_wsl_diagnosis=bool(args.include_wsl_diagnosis),
        integration_report=integration_payload,
    )

    summary = payload.get("summary", {})
    if integration_parse_warning and isinstance(summary, dict):
        warnings = summary.get("parse_warnings", [])
        if not isinstance(warnings, list):
            warnings = [str(warnings)]
        warnings.append(integration_parse_warning)
        summary["parse_warnings"] = warnings
        # Fail closed: malformed integration input must not be treated as healthy/unknown.
        summary["integration_overall_healthy"] = False
    run_id = _normalize_run_id(args.run_id)
    if not run_id:
        run_id = str(uuid.uuid4())

    enforcement_run_id = _extract_run_id(enforcement)
    integration_run_id = _extract_run_id(integration_payload)
    source_run_ids: dict[str, str] = {
        "repo_guard_enforcement": enforcement_run_id,
        "integration_fleet_status": integration_run_id,
        "repo_guard_runtime_status": run_id,
    }

    source_matches = [
        value == run_id for value in [enforcement_run_id, integration_run_id] if value
    ]
    source_values_present = [bool(enforcement_run_id), bool(integration_run_id)]
    run_id_consistent = bool(source_matches) and all(source_matches) and all(source_values_present)

    payload["run_id"] = run_id
    payload["source_run_ids"] = source_run_ids
    payload["run_id_consistent"] = run_id_consistent
    summary["run_id"] = run_id
    summary["source_enforcement_run_id"] = enforcement_run_id
    summary["source_integration_run_id"] = integration_run_id
    summary["run_id_consistent"] = run_id_consistent
    repo_root = Path(__file__).resolve().parent.parent
    provenance_inputs: dict[str, Any] = {
        "source_artifact_hashes": {
            "repo_guard_enforcement": _sha256_file(enforcement_path),
        },
        "enforcement_report": str(enforcement_path),
    }
    if integration_path.exists():
        provenance_inputs["source_artifact_hashes"]["integration_fleet_status"] = _sha256_file(integration_path)
        provenance_inputs["integration_report"] = str(integration_path)

    payload["provenance"] = {
        "schema_version": 1,
        "tool": "repo_guard_fleet_report",
        "script": str(Path(__file__).resolve()),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
        "git_commit": _safe_git_commit(repo_root),
        "inputs": provenance_inputs,
    }
    failed_gates: list[dict[str, Any]] = []
    evaluated_at_utc = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    extension_specs: dict[str, int] = {}
    try:
        extension_specs = _parse_extension_rss_specs(list(args.fail_on_extension_rss))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.fail_on_unenforced and int(summary.get("unenforced_repos", 0) or 0) > 0:
        failed_gates.append(
            _build_failed_gate(
                gate="fail-on-unenforced",
                run_id=run_id,
                evaluated_at_utc=evaluated_at_utc,
                actual=int(summary.get("unenforced_repos", 0) or 0),
                threshold=0,
                reason="unenforced repos present",
            )
        )
    if args.fail_on_integration_unhealthy and summary.get("integration_overall_healthy") is False:
        failed_gates.append(
            _build_failed_gate(
                gate="fail-on-integration-unhealthy",
                run_id=run_id,
                evaluated_at_utc=evaluated_at_utc,
                actual=False,
                threshold=True,
                reason="integration overall health is false",
            )
        )
    if args.fail_on_wsl_risk:
        threshold = str(args.fail_on_wsl_risk)
        actual = str(summary.get("wsl_risk_level", "low"))
        if _risk_rank(actual) >= _risk_rank(threshold):
            failed_gates.append(
                _build_failed_gate(
                    gate="fail-on-wsl-risk",
                    run_id=run_id,
                    evaluated_at_utc=evaluated_at_utc,
                    actual=actual,
                    threshold=threshold,
                    reason="WSL risk level meets/exceeds threshold",
                )
            )

    if args.fail_on_extension_total_rss_mb > 0:
        actual_total = int(summary.get("wsl_vscode_extension_total_rss_mb", 0) or 0)
        if actual_total >= int(args.fail_on_extension_total_rss_mb):
            failed_gates.append(
                _build_failed_gate(
                    gate="fail-on-extension-total-rss-mb",
                    run_id=run_id,
                    evaluated_at_utc=evaluated_at_utc,
                    actual=actual_total,
                    threshold=int(args.fail_on_extension_total_rss_mb),
                    reason="extension total RSS meets/exceeds threshold",
                )
            )

    if extension_specs:
        wsl_diag = payload.get("wsl_diagnosis", {})
        ext_rows = (
            wsl_diag.get("guest_vscode_extension_rss", [])
            if isinstance(wsl_diag, dict)
            else []
        )
        ext_totals: dict[str, int] = {}
        if isinstance(ext_rows, list):
            for row in ext_rows:
                if not isinstance(row, dict):
                    continue
                ext_name = str(row.get("extension", "") or "").strip()
                if not ext_name:
                    continue
                ext_rss_mb, ext_rss_ok = _strict_non_negative_int(row.get("rss_mb", 0))
                if not ext_rss_ok:
                    warnings = summary.get("parse_warnings", [])
                    if not isinstance(warnings, list):
                        warnings = [str(warnings)]
                    warnings.append(
                        f"wsl_diagnosis.guest_vscode_extension_rss[{ext_name}].rss_mb must be a non-negative integer"
                    )
                    summary["parse_warnings"] = warnings
                    continue
                ext_totals[ext_name] = ext_rss_mb

        for ext_name, threshold_mb in extension_specs.items():
            actual_mb = int(ext_totals.get(ext_name, 0) or 0)
            if actual_mb >= threshold_mb:
                failed_gates.append(
                    _build_failed_gate(
                        gate="fail-on-extension-rss",
                        run_id=run_id,
                        evaluated_at_utc=evaluated_at_utc,
                        extension=ext_name,
                        actual=actual_mb,
                        threshold=threshold_mb,
                        reason="extension RSS meets/exceeds threshold",
                    )
                )

    if bool(args.fail_on_run_id_mismatch) and not run_id_consistent:
        failed_gates.append(
            _build_failed_gate(
                gate="fail-on-run-id-mismatch",
                run_id=run_id,
                evaluated_at_utc=evaluated_at_utc,
                actual=source_run_ids,
                threshold={"all_sources_match_run_id": True},
                reason="source artifact run_id values are missing or mismatched",
            )
        )

    payload["failed_gates"] = failed_gates
    summary["failed_gate_count"] = len(failed_gates)
    _stamp_artifact_sha256(payload)
    prov = payload.get("provenance")
    if isinstance(prov, dict):
        prov["signature"] = _build_signature_envelope(str(prov.get("artifact_sha256") or ""))

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = Path.cwd() / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps(payload["summary"], indent=2, sort_keys=True))
    print(f"report: {output_path}")

    if failed_gates:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
