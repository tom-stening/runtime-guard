#!/usr/bin/env python3
"""Build an external-auditor kickoff package from SOC2 readiness outputs."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_json(path: Path, *, expected: str) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"{expected} JSON must be an object")
    return dict(raw)


def _validate_cli_configuration(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []

    for field in ["readiness_report", "contacts", "output"]:
        value = getattr(args, field, "")
        if not isinstance(value, str) or not value.strip():
            errors.append(f"--{field.replace('_', '-')} must be a non-empty string path")

    for field in ["audit_window_start", "audit_window_end"]:
        value = getattr(args, field, None)
        if value is not None and not isinstance(value, str):
            errors.append(f"--{field.replace('_', '-')} must be a string")

    fail_on_gaps = getattr(args, "fail_on_gaps", False)
    if not isinstance(fail_on_gaps, bool):
        errors.append("--fail-on-gaps flag must be boolean")

    return errors


def _as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item)
    return out


def _as_float(value: Any, *, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _as_string(value: Any, *, default: str = "") -> str:
    if isinstance(value, str):
        return value
    return default


def _build_open_items(readiness: dict[str, Any]) -> list[dict[str, str]]:
    open_items: list[dict[str, str]] = []

    for control_id in _as_string_list(readiness.get("missing_required_controls")):
        open_items.append(
            {
                "category": "missing_required_control",
                "control_id": control_id,
                "action": f"Provide implementation and evidence for {control_id}",
            }
        )

    for control_id in _as_string_list(readiness.get("missing_controls")):
        open_items.append(
            {
                "category": "control_not_implemented",
                "control_id": control_id,
                "action": f"Implement control {control_id}",
            }
        )

    for control_id in _as_string_list(readiness.get("missing_evidence_controls")):
        open_items.append(
            {
                "category": "missing_evidence",
                "control_id": control_id,
                "action": f"Attach required artifacts for {control_id}",
            }
        )

    return open_items


def _normalize_contacts(contacts: dict[str, Any]) -> dict[str, str]:
    keys = ["company", "security_owner", "engineering_owner", "audit_contact", "notes"]
    normalized: dict[str, str] = {}
    for key in keys:
        normalized[key] = _as_string(contacts.get(key), default="")
    return normalized


def _build_kickoff_package(
    readiness: dict[str, Any],
    contacts: dict[str, Any],
    *,
    audit_window_start: str | None,
    audit_window_end: str | None,
) -> dict[str, Any]:
    status = readiness.get("status", "")
    if not isinstance(status, str):
        raise ValueError("readiness status must be a string")

    readiness_summary = {
        "status": status,
        "maturity": _as_string(readiness.get("maturity"), default="unknown"),
        "coverage_ratio": _as_float(readiness.get("coverage_ratio"), default=0.0),
        "evidence_ratio": _as_float(readiness.get("evidence_ratio"), default=0.0),
        "total_controls": int(_as_float(readiness.get("total_controls"), default=0.0)),
        "covered_controls": int(_as_float(readiness.get("covered_controls"), default=0.0)),
    }

    open_items = _build_open_items(readiness)

    return {
        "tool": "soc2_audit_kickoff_pack",
        "generated_at_utc": _utc_now_iso(),
        "audit_window": {
            "start": _as_string(audit_window_start, default=""),
            "end": _as_string(audit_window_end, default=""),
        },
        "contacts": _normalize_contacts(contacts),
        "readiness_summary": readiness_summary,
        "open_items": open_items,
        "kickoff_checklist": [
            "Confirm auditor scope and trust service criteria in writing",
            "Freeze evidence collection window and repository tags",
            "Assign control owners for each open SOC2 control",
            "Export and verify hash-chained audit log evidence",
            "Schedule weekly remediation and evidence review with auditor",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build SOC2 external-audit kickoff package from readiness report"
    )
    parser.add_argument(
        "--readiness-report",
        required=True,
        help="Path to soc2_readiness_report JSON output",
    )
    parser.add_argument(
        "--contacts",
        required=True,
        help="Path to contacts JSON (company, security_owner, engineering_owner, audit_contact)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write kickoff package JSON",
    )
    parser.add_argument("--audit-window-start", help="Optional ISO8601 audit window start")
    parser.add_argument("--audit-window-end", help="Optional ISO8601 audit window end")
    parser.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help="Exit 1 when readiness status is not 'ready'",
    )

    args = parser.parse_args()

    config_errors = _validate_cli_configuration(args)
    if config_errors:
        for row in config_errors:
            print(f"error: {row}", file=sys.stderr)
        return 2

    try:
        readiness = _load_json(Path(args.readiness_report), expected="readiness-report")
        contacts = _load_json(Path(args.contacts), expected="contacts")
        package = _build_kickoff_package(
            readiness,
            contacts,
            audit_window_start=args.audit_window_start,
            audit_window_end=args.audit_window_end,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(package, indent=2, sort_keys=True)
    Path(args.output).write_text(rendered + "\n", encoding="utf-8")

    if args.fail_on_gaps:
        status = package.get("readiness_summary", {}).get("status", "")
        if not isinstance(status, str):
            print("error: readiness status must be a string", file=sys.stderr)
            return 2
        if status.strip().lower() != "ready":
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
