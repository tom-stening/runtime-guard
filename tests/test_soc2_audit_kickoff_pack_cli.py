from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "soc2_audit_kickoff_pack.py"


def test_soc2_kickoff_cli_writes_package_and_open_items(tmp_path: Path):
    readiness = tmp_path / "readiness.json"
    contacts = tmp_path / "contacts.json"
    output = tmp_path / "kickoff.json"

    readiness.write_text(
        json.dumps(
            {
                "status": "gaps-found",
                "maturity": "partial",
                "coverage_ratio": 0.75,
                "evidence_ratio": 0.50,
                "total_controls": 8,
                "covered_controls": 6,
                "missing_required_controls": ["CC7.1"],
                "missing_controls": ["CC7.2"],
                "missing_evidence_controls": ["CC8.1"],
            }
        ),
        encoding="utf-8",
    )
    contacts.write_text(
        json.dumps(
            {
                "company": "ExampleCo",
                "security_owner": "sec@example.com",
                "engineering_owner": "eng@example.com",
                "audit_contact": "audit@example.com",
                "notes": "Initial audit intake",
            }
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--readiness-report",
            str(readiness),
            "--contacts",
            str(contacts),
            "--output",
            str(output),
            "--audit-window-start",
            "2026-06-01T00:00:00Z",
            "--audit-window-end",
            "2026-06-30T23:59:59Z",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["tool"] == "soc2_audit_kickoff_pack"
    assert payload["contacts"]["company"] == "ExampleCo"
    assert payload["readiness_summary"]["status"] == "gaps-found"
    assert payload["audit_window"]["start"] == "2026-06-01T00:00:00Z"
    assert len(payload["kickoff_checklist"]) >= 5

    categories = {item["category"] for item in payload["open_items"]}
    assert "missing_required_control" in categories
    assert "control_not_implemented" in categories
    assert "missing_evidence" in categories


def test_soc2_kickoff_cli_fail_on_gaps_exits_1(tmp_path: Path):
    readiness = tmp_path / "readiness.json"
    contacts = tmp_path / "contacts.json"
    output = tmp_path / "kickoff.json"

    readiness.write_text(
        json.dumps(
            {
                "status": "gaps-found",
                "coverage_ratio": 0.5,
                "evidence_ratio": 0.5,
            }
        ),
        encoding="utf-8",
    )
    contacts.write_text(json.dumps({"company": "ExampleCo"}), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--readiness-report",
            str(readiness),
            "--contacts",
            str(contacts),
            "--output",
            str(output),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1


def test_soc2_kickoff_cli_fail_on_gaps_ready_exits_0(tmp_path: Path):
    readiness = tmp_path / "readiness.json"
    contacts = tmp_path / "contacts.json"
    output = tmp_path / "kickoff.json"

    readiness.write_text(
        json.dumps(
            {
                "status": "ready",
                "coverage_ratio": 1.0,
                "evidence_ratio": 1.0,
                "missing_required_controls": [],
                "missing_controls": [],
                "missing_evidence_controls": [],
            }
        ),
        encoding="utf-8",
    )
    contacts.write_text(json.dumps({"company": "ExampleCo"}), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--readiness-report",
            str(readiness),
            "--contacts",
            str(contacts),
            "--output",
            str(output),
            "--fail-on-gaps",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["readiness_summary"]["status"] == "ready"


def test_soc2_kickoff_cli_fail_on_placeholder_contacts_exits_1(tmp_path: Path):
    readiness = tmp_path / "readiness.json"
    contacts = tmp_path / "contacts.json"
    output = tmp_path / "kickoff.json"

    readiness.write_text(json.dumps({"status": "ready"}), encoding="utf-8")
    contacts.write_text(
        json.dumps(
            {
                "company": "ExampleCo",
                "security_owner": "security@example.com",
                "engineering_owner": "eng@prod.example.org",
                "audit_contact": "audit@example.net",
            }
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--readiness-report",
            str(readiness),
            "--contacts",
            str(contacts),
            "--output",
            str(output),
            "--fail-on-placeholder-contacts",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    assert "placeholder or missing contact values detected" in proc.stderr


def test_soc2_kickoff_cli_fail_on_placeholder_contacts_ready_exits_0(tmp_path: Path):
    readiness = tmp_path / "readiness.json"
    contacts = tmp_path / "contacts.json"
    output = tmp_path / "kickoff.json"

    readiness.write_text(json.dumps({"status": "ready"}), encoding="utf-8")
    contacts.write_text(
        json.dumps(
            {
                "company": "ExampleCo",
                "security_owner": "security@company.tld",
                "engineering_owner": "engineering@company.tld",
                "audit_contact": "audit@auditor.tld",
            }
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--readiness-report",
            str(readiness),
            "--contacts",
            str(contacts),
            "--output",
            str(output),
            "--fail-on-placeholder-contacts",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
