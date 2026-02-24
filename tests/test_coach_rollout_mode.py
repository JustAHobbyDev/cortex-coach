from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_rollout_mode_defaults_to_experimental(initialized_project: Path) -> None:
    proc = run_coach(initialized_project, "rollout-mode", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["mode"] == "experimental"
    assert payload["result"]["transition_count"] == 0


def test_rollout_mode_default_requires_linkage(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        "rollout-mode",
        "--set-mode",
        "default",
        "--changed-by",
        "maintainer_a",
        "--reason",
        "attempt default without linkage",
        "--format",
        "json",
        expect_code=2,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "invalid_arguments"


def test_rollout_mode_transition_and_audit_pass(initialized_project: Path) -> None:
    set_proc = run_coach(
        initialized_project,
        "rollout-mode",
        "--set-mode",
        "default",
        "--changed-by",
        "maintainer_a",
        "--reason",
        "gate-f-ready",
        "--decision-refs",
        "dec_gate_f_001",
        "--reflection-refs",
        "ref_gate_f_001",
        "--audit-refs",
        ".cortex/reports/project_state/phase5_cycle2_rollout_reliability_report_v0.json",
        "--format",
        "json",
    )
    set_payload = json.loads(set_proc.stdout)
    assert set_payload["status"] == "pass"
    assert set_payload["result"]["mode"] == "default"
    assert set_payload["result"]["default_mode_linkage_complete"] is True

    audit_proc = run_coach(initialized_project, "rollout-mode-audit", "--format", "json")
    audit_payload = json.loads(audit_proc.stdout)
    assert audit_payload["status"] == "pass"
    assert audit_payload["result"]["transition_completeness_rate"] == 1.0

    report_path = initialized_project / ".cortex" / "reports" / "project_state" / "phase5_mode_transition_audit_report_v0.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    assert report["summary"]["transition_count"] == 1
    assert report["summary"]["transition_completeness_rate"] == 1.0


def test_rollout_mode_rollback_from_default_requires_incident_ref(initialized_project: Path) -> None:
    run_coach(
        initialized_project,
        "rollout-mode",
        "--set-mode",
        "default",
        "--changed-by",
        "maintainer_a",
        "--reason",
        "gate-f-ready",
        "--decision-refs",
        "dec_gate_f_001",
        "--reflection-refs",
        "ref_gate_f_001",
        "--audit-refs",
        ".cortex/reports/project_state/phase5_cycle2_rollout_reliability_report_v0.json",
        "--format",
        "json",
    )

    fail_proc = run_coach(
        initialized_project,
        "rollout-mode",
        "--set-mode",
        "experimental",
        "--changed-by",
        "maintainer_a",
        "--reason",
        "rollback-needed",
        "--format",
        "json",
        expect_code=2,
    )
    fail_payload = json.loads(fail_proc.stdout)
    assert fail_payload["status"] == "fail"
    assert fail_payload["error"]["code"] == "invalid_arguments"

    pass_proc = run_coach(
        initialized_project,
        "rollout-mode",
        "--set-mode",
        "experimental",
        "--changed-by",
        "maintainer_a",
        "--reason",
        "rollback-needed",
        "--incident-ref",
        "inc_2026_02_24_001",
        "--format",
        "json",
    )
    pass_payload = json.loads(pass_proc.stdout)
    assert pass_payload["status"] == "pass"
    assert pass_payload["result"]["mode"] == "experimental"

