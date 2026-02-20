from __future__ import annotations

import json
from pathlib import Path

from conftest import load_json, run_coach


def test_decision_capture_and_promote_and_list(initialized_project: Path) -> None:
    capture = run_coach(
        initialized_project,
        "decision-capture",
        "--title",
        "Split local and CI quality gates",
        "--decision",
        "Use quality-gate locally and quality-gate-ci in CI.",
        "--rationale",
        "Avoid dirty-tree false negatives in CI.",
        "--impact-scope",
        "governance,ci,docs",
        "--linked-artifacts",
        ".github/workflows/cortex-validation.yml,docs/cortex-coach/quality-gate.md",
        "--format",
        "json",
    )
    candidate = json.loads(capture.stdout)
    decision_id = candidate["decision_id"]

    promoted = run_coach(
        initialized_project,
        "decision-promote",
        "--decision-id",
        decision_id,
        "--format",
        "json",
    )
    promoted_payload = json.loads(promoted.stdout)
    assert promoted_payload["status"] == "promoted"
    artifact = initialized_project / promoted_payload["decision_artifact"]
    assert artifact.exists()

    listed = run_coach(initialized_project, "decision-list", "--status", "promoted", "--format", "json")
    listed_payload = json.loads(listed.stdout)
    assert any(e["decision_id"] == decision_id for e in listed_payload["entries"])


def test_audit_fails_when_promoted_decision_has_impact_without_links(initialized_project: Path) -> None:
    capture = run_coach(
        initialized_project,
        "decision-capture",
        "--title",
        "Unpropagated policy shift",
        "--decision",
        "Change governance policy.",
        "--impact-scope",
        "governance",
        "--format",
        "json",
    )
    decision_id = json.loads(capture.stdout)["decision_id"]
    run_coach(initialized_project, "decision-promote", "--decision-id", decision_id)

    run_coach(initialized_project, "audit", expect_code=1)
    audit = load_json(initialized_project / ".cortex" / "reports" / "lifecycle_audit_v0.json")
    unsynced = audit["unsynced_decisions"]
    assert unsynced["status"] == "fail"
    assert any(f["check"] == "impact_scope_without_links" for f in unsynced["findings"])


def test_context_load_prioritizes_active_decisions(initialized_project: Path) -> None:
    capture = run_coach(
        initialized_project,
        "decision-capture",
        "--title",
        "Context loader should prioritize decisions",
        "--decision",
        "Include active decisions in control-plane context.",
        "--impact-scope",
        "context-loader",
        "--linked-artifacts",
        "scripts/agent_context_loader_v0.py",
        "--format",
        "json",
    )
    decision_id = json.loads(capture.stdout)["decision_id"]
    run_coach(initialized_project, "decision-promote", "--decision-id", decision_id)

    out_file = initialized_project / ".cortex" / "reports" / "bundle_with_decisions.json"
    run_coach(
        initialized_project,
        "context-load",
        "--task",
        "governance",
        "--max-files",
        "8",
        "--max-chars-per-file",
        "600",
        "--out-file",
        str(out_file),
    )
    payload = load_json(out_file)
    assert any("decisions/decision_" in f["path"] for f in payload["files"])
    assert any(f["selected_by"] == "control_plane:active_decision" for f in payload["files"])
