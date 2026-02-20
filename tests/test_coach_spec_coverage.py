from __future__ import annotations

from pathlib import Path

from conftest import load_json, run_coach


def test_spec_coverage_detects_missing_required(initialized_project: Path) -> None:
    # Remove required governance artifact to trigger coverage failure.
    governance = initialized_project / ".cortex" / "artifacts" / "governance_demo_v0.md"
    governance.unlink()

    run_coach(initialized_project, "audit", expect_code=1)
    audit = load_json(initialized_project / ".cortex" / "reports" / "lifecycle_audit_v0.json")

    assert audit["status"] == "fail"
    coverage = audit["spec_coverage"]
    assert coverage["status"] == "fail"
    assert any(item["domain_id"] == "governance" for item in coverage["missing_required"])


def test_coach_apply_drafts_missing_required_specs(initialized_project: Path) -> None:
    governance = initialized_project / ".cortex" / "artifacts" / "governance_demo_v0.md"
    governance.unlink()

    run_coach(initialized_project, "coach", "--apply", expect_code=1)
    reports = sorted((initialized_project / ".cortex" / "reports").glob("coach_cycle_*_v0.json"))
    assert reports, "expected coach cycle report"

    payload = load_json(reports[-1])
    drafted = payload.get("drafted_specs", [])
    assert drafted, "expected drafted missing spec entries"
