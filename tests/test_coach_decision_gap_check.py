from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_decision_gap_check_passes_when_no_governance_impact_files(initialized_project: Path) -> None:
    proc = run_coach(initialized_project, "decision-gap-check", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["governance_impact_files"] == []


def test_decision_gap_check_fails_when_governance_change_unlinked(initialized_project: Path) -> None:
    manifest = initialized_project / ".cortex" / "manifest_v0.json"
    original = manifest.read_text(encoding="utf-8")
    manifest.write_text(original + "\n", encoding="utf-8")

    proc = run_coach(initialized_project, "decision-gap-check", "--format", "json", expect_code=1)
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert ".cortex/manifest_v0.json" in payload["uncovered_files"]


def test_decision_gap_check_passes_when_change_is_linked_in_decision(initialized_project: Path) -> None:
    manifest = initialized_project / ".cortex" / "manifest_v0.json"
    original = manifest.read_text(encoding="utf-8")
    manifest.write_text(original + "\n", encoding="utf-8")

    capture = run_coach(
        initialized_project,
        "decision-capture",
        "--title",
        "Track manifest mutation",
        "--decision",
        "Manifest updates in this change are intentional.",
        "--rationale",
        "Ensure governance impact is explicit.",
        "--impact-scope",
        "governance",
        "--linked-artifacts",
        ".cortex/manifest_v0.json",
        "--format",
        "json",
    )
    captured = json.loads(capture.stdout)
    assert captured["status"] == "candidate"

    proc = run_coach(initialized_project, "decision-gap-check", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert ".cortex/manifest_v0.json" in payload["covered_files"]
