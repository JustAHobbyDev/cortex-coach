from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_reflection_completeness_passes_when_no_scaffolds(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        "reflection-completeness-check",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["scaffold_reports_scanned"] == 0
    assert payload["findings"] == []


def test_reflection_completeness_fails_when_scaffold_has_no_decision(initialized_project: Path) -> None:
    run_coach(
        initialized_project,
        "reflection-scaffold",
        "--title",
        "Missing reflection decision mapping",
        "--linked-artifacts",
        "docs/cortex-coach/commands.md",
        "--format",
        "json",
    )

    proc = run_coach(
        initialized_project,
        "reflection-completeness-check",
        "--format",
        "json",
        expect_code=1,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert any(f["check"] == "reflection_without_decision" for f in payload["findings"])


def test_reflection_completeness_passes_with_linked_decision(initialized_project: Path) -> None:
    scaffold_proc = run_coach(
        initialized_project,
        "reflection-scaffold",
        "--title",
        "Mapped reflection decision",
        "--linked-artifacts",
        "docs/cortex-coach/commands.md,docs/cortex-coach/quality-gate.md",
        "--format",
        "json",
    )
    scaffold = json.loads(scaffold_proc.stdout)

    run_coach(
        initialized_project,
        "decision-capture",
        "--title",
        scaffold["title"],
        "--decision",
        "Capture reflected learning.",
        "--impact-scope",
        "governance,docs",
        "--linked-artifacts",
        "docs/cortex-coach/commands.md,docs/cortex-coach/quality-gate.md",
        "--reflection-id",
        scaffold["reflection_id"],
        "--reflection-report",
        scaffold["report_file"],
    )

    proc = run_coach(
        initialized_project,
        "reflection-completeness-check",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["findings"] == []
    assert len(payload["mappings"]) == 1


def test_reflection_completeness_fails_when_decision_missing_scaffold_links(initialized_project: Path) -> None:
    scaffold_proc = run_coach(
        initialized_project,
        "reflection-scaffold",
        "--title",
        "Missing scaffold links in decision",
        "--linked-artifacts",
        "docs/cortex-coach/commands.md,docs/cortex-coach/quality-gate.md",
        "--format",
        "json",
    )
    scaffold = json.loads(scaffold_proc.stdout)

    run_coach(
        initialized_project,
        "decision-capture",
        "--title",
        scaffold["title"],
        "--decision",
        "Capture reflected learning.",
        "--impact-scope",
        "governance,docs",
        "--linked-artifacts",
        "docs/cortex-coach/commands.md",
        "--reflection-id",
        scaffold["reflection_id"],
        "--reflection-report",
        scaffold["report_file"],
    )

    proc = run_coach(
        initialized_project,
        "reflection-completeness-check",
        "--format",
        "json",
        expect_code=1,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert any(f["check"] == "reflection_missing_linked_artifacts" for f in payload["findings"])
