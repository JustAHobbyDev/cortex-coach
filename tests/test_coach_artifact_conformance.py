from __future__ import annotations

from pathlib import Path

from conftest import load_json, run_coach


def test_audit_fails_on_foreign_project_scope_without_reference(initialized_project: Path) -> None:
    foreign = initialized_project / "philosophy" / "second_brain_taxonomy_v0.md"
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_text(
        "# Second Brain Taxonomy\n\n"
        "Status: Experimental\n"
        "Project: project/dan_personal_cognitive_infrastructure\n",
        encoding="utf-8",
    )

    run_coach(initialized_project, "audit", "--audit-scope", "all", expect_code=1)
    audit = load_json(initialized_project / ".cortex" / "reports" / "lifecycle_audit_v0.json")

    assert audit["status"] == "fail"
    conformance = audit["artifact_conformance"]
    assert conformance["status"] == "fail"
    assert any(item["check"] == "foreign_project_scope" for item in conformance["findings"])


def test_cortexignore_excludes_paths_from_artifact_conformance(initialized_project: Path) -> None:
    foreign = initialized_project / "philosophy" / "second_brain_taxonomy_v0.md"
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_text(
        "# Second Brain Taxonomy\n\n"
        "Status: Experimental\n"
        "Project: project/dan_personal_cognitive_infrastructure\n",
        encoding="utf-8",
    )
    (initialized_project / ".cortexignore").write_text(
        "philosophy/second_brain_taxonomy_v0.md\n",
        encoding="utf-8",
    )

    run_coach(initialized_project, "audit", "--audit-scope", "all")
    audit = load_json(initialized_project / ".cortex" / "reports" / "lifecycle_audit_v0.json")
    conformance = audit["artifact_conformance"]

    assert audit["status"] == "pass"
    assert audit["audit_scope"] == "all"
    assert conformance["status"] == "pass"
    assert conformance["findings"] == []
    assert audit["cortexignore"]["enabled"] is True
