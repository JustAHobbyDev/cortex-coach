from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_reflection_scaffold_auto_links_governance_dirty_files(initialized_project: Path) -> None:
    policy_file = initialized_project / "policies" / "new_reflection_policy_v0.md"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text("# Policy\n\nStatus: Draft\n", encoding="utf-8")

    proc = run_coach(
        initialized_project,
        "reflection-scaffold",
        "--title",
        "Capture reflection for repeated policy misses",
        "--mistake",
        "Forgot to promote governance decision before closeout.",
        "--pattern",
        "Decision reflection handled ad hoc and too late.",
        "--rule",
        "Require reflection scaffold before closeout when governance files are touched.",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)

    assert payload["title"] == "Capture reflection for repeated policy misses"
    assert "policies/new_reflection_policy_v0.md" in payload["auto_linked_governance_files"]
    assert "policies/new_reflection_policy_v0.md" in payload["suggested_linked_artifacts"]
    assert payload["suggested_decision_artifact"].startswith(".cortex/artifacts/decisions/decision_capture_reflection_for_re")


def test_reflection_scaffold_can_disable_auto_linking(initialized_project: Path) -> None:
    playbook_file = initialized_project / "playbooks" / "tmp_reflection_playbook_v0.md"
    playbook_file.parent.mkdir(parents=True, exist_ok=True)
    playbook_file.write_text("# Playbook\n", encoding="utf-8")

    proc = run_coach(
        initialized_project,
        "reflection-scaffold",
        "--title",
        "Reflection with explicit links only",
        "--linked-artifacts",
        "docs/cortex-coach/commands.md",
        "--no-auto-link-governance-dirty",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)

    assert payload["auto_linked_governance_files"] == []
    assert payload["suggested_linked_artifacts"] == ["docs/cortex-coach/commands.md"]
