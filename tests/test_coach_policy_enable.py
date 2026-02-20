from __future__ import annotations

from pathlib import Path

from conftest import load_json, run_coach


def test_policy_enable_registers_manifest(initialized_project: Path) -> None:
    run_coach(initialized_project, "policy-enable", "--policy", "usage-decision")

    policy_file = initialized_project / ".cortex" / "policies" / "cortex_coach_usage_decision_policy_v0.md"
    assert policy_file.exists()

    manifest = load_json(initialized_project / ".cortex" / "manifest_v0.json")
    enabled = manifest.get("policies", {}).get("enabled", [])
    assert ".cortex/policies/cortex_coach_usage_decision_policy_v0.md" in enabled


def test_policy_enable_decision_reflection_registers_manifest(initialized_project: Path) -> None:
    run_coach(initialized_project, "policy-enable", "--policy", "decision-reflection")

    policy_file = initialized_project / ".cortex" / "policies" / "cortex_coach_decision_reflection_policy_v0.md"
    assert policy_file.exists()

    manifest = load_json(initialized_project / ".cortex" / "manifest_v0.json")
    enabled = manifest.get("policies", {}).get("enabled", [])
    assert ".cortex/policies/cortex_coach_decision_reflection_policy_v0.md" in enabled
