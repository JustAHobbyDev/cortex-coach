from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def _write_fixture(project_dir: Path, name: str, payload: dict) -> Path:
    fixture_path = project_dir / ".cortex" / "fixtures" / name
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return fixture_path


def test_promotion_candidates_ranks_linked_candidate_first(initialized_project: Path) -> None:
    fixture_path = _write_fixture(
        initialized_project,
        "promotion_candidates_fixture.json",
        {
            "profile_id": "small",
            "scenario_id": "s_linked_vs_unlinked",
            "captured_at": "2026-02-24T11:00:00Z",
            "tactical_candidates": [
                {
                    "candidate_id": "pc_alpha",
                    "title": "Linked governance closure with strong evidence",
                    "summary": "Promote linked governance closure.",
                    "state": "ready",
                    "governance_impact": "high",
                    "decision_refs": ["dec_alpha"],
                    "reflection_refs": ["ref_alpha"],
                    "evidence_refs": ["evidence://alpha/a", "evidence://alpha/b"],
                    "impacted_artifacts": ["playbooks/cortex_phase4_measurement_plan_v0.md"],
                },
                {
                    "candidate_id": "pc_beta",
                    "title": "Unlinked governance closure",
                    "summary": "Candidate missing linkage.",
                    "state": "ready",
                    "governance_impact": "high",
                    "evidence_refs": ["evidence://beta/a"],
                    "impacted_artifacts": ["playbooks/cortex_phase4_promotion_enforcement_ticket_breakdown_v0.md"],
                },
            ],
        },
    )

    proc = run_coach(
        initialized_project,
        "promotion-candidates",
        "--fixture-file",
        str(fixture_path),
        "--query",
        "linked governance evidence",
        "--score-mode",
        "evidence_bias",
        "--candidate-limit",
        "8",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    result = payload["result"]
    assert result["candidate_count"] == 2
    assert result["selected_count"] == 2
    assert result["tie_break_order"] == [
        "combined_score_desc",
        "evidence_coverage_desc",
        "governance_impact_priority_asc",
        "candidate_id_asc",
    ]

    first = result["candidates"][0]
    second = result["candidates"][1]
    assert first["candidate_id"] == "pc_alpha"
    assert first["rank"] == 1
    assert first["linkage_complete"] is True
    assert first["contract_candidate_valid"] is True
    assert first["enforcement_recommendation"] == "eligible_for_promotion"

    assert second["candidate_id"] == "pc_beta"
    assert second["rank"] == 2
    assert second["linkage_complete"] is False
    assert second["contract_candidate_valid"] is False
    assert second["enforcement_recommendation"] == "block_unlinked_governance_closure"


def test_promotion_candidates_is_deterministic_for_identical_inputs(initialized_project: Path) -> None:
    fixture_path = _write_fixture(
        initialized_project,
        "promotion_determinism_fixture.json",
        {
            "profile_id": "medium",
            "scenario_id": "s_determinism",
            "captured_at": "2026-02-24T11:02:00Z",
            "tactical_candidates": [
                {
                    "candidate_id": "pc_001",
                    "title": "A governance candidate",
                    "state": "ready",
                    "governance_impact": "high",
                    "decision_refs": ["dec_001"],
                    "reflection_refs": ["ref_001"],
                    "evidence_refs": ["evidence://a/1"],
                    "impacted_artifacts": ["playbooks/cortex_phase4_measurement_plan_v0.md"],
                },
                {
                    "candidate_id": "pc_002",
                    "title": "B governance candidate",
                    "state": "ready",
                    "governance_impact": "medium",
                    "decision_refs": ["dec_002"],
                    "reflection_refs": ["ref_002"],
                    "evidence_refs": ["evidence://b/1"],
                    "impacted_artifacts": ["playbooks/cortex_phase4_promotion_enforcement_ticket_breakdown_v0.md"],
                },
            ],
        },
    )

    proc_one = run_coach(
        initialized_project,
        "promotion-candidates",
        "--fixture-file",
        str(fixture_path),
        "--query",
        "governance candidate",
        "--score-mode",
        "uniform",
        "--format",
        "json",
    )
    proc_two = run_coach(
        initialized_project,
        "promotion-candidates",
        "--fixture-file",
        str(fixture_path),
        "--query",
        "governance candidate",
        "--score-mode",
        "uniform",
        "--format",
        "json",
    )
    payload_one = json.loads(proc_one.stdout)
    payload_two = json.loads(proc_two.stdout)
    assert payload_one["status"] == "pass"
    assert payload_two["status"] == "pass"
    assert payload_one["result"] == payload_two["result"]


def test_promotion_candidates_supports_governance_debt_fixtures(initialized_project: Path) -> None:
    fixture_path = _write_fixture(
        initialized_project,
        "promotion_debt_fixture.json",
        {
            "profile_id": "large",
            "scenario_id": "s_governance_debt",
            "captured_at": "2026-02-24T11:10:00Z",
            "governance_debt_items": [
                {
                    "debt_id": "gd_001",
                    "state": "blocked",
                    "owner": "Governance Enforcement Lead",
                    "next_action": "Link reflection scaffold before closure.",
                    "dependency_refs": ["ref_001"],
                },
                {
                    "debt_id": "gd_002",
                    "state": "ready",
                    "owner": "Runtime Reliability Lead",
                    "next_action": "Promote candidate with complete evidence mapping.",
                    "dependency_refs": ["dec_002"],
                },
            ],
        },
    )

    proc = run_coach(
        initialized_project,
        "promotion-candidates",
        "--fixture-file",
        str(fixture_path),
        "--candidate-limit",
        "5",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    result = payload["result"]
    assert result["candidate_count"] == 2
    assert result["selected_count"] == 2
    assert result["candidates"][0]["candidate_id"] == "pc_gd_001"
    assert result["candidates"][0]["enforcement_recommendation"] == "block_unlinked_governance_closure"
    assert result["candidates"][1]["candidate_id"] == "pc_gd_002"
    assert result["candidates"][1]["enforcement_recommendation"] == "eligible_for_promotion"


def test_promotion_candidates_requires_supported_fixture_shape(initialized_project: Path) -> None:
    fixture_path = _write_fixture(
        initialized_project,
        "promotion_invalid_fixture.json",
        {
            "scenario_id": "s_invalid",
            "captured_at": "2026-02-24T11:10:00Z",
            "unsupported": [],
        },
    )

    proc = run_coach(
        initialized_project,
        "promotion-candidates",
        "--fixture-file",
        str(fixture_path),
        "--format",
        "json",
        expect_code=2,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "invalid_arguments"

