from __future__ import annotations

import json
import subprocess
from pathlib import Path

from conftest import COACH_SCRIPT, run_coach


def test_context_load_fallback_metadata(initialized_project: Path) -> None:
    out_file = initialized_project / ".cortex" / "reports" / "bundle.json"
    run_coach(
        initialized_project,
        "context-load",
        "--task",
        "design",
        "--max-files",
        "1",
        "--max-chars-per-file",
        "100",
        "--fallback-mode",
        "priority",
        "--out-file",
        str(out_file),
    )

    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert "fallback_level" in payload
    assert "fallback_attempts" in payload
    assert payload["ranking"]["contract_version"] == "v0"
    assert payload["retrieval_profile"] == "medium"
    assert payload["weighting_mode"] == "uniform"
    assert payload["ranking"]["tie_break_order"] == [
        "combined_score_desc",
        "evidence_score_desc",
        "pattern_priority_asc",
        "path_asc",
    ]
    assert payload["ranking"]["confidence_bounds"] == {"min": 0.0, "max": 1.0}
    assert payload["selected_file_count"] >= 1
    assert any(f["selected_by"] == "control_plane" for f in payload["files"])
    for item in payload["files"]:
        assert 0.0 <= float(item["confidence"]) <= 1.0
        prov = item["provenance"]
        assert isinstance(prov["source_kind"], str) and prov["source_kind"]
        assert isinstance(prov["source_ref"], str) and prov["source_ref"]
        assert isinstance(prov["source_refs"], list) and len(prov["source_refs"]) >= 1


def test_context_load_ranking_is_deterministic_across_runs(initialized_project: Path) -> None:
    out_file_a = initialized_project / ".cortex" / "reports" / "bundle_rank_a.json"
    out_file_b = initialized_project / ".cortex" / "reports" / "bundle_rank_b.json"

    run_coach(
        initialized_project,
        "context-load",
        "--task",
        "governance ranking determinism",
        "--retrieval-profile",
        "large",
        "--weighting-mode",
        "evidence_outcome_bias",
        "--max-files",
        "16",
        "--max-chars-per-file",
        "700",
        "--out-file",
        str(out_file_a),
    )
    run_coach(
        initialized_project,
        "context-load",
        "--task",
        "governance ranking determinism",
        "--retrieval-profile",
        "large",
        "--weighting-mode",
        "evidence_outcome_bias",
        "--max-files",
        "16",
        "--max-chars-per-file",
        "700",
        "--out-file",
        str(out_file_b),
    )

    payload_a = json.loads(out_file_a.read_text(encoding="utf-8"))
    payload_b = json.loads(out_file_b.read_text(encoding="utf-8"))
    assert payload_a == payload_b


def test_context_load_ranking_tie_break_falls_back_to_path_order(initialized_project: Path) -> None:
    policy_dir = initialized_project / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    path_a = policy_dir / "aaa_governance_rank_tie.md"
    path_z = policy_dir / "zzz_governance_rank_tie.md"
    content = "governance policy rank tie deterministic"
    path_a.write_text(content, encoding="utf-8")
    path_z.write_text(content, encoding="utf-8")

    out_file = initialized_project / ".cortex" / "reports" / "bundle_tie_break.json"
    run_coach(
        initialized_project,
        "context-load",
        "--task",
        "governance",
        "--max-files",
        "24",
        "--max-chars-per-file",
        "900",
        "--out-file",
        str(out_file),
    )

    payload = json.loads(out_file.read_text(encoding="utf-8"))
    task_files = [f for f in payload["files"] if str(f.get("selected_by", "")).startswith("task:")]
    idx_a = next(i for i, item in enumerate(task_files) if item["path"] == "policies/aaa_governance_rank_tie.md")
    idx_z = next(i for i, item in enumerate(task_files) if item["path"] == "policies/zzz_governance_rank_tie.md")
    assert idx_a < idx_z

    tie_entry = task_files[idx_a]
    assert isinstance(tie_entry["rank"], int)
    assert isinstance(tie_entry["combined_score"], float)
    assert isinstance(tie_entry["confidence"], float)
    assert 0.0 <= tie_entry["confidence"] <= 1.0
    assert tie_entry["provenance"]["source_kind"] == "task_pattern_match"
    assert "policies/aaa_governance_rank_tie.md" in tie_entry["provenance"]["source_refs"]
    assert set(tie_entry["score_breakdown"].keys()) == {
        "lexical_score",
        "evidence_score",
        "outcome_score",
        "freshness_score",
    }


def test_context_load_weighting_mode_can_change_ranking(initialized_project: Path) -> None:
    policy_dir = initialized_project / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    lexical_heavy = policy_dir / "governance_governance_notes.md"
    evidence_outcome_heavy = policy_dir / "decision_reflection_report_policy_gate_plan.md"
    lexical_heavy.write_text("governance governance governance governance governance", encoding="utf-8")
    evidence_outcome_heavy.write_text("context document with governance evidence markers", encoding="utf-8")

    out_uniform = initialized_project / ".cortex" / "reports" / "bundle_uniform.json"
    out_bias = initialized_project / ".cortex" / "reports" / "bundle_bias.json"

    run_coach(
        initialized_project,
        "context-load",
        "--task",
        "governance",
        "--weighting-mode",
        "uniform",
        "--max-files",
        "24",
        "--max-chars-per-file",
        "800",
        "--out-file",
        str(out_uniform),
    )
    run_coach(
        initialized_project,
        "context-load",
        "--task",
        "governance",
        "--weighting-mode",
        "evidence_outcome_bias",
        "--max-files",
        "24",
        "--max-chars-per-file",
        "800",
        "--out-file",
        str(out_bias),
    )

    payload_uniform = json.loads(out_uniform.read_text(encoding="utf-8"))
    payload_bias = json.loads(out_bias.read_text(encoding="utf-8"))

    files_uniform = [f for f in payload_uniform["files"] if str(f.get("selected_by", "")).startswith("task:")]
    files_bias = [f for f in payload_bias["files"] if str(f.get("selected_by", "")).startswith("task:")]

    idx_uniform_lexical = next(
        i for i, item in enumerate(files_uniform) if item["path"] == "policies/governance_governance_notes.md"
    )
    idx_uniform_evidence = next(
        i for i, item in enumerate(files_uniform) if item["path"] == "policies/decision_reflection_report_policy_gate_plan.md"
    )
    idx_bias_lexical = next(i for i, item in enumerate(files_bias) if item["path"] == "policies/governance_governance_notes.md")
    idx_bias_evidence = next(
        i for i, item in enumerate(files_bias) if item["path"] == "policies/decision_reflection_report_policy_gate_plan.md"
    )

    assert idx_uniform_lexical < idx_uniform_evidence
    assert idx_bias_evidence < idx_bias_lexical
    assert payload_uniform["weighting_mode"] == "uniform"
    assert payload_bias["weighting_mode"] == "evidence_outcome_bias"
    assert payload_uniform["ranking"]["weights"] != payload_bias["ranking"]["weights"]
    for payload in (payload_uniform, payload_bias):
        for item in payload["files"]:
            assert 0.0 <= float(item["confidence"]) <= 1.0
            assert "provenance" in item


def test_context_load_invalid_weighting_mode_fails_argument_validation(initialized_project: Path) -> None:
    proc = subprocess.run(
        [
            "python3",
            str(COACH_SCRIPT),
            "context-load",
            "--task",
            "governance",
            "--weighting-mode",
            "not_a_mode",
            "--project-dir",
            str(initialized_project),
        ],
        cwd=str(COACH_SCRIPT.parent.parent),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "invalid choice" in proc.stderr
