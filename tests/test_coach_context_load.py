from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


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
    assert payload["selected_file_count"] >= 1
    assert any(f["selected_by"] == "control_plane" for f in payload["files"])


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
    assert set(tie_entry["score_breakdown"].keys()) == {
        "lexical_score",
        "evidence_score",
        "outcome_score",
        "freshness_score",
    }
