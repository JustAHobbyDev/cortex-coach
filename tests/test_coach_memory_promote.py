from __future__ import annotations

import json
import os
import time
from pathlib import Path

from conftest import run_coach


def _capture_record(
    project_dir: Path,
    *,
    source_ref: str,
    captured_at: str,
    text: str,
) -> str:
    proc = run_coach(
        project_dir,
        "memory-record",
        "--source-kind",
        "manual_capture",
        "--source-ref",
        source_ref,
        "--captured-by",
        "tester",
        "--source-refs",
        source_ref,
        "--captured-at",
        captured_at,
        "--content-class",
        "task_state",
        "--retention-class",
        "short",
        "--ttl-expires-at",
        "2026-03-31T00:00:00Z",
        "--text",
        text,
        "--tags",
        "phase1",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    return payload["result"]["record_id"]


def test_memory_promote_governance_mode_emits_contract(initialized_project: Path) -> None:
    record_id = _capture_record(
        initialized_project,
        source_ref="session://gov",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha governance candidate",
    )
    out_file = initialized_project / ".cortex" / "reports" / "promotion_contract_test.json"
    proc = run_coach(
        initialized_project,
        "memory-promote",
        "--record-ids",
        record_id,
        "--bridge-mode",
        "governance_impacting",
        "--decision-refs",
        "dec_001",
        "--reflection-refs",
        "ref_001",
        "--impacted-artifacts",
        "specs/demo.md::updated governance flow",
        "--rationale-summary",
        "Required policy promotion.",
        "--evidence-refs",
        "evidence://demo",
        "--reviewed-by",
        "maintainer_a",
        "--approval-state",
        "proposed",
        "--out-file",
        str(out_file),
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["bridge_mode"] == "governance_impacting"
    assert payload["result"]["required_fields_complete"] is True
    assert payload["result"]["failure_mode"] == "none"
    assert payload["result"]["promotion_contract_path"]

    contract = json.loads(out_file.read_text(encoding="utf-8"))
    assert contract["promotion_trace_metadata"]["bridge_command"] == "memory-promote"
    assert contract["promotion_trace_metadata"]["bridge_mode"] == "governance_impacting"
    assert contract["promotion_trace_metadata"]["tactical_record_refs"] == [record_id]


def test_memory_promote_fail_closed_missing_linkage(initialized_project: Path) -> None:
    record_id = _capture_record(
        initialized_project,
        source_ref="session://gov",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha governance candidate",
    )
    proc = run_coach(
        initialized_project,
        "memory-promote",
        "--record-ids",
        record_id,
        "--bridge-mode",
        "governance_impacting",
        "--impacted-artifacts",
        "specs/demo.md::updated governance flow",
        "--rationale-summary",
        "Required policy promotion.",
        "--evidence-refs",
        "evidence://demo",
        "--reviewed-by",
        "maintainer_a",
        "--format",
        "json",
        expect_code=3,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "missing_decision_reflection_linkage"
    assert payload["result"]["required_fields_complete"] is False


def test_memory_promote_non_governance_mode_is_explicit(initialized_project: Path) -> None:
    record_id = _capture_record(
        initialized_project,
        source_ref="session://non-gov",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha non governance note",
    )
    proc = run_coach(
        initialized_project,
        "memory-promote",
        "--record-ids",
        record_id,
        "--bridge-mode",
        "non_governance",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["bridge_mode"] == "non_governance"
    assert payload["result"]["non_governance_output"] is True
    assert payload["result"]["canonical_effect"] == "none"
    assert payload["result"]["promotion_contract_path"] is None


def test_memory_promote_lock_conflict_returns_exit_4(initialized_project: Path) -> None:
    record_id = _capture_record(
        initialized_project,
        source_ref="session://gov",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha governance candidate",
    )
    lock_path = initialized_project / ".cortex" / ".lock"
    lock_path.write_text(
        json.dumps(
            {
                "token": "test-lock",
                "pid": os.getpid(),
                "created_epoch": time.time(),
                "created_at": "2026-02-23T00:00:00Z",
                "command": "manual-test",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    proc = run_coach(
        initialized_project,
        "memory-promote",
        "--record-ids",
        record_id,
        "--bridge-mode",
        "governance_impacting",
        "--decision-refs",
        "dec_001",
        "--reflection-refs",
        "ref_001",
        "--impacted-artifacts",
        "specs/demo.md::updated governance flow",
        "--rationale-summary",
        "Required policy promotion.",
        "--evidence-refs",
        "evidence://demo",
        "--reviewed-by",
        "maintainer_a",
        "--lock-timeout-seconds",
        "0.01",
        "--format",
        "json",
        expect_code=4,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "lock_conflict"
