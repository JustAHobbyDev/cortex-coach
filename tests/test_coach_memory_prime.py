from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def _capture_record(
    project_dir: Path,
    *,
    source_ref: str,
    captured_at: str,
    text: str,
    tags: str = "phase1",
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
        tags,
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    return payload["result"]["record_id"]


def test_memory_prime_applies_record_limit_truncation(initialized_project: Path) -> None:
    old_id = _capture_record(
        initialized_project,
        source_ref="session://a",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha item one",
    )
    mid_id = _capture_record(
        initialized_project,
        source_ref="session://b",
        captured_at="2026-02-24T00:00:00Z",
        text="alpha item two",
    )
    new_id = _capture_record(
        initialized_project,
        source_ref="session://c",
        captured_at="2026-02-25T00:00:00Z",
        text="alpha item three",
    )

    proc = run_coach(
        initialized_project,
        "memory-prime",
        "--task",
        "phase1-handoff",
        "--query-ref",
        "alpha",
        "--requested-limit",
        "3",
        "--max-records",
        "2",
        "--max-chars",
        "5000",
        "--per-record-max-chars",
        "500",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["selected_count"] == 2
    ids = [item["record_id"] for item in payload["result"]["bundle"]]
    assert ids == [new_id, mid_id]
    assert old_id in payload["result"]["truncation"]["dropped_record_ids"]
    assert payload["result"]["truncation"]["reason"] == "record_limit"


def test_memory_prime_applies_per_record_char_budget(initialized_project: Path) -> None:
    _capture_record(
        initialized_project,
        source_ref="session://long",
        captured_at="2026-02-23T00:00:00Z",
        text=("alpha " * 100).strip(),
    )

    proc = run_coach(
        initialized_project,
        "memory-prime",
        "--task",
        "phase1-handoff",
        "--query-ref",
        "alpha",
        "--requested-limit",
        "1",
        "--max-records",
        "5",
        "--max-chars",
        "5000",
        "--per-record-max-chars",
        "40",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    bundle = payload["result"]["bundle"]
    assert len(bundle) == 1
    assert bundle[0]["char_count"] <= 40
    assert payload["result"]["truncation"]["applied"] is True
    assert payload["result"]["truncation"]["reason"] == "per_record_char_limit"
    assert payload["result"]["truncation"]["truncated_record_count"] >= 1
    assert payload["result"]["truncation"]["truncated_char_count"] > 0


def test_memory_prime_applies_char_budget_drop(initialized_project: Path) -> None:
    first_id = _capture_record(
        initialized_project,
        source_ref="session://first",
        captured_at="2026-02-24T00:00:00Z",
        text="alpha " + ("x" * 80),
    )
    second_id = _capture_record(
        initialized_project,
        source_ref="session://second",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha " + ("y" * 80),
    )

    proc = run_coach(
        initialized_project,
        "memory-prime",
        "--task",
        "phase1-handoff",
        "--query-ref",
        "alpha",
        "--requested-limit",
        "2",
        "--max-records",
        "5",
        "--max-chars",
        "90",
        "--per-record-max-chars",
        "80",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    ids = [item["record_id"] for item in payload["result"]["bundle"]]
    assert ids == [first_id]
    assert second_id in payload["result"]["truncation"]["dropped_record_ids"]
    assert payload["result"]["truncation"]["reason"] == "char_budget"


def test_memory_prime_no_matches_returns_empty_bundle(initialized_project: Path) -> None:
    _capture_record(
        initialized_project,
        source_ref="session://beta",
        captured_at="2026-02-23T00:00:00Z",
        text="beta note only",
    )

    proc = run_coach(
        initialized_project,
        "memory-prime",
        "--task",
        "phase1-handoff",
        "--query-ref",
        "alpha",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["selected_count"] == 0
    assert payload["result"]["bundle"] == []
    assert payload["result"]["truncation"]["applied"] is False
    assert payload["result"]["truncation"]["reason"] == "none"


def test_memory_prime_invalid_query_ref_fails(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        "memory-prime",
        "--task",
        "phase1-handoff",
        "--query-ref",
        "   ",
        "--format",
        "json",
        expect_code=2,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "invalid_arguments"
