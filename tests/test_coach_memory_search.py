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


def test_memory_search_tie_break_uses_captured_at_desc(initialized_project: Path) -> None:
    old_id = _capture_record(
        initialized_project,
        source_ref="session://old",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha task state",
    )
    new_id = _capture_record(
        initialized_project,
        source_ref="session://new",
        captured_at="2026-02-24T00:00:00Z",
        text="alpha task state",
    )

    proc = run_coach(
        initialized_project,
        "memory-search",
        "--query",
        "alpha",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    ids = [item["record_id"] for item in payload["result"]["results"]]
    assert ids == [new_id, old_id]
    assert payload["result"]["ranking"]["tie_break_order"] == [
        "score_desc",
        "captured_at_desc",
        "record_id_asc",
    ]


def test_memory_search_tie_break_uses_record_id_asc_after_score_and_time(initialized_project: Path) -> None:
    first_id = _capture_record(
        initialized_project,
        source_ref="session://aaa",
        captured_at="2026-02-25T00:00:00Z",
        text="alpha project update",
    )
    second_id = _capture_record(
        initialized_project,
        source_ref="session://bbb",
        captured_at="2026-02-25T00:00:00Z",
        text="alpha project update",
    )

    proc = run_coach(
        initialized_project,
        "memory-search",
        "--query",
        "alpha",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    ids = [item["record_id"] for item in payload["result"]["results"]]
    assert ids == sorted([first_id, second_id])


def test_memory_search_filtered_out_payload(initialized_project: Path) -> None:
    _capture_record(
        initialized_project,
        source_ref="session://ops",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha release note",
        tags="ops,release",
    )

    proc = run_coach(
        initialized_project,
        "memory-search",
        "--query",
        "alpha",
        "--tags-all",
        "missing_tag",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["result_count"] == 0
    assert payload["result"]["no_match"]["reason"] == "filtered_out"
    assert payload["result"]["no_match"]["matched"] is False


def test_memory_search_no_match_payload(initialized_project: Path) -> None:
    _capture_record(
        initialized_project,
        source_ref="session://beta",
        captured_at="2026-02-23T00:00:00Z",
        text="beta release note",
    )

    proc = run_coach(
        initialized_project,
        "memory-search",
        "--query",
        "alpha",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["result_count"] == 0
    assert payload["result"]["results"] == []
    assert payload["result"]["no_match"]["reason"] == "no_match"
    assert payload["result"]["no_match"]["matched"] is False


def test_memory_search_invalid_content_filter_fails(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        "memory-search",
        "--query",
        "alpha",
        "--content-classes-any",
        "bad_class",
        "--format",
        "json",
        expect_code=2,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "invalid_arguments"
