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


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    lines = [json.dumps(row, sort_keys=True) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_memory_diff_detects_added_removed_modified_unchanged(initialized_project: Path) -> None:
    removed_id = _capture_record(
        initialized_project,
        source_ref="session://removed",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha removed",
    )
    modified_id = _capture_record(
        initialized_project,
        source_ref="session://modified",
        captured_at="2026-02-24T00:00:00Z",
        text="alpha modified before",
    )
    unchanged_id = _capture_record(
        initialized_project,
        source_ref="session://unchanged",
        captured_at="2026-02-25T00:00:00Z",
        text="alpha unchanged",
    )

    records_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "records_v0.jsonl"
    base_snapshot = initialized_project / ".cortex" / "reports" / "diff_base_snapshot.jsonl"
    base_snapshot.parent.mkdir(parents=True, exist_ok=True)
    base_snapshot.write_text(records_path.read_text(encoding="utf-8"), encoding="utf-8")

    target_rows = _read_jsonl(records_path)
    target_rows = [row for row in target_rows if row["record_id"] != removed_id]
    for row in target_rows:
        if row["record_id"] == modified_id:
            row["content"]["text"] = "alpha modified after"
    _write_jsonl(records_path, target_rows)

    added_id = _capture_record(
        initialized_project,
        source_ref="session://added",
        captured_at="2026-02-26T00:00:00Z",
        text="alpha added",
    )

    proc = run_coach(
        initialized_project,
        "memory-diff",
        "--base-file",
        str(base_snapshot),
        "--target-file",
        str(records_path),
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    summary = payload["result"]["summary"]
    assert summary == {
        "added_count": 1,
        "removed_count": 1,
        "modified_count": 1,
        "unchanged_count": 1,
    }

    entries = payload["result"]["entries"]
    assert [e["change_type"] for e in entries] == ["added", "modified", "removed", "unchanged"]
    assert [e["record_id"] for e in entries] == [added_id, modified_id, removed_id, unchanged_id]
    for entry in entries:
        assert entry["lineage"]["source_refs"]


def test_memory_diff_current_vs_current_is_all_unchanged(initialized_project: Path) -> None:
    _capture_record(
        initialized_project,
        source_ref="session://one",
        captured_at="2026-02-23T00:00:00Z",
        text="alpha one",
    )
    _capture_record(
        initialized_project,
        source_ref="session://two",
        captured_at="2026-02-24T00:00:00Z",
        text="alpha two",
    )

    proc = run_coach(initialized_project, "memory-diff", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    summary = payload["result"]["summary"]
    assert summary["added_count"] == 0
    assert summary["removed_count"] == 0
    assert summary["modified_count"] == 0
    assert summary["unchanged_count"] == 2


def test_memory_diff_missing_base_file_fails(initialized_project: Path) -> None:
    missing = initialized_project / "does_not_exist.jsonl"
    proc = run_coach(
        initialized_project,
        "memory-diff",
        "--base-file",
        str(missing),
        "--format",
        "json",
        expect_code=2,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "invalid_arguments"
