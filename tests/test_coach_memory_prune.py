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
    ttl_expires_at: str,
    text: str,
    tags: str = "phase1",
    content_class: str = "task_state",
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
        content_class,
        "--retention-class",
        "short",
        "--ttl-expires-at",
        ttl_expires_at,
        "--text",
        text,
        "--tags",
        tags,
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    return payload["result"]["record_id"]


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def test_memory_prune_dry_run_is_non_mutating(initialized_project: Path) -> None:
    _capture_record(
        initialized_project,
        source_ref="session://one",
        captured_at="2026-02-20T00:00:00Z",
        ttl_expires_at="2026-02-21T00:00:00Z",
        text="alpha one",
    )
    _capture_record(
        initialized_project,
        source_ref="session://two",
        captured_at="2026-02-20T00:00:00Z",
        ttl_expires_at="2026-02-22T00:00:00Z",
        text="alpha two",
    )

    records_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "records_v0.jsonl"
    before_rows = _read_jsonl(records_path)

    proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-03-01T00:00:00Z",
        "--dry-run",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["dry_run"] is True
    assert payload["result"]["summary"]["candidate_count"] == 2
    assert payload["result"]["summary"]["pruned_count"] == 0
    assert payload["result"]["summary"]["skipped_count"] == 2
    assert all(action["decision"] == "skip" for action in payload["result"]["actions"])
    assert all(action["reason"] == "dry_run_only" for action in payload["result"]["actions"])

    after_rows = _read_jsonl(records_path)
    assert before_rows == after_rows


def test_memory_prune_no_dry_run_removes_expired_records(initialized_project: Path) -> None:
    expired_id = _capture_record(
        initialized_project,
        source_ref="session://expired",
        captured_at="2026-02-20T00:00:00Z",
        ttl_expires_at="2026-02-21T00:00:00Z",
        text="alpha expired",
    )
    retained_id = _capture_record(
        initialized_project,
        source_ref="session://retained",
        captured_at="2026-02-20T00:00:00Z",
        ttl_expires_at="2026-04-01T00:00:00Z",
        text="alpha retained",
    )

    proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-03-01T00:00:00Z",
        "--no-dry-run",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["summary"]["candidate_count"] == 1
    assert payload["result"]["summary"]["pruned_count"] == 1
    assert payload["result"]["summary"]["skipped_count"] == 0
    action = payload["result"]["actions"][0]
    assert action["record_id"] == expired_id
    assert action["decision"] == "prune"
    assert action["reason"] == "expired_ttl"

    records_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "records_v0.jsonl"
    remaining = {row["record_id"] for row in _read_jsonl(records_path)}
    assert expired_id not in remaining
    assert retained_id in remaining


def test_memory_prune_policy_violation_class_can_prune(initialized_project: Path) -> None:
    violation_id = _capture_record(
        initialized_project,
        source_ref="session://secret",
        captured_at="2026-02-20T00:00:00Z",
        ttl_expires_at="2026-04-01T00:00:00Z",
        text="alpha api_key=12345",
    )

    proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-02-01T00:00:00Z",
        "--policy-violation-classes-any",
        "secret",
        "--no-dry-run",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["summary"]["pruned_count"] == 1
    action = payload["result"]["actions"][0]
    assert action["record_id"] == violation_id
    assert action["reason"] == "policy_violation"


def test_memory_prune_linked_dependency_skips_when_not_dry_run(initialized_project: Path) -> None:
    linked_id = _capture_record(
        initialized_project,
        source_ref="session://linked",
        captured_at="2026-02-20T00:00:00Z",
        ttl_expires_at="2026-04-01T00:00:00Z",
        text="alpha api_key=abcd",
        tags="phase1,governance_linked",
    )

    proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-02-01T00:00:00Z",
        "--policy-violation-classes-any",
        "secret",
        "--no-dry-run",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["summary"]["pruned_count"] == 0
    assert payload["result"]["summary"]["skipped_count"] == 1
    action = payload["result"]["actions"][0]
    assert action["record_id"] == linked_id
    assert action["decision"] == "skip"
    assert action["reason"] == "linked_governance_dependency"


def test_memory_prune_stale_compaction_prunes_non_protected_records(initialized_project: Path) -> None:
    stale_id = _capture_record(
        initialized_project,
        source_ref="session://stale",
        captured_at="2026-01-01T00:00:00Z",
        ttl_expires_at="2026-12-31T00:00:00Z",
        text="old implementation note",
        tags="phase2",
    )

    proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-01-01T00:00:00Z",
        "--compaction-policy",
        "stale_only",
        "--stale-before",
        "2026-02-01T00:00:00Z",
        "--no-dry-run",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["summary"]["candidate_count"] == 1
    assert payload["result"]["summary"]["pruned_count"] == 1
    assert payload["result"]["summary"]["stale_candidate_count"] == 1
    action = payload["result"]["actions"][0]
    assert action["record_id"] == stale_id
    assert action["reason"] == "stale_compaction"
    assert "stale_compaction" in action["matched_criteria"]


def test_memory_prune_stale_compaction_protects_governance_content_class(initialized_project: Path) -> None:
    protected_id = _capture_record(
        initialized_project,
        source_ref="session://gov-context",
        captured_at="2026-01-01T00:00:00Z",
        ttl_expires_at="2026-12-31T00:00:00Z",
        text="governance trace note",
        content_class="governance_context",
        tags="phase2",
    )

    proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-01-01T00:00:00Z",
        "--compaction-policy",
        "stale_only",
        "--stale-before",
        "2026-02-01T00:00:00Z",
        "--no-dry-run",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["summary"]["pruned_count"] == 0
    assert payload["result"]["summary"]["protected_skip_count"] == 1
    action = payload["result"]["actions"][0]
    assert action["record_id"] == protected_id
    assert action["decision"] == "skip"
    assert action["reason"] == "protected_content_class"
    assert "protected_content_class" in action["protection_blocks"]


def test_memory_prune_duplicate_compaction_keeps_latest_record(initialized_project: Path) -> None:
    older_id = _capture_record(
        initialized_project,
        source_ref="session://dup",
        captured_at="2026-01-01T00:00:00Z",
        ttl_expires_at="2026-12-31T00:00:00Z",
        text="same duplicate compaction text",
        tags="phase2",
    )
    newer_id = _capture_record(
        initialized_project,
        source_ref="session://dup",
        captured_at="2026-01-15T00:00:00Z",
        ttl_expires_at="2026-12-31T00:00:00Z",
        text="same duplicate compaction text",
        tags="phase2",
    )

    proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-01-01T00:00:00Z",
        "--compaction-policy",
        "stale_and_duplicate",
        "--no-dry-run",
        "--format",
        "json",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["summary"]["candidate_count"] == 1
    assert payload["result"]["summary"]["duplicate_candidate_count"] == 1
    action = payload["result"]["actions"][0]
    assert action["record_id"] == older_id
    assert action["reason"] == "duplicate_compaction"
    assert "duplicate_compaction" in action["matched_criteria"]

    records_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "records_v0.jsonl"
    remaining = {row["record_id"] for row in _read_jsonl(records_path)}
    assert older_id not in remaining
    assert newer_id in remaining


def test_memory_prune_lock_conflict_returns_exit_4(initialized_project: Path) -> None:
    _capture_record(
        initialized_project,
        source_ref="session://one",
        captured_at="2026-02-20T00:00:00Z",
        ttl_expires_at="2026-02-21T00:00:00Z",
        text="alpha one",
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
        "memory-prune",
        "--expired-before",
        "2026-03-01T00:00:00Z",
        "--lock-timeout-seconds",
        "0.01",
        "--format",
        "json",
        expect_code=4,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "lock_conflict"
