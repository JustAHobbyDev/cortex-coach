from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_memory_command_family_smoke(initialized_project: Path) -> None:
    record_proc = run_coach(
        initialized_project,
        "memory-record",
        "--source-kind",
        "manual_capture",
        "--source-ref",
        "session://smoke",
        "--captured-by",
        "smoke-test",
        "--source-refs",
        "session://smoke",
        "--captured-at",
        "2026-02-23T00:00:00Z",
        "--text",
        "alpha smoke verification record",
        "--content-class",
        "task_state",
        "--tags",
        "phase1,smoke",
        "--retention-class",
        "short",
        "--ttl-expires-at",
        "2026-12-31T00:00:00Z",
        "--format",
        "json",
    )
    record_payload = json.loads(record_proc.stdout)
    assert record_payload["status"] == "pass"
    record_id = record_payload["result"]["record_id"]

    search_proc = run_coach(
        initialized_project,
        "memory-search",
        "--query",
        "alpha smoke",
        "--format",
        "json",
    )
    search_payload = json.loads(search_proc.stdout)
    assert search_payload["status"] == "pass"
    assert search_payload["result"]["result_count"] >= 1

    prime_proc = run_coach(
        initialized_project,
        "memory-prime",
        "--task",
        "smoke-task",
        "--query-ref",
        "alpha smoke",
        "--requested-limit",
        "5",
        "--max-records",
        "3",
        "--max-chars",
        "400",
        "--per-record-max-chars",
        "120",
        "--format",
        "json",
    )
    prime_payload = json.loads(prime_proc.stdout)
    assert prime_payload["status"] == "pass"

    diff_proc = run_coach(initialized_project, "memory-diff", "--format", "json")
    diff_payload = json.loads(diff_proc.stdout)
    assert diff_payload["status"] == "pass"

    prune_proc = run_coach(
        initialized_project,
        "memory-prune",
        "--expired-before",
        "2026-03-01T00:00:00Z",
        "--dry-run",
        "--format",
        "json",
    )
    prune_payload = json.loads(prune_proc.stdout)
    assert prune_payload["status"] == "pass"

    promote_proc = run_coach(
        initialized_project,
        "memory-promote",
        "--record-ids",
        record_id,
        "--bridge-mode",
        "non_governance",
        "--format",
        "json",
    )
    promote_payload = json.loads(promote_proc.stdout)
    assert promote_payload["status"] == "pass"
