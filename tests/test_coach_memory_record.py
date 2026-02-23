from __future__ import annotations

import json
import os
import time
from pathlib import Path

from conftest import run_coach


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def _base_args() -> list[str]:
    return [
        "memory-record",
        "--source-kind",
        "manual_capture",
        "--source-ref",
        "session://unit-test",
        "--captured-by",
        "tester",
        "--source-refs",
        "session://unit-test",
        "--captured-at",
        "2026-02-23T00:00:00Z",
        "--content-class",
        "task_state",
        "--retention-class",
        "short",
        "--ttl-expires-at",
        "2026-03-01T00:00:00Z",
        "--format",
        "json",
    ]


def test_memory_record_json_persists_clean_record(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        *_base_args(),
        "--text",
        "Completed governance closeout checklist.",
        "--tags",
        "phase1,closeout",
    )
    payload = json.loads(proc.stdout)
    assert payload["command"] == "memory-record"
    assert payload["status"] == "pass"
    assert payload["result"]["persisted"] is True
    assert payload["result"]["sanitization_status"] == "clean"
    assert payload["result"]["record_id"].startswith("tmr_")

    records_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "records_v0.jsonl"
    records = _read_jsonl(records_path)
    assert len(records) == 1
    record = records[0]
    assert record["record_id"] == payload["result"]["record_id"]
    assert record["sanitization"]["status"] == "clean"
    assert record["write_lock"]["lock_timeout_seconds"] > 0


def test_memory_record_redacts_prohibited_patterns(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        *_base_args(),
        "--text",
        "Set password=hunter2 and notify owner@example.com",
        "--tags",
        "sensitive,ops",
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["result"]["sanitization_status"] == "redacted"
    assert payload["result"]["redaction_actions"]

    records_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "records_v0.jsonl"
    records = _read_jsonl(records_path)
    assert len(records) == 1
    stored_text = records[0]["content"]["text"]
    assert "hunter2" not in stored_text
    assert "owner@example.com" not in stored_text


def test_memory_record_blocks_private_key_material(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        *_base_args(),
        "--text",
        "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        expect_code=3,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "policy_violation"
    assert payload["result"]["sanitization_status"] == "blocked"

    records_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "records_v0.jsonl"
    assert _read_jsonl(records_path) == []

    incidents_path = initialized_project / ".cortex" / "state" / "tactical_memory" / "sanitization_incidents_v0.jsonl"
    incidents = _read_jsonl(incidents_path)
    assert len(incidents) == 1
    assert incidents[0]["record_id"] == payload["result"]["record_id"]


def test_memory_record_invalid_ttl_returns_invalid_args(initialized_project: Path) -> None:
    proc = run_coach(
        initialized_project,
        *_base_args(),
        "--text",
        "Normal message.",
        "--captured-at",
        "2026-02-23T10:00:00Z",
        "--ttl-expires-at",
        "2026-02-23T09:00:00Z",
        expect_code=2,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "invalid_arguments"


def test_memory_record_lock_conflict_returns_exit_4(initialized_project: Path) -> None:
    lock_path = initialized_project / ".cortex" / ".lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
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
        *_base_args(),
        "--text",
        "Normal message.",
        "--lock-timeout-seconds",
        "0.01",
        expect_code=4,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["error"]["code"] == "lock_conflict"
