from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_context_policy_json_output(initialized_project: Path) -> None:
    proc = run_coach(initialized_project, "context-policy", "--format", "json")
    payload = json.loads(proc.stdout)

    assert payload["version"] == "v0"
    assert "recommended_budget" in payload
    assert payload["recommended_budget"]["max_files"] >= 1
    assert payload["recommended_budget"]["max_chars_per_file"] >= 100
    assert isinstance(payload["recommended_task_focus"], list)
    assert len(payload["recommended_task_focus"]) >= 1
