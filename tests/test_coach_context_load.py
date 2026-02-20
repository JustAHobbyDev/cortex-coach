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
    assert payload["selected_file_count"] >= 1
    assert any(f["selected_by"] == "control_plane" for f in payload["files"])
