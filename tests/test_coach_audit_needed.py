from __future__ import annotations

import json
import sys
from pathlib import Path

from conftest import COACH_SCRIPT, REPO_ROOT, run_cmd, run_coach


def test_audit_needed_clean_repo(initialized_project: Path) -> None:
    proc = run_coach(initialized_project, "audit-needed", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["status"] == "not_needed"
    assert payload["audit_required"] is False


def test_audit_needed_high_risk_and_fail_flag(initialized_project: Path) -> None:
    # Touch high-risk path class (specs/**) to require audit.
    spec_path = initialized_project / "specs" / "new_spec.md"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("# test spec\n", encoding="utf-8")

    proc = run_coach(initialized_project, "audit-needed", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["audit_required"] is True
    assert payload["status"] == "required"

    # Fail-on-required should exit non-zero.
    args = [
        sys.executable,
        str(COACH_SCRIPT),
        "audit-needed",
        "--project-dir",
        str(initialized_project),
        "--format",
        "json",
        "--fail-on-required",
    ]
    run_cmd(args, cwd=REPO_ROOT, expect_code=1)
