from __future__ import annotations

import json
import sys
from pathlib import Path

from conftest import COACH_SCRIPT, init_git_repo, run_cmd, run_coach


def test_audit_defaults_to_cortex_only_scope(initialized_project: Path) -> None:
    specs_dir = initialized_project / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)
    (specs_dir / "foreign_scope.md").write_text(
        "# External Reference\n\nScope: project/not_local\n",
        encoding="utf-8",
    )

    run_coach(initialized_project, "audit")
    report = json.loads((initialized_project / ".cortex" / "reports" / "lifecycle_audit_v0.json").read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    assert report["audit_scope"] == "cortex-only"


def test_audit_scope_all_includes_repo_governance_dirs(initialized_project: Path) -> None:
    specs_dir = initialized_project / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)
    (specs_dir / "foreign_scope.md").write_text(
        "# External Reference\n\nScope: project/not_local\n",
        encoding="utf-8",
    )

    proc = run_coach(initialized_project, "audit", "--audit-scope", "all", expect_code=1)
    assert ".cortex/reports/lifecycle_audit_v0.json" in proc.stdout
    report = json.loads((initialized_project / ".cortex" / "reports" / "lifecycle_audit_v0.json").read_text(encoding="utf-8"))
    assert report["status"] == "fail"
    assert report["audit_scope"] == "all"
    assert any(f["check"] == "foreign_project_scope" for f in report["artifact_conformance"]["findings"])


def test_audit_supports_custom_cortex_root(tmp_path: Path) -> None:
    project_dir = tmp_path / "proj_custom_root"
    project_dir.mkdir(parents=True, exist_ok=True)
    init_git_repo(project_dir)

    run_cmd(
        [
            sys.executable,
            str(COACH_SCRIPT),
            "init",
            "--project-dir",
            str(project_dir),
            "--project-id",
            "demo",
            "--project-name",
            "Demo",
            "--cortex-root",
            ".ops",
        ],
        cwd=Path(__file__).resolve().parents[1],
    )

    run_coach(project_dir, "audit", "--cortex-root", ".ops")
    report = json.loads((project_dir / ".ops" / "reports" / "lifecycle_audit_v0.json").read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    assert report["audit_scope"] == "cortex-only"
    assert report["cortex_root"].endswith("/.ops")
