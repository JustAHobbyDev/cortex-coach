from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
COACH_SCRIPT = REPO_ROOT / "cortex_coach" / "coach.py"


def run_cmd(args: list[str], cwd: Path, expect_code: int = 0) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True, check=False)
    if proc.returncode != expect_code:
        raise AssertionError(
            f"command failed\ncwd={cwd}\nargs={args}\n"
            f"expected={expect_code} got={proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    return proc


def run_coach(project_dir: Path, *coach_args: str, expect_code: int = 0) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, str(COACH_SCRIPT), *coach_args, "--project-dir", str(project_dir)]
    return run_cmd(args, cwd=REPO_ROOT, expect_code=expect_code)


def init_git_repo(path: Path) -> None:
    run_cmd(["git", "init"], cwd=path)
    run_cmd(["git", "config", "user.email", "test@example.com"], cwd=path)
    run_cmd(["git", "config", "user.name", "Cortex Test"], cwd=path)


@pytest.fixture()
def initialized_project(tmp_path: Path) -> Path:
    project_dir = tmp_path / "proj"
    project_dir.mkdir(parents=True, exist_ok=True)
    init_git_repo(project_dir)

    args = [
        sys.executable,
        str(COACH_SCRIPT),
        "init",
        "--project-dir",
        str(project_dir),
        "--project-id",
        "demo",
        "--project-name",
        "Demo",
    ]
    run_cmd(args, cwd=REPO_ROOT)

    # Baseline commit so dirty checks are meaningful.
    run_cmd(["git", "add", "."], cwd=project_dir)
    run_cmd(["git", "commit", "-m", "baseline"], cwd=project_dir)
    return project_dir


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
