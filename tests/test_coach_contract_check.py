from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_contract_check_passes_for_initialized_project(initialized_project: Path) -> None:
    proc = run_coach(initialized_project, "contract-check", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["status"] == "pass"
    assert payload["checks"]
    assert all(item["status"] == "pass" for item in payload["checks"])


def test_contract_check_fails_when_required_path_missing(initialized_project: Path) -> None:
    registry = initialized_project / ".cortex" / "spec_registry_v0.json"
    registry.unlink()
    proc = run_coach(initialized_project, "contract-check", "--format", "json", expect_code=1)
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert any(item["check"] == "required_path:.cortex/spec_registry_v0.json" for item in payload["checks"])


def test_contract_check_fails_on_unsupported_contract_version(initialized_project: Path, tmp_path: Path) -> None:
    contract_file = tmp_path / "coach_asset_contract_v0.json"
    contract_file.write_text(
        json.dumps(
            {
                "version": "v0",
                "asset_contract_version": "v999",
                "required_paths": [],
                "required_manifest": {"version": "v0", "required_top_level_keys": []},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    proc = run_coach(
        initialized_project,
        "contract-check",
        "--contract-file",
        str(contract_file),
        "--format",
        "json",
        expect_code=1,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["checks"][0]["check"] == "contract_file"
    assert "unsupported asset contract version" in payload["checks"][0]["detail"]
