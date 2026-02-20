from __future__ import annotations

import json
from pathlib import Path

from conftest import run_coach


def test_contract_check_uses_assets_dir_default_contract(initialized_project: Path, tmp_path: Path) -> None:
    assets_dir = tmp_path / "assets"
    contract_dir = assets_dir / "contracts"
    contract_dir.mkdir(parents=True, exist_ok=True)
    (contract_dir / "coach_asset_contract_v0.json").write_text(
        json.dumps(
            {
                "version": "v0",
                "asset_contract_version": "v0",
                "required_paths": [".cortex/definitely_missing.json"],
                "required_manifest": {"version": "v0", "required_top_level_keys": ["version"]},
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
        "--assets-dir",
        str(assets_dir),
        "--format",
        "json",
        expect_code=1,
    )
    payload = json.loads(proc.stdout)
    assert payload["status"] == "fail"
    assert payload["contract_file"].endswith("assets/contracts/coach_asset_contract_v0.json")


def test_audit_fails_when_assets_schema_missing(initialized_project: Path, tmp_path: Path) -> None:
    assets_dir = tmp_path / "assets_missing_schema"
    assets_dir.mkdir(parents=True, exist_ok=True)
    run_coach(initialized_project, "audit", "--assets-dir", str(assets_dir), expect_code=1)
    payload = json.loads((initialized_project / ".cortex" / "reports" / "lifecycle_audit_v0.json").read_text(encoding="utf-8"))
    assert payload["status"] == "fail"
    assert any(c["check"] == "design_schema_asset" and c["status"] == "fail" for c in payload["checks"])
