#!/usr/bin/env python3
"""
Deterministic context loader for Cortex projects.

Loads minimal control-plane artifacts first, then task-relevant files within
strict file/character budgets.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_MAX_FILES = 12
DEFAULT_MAX_CHARS_PER_FILE = 2500

CONTROL_PLANE_ORDER = [
    ".cortex/manifest_v0.json",
    ".cortex/reports/lifecycle_audit_v0.json",
    ".cortex/reports/audit_needed_v0.json",
    ".cortex/reports/decision_candidates_v0.json",
]
ACTIVE_DECISION_GLOB = ".cortex/artifacts/decisions/decision_*_v*.md"
MAX_ACTIVE_DECISIONS = 3

TASK_PATTERNS = {
    "direction": [
        ".cortex/artifacts/direction_*.md",
        "policies/*.md",
    ],
    "governance": [
        ".cortex/artifacts/governance_*.md",
        "policies/*.md",
    ],
    "design": [
        ".cortex/artifacts/design_*.dsl",
        ".cortex/artifacts/design_*.json",
        "templates/design_ontology*.json",
        "templates/modern_web_design_vocabulary_v0.json",
    ],
    "spec": [
        "specs/*.md",
        ".cortex/artifacts/*.md",
    ],
    "default": [
        ".cortex/artifacts/*.md",
        "specs/*.md",
    ],
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project-dir", required=True)
    p.add_argument("--task", default="default")
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    p.add_argument("--max-chars-per-file", type=int, default=DEFAULT_MAX_CHARS_PER_FILE)
    p.add_argument(
        "--fallback-mode",
        choices=["none", "priority"],
        default="priority",
        help="Fallback behavior when restricted loading fails (default: priority).",
    )
    p.add_argument(
        "--assets-dir",
        help="Optional assets root for compatibility metadata (reserved for future asset-backed loading).",
    )
    p.add_argument("--out-file", help="Optional output path; defaults to stdout")
    return p.parse_args()


def normalize_task(task: str) -> str:
    t = task.lower()
    if any(k in t for k in ["design", "ui", "frontend", "visual"]):
        return "design"
    if any(k in t for k in ["governance", "policy", "rules", "audit"]):
        return "governance"
    if any(k in t for k in ["direction", "strategy", "north star", "goal"]):
        return "direction"
    if any(k in t for k in ["spec", "schema", "contract"]):
        return "spec"
    return "default"


def read_excerpt(path: Path, max_chars: int) -> tuple[str, bool]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def find_latest(path_glob: str, project_dir: Path) -> Path | None:
    candidates = sorted(project_dir.glob(path_glob))
    if not candidates:
        return None
    return candidates[-1]


def select_control_plane(project_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    selected: list[dict[str, Any]] = []
    warnings: list[str] = []

    for rel in CONTROL_PLANE_ORDER:
        if "*" in rel:
            p = find_latest(rel, project_dir)
        else:
            p = project_dir / rel

        if p is None or not p.exists():
            warnings.append(f"missing_control_plane_file:{rel}")
            continue
        selected.append({"path": str(p.relative_to(project_dir)), "selected_by": "control_plane"})

    # Load latest promoted decision artifacts early so future agents inherit recent decisions.
    decision_candidates = sorted(project_dir.glob(ACTIVE_DECISION_GLOB))
    if not decision_candidates:
        warnings.append(f"missing_control_plane_file:{ACTIVE_DECISION_GLOB}")
    else:
        for p in decision_candidates[-MAX_ACTIVE_DECISIONS:]:
            selected.append(
                {
                    "path": str(p.relative_to(project_dir)),
                    "selected_by": "control_plane:active_decision",
                }
            )
    return selected, warnings


def select_task_files(project_dir: Path, task_key: str) -> list[dict[str, Any]]:
    patterns = TASK_PATTERNS.get(task_key, TASK_PATTERNS["default"])
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pat in patterns:
        for p in sorted(project_dir.glob(pat)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(project_dir))
            if rel in seen:
                continue
            seen.add(rel)
            out.append({"path": rel, "selected_by": f"task:{task_key}:{pat}"})
    return out


def build_bundle(
    project_dir: Path,
    task: str,
    max_files: int,
    max_chars_per_file: int,
    unrestricted: bool = False,
) -> dict[str, Any]:
    task_key = normalize_task(task)
    warnings: list[str] = []

    control_files, control_warnings = select_control_plane(project_dir)
    warnings.extend(control_warnings)

    task_files = select_task_files(project_dir, task_key)
    selected_meta: list[dict[str, Any]] = []

    # Always include control plane first.
    for entry in control_files:
        if (not unrestricted) and len(selected_meta) >= max_files:
            break
        selected_meta.append(entry)

    # Then add task files.
    for entry in task_files:
        if (not unrestricted) and len(selected_meta) >= max_files:
            break
        if any(e["path"] == entry["path"] for e in selected_meta):
            continue
        selected_meta.append(entry)

    excerpts: list[dict[str, Any]] = []
    truncated_count = 0
    for entry in selected_meta:
        path = project_dir / entry["path"]
        try:
            if unrestricted:
                excerpt = path.read_text(encoding="utf-8", errors="replace")
                truncated = False
            else:
                excerpt, truncated = read_excerpt(path, max_chars_per_file)
        except FileNotFoundError:
            warnings.append(f"missing_after_select:{entry['path']}")
            continue
        if truncated:
            truncated_count += 1
        excerpts.append(
            {
                "path": entry["path"],
                "selected_by": entry["selected_by"],
                "truncated": truncated,
                "excerpt": excerpt,
            }
        )

    report = {
        "version": "v0",
        "project_dir": str(project_dir),
        "assets_dir": None,
        "task": task,
        "task_key": task_key,
        "budget": {
            "max_files": None if unrestricted else max_files,
            "max_chars_per_file": None if unrestricted else max_chars_per_file,
            "unrestricted": unrestricted,
        },
        "selected_file_count": len(excerpts),
        "truncated_file_count": truncated_count,
        "warnings": warnings,
        "files": excerpts,
    }
    return report


def _bundle_success(report: dict[str, Any]) -> bool:
    files = report.get("files", [])
    if not files:
        return False
    control = [f for f in files if str(f.get("selected_by", "")).startswith("control_plane")]
    task = [f for f in files if str(f.get("selected_by", "")).startswith("task:")]
    if not control:
        return False
    if not task:
        return False
    return True


def main() -> int:
    args = parse_args()
    project_dir = Path(args.project_dir).resolve()
    base_files = max(1, args.max_files)
    base_chars = max(100, args.max_chars_per_file)
    bundle = build_bundle(
        project_dir=project_dir,
        task=args.task,
        max_files=base_files,
        max_chars_per_file=base_chars,
    )
    if args.assets_dir:
        bundle["assets_dir"] = str(Path(args.assets_dir).resolve())

    attempts: list[dict[str, Any]] = [
        {
            "level": "restricted",
            "max_files": base_files,
            "max_chars_per_file": base_chars,
            "unrestricted": False,
            "success": _bundle_success(bundle),
        }
    ]
    fallback_level = "restricted"

    if args.fallback_mode == "priority" and not _bundle_success(bundle):
        relaxed_files = max(2, int(base_files * 2))
        relaxed_chars = max(200, int(base_chars * 2))
        relaxed = build_bundle(
            project_dir=project_dir,
            task=args.task,
            max_files=relaxed_files,
            max_chars_per_file=relaxed_chars,
        )
        relaxed_ok = _bundle_success(relaxed)
        attempts.append(
            {
                "level": "relaxed",
                "max_files": relaxed_files,
                "max_chars_per_file": relaxed_chars,
                "unrestricted": False,
                "success": relaxed_ok,
            }
        )
        if relaxed_ok:
            bundle = relaxed
            fallback_level = "relaxed"

    if args.fallback_mode == "priority" and not _bundle_success(bundle):
        unrestricted = build_bundle(
            project_dir=project_dir,
            task=args.task,
            max_files=base_files,
            max_chars_per_file=base_chars,
            unrestricted=True,
        )
        unrestricted_ok = _bundle_success(unrestricted)
        attempts.append(
            {
                "level": "unrestricted",
                "max_files": None,
                "max_chars_per_file": None,
                "unrestricted": True,
                "success": unrestricted_ok,
            }
        )
        bundle = unrestricted
        fallback_level = "unrestricted"

    bundle["fallback_level"] = fallback_level
    bundle["fallback_attempts"] = attempts

    output = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    if args.out_file:
        out = Path(args.out_file)
        if not out.is_absolute():
            out = project_dir / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
