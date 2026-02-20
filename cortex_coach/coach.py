#!/usr/bin/env python3
"""
Cortex Project Coach v0

CLI to bootstrap and audit `.cortex/` lifecycle artifacts in a target project.
"""

from __future__ import annotations

import argparse
from fnmatch import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema


MANIFEST_FILE = "manifest_v0.json"
LIFECYCLE_SCHEMA_VERSION = "v0"
PHASE_ORDER = [
    "direction_defined",
    "governance_defined",
    "design_spec_compiled",
    "lifecycle_audited",
]
VALID_APPLY_SCOPES = {"direction", "governance", "design"}
LOCK_FILE = ".lock"
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
DEFAULT_LOCK_STALE_SECONDS = 300.0
DEFAULT_CORTEX_ROOT = ".cortex"
DEFAULT_HIGH_RISK_PATTERNS = [
    ".cortex/manifest_v0.json",
    ".cortex/artifacts/**",
    "specs/**",
    "policies/**",
    "cortex_coach/coach.py",
]
DEFAULT_MEDIUM_RISK_PATTERNS = [
    ".cortex/prompts/**",
    "playbooks/**",
    "templates/**",
]
DEFAULT_DECISION_GAP_PATTERNS = [
    ".cortex/manifest_v0.json",
    ".cortex/policies/**",
    ".cortex/artifacts/decisions/**",
    "policies/**",
    "playbooks/**",
    "scripts/quality_gate*.sh",
    "cortex_coach/coach.py",
    "Justfile",
    "pyproject.toml",
    "uv.lock",
    "docs/cortex-coach/**",
]
DEFAULT_IGNORED_PATTERNS = [
    ".cortex/.lock",
    ".cortex/**/*.tmp",
    ".cortex/**/*.bak",
    ".cortex/**/*.swp",
]
DEFAULT_CORTEX_AUDIT_SCAN_DIRS = [
    "principles",
    "patterns",
    "contracts",
    "specs",
    "templates",
    "prompts",
    "playbooks",
    "policies",
    "philosophy",
    "operating_model",
]
DECISION_CANDIDATES_FILE = ".cortex/reports/decision_candidates_v0.json"
DECISION_ARTIFACTS_DIR = ".cortex/artifacts/decisions"
DEFAULT_CONTRACT_FILE = "contracts/coach_asset_contract_v0.json"


def resolve_cortex_dir(project_dir: Path, raw_cortex_root: str | None) -> Path:
    if raw_cortex_root:
        root = Path(raw_cortex_root)
        return root.resolve() if root.is_absolute() else (project_dir / root).resolve()
    return (project_dir / DEFAULT_CORTEX_ROOT).resolve()


def default_spec_registry(project_id: str, cortex_root_rel: str = DEFAULT_CORTEX_ROOT) -> dict[str, Any]:
    return {
        "version": "v0",
        "domains": [
            {
                "id": "direction",
                "name": "Direction",
                "required": True,
                "severity": "block",
                "spec_patterns": [f"{cortex_root_rel}/artifacts/direction_*.md"],
                "source_patterns": [],
            },
            {
                "id": "governance",
                "name": "Governance",
                "required": True,
                "severity": "block",
                "spec_patterns": [f"{cortex_root_rel}/artifacts/governance_*.md"],
                "source_patterns": [],
            },
            {
                "id": "design",
                "name": "Design",
                "required": True,
                "severity": "warn",
                "spec_patterns": [f"{cortex_root_rel}/artifacts/design_*.json", f"{cortex_root_rel}/artifacts/design_*.dsl"],
                "source_patterns": [],
            },
            {
                "id": f"{project_id}_specs",
                "name": "Project Specs",
                "required": False,
                "severity": "warn",
                "spec_patterns": ["specs/*.md"],
                "source_patterns": ["src/**", "app/**", "api/**", "server/**"],
            },
        ],
        "orphan_spec_patterns": ["specs/*.md"],
    }


def usage_decision_policy_text(project_dir: Path) -> str:
    return f"""# Cortex Coach Usage Decision Policy

Version: v0
Status: Active
Scope: This repository (`{project_dir}`)

## Purpose

Ensure `cortex-coach` is consistently considered before next-step execution so lifecycle governance is not skipped due to operator memory gaps.

## Rule

Before substantial next-step work, the operator/agent must make an explicit decision:

1. `Use coach now`, or
2. `Coach not needed yet` (with concrete reason).

## Default Decision Procedure

1. Run:
   ```bash
   cortex-coach audit-needed --project-dir .
   ```
2. If `audit_required=true`:
   - run `cortex-coach coach --project-dir .`
   - run `cortex-coach audit --project-dir .`
   - proceed only after handling blocking findings
3. If `audit_required=false`:
   - proceed with work
   - run audit at the next milestone boundary (before merge/release)

## High-Risk Trigger Guidance

Treat changes as high-risk (likely requiring coach/audit) when they touch:

- `specs/`
- `policies/`
- `.cortex/manifest_v0.json`
- `.cortex/artifacts/`
- `cortex_coach/coach.py`

## Exceptions

Skip immediate coach usage only for tiny, non-governance edits (for example simple typo-only changes), but still run audit before merge/release.

## Enforcement Style

This policy is enforced as an operating discipline (human + agent behavior), and may later be promoted to CI gating.
"""


def decision_reflection_policy_text(project_dir: Path) -> str:
    return f"""# Cortex Coach Decision Reflection Policy

Version: v0
Status: Active
Scope: This repository (`{project_dir}`)

## Purpose

Ensure important process/governance decisions made during implementation are captured and reflected in operating artifacts, not left implicit in code diffs.

## Rule

Before closing a substantial task, run a decision reflection step:

1. Ask: "Did this work change operating behavior, governance, policy, release gates, safety posture, or maintainer workflow?"
2. If yes:
   - run `cortex-coach decision-capture`
   - include concrete impact scope and linked artifacts
   - promote with `cortex-coach decision-promote` when accepted
3. If no:
   - proceed without capture
   - note that no operating-layer decision was introduced

## Trigger Examples

Treat these as likely requiring decision capture:

- quality-gate behavior changes
- dependency/toolchain determinism changes
- contract compatibility rules
- audit/validation severity or blocking logic changes
- operating policy additions/removals

## Minimum Decision Entry Requirements

Each captured decision should include:

- clear decision statement
- rationale/tradeoff
- impact scope tags
- linked artifacts updated by the decision

## Enforcement Style

This policy is enforced as operating discipline, and can be promoted to CI policy checks when mature.
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_rel_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def normalize_repo_rel_path(path: str) -> str:
    out = path.replace("\\", "/")
    while out.startswith("./"):
        out = out[2:]
    return out


def slugify(value: str) -> str:
    out = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower()).strip("_")
    return out or "decision"


def parse_csv_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def read_manifest_project_id(project_dir: Path) -> str | None:
    manifest = project_dir / ".cortex" / MANIFEST_FILE
    if not manifest.exists():
        return None
    try:
        obj = json.loads(manifest.read_text(encoding="utf-8"))
        project_id = obj.get("project_id")
        return project_id if isinstance(project_id, str) and project_id else None
    except Exception:  # noqa: BLE001
        return None


def load_decision_candidates(project_dir: Path, cortex_dir: Path | None = None) -> dict[str, Any]:
    base = cortex_dir if cortex_dir is not None else (project_dir / DEFAULT_CORTEX_ROOT)
    path = base / "reports" / "decision_candidates_v0.json"
    if not path.exists():
        return {"version": "v0", "entries": []}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {"version": "v0", "entries": []}
    if not isinstance(obj, dict):
        return {"version": "v0", "entries": []}
    entries = obj.get("entries")
    if not isinstance(entries, list):
        obj["entries"] = []
    obj.setdefault("version", "v0")
    return obj


def save_decision_candidates(project_dir: Path, payload: dict[str, Any], cortex_dir: Path | None = None) -> Path:
    base = cortex_dir if cortex_dir is not None else (project_dir / DEFAULT_CORTEX_ROOT)
    path = base / "reports" / "decision_candidates_v0.json"
    payload["updated_at"] = utc_now()
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def next_versioned_decision_path(project_dir: Path, slug: str, cortex_dir: Path | None = None) -> Path:
    base = cortex_dir if cortex_dir is not None else (project_dir / DEFAULT_CORTEX_ROOT)
    root = base / "artifacts" / "decisions"
    root.mkdir(parents=True, exist_ok=True)
    matches = sorted(root.glob(f"decision_{slug}_v*.md"))
    if not matches:
        return root / f"decision_{slug}_v1.md"
    latest = matches[-1]
    m = re.search(r"_v(\d+)\.md$", latest.name)
    current = int(m.group(1)) if m else 1
    return root / f"decision_{slug}_v{current + 1}.md"


def load_cortexignore(project_dir: Path) -> list[tuple[str, bool]]:
    """
    Load .cortexignore patterns.
    Returns a list of (pattern, is_negated) with order preserved.
    """
    path = project_dir / ".cortexignore"
    if not path.exists():
        return []

    rules: list[tuple[str, bool]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        is_negated = line.startswith("!")
        pattern = line[1:] if is_negated else line
        pattern = normalize_rel_path(pattern)
        if not pattern:
            continue
        if pattern.endswith("/"):
            pattern = f"{pattern}**"
        rules.append((pattern, is_negated))
    return rules


def matches_cortexignore(rel_path: str, rules: list[tuple[str, bool]]) -> bool:
    if not rules:
        return False
    path = normalize_rel_path(rel_path)
    ignored = False
    for pattern, is_negated in rules:
        norm_pattern = pattern.lstrip("/")
        if fnmatch(path, norm_pattern):
            ignored = not is_negated
    return ignored


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.tmp.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except FileNotFoundError:
            pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True


def _read_lock_metadata(lock_path: Path) -> dict[str, Any]:
    try:
        raw = lock_path.read_text(encoding="utf-8")
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _lock_stale_reason(lock_path: Path, stale_seconds: float) -> str | None:
    meta = _read_lock_metadata(lock_path)
    created = meta.get("created_epoch")
    pid = meta.get("pid")
    now = time.time()
    if isinstance(created, (int, float)) and (now - float(created)) > stale_seconds:
        return "age_exceeded"
    if isinstance(pid, int) and not _pid_alive(pid):
        return "owner_process_missing"
    if not meta:
        return "invalid_metadata"
    return None


@contextmanager
def project_lock(
    project_dir: Path,
    cortex_root: str | None,
    lock_timeout_seconds: float,
    lock_stale_seconds: float,
    force_unlock: bool,
    command_name: str,
):
    cortex_dir = resolve_cortex_dir(project_dir, cortex_root)
    cortex_dir.mkdir(parents=True, exist_ok=True)
    lock_path = cortex_dir / LOCK_FILE

    token = f"{os.getpid()}-{int(time.time() * 1000)}"
    start = time.monotonic()
    acquired = False

    while not acquired:
        try:
            fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            payload = {
                "token": token,
                "pid": os.getpid(),
                "created_epoch": time.time(),
                "created_at": utc_now(),
                "command": command_name,
            }
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            acquired = True
        except FileExistsError:
            stale_reason = _lock_stale_reason(lock_path, lock_stale_seconds)
            if stale_reason or force_unlock:
                try:
                    lock_path.unlink()
                    continue
                except FileNotFoundError:
                    continue
            if (time.monotonic() - start) >= lock_timeout_seconds:
                owner = _read_lock_metadata(lock_path)
                raise RuntimeError(
                    "lock_timeout: unable to acquire .cortex lock; "
                    f"owner={owner if owner else 'unknown'}"
                )
            time.sleep(0.1)

    try:
        yield
    finally:
        owner = _read_lock_metadata(lock_path)
        if owner.get("token") == token:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


def write_if_missing(path: Path, content: str, force: bool) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return False
    atomic_write_text(path, content)
    return True


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_assets_dir(raw_assets_dir: str | None) -> Path:
    if raw_assets_dir:
        return Path(raw_assets_dir).resolve()
    env_assets = os.environ.get("CORTEX_ASSETS_DIR")
    if env_assets:
        return Path(env_assets).resolve()
    return repo_root_from_script()


def resolve_asset_path(assets_dir: Path, rel_path: str) -> Path:
    return assets_dir / rel_path


def default_design_dsl(project_id: str, project_name: str) -> str:
    return f"""# Generated by cortex_project_coach_v0.py
id {project_id}_design_v0
version v0
name {project_name} Design Baseline

token layout.grid | 12-column asymmetric grid
token layout.spacing | 96px vertical rhythm
token layout.structure | hero-dominant above fold
set layout.density | "balanced"
set layout.rhythm | "alternating panel cadence"
set layout.narrative_flow | "problem-to-solution arc"

token typography.hero | oversized neo-grotesk hero
set typography.body | "high x-height body face with line-height breathing room"
set typography.families | ["Space Grotesk", "IBM Plex Sans"]
set typography.scale | "optical size contrast"
set typography.weight_strategy | "weight-contrast ladder"
token typography.tracking_strategy | tight display tracking

token surface.base | charcoal base layer
token surface.accent | electric accent glow
token surface.panels | frosted glass panel
token surface.depth_model | hybrid
token surface.shadows | ambient shadow cloud
add surface.textures | "restrained gradient diffusion"

token motion.scroll | fade-up staggered reveal
token motion.hover | 200ms ease-out hover scale
token motion.timing_profile | snappy timing profile
add motion.interaction_signatures | "magnetic CTA pull"
set motion.reduced_motion_strategy | "opacity-only fallback"

token influence.primary | Swiss grid discipline
token influence.secondary | SaaS futurism
token influence.style_cluster | tech minimalism cluster
add influence.anti_patterns | "avoid ornamental motion"

score clarity | 8
score novelty | 7
score usability | 8
score brand_fit | 8
"""


def init_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    try:
        cortex_root_rel = str(cortex_dir.relative_to(project_dir))
    except ValueError:
        cortex_root_rel = DEFAULT_CORTEX_ROOT
    artifacts_dir = cortex_dir / "artifacts"
    prompts_dir = cortex_dir / "prompts"
    reports_dir = cortex_dir / "reports"
    registry_path = cortex_dir / "spec_registry_v0.json"
    project_id = args.project_id
    project_name = args.project_name

    manifest = {
        "version": LIFECYCLE_SCHEMA_VERSION,
        "project_id": project_id,
        "project_name": project_name,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "phases": {
            "direction_defined": False,
            "governance_defined": False,
            "design_spec_compiled": False,
            "lifecycle_audited": False,
        },
        "artifacts": {
            "direction": f"{cortex_root_rel}/artifacts/direction_{project_id}_v0.md",
            "governance": f"{cortex_root_rel}/artifacts/governance_{project_id}_v0.md",
            "design_dsl": f"{cortex_root_rel}/artifacts/design_{project_id}_v0.dsl",
            "design_json": f"{cortex_root_rel}/artifacts/design_{project_id}_v0.json",
            "project_prompt": f"{cortex_root_rel}/prompts/project_coach_prompt_{project_id}_v0.md",
        },
    }

    direction_md = f"""# {project_name} Direction v0

## North Star
- Define the single most important project outcome.

## Anti-Goals
- List what this project will explicitly avoid.

## Success Signals
- Define measurable outcomes for a successful first release.
"""
    governance_md = f"""# {project_name} Governance v0

## Invariants
- No silent mutation of core artifacts.
- Version bumps for semantic changes.
- Fail closed when required fields are missing.

## Delivery Constraints
- Accessibility and usability checks required before release.
- Deterministic artifact generation where applicable.
"""
    prompt_md = f"""# Project Coach Prompt ({project_id}) v0

Use `{cortex_root_rel}/manifest_v0.json` and `{cortex_root_rel}/artifacts/*` as source of truth.

Tasks:
1. Propose concrete updates to direction/governance/design artifacts.
2. Keep changes versioned (`vN`) and explicit.
3. Report lifecycle gaps and next corrective action.
"""

    changed = []
    changed.append(write_if_missing(cortex_dir / MANIFEST_FILE, json.dumps(manifest, indent=2, sort_keys=True) + "\n", args.force))
    changed.append(write_if_missing(artifacts_dir / f"direction_{project_id}_v0.md", direction_md, args.force))
    changed.append(write_if_missing(artifacts_dir / f"governance_{project_id}_v0.md", governance_md, args.force))
    changed.append(write_if_missing(artifacts_dir / f"design_{project_id}_v0.dsl", default_design_dsl(project_id, project_name), args.force))
    changed.append(write_if_missing(prompts_dir / f"project_coach_prompt_{project_id}_v0.md", prompt_md, args.force))
    changed.append(
        write_if_missing(
            registry_path,
            json.dumps(default_spec_registry(project_id, cortex_root_rel=cortex_root_rel), indent=2, sort_keys=True) + "\n",
            args.force,
        )
    )
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Compile DSL to JSON via existing compiler.
    repo_root = repo_root_from_script()
    dsl_path = artifacts_dir / f"design_{project_id}_v0.dsl"
    json_path = artifacts_dir / f"design_{project_id}_v0.json"
    vocab_path = resolve_asset_path(assets_dir, "templates/modern_web_design_vocabulary_v0.json")
    if not vocab_path.exists():
        print(
            f"missing design vocabulary asset: {vocab_path} (set --assets-dir or CORTEX_ASSETS_DIR)",
            file=sys.stderr,
        )
        return 1
    compile_cmd = [
        sys.executable,
        str(repo_root / "scripts" / "design_prompt_dsl_compile_v0.py"),
        "--dsl-file",
        str(dsl_path),
        "--out-file",
        str(json_path),
        "--vocab-file",
        str(vocab_path),
    ]
    proc = subprocess.run(compile_cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(proc.stderr.strip() or proc.stdout.strip(), file=sys.stderr)
        return 1

    # Update manifest progress flags.
    manifest_path = cortex_dir / MANIFEST_FILE
    manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_obj["updated_at"] = utc_now()
    manifest_obj["phases"]["direction_defined"] = True
    manifest_obj["phases"]["governance_defined"] = True
    manifest_obj["phases"]["design_spec_compiled"] = True
    atomic_write_text(manifest_path, json.dumps(manifest_obj, indent=2, sort_keys=True) + "\n")

    print(f"initialized: {project_dir}")
    if args.force:
        print("mode: force (existing files may be overwritten)")
    else:
        created_count = sum(1 for c in changed if c)
        print(f"created_or_updated_files: {created_count}")
    return 0


def validate_design_json(design_json: Path, schema: Path) -> tuple[bool, str]:
    try:
        schema_obj = json.loads(schema.read_text(encoding="utf-8"))
        data_obj = json.loads(design_json.read_text(encoding="utf-8"))
        jsonschema.validate(instance=data_obj, schema=schema_obj)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def detect_foreign_project_ids(text: str, local_project_id: str | None) -> list[str]:
    ids = sorted(set(re.findall(r"project/[A-Za-z0-9_.-]+", text)))
    if not ids:
        return []
    if not local_project_id:
        return ids
    local = f"project/{local_project_id}"
    return [pid for pid in ids if pid != local]


def is_reference_file(text: str) -> bool:
    return bool(
        re.search(r"(?im)^\s*status\s*:\s*reference\b", text)
        or re.search(r"(?im)^\s*canonical\s*:\s*false\b", text)
        or re.search(r"(?im)\bnon-canonical\b", text)
    )


def extract_backticked_rel_paths(text: str) -> list[str]:
    out: list[str] = []
    for raw in re.findall(r"`([^`]+)`", text):
        candidate = normalize_rel_path(raw)
        if "/" not in candidate:
            continue
        if candidate.startswith(("http://", "https://", "file://")):
            continue
        if candidate.startswith("../"):
            continue
        if " " in candidate:
            continue
        out.append(candidate)
    return out


def compute_artifact_conformance(
    project_dir: Path,
    cortex_dir: Path,
    local_project_id: str | None,
    audit_scope: str = "cortex-only",
    ignore_rules: list[tuple[str, bool]] | None = None,
) -> dict[str, Any]:
    rules = ignore_rules or []
    findings: list[dict[str, Any]] = []
    scanned = 0

    roots: list[Path] = []
    if audit_scope == "all":
        for rel_dir in DEFAULT_CORTEX_AUDIT_SCAN_DIRS:
            root = project_dir / rel_dir
            if root.exists():
                roots.append(root)
    else:
        if cortex_dir.exists():
            roots.append(cortex_dir)

    for root in roots:
        for path in sorted(root.rglob("*.md")):
            rel = str(path.relative_to(project_dir))
            if matches_cortexignore(rel, rules):
                continue
            scanned += 1
            text = path.read_text(encoding="utf-8")
            foreign = detect_foreign_project_ids(text, local_project_id)
            reference = is_reference_file(text)

            if foreign and not reference:
                findings.append(
                    {
                        "severity": "fail",
                        "path": rel,
                        "check": "foreign_project_scope",
                        "detail": (
                            "references project IDs outside local manifest scope "
                            f"(foreign_ids={foreign[:5]}) without explicit reference status"
                        ),
                    }
                )
            elif foreign and reference:
                findings.append(
                    {
                        "severity": "warn",
                        "path": rel,
                        "check": "foreign_project_scope_reference",
                        "detail": f"reference-scoped foreign project IDs present (foreign_ids={foreign[:5]})",
                    }
                )

            missing_rel_paths: list[str] = []
            for candidate in extract_backticked_rel_paths(text):
                if candidate.startswith(".cortex/"):
                    continue
                if not (project_dir / candidate).exists():
                    missing_rel_paths.append(candidate)
            if missing_rel_paths and not reference:
                findings.append(
                    {
                        "severity": "warn",
                        "path": rel,
                        "check": "missing_source_paths",
                        "detail": f"references missing project paths (examples={missing_rel_paths[:5]})",
                    }
                )

    has_fail = any(f["severity"] == "fail" for f in findings)
    has_warn = any(f["severity"] == "warn" for f in findings)
    status = "fail" if has_fail else ("warn" if has_warn else "pass")
    return {
        "status": status,
        "scanned_files": scanned,
        "findings": findings[:100],
    }


def compute_unsynced_decisions(
    project_dir: Path,
    cortex_dir: Path,
    ignore_rules: list[tuple[str, bool]] | None = None,
) -> dict[str, Any]:
    rules = ignore_rules or []
    registry = load_decision_candidates(project_dir, cortex_dir=cortex_dir)
    entries = registry.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    findings: list[dict[str, Any]] = []
    promoted_count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status", "candidate")).lower()
        if status != "promoted":
            continue
        promoted_count += 1

        decision_id = str(entry.get("decision_id", "unknown"))
        artifact_path = str(entry.get("decision_artifact", "")).strip()
        impact_scope = entry.get("impact_scope", [])
        linked = entry.get("linked_artifacts", [])
        if not isinstance(impact_scope, list):
            impact_scope = []
        if not isinstance(linked, list):
            linked = []

        if not artifact_path:
            findings.append(
                {
                    "severity": "fail",
                    "decision_id": decision_id,
                    "check": "missing_decision_artifact",
                    "detail": "promoted decision missing decision_artifact path",
                }
            )
            continue

        artifact = project_dir / artifact_path
        if (not matches_cortexignore(artifact_path, rules)) and not artifact.exists():
            findings.append(
                {
                    "severity": "fail",
                    "decision_id": decision_id,
                    "path": artifact_path,
                    "check": "decision_artifact_missing",
                    "detail": "promoted decision artifact path does not exist",
                }
            )

        if impact_scope and not linked:
            findings.append(
                {
                    "severity": "fail",
                    "decision_id": decision_id,
                    "path": artifact_path,
                    "check": "impact_scope_without_links",
                    "detail": "promoted decision has impact_scope but no linked_artifacts",
                }
            )

        for rel in linked:
            rel_path = str(rel)
            if matches_cortexignore(rel_path, rules):
                continue
            if not (project_dir / rel_path).exists():
                findings.append(
                    {
                        "severity": "fail",
                        "decision_id": decision_id,
                        "path": rel_path,
                        "check": "linked_artifact_missing",
                        "detail": "linked_artifact path does not exist",
                    }
                )

    has_fail = any(f["severity"] == "fail" for f in findings)
    status = "fail" if has_fail else "pass"
    return {
        "status": status,
        "promoted_decision_count": promoted_count,
        "findings": findings[:100],
    }


def load_asset_contract(contract_file: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not contract_file.exists():
        return None, f"missing contract file: {contract_file}"
    try:
        obj = json.loads(contract_file.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, f"invalid contract json: {exc}"
    if not isinstance(obj, dict):
        return None, "invalid contract shape: expected object"
    if obj.get("asset_contract_version") != "v0":
        return None, (
            "unsupported asset contract version: "
            f"{obj.get('asset_contract_version')!r}; supported: 'v0'"
        )
    return obj, None


def compute_contract_check(project_dir: Path, contract_file: Path, cortex_dir: Path | None = None) -> dict[str, Any]:
    contract_obj, err = load_asset_contract(contract_file)
    checks: list[dict[str, Any]] = []
    status = "pass"
    if err is not None:
        return {
            "version": "v0",
            "run_at": utc_now(),
            "project_dir": str(project_dir),
            "contract_file": str(contract_file),
            "status": "fail",
            "checks": [{"check": "contract_file", "status": "fail", "detail": err}],
        }

    required_paths = contract_obj.get("required_paths", [])
    if not isinstance(required_paths, list):
        required_paths = []
    for rel in required_paths:
        rel_path = str(rel)
        exists = (project_dir / rel_path).exists()
        checks.append(
            {
                "check": f"required_path:{rel_path}",
                "status": "pass" if exists else "fail",
            }
        )
        if not exists:
            status = "fail"

    manifest_rules = contract_obj.get("required_manifest", {})
    resolved_cortex_dir = cortex_dir or resolve_cortex_dir(project_dir, None)
    manifest = resolved_cortex_dir / MANIFEST_FILE
    if manifest.exists():
        try:
            manifest_obj = json.loads(manifest.read_text(encoding="utf-8"))
            expected_version = str(manifest_rules.get("version", "v0"))
            manifest_version_ok = manifest_obj.get("version") == expected_version
            checks.append(
                {
                    "check": "manifest_version",
                    "status": "pass" if manifest_version_ok else "fail",
                    "detail": f"expected={expected_version} actual={manifest_obj.get('version')}",
                }
            )
            if not manifest_version_ok:
                status = "fail"

            required_keys = manifest_rules.get("required_top_level_keys", [])
            if not isinstance(required_keys, list):
                required_keys = []
            missing = [k for k in required_keys if k not in manifest_obj]
            checks.append(
                {
                    "check": "manifest_required_keys",
                    "status": "pass" if not missing else "fail",
                    "detail": f"missing={missing}" if missing else "",
                }
            )
            if missing:
                status = "fail"
        except Exception as exc:  # noqa: BLE001
            checks.append({"check": "manifest_parse", "status": "fail", "detail": str(exc)})
            status = "fail"
    else:
        checks.append({"check": "manifest_exists", "status": "fail"})
        status = "fail"

    return {
        "version": "v0",
        "run_at": utc_now(),
        "project_dir": str(project_dir),
        "contract_file": str(contract_file),
        "status": status,
        "checks": checks,
    }


def compute_audit_report(
    project_dir: Path,
    assets_dir: Path | None = None,
    cortex_dir: Path | None = None,
    audit_scope: str = "cortex-only",
) -> tuple[str, dict[str, Any]]:
    resolved_cortex_dir = cortex_dir or resolve_cortex_dir(project_dir, None)
    manifest_path = resolved_cortex_dir / MANIFEST_FILE
    resolved_assets_dir = assets_dir or resolve_assets_dir(None)
    schema_path = resolve_asset_path(resolved_assets_dir, "templates/design_ontology_v0.schema.json")

    checks: list[dict[str, Any]] = []
    status = "pass"

    required = [
        manifest_path,
        resolved_cortex_dir / "artifacts",
        resolved_cortex_dir / "prompts",
        resolved_cortex_dir / "reports",
    ]
    for p in required:
        exists = p.exists()
        checks.append({"check": f"exists:{p.relative_to(project_dir)}", "status": "pass" if exists else "fail"})
        if not exists:
            status = "fail"

    manifest_obj: dict[str, Any] | None = None
    if manifest_path.exists():
        try:
            manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest_obj.get("version") != LIFECYCLE_SCHEMA_VERSION:
                checks.append({"check": "manifest_version", "status": "fail", "detail": f"expected {LIFECYCLE_SCHEMA_VERSION}"})
                status = "fail"
            else:
                checks.append({"check": "manifest_version", "status": "pass"})
        except Exception as exc:  # noqa: BLE001
            checks.append({"check": "manifest_parse", "status": "fail", "detail": str(exc)})
            status = "fail"

    design_json_path: Path | None = None
    if manifest_obj:
        path = manifest_obj.get("artifacts", {}).get("design_json")
        if isinstance(path, str):
            design_json_path = project_dir / path

    if not schema_path.exists():
        checks.append(
            {
                "check": "design_schema_asset",
                "status": "fail",
                "detail": f"missing schema asset: {schema_path}",
            }
        )
        status = "fail"
    elif design_json_path is not None and design_json_path.exists():
        ok, detail = validate_design_json(design_json_path, schema_path)
        checks.append(
            {
                "check": "design_schema_validation",
                "status": "pass" if ok else "fail",
                "detail": detail,
            }
        )
        if not ok:
            status = "fail"
    else:
        checks.append({"check": "design_schema_validation", "status": "fail", "detail": "design_json missing"})
        status = "fail"

    ignore_rules = load_cortexignore(project_dir)

    local_project_id: str | None = None
    if manifest_obj and isinstance(manifest_obj.get("project_id"), str):
        local_project_id = manifest_obj["project_id"]

    spec_coverage = compute_spec_coverage(project_dir, resolved_cortex_dir, ignore_rules=ignore_rules)
    checks.append(
        {
            "check": "spec_coverage",
            "status": spec_coverage.get("status", "warn"),
            "detail": (
                f"missing_required={len(spec_coverage.get('missing_required', []))}, "
                f"stale={len(spec_coverage.get('stale', []))}, "
                f"orphan={len(spec_coverage.get('orphan', []))}"
            ),
        }
    )
    if spec_coverage.get("status") == "fail":
        status = "fail"

    artifact_conformance = compute_artifact_conformance(
        project_dir,
        resolved_cortex_dir,
        local_project_id=local_project_id,
        audit_scope=audit_scope,
        ignore_rules=ignore_rules,
    )
    checks.append(
        {
            "check": "artifact_conformance",
            "status": artifact_conformance.get("status", "warn"),
            "detail": (
                f"scanned={artifact_conformance.get('scanned_files', 0)}, "
                f"findings={len(artifact_conformance.get('findings', []))}"
            ),
        }
    )
    if artifact_conformance.get("status") == "fail":
        status = "fail"

    unsynced_decisions = compute_unsynced_decisions(
        project_dir,
        resolved_cortex_dir,
        ignore_rules=ignore_rules,
    )
    checks.append(
        {
            "check": "unsynced_decisions",
            "status": unsynced_decisions.get("status", "warn"),
            "detail": (
                f"promoted={unsynced_decisions.get('promoted_decision_count', 0)}, "
                f"findings={len(unsynced_decisions.get('findings', []))}"
            ),
        }
    )
    if unsynced_decisions.get("status") == "fail":
        status = "fail"

    report = {
        "version": "v0",
        "run_at": utc_now(),
        "project_dir": str(project_dir),
        "cortex_root": str(resolved_cortex_dir),
        "assets_dir": str(resolved_assets_dir),
        "audit_scope": audit_scope,
        "status": status,
        "checks": checks,
        "spec_coverage": spec_coverage,
        "artifact_conformance": artifact_conformance,
        "unsynced_decisions": unsynced_decisions,
        "cortexignore": {
            "enabled": bool(ignore_rules),
            "path": str((project_dir / ".cortexignore").relative_to(project_dir)),
            "rules": len(ignore_rules),
        },
    }
    return status, report


def infer_phase_status(project_dir: Path, manifest_obj: dict[str, Any]) -> dict[str, bool]:
    artifacts = manifest_obj.get("artifacts", {})
    direction_path = artifacts.get("direction")
    governance_path = artifacts.get("governance")
    design_dsl_path = artifacts.get("design_dsl")
    design_json_path = artifacts.get("design_json")

    inferred = {
        "direction_defined": isinstance(direction_path, str) and (project_dir / direction_path).exists(),
        "governance_defined": isinstance(governance_path, str) and (project_dir / governance_path).exists(),
        "design_spec_compiled": isinstance(design_dsl_path, str)
        and isinstance(design_json_path, str)
        and (project_dir / design_dsl_path).exists()
        and (project_dir / design_json_path).exists(),
        "lifecycle_audited": False,
    }
    return inferred


def next_versioned_path(path: Path) -> Path:
    m = re.search(r"_v(\d+)(\.[A-Za-z0-9]+)$", path.name)
    if not m:
        return path.with_name(f"{path.stem}_draft{path.suffix}")
    current = int(m.group(1))
    ext = m.group(2)
    next_name = re.sub(r"_v\d+" + re.escape(ext) + r"$", f"_v{current + 1}{ext}", path.name)
    return path.with_name(next_name)


def parse_apply_scopes(raw: str) -> set[str]:
    scopes = {s.strip().lower() for s in raw.split(",") if s.strip()}
    if not scopes:
        return set(VALID_APPLY_SCOPES)
    unknown = scopes - VALID_APPLY_SCOPES
    if unknown:
        raise ValueError(
            "invalid apply scope(s): "
            + ", ".join(sorted(unknown))
            + f"; valid: {', '.join(sorted(VALID_APPLY_SCOPES))}"
        )
    return scopes


def classify_artifact_scope(target: str) -> str | None:
    name = Path(target).name
    if name.startswith("direction_"):
        return "direction"
    if name.startswith("governance_"):
        return "governance"
    if name.startswith("design_"):
        return "design"
    return None


def _glob_files(
    project_dir: Path,
    patterns: list[str],
    ignore_rules: list[tuple[str, bool]] | None = None,
) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    rules = ignore_rules or []
    for pat in patterns:
        for p in sorted(project_dir.glob(pat)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(project_dir))
            if matches_cortexignore(rel, rules):
                continue
            if rel in seen:
                continue
            seen.add(rel)
            out.append(p)
    return out


def load_spec_registry(project_dir: Path, cortex_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    path = cortex_dir / "spec_registry_v0.json"
    if not path.exists():
        return None, f"missing spec registry ({path.relative_to(project_dir)})"
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, f"invalid spec registry json: {exc}"
    if not isinstance(obj, dict):
        return None, "invalid spec registry shape: expected object"
    domains = obj.get("domains")
    if not isinstance(domains, list):
        return None, "invalid spec registry shape: domains must be array"
    return obj, None


def compute_spec_coverage(
    project_dir: Path,
    cortex_dir: Path,
    ignore_rules: list[tuple[str, bool]] | None = None,
) -> dict[str, Any]:
    registry, err = load_spec_registry(project_dir, cortex_dir=cortex_dir)
    if err is not None:
        return {
            "status": "warn",
            "registry_loaded": False,
            "warnings": [err],
            "missing_required": [],
            "stale": [],
            "orphan": [],
        }

    domains = registry.get("domains", [])
    missing_required: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    orphan: list[dict[str, Any]] = []
    warnings: list[str] = []

    matched_spec_paths: set[str] = set()
    blocking = False

    for domain in domains:
        if not isinstance(domain, dict):
            continue
        domain_id = str(domain.get("id", "unknown"))
        severity = str(domain.get("severity", "warn"))
        required = bool(domain.get("required", False))
        spec_patterns = domain.get("spec_patterns", [])
        source_patterns = domain.get("source_patterns", [])
        if not isinstance(spec_patterns, list):
            spec_patterns = []
        if not isinstance(source_patterns, list):
            source_patterns = []

        spec_files = _glob_files(project_dir, [str(p) for p in spec_patterns], ignore_rules=ignore_rules)
        source_files = _glob_files(project_dir, [str(p) for p in source_patterns], ignore_rules=ignore_rules)
        for sf in spec_files:
            matched_spec_paths.add(str(sf.relative_to(project_dir)))

        if required and not spec_files:
            item = {
                "domain_id": domain_id,
                "severity": severity,
                "spec_patterns": spec_patterns,
                "reason": "no spec files matched required domain",
            }
            missing_required.append(item)
            if severity == "block":
                blocking = True

        if spec_files and source_files:
            newest_spec = max(s.stat().st_mtime for s in spec_files)
            newer_sources = [s for s in source_files if s.stat().st_mtime > newest_spec]
            if newer_sources:
                item = {
                    "domain_id": domain_id,
                    "severity": severity,
                    "newer_source_count": len(newer_sources),
                    "newer_source_examples": [str(s.relative_to(project_dir)) for s in newer_sources[:5]],
                    "reason": "source files changed after latest mapped spec update",
                }
                stale.append(item)
                if severity == "block":
                    blocking = True

    orphan_patterns = registry.get("orphan_spec_patterns", [])
    if isinstance(orphan_patterns, list):
        all_candidate_specs = _glob_files(project_dir, [str(p) for p in orphan_patterns], ignore_rules=ignore_rules)
        for p in all_candidate_specs:
            rel = str(p.relative_to(project_dir))
            if rel not in matched_spec_paths:
                orphan.append({"path": rel, "reason": "unmapped spec file"})

    if blocking:
        status = "fail"
    elif missing_required or stale or orphan:
        status = "warn"
    else:
        status = "pass"

    return {
        "status": status,
        "registry_loaded": True,
        "warnings": warnings,
        "missing_required": missing_required,
        "stale": stale,
        "orphan": orphan[:50],
    }


def git_dirty_files(project_dir: Path) -> tuple[list[str], str | None]:
    cmd = ["git", "-C", str(project_dir), "status", "--porcelain"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip() or "git status failed"
        return [], msg

    files: list[str] = []
    for raw in proc.stdout.splitlines():
        if len(raw) < 4:
            continue
        path = raw[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        files.append(path.strip())
    return files, None


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch(path, pat) for pat in patterns)


def classify_dirty_files(files: list[str]) -> dict[str, list[str]]:
    out = {"high": [], "medium": [], "low": [], "ignored": []}
    for path in files:
        if _matches_any(path, DEFAULT_IGNORED_PATTERNS):
            out["ignored"].append(path)
        elif _matches_any(path, DEFAULT_HIGH_RISK_PATTERNS):
            out["high"].append(path)
        elif _matches_any(path, DEFAULT_MEDIUM_RISK_PATTERNS):
            out["medium"].append(path)
        else:
            out["low"].append(path)
    return out


def compute_decision_gap_check(project_dir: Path, cortex_dir: Path) -> tuple[str, dict[str, Any]]:
    files, err = git_dirty_files(project_dir)
    if err is not None:
        report = {
            "version": "v0",
            "run_at": utc_now(),
            "project_dir": str(project_dir),
            "cortex_root": str(cortex_dir),
            "status": "unknown",
            "reason": err,
            "dirty_files": [],
            "governance_impact_files": [],
            "covered_files": [],
            "uncovered_files": [],
            "decision_matches": [],
        }
        return "unknown", report

    normalized_files = sorted({normalize_repo_rel_path(f) for f in files if f.strip()})
    impact_files = [
        path for path in normalized_files if any(fnmatch(path, pat) for pat in DEFAULT_DECISION_GAP_PATTERNS)
    ]

    registry = load_decision_candidates(project_dir, cortex_dir=cortex_dir)
    entries = registry.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    decision_matches: dict[str, list[str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status", "candidate")).lower()
        if status not in {"candidate", "promoted"}:
            continue
        decision_id = str(entry.get("decision_id", "unknown"))
        linked = entry.get("linked_artifacts", [])
        if not isinstance(linked, list):
            continue
        linked_norm = {normalize_repo_rel_path(str(x)) for x in linked}
        matched = sorted([p for p in impact_files if p in linked_norm])
        if matched:
            decision_matches[decision_id] = matched

    covered = sorted({p for matched in decision_matches.values() for p in matched})
    uncovered = [p for p in impact_files if p not in covered]
    status = "pass" if not uncovered else "fail"
    report = {
        "version": "v0",
        "run_at": utc_now(),
        "project_dir": str(project_dir),
        "cortex_root": str(cortex_dir),
        "status": status,
        "dirty_files": normalized_files,
        "governance_impact_files": impact_files,
        "covered_files": covered,
        "uncovered_files": uncovered,
        "decision_matches": [
            {"decision_id": did, "matched_files": matched}
            for did, matched in sorted(decision_matches.items(), key=lambda item: item[0])
        ],
    }
    return status, report


def apply_coach_actions(
    project_dir: Path,
    actions: list[dict[str, str]],
    cycle_id: str,
    apply_scopes: set[str],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    applied: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for action in actions:
        target = action.get("target", "")
        step = action.get("step", "")
        instruction = action.get("instruction", "")
        if not isinstance(target, str) or not target.startswith(".cortex/artifacts/"):
            skipped.append({"target": str(target), "reason": "non-artifact target"})
            continue
        scope = classify_artifact_scope(target)
        if scope is None:
            skipped.append({"target": str(target), "reason": "unclassified artifact scope"})
            continue
        if scope not in apply_scopes:
            skipped.append({"target": str(target), "reason": f"scope excluded: {scope}"})
            continue

        src = project_dir / target
        dst = next_versioned_path(src)
        dst.parent.mkdir(parents=True, exist_ok=True)

        if src.exists():
            content = src.read_text(encoding="utf-8")
        else:
            content = ""

        if dst.suffix == ".md":
            draft = (
                f"# Draft from {src.name if src.name else target}\n\n"
                f"- cycle_id: `{cycle_id}`\n"
                f"- action: `{step}`\n"
                f"- instruction: {instruction}\n\n"
                "## Proposed Update\n"
                + (content if content else "- Fill this artifact according to action instruction.\n")
            )
            atomic_write_text(dst, draft)
        elif dst.suffix == ".dsl":
            lines = content.splitlines()
            out_lines: list[str] = [f"# Draft generated by coach cycle {cycle_id}"]
            replaced_version = False
            for line in lines:
                if line.startswith("version "):
                    m = re.search(r"_v(\d+)$", dst.stem)
                    next_ver = f"v{m.group(1)}" if m else "v1"
                    out_lines.append(f"version {next_ver}")
                    replaced_version = True
                elif line.startswith("id ") and re.search(r"_v\d+$", line):
                    out_lines.append(re.sub(r"_v\d+$", lambda mm: f"_v{(int(mm.group(0)[2:]) + 1)}", line))
                else:
                    out_lines.append(line)
            if not lines:
                out_lines.extend(
                    [
                        "id draft_design_v1",
                        "version v1",
                        "name Draft Design Spec",
                    ]
                )
            if lines and not replaced_version:
                m = re.search(r"_v(\d+)$", dst.stem)
                next_ver = f"v{m.group(1)}" if m else "v1"
                out_lines.insert(1, f"version {next_ver}")
            atomic_write_text(dst, "\n".join(out_lines).rstrip() + "\n")
        elif dst.suffix == ".json":
            if content.strip():
                try:
                    obj = json.loads(content)
                except Exception:
                    obj = {"source": src.name, "note": "source was invalid json"}
            else:
                obj = {}
            m = re.search(r"_v(\d+)$", dst.stem)
            next_ver = f"v{m.group(1)}" if m else "v1"
            obj["version"] = next_ver
            obj["generated_by"] = "cortex_project_coach_v0.py"
            obj["generated_cycle_id"] = cycle_id
            obj["action"] = step
            obj["instruction"] = instruction
            atomic_write_text(dst, json.dumps(obj, indent=2, sort_keys=True) + "\n")
        else:
            skipped.append({"target": str(target), "reason": f"unsupported extension: {dst.suffix}"})
            continue

        applied.append({"source": str(target), "draft": str(dst.relative_to(project_dir))})
    return applied, skipped


def draft_missing_specs_from_coverage(
    project_dir: Path,
    coverage: dict[str, Any],
    cycle_id: str,
) -> list[dict[str, str]]:
    drafted: list[dict[str, str]] = []
    for item in coverage.get("missing_required", []):
        if not isinstance(item, dict):
            continue
        domain_id = str(item.get("domain_id", "unknown"))
        patterns = item.get("spec_patterns", [])
        if not isinstance(patterns, list) or not patterns:
            continue
        target_rel = None
        for pat in patterns:
            if not isinstance(pat, str):
                continue
            if "*" in pat:
                if pat.startswith(".cortex/artifacts/"):
                    target_rel = pat.replace("*", f"{domain_id}_auto_v1")
                elif pat.startswith("specs/"):
                    target_rel = f"specs/{domain_id}_spec_v1.md"
                else:
                    target_rel = pat.replace("*", f"{domain_id}_auto_v1")
            else:
                target_rel = pat
            if target_rel:
                break
        if not target_rel:
            continue
        target = project_dir / target_rel
        if target.exists():
            continue
        if target.suffix != ".md":
            continue
        content = (
            f"# {domain_id} Spec\n\n"
            f"Version: v1\n"
            f"Status: Draft\n"
            f"GeneratedBy: cortex_project_coach_v0.py\n"
            f"GeneratedCycle: {cycle_id}\n\n"
            "## Purpose\n"
            "- Define the required behavior for this domain.\n\n"
            "## Scope\n"
            "- In scope:\n"
            "- Out of scope:\n\n"
            "## Requirements\n"
            "- Fill required constraints and invariants.\n"
        )
        atomic_write_text(target, content)
        drafted.append({"domain_id": domain_id, "draft": str(target.relative_to(project_dir))})
    return drafted


def audit_needed_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    files, err = git_dirty_files(project_dir)

    if err is not None:
        report = {
            "version": "v0",
            "run_at": utc_now(),
            "project_dir": str(project_dir),
            "status": "unknown",
            "audit_required": False,
            "audit_recommended": True,
            "reason": err,
            "dirty_files": [],
            "risk_buckets": {"high": [], "medium": [], "low": [], "ignored": []},
            "recommended_action": "Ensure target is a git repository and rerun.",
        }
    else:
        buckets = classify_dirty_files(files)
        non_ignored = len(files) - len(buckets["ignored"])
        if buckets["high"]:
            status = "required"
            required = True
            recommended = True
            action = "Run `cortex-coach audit --project-dir <path>` before merge/release."
        elif buckets["medium"]:
            status = "recommended"
            required = False
            recommended = True
            action = "Run audit at milestone boundary or before release."
        elif non_ignored > 0:
            status = "not_needed"
            required = False
            recommended = False
            action = "No immediate audit required; run audit before release."
        else:
            status = "not_needed"
            required = False
            recommended = False
            action = "Working tree is clean."

        report = {
            "version": "v0",
            "run_at": utc_now(),
            "project_dir": str(project_dir),
            "status": status,
            "audit_required": required,
            "audit_recommended": recommended,
            "dirty_file_count": len(files),
            "dirty_files": sorted(files),
            "risk_buckets": {
                "high": sorted(buckets["high"]),
                "medium": sorted(buckets["medium"]),
                "low": sorted(buckets["low"]),
                "ignored": sorted(buckets["ignored"]),
            },
            "recommended_action": action,
        }

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"status: {report['status']}")
        print(f"audit_required: {report['audit_required']}")
        print(f"audit_recommended: {report['audit_recommended']}")
        print(f"recommended_action: {report['recommended_action']}")
        if report.get("risk_buckets"):
            buckets = report["risk_buckets"]
            print(
                "risk_counts: "
                f"high={len(buckets.get('high', []))} "
                f"medium={len(buckets.get('medium', []))} "
                f"low={len(buckets.get('low', []))} "
                f"ignored={len(buckets.get('ignored', []))}"
            )

    if args.out_file:
        out_path = Path(args.out_file)
        if not out_path.is_absolute():
            out_path = project_dir / out_path
        atomic_write_text(out_path, json.dumps(report, indent=2, sort_keys=True) + "\n")

    if args.fail_on_required and report.get("audit_required"):
        return 1
    return 0


def context_load_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    repo_root = repo_root_from_script()
    loader = repo_root / "scripts" / "agent_context_loader_v0.py"
    if not loader.exists():
        print(f"missing loader script: {loader}", file=sys.stderr)
        return 1

    cmd = [
        sys.executable,
        str(loader),
        "--project-dir",
        str(project_dir),
        "--task",
        args.task,
        "--max-files",
        str(args.max_files),
        "--max-chars-per-file",
        str(args.max_chars_per_file),
        "--fallback-mode",
        args.fallback_mode,
    ]
    if args.out_file:
        cmd.extend(["--out-file", args.out_file])
    if getattr(args, "assets_dir", None):
        cmd.extend(["--assets-dir", str(Path(args.assets_dir).resolve())])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        return proc.returncode
    return 0


def _repo_file_inventory(project_dir: Path) -> tuple[int, list[str]]:
    files: list[str] = []
    ignore_prefixes = (".git/", ".venv/", "venv/", "env/", "cortex_project_coach.egg-info/")
    for p in project_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(project_dir))
        if rel.startswith(ignore_prefixes):
            continue
        files.append(rel)
    return len(files), sorted(files)


def context_policy_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    file_count, files = _repo_file_inventory(project_dir)

    has_design = any(
        f.startswith(("src/", "frontend/", "web/", "ui/")) or "/components/" in f
        for f in files
    )
    has_backend = any(
        f.startswith(("api/", "server/", "backend/")) or "/routes/" in f
        for f in files
    )
    has_specs = any(f.startswith("specs/") for f in files)

    if file_count > 2000:
        max_files, max_chars = 8, 1400
        size_tier = "large"
    elif file_count > 700:
        max_files, max_chars = 10, 1800
        size_tier = "medium"
    else:
        max_files, max_chars = 14, 2600
        size_tier = "small"

    focus: list[str] = []
    if has_design:
        focus.append("design")
    if has_backend:
        focus.append("governance")
    if has_specs:
        focus.append("spec")
    if not focus:
        focus = ["default"]

    policy = {
        "version": "v0",
        "run_at": utc_now(),
        "project_dir": str(project_dir),
        "size_tier": size_tier,
        "repo_file_count": file_count,
        "recommended_task_focus": focus,
        "recommended_budget": {
            "max_files": max_files,
            "max_chars_per_file": max_chars,
        },
        "notes": [
            "Control-plane files should always be loaded first.",
            "Use task-focused loading after control-plane to avoid context overflow.",
            "Recompute this policy when repository shape changes materially.",
        ],
    }

    if args.format == "json":
        print(json.dumps(policy, indent=2, sort_keys=True))
    else:
        print(f"size_tier: {policy['size_tier']}")
        print(f"repo_file_count: {policy['repo_file_count']}")
        print(f"recommended_task_focus: {','.join(policy['recommended_task_focus'])}")
        b = policy["recommended_budget"]
        print(f"recommended_budget: max_files={b['max_files']} max_chars_per_file={b['max_chars_per_file']}")

    if args.out_file:
        out = Path(args.out_file)
        if not out.is_absolute():
            out = project_dir / out
        atomic_write_text(out, json.dumps(policy, indent=2, sort_keys=True) + "\n")

    return 0


def policy_enable_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    policy_name = args.policy.lower().strip()
    if policy_name not in {"usage-decision", "decision-reflection"}:
        print(
            "unsupported policy. valid values: usage-decision, decision-reflection",
            file=sys.stderr,
        )
        return 1

    default_rel_path = (
        ".cortex/policies/cortex_coach_usage_decision_policy_v0.md"
        if policy_name == "usage-decision"
        else ".cortex/policies/cortex_coach_decision_reflection_policy_v0.md"
    )
    rel_path = args.out_file if args.out_file else default_rel_path
    out = Path(rel_path)
    if not out.is_absolute():
        out = project_dir / out
    if out.exists() and not args.force:
        print(f"policy already exists: {out}", file=sys.stderr)
        print("rerun with --force to overwrite", file=sys.stderr)
        return 1

    if policy_name == "usage-decision":
        text = usage_decision_policy_text(project_dir)
    else:
        text = decision_reflection_policy_text(project_dir)
    atomic_write_text(out, text)

    manifest_path = project_dir / ".cortex" / MANIFEST_FILE
    if manifest_path.exists():
        try:
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
            m.setdefault("policies", {})
            enabled = m["policies"].setdefault("enabled", [])
            rel = str(out.relative_to(project_dir))
            if rel not in enabled:
                enabled.append(rel)
            m["updated_at"] = utc_now()
            atomic_write_text(manifest_path, json.dumps(m, indent=2, sort_keys=True) + "\n")
        except Exception:
            pass

    print(str(out))
    return 0


def decision_capture_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    payload = load_decision_candidates(project_dir)
    entries = payload.setdefault("entries", [])
    if not isinstance(entries, list):
        entries = []
        payload["entries"] = entries

    title = args.title.strip()
    decision_id = f"dec_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{slugify(title)[:24]}"
    entry = {
        "decision_id": decision_id,
        "title": title,
        "status": "candidate",
        "captured_at": utc_now(),
        "decision": args.decision.strip(),
        "rationale": args.rationale.strip(),
        "impact_scope": parse_csv_list(args.impact_scope),
        "linked_artifacts": parse_csv_list(args.linked_artifacts),
        "decision_artifact": None,
    }
    entries.append(entry)
    path = save_decision_candidates(project_dir, payload)

    if args.format == "json":
        print(json.dumps(entry, indent=2, sort_keys=True))
    else:
        print(f"decision_id: {decision_id}")
        print(f"registry: {path}")
    return 0


def decision_list_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    payload = load_decision_candidates(project_dir)
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        entries = []
    status_filter = args.status.lower().strip() if args.status else None
    if status_filter:
        entries = [e for e in entries if str(e.get("status", "")).lower() == status_filter]
    if args.format == "json":
        print(json.dumps({"version": payload.get("version", "v0"), "entries": entries}, indent=2, sort_keys=True))
    else:
        print(f"entries: {len(entries)}")
        for e in entries:
            print(f"- {e.get('decision_id')} [{e.get('status')}] {e.get('title')}")
    return 0


def decision_gap_check_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    status, report = compute_decision_gap_check(project_dir, cortex_dir)

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"status: {report['status']}")
        print(f"governance_impact_files: {len(report.get('governance_impact_files', []))}")
        print(f"covered_files: {len(report.get('covered_files', []))}")
        print(f"uncovered_files: {len(report.get('uncovered_files', []))}")
        if report.get("uncovered_files"):
            print("uncovered:")
            for rel in report["uncovered_files"]:
                print(f"- {rel}")

    if args.out_file:
        out = Path(args.out_file)
        if not out.is_absolute():
            out = project_dir / out
        atomic_write_text(out, json.dumps(report, indent=2, sort_keys=True) + "\n")

    return 0 if status == "pass" else 1


def decision_promote_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    payload = load_decision_candidates(project_dir)
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        print("invalid decision candidates registry", file=sys.stderr)
        return 1

    candidate = None
    for e in entries:
        if isinstance(e, dict) and e.get("decision_id") == args.decision_id:
            candidate = e
            break
    if candidate is None:
        print(f"decision candidate not found: {args.decision_id}", file=sys.stderr)
        return 1

    title = str(candidate.get("title", "Decision"))
    decision_text = str(candidate.get("decision", ""))
    rationale = str(candidate.get("rationale", ""))
    impact_scope = candidate.get("impact_scope", [])
    linked_artifacts = candidate.get("linked_artifacts", [])
    if not isinstance(impact_scope, list):
        impact_scope = []
    if not isinstance(linked_artifacts, list):
        linked_artifacts = []

    slug = slugify(title)
    target = next_versioned_decision_path(project_dir, slug)
    rel_target = str(target.relative_to(project_dir))
    project_id = read_manifest_project_id(project_dir)
    project_scope = f"project/{project_id}" if project_id else "project/unknown"

    lines = [
        f"# Decision: {title}",
        "",
        f"DecisionID: {candidate.get('decision_id')}",
        "Status: Active",
        f"Scope: {project_scope}",
        f"CapturedAt: {candidate.get('captured_at', utc_now())}",
        f"PromotedAt: {utc_now()}",
        f"ImpactScope: {', '.join(str(x) for x in impact_scope) if impact_scope else '(none)'}",
        "LinkedArtifacts:",
    ]
    if linked_artifacts:
        for rel in linked_artifacts:
            lines.append(f"- `{rel}`")
    else:
        lines.append("- (none)")

    lines.extend(
        [
            "",
            "## Context",
            "- Captured via `cortex-coach decision-capture`.",
            "",
            "## Decision",
            decision_text if decision_text else "- Fill decision statement.",
            "",
            "## Rationale",
            rationale if rationale else "- Fill rationale.",
        ]
    )
    atomic_write_text(target, "\n".join(lines).rstrip() + "\n")

    candidate["status"] = "promoted"
    candidate["promoted_at"] = utc_now()
    candidate["decision_artifact"] = rel_target
    save_decision_candidates(project_dir, payload)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "decision_id": candidate.get("decision_id"),
                    "status": "promoted",
                    "decision_artifact": rel_target,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(rel_target)
    return 0


def contract_check_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    contract_file = Path(args.contract_file).resolve() if args.contract_file else resolve_asset_path(assets_dir, DEFAULT_CONTRACT_FILE)
    report = compute_contract_check(project_dir, contract_file, cortex_dir=cortex_dir)

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"status: {report['status']}")
        print(f"contract_file: {report['contract_file']}")
        failed = [c for c in report.get("checks", []) if c.get("status") != "pass"]
        print(f"failed_checks: {len(failed)}")

    if args.out_file:
        out = Path(args.out_file)
        if not out.is_absolute():
            out = project_dir / out
        atomic_write_text(out, json.dumps(report, indent=2, sort_keys=True) + "\n")

    return 0 if report.get("status") == "pass" else 1


def audit_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    manifest_path = cortex_dir / MANIFEST_FILE
    status, report = compute_audit_report(
        project_dir,
        assets_dir=assets_dir,
        cortex_dir=cortex_dir,
        audit_scope=args.audit_scope,
    )

    reports_dir = cortex_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / "lifecycle_audit_v0.json"
    atomic_write_text(out_path, json.dumps(report, indent=2, sort_keys=True) + "\n")

    # Update manifest lifecycle flag if available.
    if manifest_path.exists():
        try:
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
            m["updated_at"] = utc_now()
            if "phases" in m and isinstance(m["phases"], dict):
                m["phases"]["lifecycle_audited"] = status == "pass"
            atomic_write_text(manifest_path, json.dumps(m, indent=2, sort_keys=True) + "\n")
        except Exception:
            pass

    print(str(out_path))
    return 0 if status == "pass" else 1


def coach_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    manifest_path = cortex_dir / MANIFEST_FILE
    if not manifest_path.exists():
        print(f"missing manifest: {manifest_path}", file=sys.stderr)
        return 1

    try:
        manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"invalid manifest: {exc}", file=sys.stderr)
        return 1

    inferred = infer_phase_status(project_dir, manifest_obj)
    if args.sync_phases:
        manifest_obj.setdefault("phases", {})
        for phase in PHASE_ORDER:
            if phase in inferred:
                manifest_obj["phases"][phase] = inferred[phase]
        manifest_obj["updated_at"] = utc_now()
        atomic_write_text(manifest_path, json.dumps(manifest_obj, indent=2, sort_keys=True) + "\n")

    audit_status, audit_report = compute_audit_report(
        project_dir,
        assets_dir=assets_dir,
        cortex_dir=cortex_dir,
        audit_scope=args.audit_scope,
    )
    reports_dir = cortex_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    audit_out = reports_dir / "lifecycle_audit_v0.json"
    atomic_write_text(audit_out, json.dumps(audit_report, indent=2, sort_keys=True) + "\n")

    phases = dict(manifest_obj.get("phases", {}))
    phases["lifecycle_audited"] = audit_status == "pass"
    incomplete_phases = [p for p in PHASE_ORDER if not phases.get(p, False)]
    failed_checks = [c for c in audit_report.get("checks", []) if c.get("status") == "fail"]
    spec_coverage = audit_report.get("spec_coverage", {})

    cycle_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        apply_scopes = parse_apply_scopes(args.apply_scope)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    actions: list[dict[str, str]] = []
    if "direction_defined" in incomplete_phases:
        actions.append(
            {
                "step": "Complete direction artifact",
                "target": manifest_obj.get("artifacts", {}).get("direction", ".cortex/artifacts/direction_<id>_v0.md"),
                "instruction": "Fill North Star, Anti-Goals, and Success Signals with concrete measurable statements.",
            }
        )
    if "governance_defined" in incomplete_phases:
        actions.append(
            {
                "step": "Complete governance artifact",
                "target": manifest_obj.get("artifacts", {}).get("governance", ".cortex/artifacts/governance_<id>_v0.md"),
                "instruction": "Define invariants, mutation/versioning rules, and release gates.",
            }
        )
    if "design_spec_compiled" in incomplete_phases:
        actions.append(
            {
                "step": "Compile design DSL into ontology JSON",
                "target": manifest_obj.get("artifacts", {}).get("design_json", ".cortex/artifacts/design_<id>_v0.json"),
                "instruction": "Update DSL and compile using scripts/design_prompt_dsl_compile_v0.py, then revalidate.",
            }
        )

    for check in failed_checks:
        actions.append(
            {
                "step": f"Resolve audit failure: {check.get('check', 'unknown')}",
                "target": ".cortex/reports/lifecycle_audit_v0.json",
                "instruction": check.get("detail", "Inspect and fix related artifact."),
            }
        )

    spec_coverage_actions: list[dict[str, str]] = []
    for item in spec_coverage.get("missing_required", []):
        if not isinstance(item, dict):
            continue
        domain_id = str(item.get("domain_id", "unknown"))
        patterns = item.get("spec_patterns", [])
        target = patterns[0] if isinstance(patterns, list) and patterns else "specs/<domain>_spec_vN.md"
        action = {
            "step": f"Create missing required spec for domain: {domain_id}",
            "target": str(target),
            "instruction": "Create a versioned spec artifact matching domain patterns and rerun audit.",
        }
        actions.append(action)
        spec_coverage_actions.append(action)

    for item in spec_coverage.get("stale", []):
        if not isinstance(item, dict):
            continue
        domain_id = str(item.get("domain_id", "unknown"))
        action = {
            "step": f"Update stale spec coverage for domain: {domain_id}",
            "target": ".cortex/reports/lifecycle_audit_v0.json",
            "instruction": "Refresh mapped specs after source changes and rerun audit.",
        }
        actions.append(action)
        spec_coverage_actions.append(action)

    if not actions:
        actions.append(
            {
                "step": "Advance project lifecycle",
                "target": ".cortex/manifest_v0.json",
                "instruction": "Create next versioned artifacts (`v1`) for changed semantics and rerun coach/audit.",
            }
        )

    applied_drafts: list[dict[str, str]] = []
    skipped_drafts: list[dict[str, str]] = []
    drafted_specs: list[dict[str, str]] = []
    if args.apply:
        applied_drafts, skipped_drafts = apply_coach_actions(project_dir, actions, cycle_id, apply_scopes)
        drafted_specs = draft_missing_specs_from_coverage(project_dir, spec_coverage, cycle_id)

    cycle_report = {
        "version": "v0",
        "cycle_id": cycle_id,
        "run_at": utc_now(),
        "project_id": manifest_obj.get("project_id"),
        "project_name": manifest_obj.get("project_name"),
        "audit_status": audit_status,
        "incomplete_phases": incomplete_phases,
        "failed_checks": failed_checks,
        "actions": actions,
        "spec_coverage_actions": spec_coverage_actions,
        "apply_mode": args.apply,
        "apply_scope": sorted(apply_scopes),
        "applied_drafts": applied_drafts,
        "skipped_drafts": skipped_drafts,
        "drafted_specs": drafted_specs,
    }

    cycle_json = reports_dir / f"coach_cycle_{cycle_id}_v0.json"
    cycle_md = reports_dir / f"coach_cycle_{cycle_id}_v0.md"
    prompts_dir = cortex_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    cycle_prompt = prompts_dir / f"coach_cycle_prompt_{cycle_id}_v0.md"

    atomic_write_text(cycle_json, json.dumps(cycle_report, indent=2, sort_keys=True) + "\n")

    md_lines = [
        "# Coach Cycle Report v0",
        "",
        f"- cycle_id: `{cycle_id}`",
        f"- project_id: `{manifest_obj.get('project_id', '')}`",
        f"- project_name: `{manifest_obj.get('project_name', '')}`",
        f"- audit_status: `{audit_status}`",
        f"- incomplete_phases: `{len(incomplete_phases)}`",
        f"- failed_checks: `{len(failed_checks)}`",
        "",
        "## Actions",
    ]
    for idx, action in enumerate(actions, start=1):
        md_lines.append(f"{idx}. {action['step']} (`{action['target']}`)")
        md_lines.append(f"   {action['instruction']}")
    if args.apply:
        md_lines.extend(["", "## Applied Drafts"])
        if applied_drafts:
            for item in applied_drafts:
                md_lines.append(f"- `{item['source']}` -> `{item['draft']}`")
        else:
            md_lines.append("- none")
        if skipped_drafts:
            md_lines.extend(["", "## Skipped Drafts"])
            for item in skipped_drafts:
                md_lines.append(f"- `{item['target']}` ({item['reason']})")
        if drafted_specs:
            md_lines.extend(["", "## Drafted Missing Specs"])
            for item in drafted_specs:
                md_lines.append(f"- `{item['domain_id']}` -> `{item['draft']}`")
    atomic_write_text(cycle_md, "\n".join(md_lines) + "\n")

    prompt_lines = [
        f"# Coach Cycle Prompt ({cycle_id}) v0",
        "",
        "You are assisting the project owner in closing lifecycle gaps.",
        "Use these files as source of truth:",
        "- `.cortex/manifest_v0.json`",
        "- `.cortex/reports/lifecycle_audit_v0.json`",
        f"- `.cortex/reports/{cycle_json.name}`",
        "",
        "Tasks:",
        "1. Propose exact edits to the targeted artifacts for each action.",
        "2. Keep semantics explicit and versioned.",
        "3. After edits, propose rerun commands for audit and next coach cycle.",
    ]
    if args.apply:
        prompt_lines.extend(
            [
                "4. Review generated draft artifacts and propose exact refinements.",
            ]
        )
    atomic_write_text(cycle_prompt, "\n".join(prompt_lines) + "\n")

    if args.sync_phases:
        manifest_obj.setdefault("phases", {})
        manifest_obj["phases"]["lifecycle_audited"] = audit_status == "pass"
        manifest_obj["updated_at"] = utc_now()
        atomic_write_text(manifest_path, json.dumps(manifest_obj, indent=2, sort_keys=True) + "\n")

    print(str(cycle_json))
    print(str(cycle_md))
    print(str(cycle_prompt))
    return 0 if audit_status == "pass" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cortex Project Coach v0")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_lock_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--lock-timeout-seconds",
            type=float,
            default=DEFAULT_LOCK_TIMEOUT_SECONDS,
            help=f"Max time to wait for .cortex lock (default: {DEFAULT_LOCK_TIMEOUT_SECONDS}).",
        )
        p.add_argument(
            "--lock-stale-seconds",
            type=float,
            default=DEFAULT_LOCK_STALE_SECONDS,
            help=f"Lock age threshold for stale recovery (default: {DEFAULT_LOCK_STALE_SECONDS}).",
        )
        p.add_argument(
            "--force-unlock",
            action="store_true",
            help="Force lock takeover if a lock file exists.",
        )

    def add_assets_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--assets-dir",
            help="Optional Cortex assets root (defaults to CORTEX_ASSETS_DIR or embedded repo assets).",
        )

    def add_cortex_root_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--cortex-root",
            default=DEFAULT_CORTEX_ROOT,
            help=f"Cortex lifecycle root directory (default: {DEFAULT_CORTEX_ROOT}).",
        )

    def add_audit_scope_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--audit-scope",
            choices=["cortex-only", "all"],
            default="cortex-only",
            help="Artifact conformance scope: cortex-only (default) or all repository governance dirs.",
        )

    p_init = sub.add_parser("init", help="Bootstrap .cortex artifacts for a project.")
    p_init.add_argument("--project-dir", required=True)
    p_init.add_argument("--project-id", required=True)
    p_init.add_argument("--project-name", required=True)
    p_init.add_argument("--force", action="store_true")
    add_cortex_root_arg(p_init)
    add_assets_arg(p_init)
    add_lock_args(p_init)
    p_init.set_defaults(func=init_project)

    p_audit = sub.add_parser("audit", help="Audit .cortex lifecycle artifact health.")
    p_audit.add_argument("--project-dir", required=True)
    add_cortex_root_arg(p_audit)
    add_audit_scope_arg(p_audit)
    add_assets_arg(p_audit)
    add_lock_args(p_audit)
    p_audit.set_defaults(func=audit_project)

    p_audit_needed = sub.add_parser(
        "audit-needed",
        help="Evaluate whether an audit is required based on dirty git state risk tiers.",
    )
    p_audit_needed.add_argument("--project-dir", required=True)
    p_audit_needed.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    p_audit_needed.add_argument(
        "--out-file",
        help="Optional output report file path (absolute or project-relative).",
    )
    p_audit_needed.add_argument(
        "--fail-on-required",
        action="store_true",
        help="Exit non-zero when audit_required=true.",
    )
    p_audit_needed.set_defaults(func=audit_needed_project)

    p_context_load = sub.add_parser(
        "context-load",
        help="Build a bounded context bundle (control-plane first, then task slice).",
    )
    p_context_load.add_argument("--project-dir", required=True)
    p_context_load.add_argument("--task", default="default")
    p_context_load.add_argument("--max-files", type=int, default=12)
    p_context_load.add_argument("--max-chars-per-file", type=int, default=2500)
    p_context_load.add_argument(
        "--fallback-mode",
        choices=["none", "priority"],
        default="priority",
        help="Fallback behavior when restricted loading fails.",
    )
    p_context_load.add_argument("--out-file")
    add_assets_arg(p_context_load)
    p_context_load.set_defaults(func=context_load_project)

    p_context_policy = sub.add_parser(
        "context-policy",
        help="Analyze repository shape and emit recommended context loading policy.",
    )
    p_context_policy.add_argument("--project-dir", required=True)
    p_context_policy.add_argument("--format", choices=["text", "json"], default="text")
    p_context_policy.add_argument("--out-file")
    p_context_policy.set_defaults(func=context_policy_project)

    p_policy_enable = sub.add_parser(
        "policy-enable",
        help="Enable an opt-in coach policy in a target project.",
    )
    p_policy_enable.add_argument("--project-dir", required=True)
    p_policy_enable.add_argument(
        "--policy",
        default="usage-decision",
        help="Policy key to enable (default: usage-decision).",
    )
    p_policy_enable.add_argument(
        "--out-file",
        help="Optional output policy path (absolute or project-relative).",
    )
    p_policy_enable.add_argument("--force", action="store_true", help="Overwrite existing policy file.")
    add_lock_args(p_policy_enable)
    p_policy_enable.set_defaults(func=policy_enable_project)

    p_decision_capture = sub.add_parser(
        "decision-capture",
        help="Capture a decision candidate from conversation/workstream.",
    )
    p_decision_capture.add_argument("--project-dir", required=True)
    p_decision_capture.add_argument("--title", required=True)
    p_decision_capture.add_argument("--decision", default="")
    p_decision_capture.add_argument("--rationale", default="")
    p_decision_capture.add_argument(
        "--impact-scope",
        default="",
        help="Comma-separated impacted domains/artifacts (for example: governance,specs,docs).",
    )
    p_decision_capture.add_argument(
        "--linked-artifacts",
        default="",
        help="Comma-separated project-relative artifact paths already updated by this decision.",
    )
    p_decision_capture.add_argument("--format", choices=["text", "json"], default="text")
    add_lock_args(p_decision_capture)
    p_decision_capture.set_defaults(func=decision_capture_project)

    p_decision_list = sub.add_parser(
        "decision-list",
        help="List decision candidates/promoted decisions.",
    )
    p_decision_list.add_argument("--project-dir", required=True)
    p_decision_list.add_argument("--status", choices=["candidate", "promoted"])
    p_decision_list.add_argument("--format", choices=["text", "json"], default="text")
    p_decision_list.set_defaults(func=decision_list_project)

    p_decision_gap = sub.add_parser(
        "decision-gap-check",
        help="Fail when governance-impacting dirty files are not linked to decision entries.",
    )
    p_decision_gap.add_argument("--project-dir", required=True)
    add_cortex_root_arg(p_decision_gap)
    p_decision_gap.add_argument("--format", choices=["text", "json"], default="text")
    p_decision_gap.add_argument("--out-file")
    p_decision_gap.set_defaults(func=decision_gap_check_project)

    p_decision_promote = sub.add_parser(
        "decision-promote",
        help="Promote a captured decision candidate into canonical decision artifact.",
    )
    p_decision_promote.add_argument("--project-dir", required=True)
    p_decision_promote.add_argument("--decision-id", required=True)
    p_decision_promote.add_argument("--format", choices=["text", "json"], default="text")
    add_lock_args(p_decision_promote)
    p_decision_promote.set_defaults(func=decision_promote_project)

    p_contract_check = sub.add_parser(
        "contract-check",
        help="Validate project compatibility against coach asset contract.",
    )
    p_contract_check.add_argument("--project-dir", required=True)
    p_contract_check.add_argument(
        "--contract-file",
        help=f"Optional contract file path (default: <assets-dir>/{DEFAULT_CONTRACT_FILE}).",
    )
    add_cortex_root_arg(p_contract_check)
    add_assets_arg(p_contract_check)
    p_contract_check.add_argument("--format", choices=["text", "json"], default="text")
    p_contract_check.add_argument("--out-file")
    p_contract_check.set_defaults(func=contract_check_project)

    p_coach = sub.add_parser("coach", help="Run one AI-guided lifecycle coaching cycle.")
    p_coach.add_argument("--project-dir", required=True)
    p_coach.add_argument("--no-sync-phases", action="store_false", dest="sync_phases")
    p_coach.add_argument("--apply", action="store_true", help="Generate draft vN+1 artifacts for action targets.")
    p_coach.add_argument(
        "--apply-scope",
        default="direction,governance,design",
        help="Comma-separated scopes for --apply: direction,governance,design",
    )
    add_cortex_root_arg(p_coach)
    add_audit_scope_arg(p_coach)
    add_assets_arg(p_coach)
    add_lock_args(p_coach)
    p_coach.set_defaults(sync_phases=True)
    p_coach.set_defaults(func=coach_project)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.cmd in {"init", "audit", "coach", "policy-enable", "decision-capture", "decision-promote"}:
        project_dir = Path(args.project_dir).resolve()
        try:
            with project_lock(
                project_dir=project_dir,
                cortex_root=getattr(args, "cortex_root", None),
                lock_timeout_seconds=args.lock_timeout_seconds,
                lock_stale_seconds=args.lock_stale_seconds,
                force_unlock=args.force_unlock,
                command_name=args.cmd,
            ):
                return args.func(args)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
