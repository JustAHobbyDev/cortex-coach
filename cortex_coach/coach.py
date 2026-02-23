#!/usr/bin/env python3
"""
Cortex Project Coach v0

CLI to bootstrap and audit `.cortex/` lifecycle artifacts in a target project.
"""

from __future__ import annotations

import argparse
from fnmatch import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
MEMORY_COMMAND_VERSION = "v0"
MEMORY_RECORD_SCHEMA_REL_PATH = "contracts/tactical_memory_record_schema_v0.json"
MEMORY_SEARCH_SCHEMA_REL_PATH = "contracts/tactical_memory_search_result_schema_v0.json"
MEMORY_PRIME_SCHEMA_REL_PATH = "contracts/tactical_memory_prime_bundle_schema_v0.json"
TACTICAL_MEMORY_RECORDS_REL_PATH = "state/tactical_memory/records_v0.jsonl"
TACTICAL_MEMORY_SANITIZATION_INCIDENTS_REL_PATH = "state/tactical_memory/sanitization_incidents_v0.jsonl"
MEMORY_EXIT_SUCCESS = 0
MEMORY_EXIT_INVALID = 2
MEMORY_EXIT_POLICY = 3
MEMORY_EXIT_LOCK = 4
MEMORY_EXIT_INTERNAL = 5
MEMORY_RETENTION_TTL_DAYS = {
    "short": 7,
    "standard": 30,
    "extended": 90,
}
MEMORY_SOURCE_KIND_CHOICES = [
    "manual_capture",
    "context_hydration",
    "adapter_signal",
    "derived_summary",
    "imported",
]
MEMORY_CONTENT_CLASS_CHOICES = [
    "governance_context",
    "implementation_note",
    "decision_signal",
    "risk_note",
    "task_state",
    "reference_excerpt",
    "incident_note",
]
MEMORY_SEARCH_TIE_BREAK_ORDER = [
    "score_desc",
    "captured_at_desc",
    "record_id_asc",
]
MEMORY_PRIME_ORDERING_POLICY = "relevance_desc_then_recency_desc_then_record_id_asc"
MEMORY_POLICY_BLOCK_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "private_key_material",
        "credential",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
]
MEMORY_POLICY_REDACTION_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "secret_token_assignment",
        "secret",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret)\b\s*[:=]\s*[^\s,;]+"
        ),
        "[REDACTED_SECRET]",
    ),
    (
        "credential_assignment",
        "credential",
        re.compile(r"(?i)\b(password|passwd|pwd|session[_-]?cookie)\b\s*[:=]\s*[^\s,;]+"),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        "pii_email",
        "pii",
        re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        "pii_ssn",
        "pii",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "[REDACTED_SSN]",
    ),
]


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


def parse_rfc3339_utc(raw: str, field: str) -> datetime:
    text = raw.strip()
    if not text:
        raise ValueError(f"{field} is required")
    try:
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        dt = datetime.fromisoformat(text)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"{field} must be RFC3339 date-time") from exc
    if dt.tzinfo is None:
        raise ValueError(f"{field} must include timezone offset")
    return dt.astimezone(timezone.utc)


def parse_optional_rfc3339_utc(raw: str | None, field: str) -> str | None:
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    return parse_rfc3339_utc(value, field).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_hash_payload(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def parse_unique_sorted_csv(raw: str | None) -> list[str]:
    return sorted(set(parse_csv_list(raw)))


def tactical_memory_paths(cortex_dir: Path) -> tuple[Path, Path]:
    records_path = cortex_dir / TACTICAL_MEMORY_RECORDS_REL_PATH
    incidents_path = cortex_dir / TACTICAL_MEMORY_SANITIZATION_INCIDENTS_REL_PATH
    records_path.parent.mkdir(parents=True, exist_ok=True)
    incidents_path.parent.mkdir(parents=True, exist_ok=True)
    return records_path, incidents_path


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def tactical_record_exists(records_path: Path, record_id: str) -> bool:
    if not records_path.exists():
        return False
    for raw in records_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(obj, dict) and obj.get("record_id") == record_id:
            return True
    return False


def detect_git_head(project_dir: Path) -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(project_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{7,40}", out):
        return out
    return None


def load_tactical_records(records_path: Path) -> list[dict[str, Any]]:
    if not records_path.exists():
        return []
    out: list[dict[str, Any]] = []
    for idx, raw in enumerate(records_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"invalid tactical record json on line {idx}: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"invalid tactical record object on line {idx}: expected JSON object")
        out.append(obj)
    return out


def normalize_query_text(query_text: str) -> str:
    return " ".join(query_text.strip().lower().split())


def query_tokens(normalized_query: str) -> list[str]:
    return [tok for tok in re.split(r"[^a-z0-9_.:-]+", normalized_query) if tok]


def parse_record_captured_at_epoch(record: dict[str, Any]) -> float:
    captured_at = str(record.get("captured_at", "")).strip()
    try:
        return parse_rfc3339_utc(captured_at, "captured_at").timestamp()
    except ValueError:
        return 0.0


def compute_rule_based_score(record: dict[str, Any], tokens: list[str], normalized_query: str) -> float:
    content_obj = record.get("content", {})
    source_obj = record.get("source", {})
    text = str(content_obj.get("text", "")).lower()
    source_ref = str(source_obj.get("source_ref", "")).lower()
    tags_raw = content_obj.get("tags", [])
    tags = [str(t).lower() for t in tags_raw] if isinstance(tags_raw, list) else []

    if not tokens:
        return 0.0

    score = 0.0
    for tok in tokens:
        if tok in text:
            score += float(text.count(tok))
        if tok in source_ref:
            score += 1.0
        if tok in tags:
            score += 1.5

    if normalized_query and normalized_query in text:
        score += 1.0
    return score


def rank_query_matches(
    records: list[dict[str, Any]],
    normalized_query: str,
    tokens: list[str],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for record in records:
        score = compute_rule_based_score(record, tokens, normalized_query)
        if score <= 0:
            continue
        matches.append(
            {
                "record": record,
                "score": float(round(score, 6)),
                "captured_epoch": parse_record_captured_at_epoch(record),
            }
        )
    matches.sort(
        key=lambda item: (
            -float(item["score"]),
            -float(item["captured_epoch"]),
            str(item["record"].get("record_id", "")),
        )
    )
    return matches


def record_matches_search_filters(
    record: dict[str, Any],
    content_classes_any: list[str],
    tags_any: list[str],
    tags_all: list[str],
    captured_at_from: str | None,
    captured_at_to: str | None,
) -> bool:
    content_obj = record.get("content", {})
    content_class = str(content_obj.get("content_class", ""))
    tags_raw = content_obj.get("tags", [])
    tags = [str(t) for t in tags_raw] if isinstance(tags_raw, list) else []

    if content_classes_any and content_class not in content_classes_any:
        return False
    if tags_any and not any(t in tags for t in tags_any):
        return False
    if tags_all and not all(t in tags for t in tags_all):
        return False

    if captured_at_from or captured_at_to:
        captured_at = str(record.get("captured_at", "")).strip()
        try:
            captured_dt = parse_rfc3339_utc(captured_at, "captured_at")
        except ValueError:
            return False
        if captured_at_from and captured_dt < parse_rfc3339_utc(captured_at_from, "captured_at_from"):
            return False
        if captured_at_to and captured_dt > parse_rfc3339_utc(captured_at_to, "captured_at_to"):
            return False

    return True


def confidence_from_score(score: float) -> float:
    if score <= 0:
        return 0.0
    return round(min(1.0, score / (score + 3.0)), 6)


def snippet_from_text(text: str, max_chars: int = 180) -> str:
    normalized = " ".join(text.strip().split())
    if not normalized:
        return "(empty)"
    if len(normalized) <= max_chars:
        return normalized
    return normalized[: max_chars - 3].rstrip() + "..."


def sanitize_tactical_text(text: str) -> tuple[str, str, list[dict[str, str]], list[dict[str, str]]]:
    blocked_hits: list[dict[str, str]] = []
    for pattern_id, reason_class, pattern in MEMORY_POLICY_BLOCK_PATTERNS:
        if pattern.search(text):
            blocked_hits.append(
                {
                    "pattern_id": pattern_id,
                    "reason_class": reason_class,
                    "field_path": "content.text",
                }
            )
    if blocked_hits:
        actions: list[dict[str, str]] = []
        for hit in blocked_hits:
            actions.append(
                {
                    "action": "remove",
                    "reason_class": hit["reason_class"],
                    "field_path": hit["field_path"],
                    "note": f"blocked_pattern:{hit['pattern_id']}",
                }
            )
        return text, "blocked", actions, blocked_hits

    working = text
    redaction_actions: list[dict[str, str]] = []
    for pattern_id, reason_class, pattern, replacement in MEMORY_POLICY_REDACTION_PATTERNS:
        updated, count = pattern.subn(replacement, working)
        if count <= 0:
            continue
        working = updated
        redaction_actions.append(
            {
                "action": "mask",
                "reason_class": reason_class,
                "field_path": "content.text",
                "note": f"pattern:{pattern_id};matches:{count}",
            }
        )

    if redaction_actions:
        return working, "redacted", redaction_actions, []
    return text, "clean", [], []


def emit_command_payload(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"command: {payload.get('command')}")
    print(f"status: {payload.get('status')}")
    result = payload.get("result")
    if isinstance(result, dict):
        for key in sorted(result):
            value = result[key]
            if isinstance(value, (dict, list)):
                print(f"{key}: {json.dumps(value, sort_keys=True)}")
            else:
                print(f"{key}: {value}")
    err = payload.get("error")
    if isinstance(err, dict):
        print(f"error_code: {err.get('code')}")
        print(f"error_message: {err.get('message')}")


def build_command_response(
    command: str,
    status: str,
    project_dir: Path,
    result: dict[str, Any],
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "version": MEMORY_COMMAND_VERSION,
        "command": command,
        "status": status,
        "project_dir": str(project_dir),
        "run_at": utc_now(),
        "result": result,
    }
    if error is not None:
        payload["error"] = error
    return payload


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
            lock_acquired_at = utc_now()
            payload = {
                "token": token,
                "pid": os.getpid(),
                "created_epoch": time.time(),
                "created_at": lock_acquired_at,
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
        yield {
            "lock_id": token,
            "lock_acquired_at": lock_acquired_at,
            "lock_file": str(lock_path),
        }
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


def package_assets_root() -> Path:
    return Path(__file__).resolve().parent / "data" / "assets"


def resolve_assets_dir(raw_assets_dir: str | None) -> Path:
    if raw_assets_dir:
        return Path(raw_assets_dir).resolve()
    env_assets = os.environ.get("CORTEX_ASSETS_DIR")
    if env_assets:
        return Path(env_assets).resolve()
    return package_assets_root().resolve()


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

    # Compile DSL to JSON via bundled compiler.
    compiler_path = Path(__file__).resolve().parent / "design_prompt_dsl_compile.py"
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
        str(compiler_path),
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
    cmd = ["git", "-C", str(project_dir), "status", "--porcelain", "--untracked-files=all"]
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


def _git_head_file_text(project_dir: Path, rel_path: str) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(project_dir), "show", f"HEAD:{rel_path}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def _collect_changed_json_paths(before: Any, after: Any, prefix: str = "") -> list[str]:
    if type(before) is not type(after):  # noqa: E721
        return [prefix or "<root>"]
    if isinstance(before, dict):
        out: list[str] = []
        keys = set(before.keys()) | set(after.keys())
        for k in sorted(keys):
            next_prefix = f"{prefix}.{k}" if prefix else str(k)
            if k not in before or k not in after:
                out.append(next_prefix)
                continue
            out.extend(_collect_changed_json_paths(before[k], after[k], next_prefix))
        return out
    if isinstance(before, list):
        if before == after:
            return []
        return [prefix or "<root>"]
    if before != after:
        return [prefix or "<root>"]
    return []


def _is_audit_managed_manifest_delta(project_dir: Path, rel_path: str) -> bool:
    head_text = _git_head_file_text(project_dir, rel_path)
    current_path = project_dir / rel_path
    if head_text is None or not current_path.exists():
        return False
    try:
        before = json.loads(head_text)
        after = json.loads(current_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    changed = set(_collect_changed_json_paths(before, after))
    if not changed:
        return False
    allowed = {"updated_at", "phases.lifecycle_audited"}
    return changed.issubset(allowed)


def _is_generated_audit_delta(project_dir: Path, cortex_dir: Path, rel_path: str) -> bool:
    try:
        cortex_rel = str(cortex_dir.relative_to(project_dir))
    except ValueError:
        return False
    manifest_rel = normalize_repo_rel_path(f"{cortex_rel}/{MANIFEST_FILE}")
    if rel_path == manifest_rel and _is_audit_managed_manifest_delta(project_dir, rel_path):
        return True
    return False


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


def compute_decision_gap_check(
    project_dir: Path,
    cortex_dir: Path,
    strict_generated: bool = False,
) -> tuple[str, dict[str, Any]]:
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
    impact_files_raw = [
        path for path in normalized_files if any(fnmatch(path, pat) for pat in DEFAULT_DECISION_GAP_PATTERNS)
    ]
    generated_ignored_files: list[str] = []
    impact_files = list(impact_files_raw)
    if not strict_generated:
        generated_ignored_files = [
            p for p in impact_files if _is_generated_audit_delta(project_dir, cortex_dir, p)
        ]
        impact_files = [p for p in impact_files if p not in generated_ignored_files]

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
        "strict_generated": strict_generated,
        "generated_ignored_files": generated_ignored_files,
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
    loader = Path(__file__).resolve().parent / "agent_context_loader.py"
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


def memory_record_project(args: argparse.Namespace) -> int:
    command = "memory-record"
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    records_path, incidents_path = tactical_memory_paths(cortex_dir)
    try:
        records_rel = normalize_repo_rel_path(str(records_path.relative_to(project_dir)))
    except ValueError:
        records_rel = str(records_path)
    try:
        incidents_rel = normalize_repo_rel_path(str(incidents_path.relative_to(project_dir)))
    except ValueError:
        incidents_rel = str(incidents_path)

    source_refs = parse_unique_sorted_csv(args.source_refs)
    tags = parse_unique_sorted_csv(args.tags)
    if not source_refs:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result={"record_id": None},
            error={
                "code": "invalid_arguments",
                "message": "--source-refs must include at least one source reference",
                "details": {"field": "source_refs"},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INVALID

    try:
        captured_dt = (
            parse_rfc3339_utc(args.captured_at, "captured_at")
            if args.captured_at
            else datetime.now(timezone.utc)
        )
        captured_at = captured_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        if args.ttl_expires_at:
            ttl_dt = parse_rfc3339_utc(args.ttl_expires_at, "ttl_expires_at")
        else:
            ttl_dt = captured_dt + timedelta(days=MEMORY_RETENTION_TTL_DAYS[args.retention_class])
        if ttl_dt <= captured_dt:
            raise ValueError("ttl_expires_at must be after captured_at")
        ttl_expires_at = ttl_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        adapter_fetched_at = parse_optional_rfc3339_utc(args.adapter_fetched_at, "adapter_fetched_at")
        source_updated_at = parse_optional_rfc3339_utc(args.source_updated_at, "source_updated_at")
    except ValueError as exc:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result={"record_id": None},
            error={
                "code": "invalid_arguments",
                "message": str(exc),
                "details": {"field": "timestamp"},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INVALID

    sanitized_text, sanitization_status, redaction_actions, blocked_hits = sanitize_tactical_text(args.text)

    provenance: dict[str, Any] = {
        "origin_command": command,
        "source_refs": source_refs,
    }
    git_head = args.git_head.strip() if args.git_head else detect_git_head(project_dir)
    if git_head:
        provenance["git_head"] = git_head
    if adapter_fetched_at:
        provenance["adapter_fetched_at"] = adapter_fetched_at
    if source_updated_at:
        provenance["source_updated_at"] = source_updated_at

    base_record: dict[str, Any] = {
        "version": MEMORY_COMMAND_VERSION,
        "captured_at": captured_at,
        "source": {
            "source_kind": args.source_kind,
            "source_ref": args.source_ref,
            "captured_by": args.captured_by,
        },
        "provenance": provenance,
        "content": {
            "text": sanitized_text,
            "content_class": args.content_class,
            "tags": tags,
        },
        "policy": {
            "ttl_expires_at": ttl_expires_at,
            "retention_class": args.retention_class,
        },
        "sanitization": {
            "status": sanitization_status,
            "redaction_actions": redaction_actions,
        },
    }
    record_id = f"tmr_{stable_hash_payload(base_record)[:16]}"

    schema_path = resolve_asset_path(assets_dir, MEMORY_RECORD_SCHEMA_REL_PATH)
    if not schema_path.exists():
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result={"record_id": record_id},
            error={
                "code": "internal_error",
                "message": f"missing schema asset: {schema_path}",
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INTERNAL

    if sanitization_status == "blocked":
        incident_payload = {
            "version": MEMORY_COMMAND_VERSION,
            "incident_id": f"sani_{stable_hash_payload({'record_id': record_id, 'hits': blocked_hits})[:16]}",
            "record_id": record_id,
            "command": command,
            "captured_at": captured_at,
            "source_ref": args.source_ref,
            "blocked_hits": blocked_hits,
            "run_at": utc_now(),
        }
        try:
            append_jsonl(incidents_path, incident_payload)
        except Exception as exc:  # noqa: BLE001
            payload = build_command_response(
                command=command,
                status="fail",
                project_dir=project_dir,
                result={"record_id": record_id},
                error={
                    "code": "internal_error",
                    "message": "failed to persist blocked sanitization incident",
                    "details": {"exception": str(exc)},
                },
            )
            emit_command_payload(payload, args.format)
            return MEMORY_EXIT_INTERNAL

        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result={
                "record_id": record_id,
                "persisted": False,
                "storage_path": records_rel,
                "sanitization_status": "blocked",
                "redaction_actions": redaction_actions,
                "incident_id": incident_payload["incident_id"],
                "incident_path": incidents_rel,
            },
            error={
                "code": "policy_violation",
                "message": "payload blocked by tactical data policy sanitization controls",
                "details": {"blocked_hits": blocked_hits},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_POLICY

    try:
        with project_lock(
            project_dir=project_dir,
            cortex_root=getattr(args, "cortex_root", None),
            lock_timeout_seconds=args.lock_timeout_seconds,
            lock_stale_seconds=args.lock_stale_seconds,
            force_unlock=args.force_unlock,
            command_name=command,
        ) as lock_info:
            write_lock = {
                "lock_id": str(lock_info.get("lock_id", "")),
                "lock_acquired_at": str(lock_info.get("lock_acquired_at", utc_now())),
                "lock_timeout_seconds": float(args.lock_timeout_seconds),
                "lock_stale_seconds": float(args.lock_stale_seconds),
                "force_unlock": bool(args.force_unlock),
            }
            record = {
                **base_record,
                "record_id": record_id,
                "write_lock": write_lock,
            }

            schema_obj = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=record, schema=schema_obj)

            persisted = False
            if not tactical_record_exists(records_path, record_id):
                append_jsonl(records_path, record)
                persisted = True

            payload = build_command_response(
                command=command,
                status="pass",
                project_dir=project_dir,
                result={
                    "record_id": record_id,
                    "persisted": persisted,
                    "storage_path": records_rel,
                    "sanitization_status": sanitization_status,
                    "redaction_actions": redaction_actions,
                    "retention_class": args.retention_class,
                    "ttl_expires_at": ttl_expires_at,
                },
            )
            emit_command_payload(payload, args.format)
            return MEMORY_EXIT_SUCCESS
    except RuntimeError as exc:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result={"record_id": record_id, "persisted": False},
            error={
                "code": "lock_conflict",
                "message": str(exc),
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_LOCK
    except jsonschema.ValidationError as exc:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result={"record_id": record_id, "persisted": False},
            error={
                "code": "invalid_payload",
                "message": "record failed schema validation",
                "details": {"validation_error": exc.message},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INVALID
    except Exception as exc:  # noqa: BLE001
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result={"record_id": record_id, "persisted": False},
            error={
                "code": "internal_error",
                "message": "unexpected runtime failure during memory-record",
                "details": {"exception": str(exc)},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INTERNAL


def memory_search_project(args: argparse.Namespace) -> int:
    command = "memory-search"
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    records_path, _ = tactical_memory_paths(cortex_dir)

    query_text = args.query.strip()
    normalized_query = normalize_query_text(query_text)
    tokens = query_tokens(normalized_query)
    content_classes_any = parse_unique_sorted_csv(args.content_classes_any)
    tags_any = parse_unique_sorted_csv(args.tags_any)
    tags_all = parse_unique_sorted_csv(args.tags_all)

    result_template: dict[str, Any] = {
        "query": {
            "query_text": query_text if query_text else "(empty)",
            "normalized_query": normalized_query if normalized_query else "(empty)",
            "requested_limit": int(args.limit),
        },
        "filters": {
            "content_classes_any": content_classes_any,
            "tags_any": tags_any,
            "tags_all": tags_all,
        },
        "ranking": {
            "method": "rule_based_v0",
            "tie_break_order": MEMORY_SEARCH_TIE_BREAK_ORDER,
        },
        "result_count": 0,
        "results": [],
        "no_match": {
            "matched": False,
            "reason": "no_match",
            "suggestion": "Try broader query terms or fewer filters.",
        },
    }

    try:
        if not query_text:
            raise ValueError("--query must be non-empty")
        if not tokens:
            raise ValueError("--query must contain at least one searchable token")
        invalid_classes = [c for c in content_classes_any if c not in MEMORY_CONTENT_CLASS_CHOICES]
        if invalid_classes:
            raise ValueError(f"invalid content class filters: {','.join(invalid_classes)}")
        if args.limit < 1:
            raise ValueError("--limit must be >= 1")

        captured_at_from = parse_optional_rfc3339_utc(args.captured_at_from, "captured_at_from")
        captured_at_to = parse_optional_rfc3339_utc(args.captured_at_to, "captured_at_to")
        if captured_at_from:
            result_template["filters"]["captured_at_from"] = captured_at_from
        if captured_at_to:
            result_template["filters"]["captured_at_to"] = captured_at_to
        if captured_at_from and captured_at_to:
            from_dt = parse_rfc3339_utc(captured_at_from, "captured_at_from")
            to_dt = parse_rfc3339_utc(captured_at_to, "captured_at_to")
            if from_dt > to_dt:
                raise ValueError("--captured-at-from must be <= --captured-at-to")

        records = load_tactical_records(records_path)

        query_matches = rank_query_matches(
            records=records,
            normalized_query=normalized_query,
            tokens=tokens,
        )

        filtered_matches: list[dict[str, Any]] = []
        for entry in query_matches:
            record = entry["record"]
            if record_matches_search_filters(
                record=record,
                content_classes_any=content_classes_any,
                tags_any=tags_any,
                tags_all=tags_all,
                captured_at_from=captured_at_from,
                captured_at_to=captured_at_to,
            ):
                filtered_matches.append(entry)

        limited = filtered_matches[: int(args.limit)]
        results: list[dict[str, Any]] = []
        for idx, item in enumerate(limited, start=1):
            record = item["record"]
            source_obj = record.get("source", {})
            provenance_obj = record.get("provenance", {})
            source_refs_raw = provenance_obj.get("source_refs", [])
            source_refs = [str(x) for x in source_refs_raw] if isinstance(source_refs_raw, list) else []
            source_ref = str(source_obj.get("source_ref", ""))
            if not source_refs and source_ref:
                source_refs = [source_ref]

            content_obj = record.get("content", {})
            tags_raw = content_obj.get("tags", [])
            tags = sorted({str(x) for x in tags_raw}) if isinstance(tags_raw, list) else []
            score = float(item["score"])
            captured_at = str(record.get("captured_at", ""))
            record_id = str(record.get("record_id", ""))

            results.append(
                {
                    "rank": idx,
                    "record_id": record_id,
                    "score": score,
                    "confidence": confidence_from_score(score),
                    "snippet": snippet_from_text(str(content_obj.get("text", ""))),
                    "content_class": str(content_obj.get("content_class", "")),
                    "tags": tags,
                    "captured_at": captured_at,
                    "provenance": {
                        "source_kind": str(source_obj.get("source_kind", "")),
                        "source_ref": source_ref,
                        "source_refs": source_refs,
                    },
                    "sort_key": {
                        "score": score,
                        "captured_at": captured_at,
                        "record_id": record_id,
                    },
                }
            )

        if results:
            no_match = {"matched": True, "reason": "matches_found"}
        elif query_matches:
            no_match = {
                "matched": False,
                "reason": "filtered_out",
                "suggestion": "Relax filters or captured-at bounds.",
            }
        else:
            no_match = {
                "matched": False,
                "reason": "no_match",
                "suggestion": "Try broader query terms or different tags.",
            }

        result_template["result_count"] = len(results)
        result_template["results"] = results
        result_template["no_match"] = no_match

        payload = build_command_response(
            command=command,
            status="pass",
            project_dir=project_dir,
            result=result_template,
        )

        schema_path = resolve_asset_path(assets_dir, MEMORY_SEARCH_SCHEMA_REL_PATH)
        if not schema_path.exists():
            raise FileNotFoundError(f"missing schema asset: {schema_path}")
        schema_obj = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=payload, schema=schema_obj)

        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_SUCCESS
    except ValueError as exc:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result=result_template,
            error={
                "code": "invalid_arguments",
                "message": str(exc),
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INVALID
    except jsonschema.ValidationError as exc:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result=result_template,
            error={
                "code": "invalid_payload",
                "message": "search payload failed schema validation",
                "details": {"validation_error": exc.message},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INVALID
    except Exception as exc:  # noqa: BLE001
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result=result_template,
            error={
                "code": "internal_error",
                "message": "unexpected runtime failure during memory-search",
                "details": {"exception": str(exc)},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INTERNAL


def memory_prime_project(args: argparse.Namespace) -> int:
    command = "memory-prime"
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    records_path, _ = tactical_memory_paths(cortex_dir)

    task = args.task.strip()
    query_ref = args.query_ref.strip()
    normalized_query = normalize_query_text(query_ref)
    tokens = query_tokens(normalized_query)

    result_template: dict[str, Any] = {
        "input": {
            "task": task if task else "(empty)",
            "query_ref": query_ref if query_ref else "(empty)",
            "requested_limit": int(args.requested_limit),
        },
        "budget": {
            "max_records": int(args.max_records),
            "max_chars": int(args.max_chars),
            "per_record_max_chars": int(args.per_record_max_chars),
        },
        "ordering_policy": MEMORY_PRIME_ORDERING_POLICY,
        "selected_count": 0,
        "selected_char_count": 0,
        "bundle": [],
        "truncation": {
            "applied": False,
            "reason": "none",
            "dropped_record_ids": [],
            "truncated_record_count": 0,
            "truncated_char_count": 0,
        },
    }

    try:
        if not task:
            raise ValueError("--task must be non-empty")
        if not query_ref:
            raise ValueError("--query-ref must be non-empty")
        if not tokens:
            raise ValueError("--query-ref must contain at least one searchable token")
        if args.requested_limit < 1:
            raise ValueError("--requested-limit must be >= 1")
        if args.max_records < 1:
            raise ValueError("--max-records must be >= 1")
        if args.max_chars < 1:
            raise ValueError("--max-chars must be >= 1")
        if args.per_record_max_chars < 1:
            raise ValueError("--per-record-max-chars must be >= 1")

        records = load_tactical_records(records_path)
        ranked = rank_query_matches(
            records=records,
            normalized_query=normalized_query,
            tokens=tokens,
        )
        candidates = ranked[: int(args.requested_limit)]

        bundle: list[dict[str, Any]] = []
        selected_char_count = 0
        dropped_record_ids: list[str] = []
        truncated_record_ids: set[str] = set()
        truncated_char_count = 0
        hit_record_limit = False
        hit_char_budget = False
        hit_per_record_limit = False

        for item in candidates:
            record = item["record"]
            record_id = str(record.get("record_id", ""))
            if len(bundle) >= args.max_records:
                dropped_record_ids.append(record_id)
                hit_record_limit = True
                continue

            content_obj = record.get("content", {})
            full_text = str(content_obj.get("text", ""))
            summary = " ".join(full_text.strip().split())
            if not summary:
                summary = "(empty)"
            original_len = len(summary)
            if len(summary) > args.per_record_max_chars:
                summary = summary[: args.per_record_max_chars]
                truncated_record_ids.add(record_id)
                truncated_char_count += original_len - len(summary)
                hit_per_record_limit = True

            char_count = len(summary)
            if (selected_char_count + char_count) > args.max_chars:
                dropped_record_ids.append(record_id)
                hit_char_budget = True
                truncated_record_ids.add(record_id)
                truncated_char_count += char_count
                continue

            source_obj = record.get("source", {})
            provenance_obj = record.get("provenance", {})
            source_refs_raw = provenance_obj.get("source_refs", [])
            source_refs = [str(x) for x in source_refs_raw] if isinstance(source_refs_raw, list) else []
            source_ref = str(source_obj.get("source_ref", ""))
            if not source_refs and source_ref:
                source_refs = [source_ref]

            bundle.append(
                {
                    "position": len(bundle) + 1,
                    "record_id": record_id,
                    "summary": summary,
                    "char_count": char_count,
                    "content_class": str(content_obj.get("content_class", "")),
                    "source_provenance": {
                        "source_kind": str(source_obj.get("source_kind", "")),
                        "source_ref": source_ref,
                        "source_refs": source_refs,
                    },
                }
            )
            selected_char_count += char_count

        if hit_char_budget:
            trunc_reason = "char_budget"
        elif hit_record_limit:
            trunc_reason = "record_limit"
        elif hit_per_record_limit:
            trunc_reason = "per_record_char_limit"
        else:
            trunc_reason = "none"

        truncation = {
            "applied": bool(dropped_record_ids or truncated_record_ids),
            "reason": trunc_reason,
            "dropped_record_ids": dropped_record_ids,
            "truncated_record_count": len(truncated_record_ids),
            "truncated_char_count": truncated_char_count,
        }

        result_template["selected_count"] = len(bundle)
        result_template["selected_char_count"] = selected_char_count
        result_template["bundle"] = bundle
        result_template["truncation"] = truncation

        payload = build_command_response(
            command=command,
            status="pass",
            project_dir=project_dir,
            result=result_template,
        )

        schema_path = resolve_asset_path(assets_dir, MEMORY_PRIME_SCHEMA_REL_PATH)
        if not schema_path.exists():
            raise FileNotFoundError(f"missing schema asset: {schema_path}")
        schema_obj = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=payload, schema=schema_obj)

        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_SUCCESS
    except ValueError as exc:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result=result_template,
            error={
                "code": "invalid_arguments",
                "message": str(exc),
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INVALID
    except jsonschema.ValidationError as exc:
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result=result_template,
            error={
                "code": "invalid_payload",
                "message": "prime payload failed schema validation",
                "details": {"validation_error": exc.message},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INVALID
    except Exception as exc:  # noqa: BLE001
        payload = build_command_response(
            command=command,
            status="fail",
            project_dir=project_dir,
            result=result_template,
            error={
                "code": "internal_error",
                "message": "unexpected runtime failure during memory-prime",
                "details": {"exception": str(exc)},
            },
        )
        emit_command_payload(payload, args.format)
        return MEMORY_EXIT_INTERNAL


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
        "reflection_id": args.reflection_id.strip() if args.reflection_id else None,
        "reflection_report": normalize_repo_rel_path(args.reflection_report) if args.reflection_report else None,
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



def reflection_scaffold_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))

    title = args.title.strip()
    mistake = args.mistake.strip()
    pattern = args.pattern.strip()
    rule = args.rule.strip()
    decision_text = args.decision.strip()
    rationale = args.rationale.strip()

    impact_scope = parse_csv_list(args.impact_scope)
    if not impact_scope:
        impact_scope = ["governance", "workflow"]

    explicit_links = [normalize_repo_rel_path(x) for x in parse_csv_list(args.linked_artifacts)]
    auto_links: list[str] = []

    if not args.no_auto_link_governance_dirty:
        files, err = git_dirty_files(project_dir)
        if err is None:
            normalized = sorted({normalize_repo_rel_path(f) for f in files if f.strip()})
            impact = [
                path for path in normalized if any(fnmatch(path, pat) for pat in DEFAULT_DECISION_GAP_PATTERNS)
            ]
            if not args.strict_generated:
                generated = [
                    path for path in impact if _is_generated_audit_delta(project_dir, cortex_dir, path)
                ]
                impact = [path for path in impact if path not in generated]
            auto_links = sorted(impact)

    combined_links = sorted(set(explicit_links + auto_links))

    if not decision_text:
        parts: list[str] = []
        if mistake:
            parts.append(f"Mistake observed: {mistake}")
        if pattern:
            parts.append(f"Recurring pattern: {pattern}")
        if rule:
            parts.append(f"Adopt reusable rule: {rule}")
        if not parts:
            parts.append("Capture this governance-relevant learning as a reusable operating rule.")
        decision_text = " ".join(parts)

    if not rationale:
        rationale = "Promote durable, auditable learning so repeated mistakes are prevented across sessions."

    suggested_artifact = next_versioned_decision_path(project_dir, slugify(title), cortex_dir=cortex_dir)
    try:
        suggested_artifact_rel = str(suggested_artifact.relative_to(project_dir))
    except ValueError:
        suggested_artifact_rel = str(suggested_artifact)

    impact_scope_csv = ",".join(impact_scope)
    linked_csv = ",".join(combined_links)
    reflection_id = f"ref_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{slugify(title)[:24]}"

    if args.out_file:
        report_out = Path(args.out_file)
        if not report_out.is_absolute():
            report_out = project_dir / report_out
    else:
        reports_dir = cortex_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_out = reports_dir / f"reflection_scaffold_{ts}_{slugify(title)[:24]}_v0.json"
    try:
        report_out_rel = normalize_repo_rel_path(str(report_out.relative_to(project_dir)))
    except ValueError:
        report_out_rel = str(report_out)

    capture_cmd = (
        f'cortex-coach decision-capture --project-dir {project_dir} --title "{title}" '
        f'--decision "{decision_text}" --rationale "{rationale}" --impact-scope {impact_scope_csv} '
        f'--reflection-id {reflection_id} --reflection-report {report_out_rel}'
    )
    if linked_csv:
        capture_cmd += f" --linked-artifacts {linked_csv}"

    report = {
        "version": "v0",
        "reflection_id": reflection_id,
        "run_at": utc_now(),
        "project_dir": str(project_dir),
        "cortex_root": str(cortex_dir),
        "report_file": report_out_rel,
        "title": title,
        "mistake": mistake,
        "pattern": pattern,
        "rule": rule,
        "suggested_decision": decision_text,
        "suggested_rationale": rationale,
        "impact_scope": impact_scope,
        "explicit_linked_artifacts": explicit_links,
        "auto_linked_governance_files": auto_links,
        "suggested_linked_artifacts": combined_links,
        "suggested_decision_artifact": suggested_artifact_rel,
        "validation_checklist": [
            "Run decision-capture with reflected decision/rationale and linked artifacts.",
            "Promote candidate with decision-promote after review.",
            "Run decision-gap-check and confirm no uncovered governance-impact files.",
            "Run audit (cortex-only or all based on workflow) before closeout.",
        ],
        "recommended_commands": [
            capture_cmd,
            "cortex-coach decision-list --project-dir <path> --status candidate",
            "cortex-coach decision-promote --project-dir <path> --decision-id <decision_id>",
            "cortex-coach decision-gap-check --project-dir <path>",
            "cortex-coach audit --project-dir <path>",
        ],
    }

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"title: {report['title']}")
        print(f"reflection_id: {report['reflection_id']}")
        print(f"impact_scope: {','.join(report['impact_scope'])}")
        print(f"suggested_decision_artifact: {report['suggested_decision_artifact']}")
        print(f"report_file: {report['report_file']}")
        print(f"suggested_linked_artifacts: {len(report['suggested_linked_artifacts'])}")
        for rel in report["suggested_linked_artifacts"]:
            print(f"- {rel}")
        print("recommended_commands:")
        for cmd in report["recommended_commands"]:
            print(f"- {cmd}")

    atomic_write_text(report_out, json.dumps(report, indent=2, sort_keys=True) + "\n")

    return 0


def compute_reflection_completeness_check(
    project_dir: Path,
    cortex_dir: Path,
    required_decision_status: str = "candidate",
) -> tuple[str, dict[str, Any]]:
    reports_dir = cortex_dir / "reports"
    scaffold_files = sorted(reports_dir.glob("reflection_scaffold_*_v0.json"))
    registry = load_decision_candidates(project_dir, cortex_dir=cortex_dir)
    entries = registry.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    required = required_decision_status.strip().lower()
    allowed_status = {"promoted"} if required == "promoted" else {"candidate", "promoted"}

    findings: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []

    for path in scaffold_files:
        rel_path = normalize_repo_rel_path(str(path.relative_to(project_dir)))
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            findings.append(
                {
                    "severity": "fail",
                    "check": "invalid_reflection_report",
                    "path": rel_path,
                    "detail": f"failed to parse reflection scaffold report: {exc}",
                }
            )
            continue
        if not isinstance(obj, dict):
            findings.append(
                {
                    "severity": "fail",
                    "check": "invalid_reflection_report",
                    "path": rel_path,
                    "detail": "reflection scaffold report is not a JSON object",
                }
            )
            continue

        reflection_id = str(obj.get("reflection_id", "")).strip()
        title = str(obj.get("title", "")).strip()
        suggested_links_raw = obj.get("suggested_linked_artifacts", [])
        if not isinstance(suggested_links_raw, list):
            suggested_links_raw = []
        suggested_links = sorted({normalize_repo_rel_path(str(x)) for x in suggested_links_raw if str(x).strip()})

        candidates: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            status = str(entry.get("status", "")).strip().lower()
            if status not in allowed_status:
                continue
            entry_reflection_id = str(entry.get("reflection_id", "")).strip()
            entry_reflection_report = normalize_repo_rel_path(str(entry.get("reflection_report", "")).strip())
            entry_title = str(entry.get("title", "")).strip()
            if reflection_id and entry_reflection_id and reflection_id == entry_reflection_id:
                candidates.append(entry)
                continue
            if entry_reflection_report and entry_reflection_report == rel_path:
                candidates.append(entry)
                continue
            if title and entry_title == title:
                candidates.append(entry)

        if not candidates:
            findings.append(
                {
                    "severity": "fail",
                    "check": "reflection_without_decision",
                    "path": rel_path,
                    "detail": (
                        "reflection scaffold has no mapped decision entry "
                        f"(required_status={required}; title={title or '(none)'})"
                    ),
                }
            )
            continue

        candidates.sort(key=lambda e: 0 if str(e.get("status", "")).lower() == "promoted" else 1)
        selected = candidates[0]
        linked_raw = selected.get("linked_artifacts", [])
        if not isinstance(linked_raw, list):
            linked_raw = []
        linked = sorted({normalize_repo_rel_path(str(x)) for x in linked_raw if str(x).strip()})
        missing = sorted([x for x in suggested_links if x not in set(linked)])

        if not linked:
            findings.append(
                {
                    "severity": "fail",
                    "check": "reflection_decision_without_links",
                    "path": rel_path,
                    "decision_id": selected.get("decision_id"),
                    "detail": "mapped decision is missing linked_artifacts",
                }
            )
            continue
        if missing:
            findings.append(
                {
                    "severity": "fail",
                    "check": "reflection_missing_linked_artifacts",
                    "path": rel_path,
                    "decision_id": selected.get("decision_id"),
                    "missing_links": missing,
                    "detail": f"mapped decision is missing {len(missing)} scaffold-linked artifact(s)",
                }
            )
            continue

        mappings.append(
            {
                "path": rel_path,
                "reflection_id": reflection_id,
                "decision_id": selected.get("decision_id"),
                "decision_status": selected.get("status"),
            }
        )

    status = "pass" if not findings else "fail"
    report = {
        "version": "v0",
        "run_at": utc_now(),
        "project_dir": str(project_dir),
        "cortex_root": str(cortex_dir),
        "status": status,
        "required_decision_status": required,
        "scaffold_reports_scanned": len(scaffold_files),
        "decision_entries_scanned": len(entries),
        "mappings": mappings,
        "findings": findings,
    }
    return status, report


def reflection_completeness_check_project(args: argparse.Namespace) -> int:
    project_dir = Path(args.project_dir).resolve()
    cortex_dir = resolve_cortex_dir(project_dir, getattr(args, "cortex_root", None))
    status, report = compute_reflection_completeness_check(
        project_dir=project_dir,
        cortex_dir=cortex_dir,
        required_decision_status=args.required_decision_status,
    )

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"status: {report['status']}")
        print(f"scaffold_reports_scanned: {report['scaffold_reports_scanned']}")
        print(f"mappings: {len(report.get('mappings', []))}")
        print(f"findings: {len(report.get('findings', []))}")
        if report.get("findings"):
            print("findings_detail:")
            for finding in report["findings"]:
                print(f"- {finding.get('check')}: {finding.get('path')}")

    if args.out_file:
        out = Path(args.out_file)
        if not out.is_absolute():
            out = project_dir / out
        atomic_write_text(out, json.dumps(report, indent=2, sort_keys=True) + "\n")

    return 0 if status == "pass" else 1

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
    status, report = compute_decision_gap_check(
        project_dir,
        cortex_dir,
        strict_generated=bool(args.strict_generated),
    )

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
                "instruction": "Update DSL and compile using cortex_coach/design_prompt_dsl_compile.py, then revalidate.",
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
    p_decision_capture.add_argument(
        "--reflection-id",
        default="",
        help="Optional reflection scaffold identifier to link decision back to a reflection event.",
    )
    p_decision_capture.add_argument(
        "--reflection-report",
        default="",
        help="Optional reflection scaffold report path to link decision back to a reflection event.",
    )
    p_decision_capture.add_argument("--format", choices=["text", "json"], default="text")
    add_lock_args(p_decision_capture)
    p_decision_capture.set_defaults(func=decision_capture_project)

    p_reflection_scaffold = sub.add_parser(
        "reflection-scaffold",
        help="Scaffold reflection outputs into decision-capture/promotion inputs.",
    )
    p_reflection_scaffold.add_argument("--project-dir", required=True)
    add_cortex_root_arg(p_reflection_scaffold)
    p_reflection_scaffold.add_argument("--title", required=True, help="Decision title for the reflection outcome.")
    p_reflection_scaffold.add_argument("--mistake", default="", help="Concrete mistake instance to reflect on.")
    p_reflection_scaffold.add_argument("--pattern", default="", help="Abstracted recurring pattern.")
    p_reflection_scaffold.add_argument("--rule", default="", help="Generalized reusable rule.")
    p_reflection_scaffold.add_argument("--decision", default="", help="Optional explicit decision statement override.")
    p_reflection_scaffold.add_argument("--rationale", default="", help="Optional explicit rationale override.")
    p_reflection_scaffold.add_argument(
        "--impact-scope",
        default="governance,workflow",
        help="Comma-separated impacted domains/artifacts (default: governance,workflow).",
    )
    p_reflection_scaffold.add_argument(
        "--linked-artifacts",
        default="",
        help="Comma-separated project-relative artifacts to include in scaffold output.",
    )
    p_reflection_scaffold.add_argument(
        "--no-auto-link-governance-dirty",
        action="store_true",
        help="Disable auto-including governance-impacting dirty files in linked artifacts.",
    )
    p_reflection_scaffold.add_argument(
        "--strict-generated",
        action="store_true",
        help="Include generated audit bookkeeping deltas when auto-linking dirty files.",
    )
    p_reflection_scaffold.add_argument("--format", choices=["text", "json"], default="text")
    p_reflection_scaffold.add_argument("--out-file")
    add_lock_args(p_reflection_scaffold)
    p_reflection_scaffold.set_defaults(func=reflection_scaffold_project)

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
    p_decision_gap.add_argument(
        "--strict-generated",
        action="store_true",
        help="Include generated audit bookkeeping deltas in governance-impact matching.",
    )
    p_decision_gap.add_argument("--out-file")
    p_decision_gap.set_defaults(func=decision_gap_check_project)

    p_reflection_complete = sub.add_parser(
        "reflection-completeness-check",
        help="Fail when persisted reflection scaffolds are not mapped to decision entries with linked artifacts.",
    )
    p_reflection_complete.add_argument("--project-dir", required=True)
    add_cortex_root_arg(p_reflection_complete)
    p_reflection_complete.add_argument(
        "--required-decision-status",
        choices=["candidate", "promoted"],
        default="candidate",
        help="Minimum decision status required for reflection mapping (default: candidate).",
    )
    p_reflection_complete.add_argument("--format", choices=["text", "json"], default="text")
    p_reflection_complete.add_argument("--out-file")
    p_reflection_complete.set_defaults(func=reflection_completeness_check_project)

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

    p_memory_record = sub.add_parser(
        "memory-record",
        help="Capture and persist a tactical memory record with policy sanitization.",
    )
    p_memory_record.add_argument("--project-dir", required=True)
    add_cortex_root_arg(p_memory_record)
    add_assets_arg(p_memory_record)
    p_memory_record.add_argument("--format", choices=["text", "json"], default="text")
    p_memory_record.add_argument("--captured-at", help="Optional RFC3339 timestamp override for capture time.")
    p_memory_record.add_argument(
        "--source-kind",
        required=True,
        choices=MEMORY_SOURCE_KIND_CHOICES,
    )
    p_memory_record.add_argument("--source-ref", required=True)
    p_memory_record.add_argument("--captured-by", default="cortex-coach")
    p_memory_record.add_argument(
        "--source-refs",
        required=True,
        help="Comma-separated provenance source references (min 1).",
    )
    p_memory_record.add_argument("--git-head", default="", help="Optional explicit git head SHA.")
    p_memory_record.add_argument("--adapter-fetched-at", default="", help="Optional RFC3339 adapter fetch time.")
    p_memory_record.add_argument("--source-updated-at", default="", help="Optional RFC3339 source update time.")
    p_memory_record.add_argument("--text", required=True, help="Record body text.")
    p_memory_record.add_argument("--content-class", required=True, choices=MEMORY_CONTENT_CLASS_CHOICES)
    p_memory_record.add_argument("--tags", default="", help="Optional comma-separated tag list.")
    p_memory_record.add_argument(
        "--retention-class",
        choices=sorted(MEMORY_RETENTION_TTL_DAYS.keys()),
        default="standard",
    )
    p_memory_record.add_argument("--ttl-expires-at", default="", help="Optional RFC3339 TTL expiry override.")
    add_lock_args(p_memory_record)
    p_memory_record.set_defaults(func=memory_record_project)

    p_memory_search = sub.add_parser(
        "memory-search",
        help="Search tactical memory records with deterministic ranking output.",
    )
    p_memory_search.add_argument("--project-dir", required=True)
    add_cortex_root_arg(p_memory_search)
    add_assets_arg(p_memory_search)
    p_memory_search.add_argument("--format", choices=["text", "json"], default="text")
    p_memory_search.add_argument("--query", required=True, help="Search query text.")
    p_memory_search.add_argument("--limit", type=int, default=10, help="Maximum results to return (default: 10).")
    p_memory_search.add_argument(
        "--content-classes-any",
        default="",
        help="Optional comma-separated content_class filters (any-match).",
    )
    p_memory_search.add_argument("--tags-any", default="", help="Optional comma-separated tags any-match filter.")
    p_memory_search.add_argument("--tags-all", default="", help="Optional comma-separated tags all-match filter.")
    p_memory_search.add_argument("--captured-at-from", default="", help="Optional RFC3339 lower bound.")
    p_memory_search.add_argument("--captured-at-to", default="", help="Optional RFC3339 upper bound.")
    p_memory_search.set_defaults(func=memory_search_project)

    p_memory_prime = sub.add_parser(
        "memory-prime",
        help="Build a bounded tactical memory priming bundle.",
    )
    p_memory_prime.add_argument("--project-dir", required=True)
    add_cortex_root_arg(p_memory_prime)
    add_assets_arg(p_memory_prime)
    p_memory_prime.add_argument("--format", choices=["text", "json"], default="text")
    p_memory_prime.add_argument("--task", required=True, help="Task context identifier for priming.")
    p_memory_prime.add_argument("--query-ref", required=True, help="Search reference/query for bundle selection.")
    p_memory_prime.add_argument(
        "--requested-limit",
        type=int,
        default=10,
        help="Maximum ranked records to consider before budgeting (default: 10).",
    )
    p_memory_prime.add_argument("--max-records", type=int, default=5, help="Bundle record count budget (default: 5).")
    p_memory_prime.add_argument("--max-chars", type=int, default=4000, help="Bundle char budget (default: 4000).")
    p_memory_prime.add_argument(
        "--per-record-max-chars",
        type=int,
        default=500,
        help="Per-record summary char budget (default: 500).",
    )
    p_memory_prime.set_defaults(func=memory_prime_project)

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
    if args.cmd in {"init", "audit", "coach", "policy-enable", "decision-capture", "decision-promote", "reflection-scaffold"}:
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
