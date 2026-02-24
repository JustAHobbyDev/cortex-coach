#!/usr/bin/env python3
"""
Deterministic context loader for Cortex projects.

Loads minimal control-plane artifacts first, then task-relevant files within
strict file/character budgets.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_MAX_FILES = 12
DEFAULT_MAX_CHARS_PER_FILE = 2500
DEFAULT_ADAPTER_MAX_ITEMS = 4
DEFAULT_ADAPTER_STALE_SECONDS = 86400

CONTEXT_LOAD_RANKING_CONTRACT_VERSION = "v0"
CONTEXT_LOAD_RETRIEVAL_PROFILES = ("small", "medium", "large")
CONTEXT_LOAD_WEIGHT_PRESETS = {
    "uniform": {
        "lexical_score": 0.55,
        "evidence_score": 0.20,
        "outcome_score": 0.15,
        "freshness_score": 0.10,
    },
    "evidence_outcome_bias": {
        "lexical_score": 0.40,
        "evidence_score": 0.30,
        "outcome_score": 0.20,
        "freshness_score": 0.10,
    },
}
CONTEXT_LOAD_TIE_BREAK_ORDER = [
    "combined_score_desc",
    "evidence_score_desc",
    "pattern_priority_asc",
    "path_asc",
]
CONTEXT_LOAD_CONFIDENCE_BOUNDS = {
    "min": 0.0,
    "max": 1.0,
}
CONTEXT_LOAD_ADAPTER_MODES = ("off", "beads_file")
CONTEXT_LOAD_ADAPTER_TIE_BREAK_ORDER = [
    "combined_score_desc",
    "state_priority_asc",
    "priority_asc",
    "source_updated_at_desc",
    "path_asc",
]
ADAPTER_STATE_PRIORITY = {
    "blocked": 0,
    "ready": 1,
    "priority": 2,
    "stale": 3,
    "unknown": 4,
}

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
    p.add_argument(
        "--retrieval-profile",
        choices=CONTEXT_LOAD_RETRIEVAL_PROFILES,
        default="medium",
        help="Retrieval evaluation profile label for ranking metadata (default: medium).",
    )
    p.add_argument(
        "--weighting-mode",
        choices=sorted(CONTEXT_LOAD_WEIGHT_PRESETS.keys()),
        default="uniform",
        help="Deterministic score weighting preset (default: uniform).",
    )
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
    p.add_argument(
        "--adapter-mode",
        choices=CONTEXT_LOAD_ADAPTER_MODES,
        default="off",
        help="Optional adapter enrichment mode (default: off).",
    )
    p.add_argument(
        "--adapter-file",
        help="Adapter payload file path used when --adapter-mode=beads_file.",
    )
    p.add_argument(
        "--adapter-max-items",
        type=int,
        default=DEFAULT_ADAPTER_MAX_ITEMS,
        help="Maximum adapter items considered for selection (default: 4).",
    )
    p.add_argument(
        "--adapter-stale-seconds",
        type=int,
        default=DEFAULT_ADAPTER_STALE_SECONDS,
        help="Staleness threshold in seconds for adapter freshness warnings (default: 86400).",
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


def _tokenize(value: str) -> list[str]:
    out: list[str] = []
    for tok in re.findall(r"[a-z0-9]+", value.lower()):
        if len(tok) < 3:
            continue
        out.append(tok)
    return out


def _query_tokens(task: str, task_key: str) -> list[str]:
    tokens = set(_tokenize(task))
    tokens.add(task_key.lower())
    return sorted(tokens)


def _count_hits(text: str, tokens: list[str]) -> int:
    if not tokens:
        return 0
    lowered = text.lower()
    return sum(lowered.count(tok) for tok in tokens)


def _score_from_hits(hit_count: int, norm: float) -> float:
    if hit_count <= 0:
        return 0.0
    return round(min(1.0, float(hit_count) / norm), 6)


def _confidence_from_combined(combined_score: float) -> float:
    if combined_score <= 0:
        return 0.0
    return round(min(1.0, combined_score / (combined_score + 0.35)), 6)


def _clamp_confidence(value: float) -> float:
    lower = float(CONTEXT_LOAD_CONFIDENCE_BOUNDS["min"])
    upper = float(CONTEXT_LOAD_CONFIDENCE_BOUNDS["max"])
    return round(max(lower, min(upper, float(value))), 6)


def _default_control_plane_score(selected_by: str) -> tuple[float, float, dict[str, float]]:
    if selected_by.startswith("control_plane:active_decision"):
        breakdown = {
            "lexical_score": 0.70,
            "evidence_score": 1.0,
            "outcome_score": 0.95,
            "freshness_score": 0.0,
        }
        return 0.90, 0.98, breakdown
    breakdown = {
        "lexical_score": 0.65,
        "evidence_score": 1.0,
        "outcome_score": 0.90,
        "freshness_score": 0.0,
    }
    return 0.87, 0.97, breakdown


def _entry_provenance(entry: dict[str, Any], task_key: str) -> dict[str, Any]:
    selected_by = str(entry.get("selected_by", ""))
    path = str(entry.get("path", ""))
    source_kind = "unknown"
    source_ref = selected_by or path or "unknown"
    source_refs = [path] if path else ["unknown"]
    if selected_by.startswith("control_plane:active_decision"):
        source_kind = "control_plane_active_decision"
        source_ref = ACTIVE_DECISION_GLOB
    elif selected_by.startswith("control_plane"):
        source_kind = "control_plane_required"
        source_ref = "control_plane"
    elif selected_by.startswith("task:"):
        source_kind = "task_pattern_match"
        parts = selected_by.split(":", 2)
        source_ref = parts[2] if len(parts) == 3 else f"task:{task_key}"
        if source_ref and source_ref not in source_refs:
            source_refs.append(source_ref)
    elif selected_by.startswith("adapter:"):
        source_kind = "adapter_signal"
        parts = selected_by.split(":", 2)
        source_ref = parts[1] if len(parts) >= 2 else "adapter"
        adapter_ref = str(entry.get("adapter_ref", ""))
        if adapter_ref and adapter_ref not in source_refs:
            source_refs.append(adapter_ref)

    return {
        "source_kind": source_kind,
        "source_ref": source_ref,
        "source_refs": source_refs,
    }


def _parse_rfc3339_utc(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _adapter_excerpt(item: dict[str, Any]) -> str:
    tags = item.get("tags", [])
    tags_text = ""
    if isinstance(tags, list):
        tags_text = ", ".join(str(tag) for tag in tags if str(tag).strip())
    lines = [
        f"adapter_id: {item.get('adapter_id', '')}",
        f"item_id: {item.get('item_id', '')}",
        f"state: {item.get('state', 'unknown')}",
        f"priority: {item.get('priority', '')}",
        f"title: {item.get('title', '')}",
        f"summary: {item.get('summary', '')}",
        f"tags: {tags_text}",
    ]
    if item.get("source_updated_at"):
        lines.append(f"source_updated_at: {item.get('source_updated_at')}")
    if item.get("adapter_fetched_at"):
        lines.append(f"adapter_fetched_at: {item.get('adapter_fetched_at')}")
    if item.get("staleness_seconds") is not None:
        lines.append(f"staleness_seconds: {item.get('staleness_seconds')}")
    return "\n".join(lines) + "\n"


def _score_adapter_item(
    item: dict[str, Any],
    task_tokens: list[str],
    weight_map: dict[str, float],
    stale_threshold_seconds: int,
) -> dict[str, Any]:
    state = str(item.get("state", "unknown")).strip().lower() or "unknown"
    title = str(item.get("title", ""))
    summary = str(item.get("summary", ""))
    tags = item.get("tags", [])
    tags_text = " ".join(str(tag) for tag in tags) if isinstance(tags, list) else ""
    searchable_text = " ".join(
        [
            str(item.get("item_id", "")),
            title,
            summary,
            state,
            tags_text,
        ]
    )
    lexical_score = _score_from_hits(_count_hits(searchable_text, task_tokens), norm=6.0)

    if state in {"blocked", "ready"}:
        evidence_score = 0.9
        outcome_score = 1.0
    elif state == "priority":
        evidence_score = 0.75
        outcome_score = 0.8
    elif state == "stale":
        evidence_score = 0.55
        outcome_score = 0.4
    else:
        evidence_score = 0.45
        outcome_score = 0.35

    staleness_value = item.get("staleness_seconds")
    freshness_score = 0.4
    if isinstance(staleness_value, (int, float)):
        if stale_threshold_seconds <= 0:
            freshness_score = 0.0
        else:
            ratio = min(1.0, max(0.0, float(staleness_value) / float(stale_threshold_seconds)))
            freshness_score = round(1.0 - ratio, 6)

    combined_score = round(
        (weight_map["lexical_score"] * lexical_score)
        + (weight_map["evidence_score"] * evidence_score)
        + (weight_map["outcome_score"] * outcome_score)
        + (weight_map["freshness_score"] * freshness_score),
        6,
    )
    score_breakdown = {
        "lexical_score": lexical_score,
        "evidence_score": round(float(evidence_score), 6),
        "outcome_score": round(float(outcome_score), 6),
        "freshness_score": round(float(freshness_score), 6),
    }
    state_priority = ADAPTER_STATE_PRIORITY.get(state, ADAPTER_STATE_PRIORITY["unknown"])
    priority_raw = item.get("priority")
    try:
        priority_value = int(priority_raw)
    except (TypeError, ValueError):
        priority_value = 999999
    updated_dt = _parse_rfc3339_utc(str(item.get("source_updated_at", "")))
    updated_sort = -int(updated_dt.timestamp()) if updated_dt is not None else 0

    entry = {
        "path": f"adapter/{item.get('adapter_id', 'adapter')}/{item.get('item_id', 'item')}.json",
        "selected_by": f"adapter:{item.get('adapter_id', 'adapter')}:{state}",
        "adapter_ref": f"adapter:{item.get('adapter_id', 'adapter')}:{item.get('item_id', 'item')}",
        "combined_score": combined_score,
        "confidence": _confidence_from_combined(combined_score),
        "score_breakdown": score_breakdown,
        "state_priority": state_priority,
        "priority": priority_value,
        "source_updated_at": str(item.get("source_updated_at", "")),
        "source_updated_at_sort": updated_sort,
        "adapter_item": item,
        "adapter_excerpt": _adapter_excerpt(item),
    }
    return entry


def select_adapter_files(
    project_dir: Path,
    adapter_mode: str,
    adapter_file: str | None,
    adapter_max_items: int,
    adapter_stale_seconds: int,
    task_tokens: list[str],
    weighting_mode: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    warnings: list[str] = []
    adapter_meta: dict[str, Any] = {
        "mode": adapter_mode,
        "status": "disabled",
        "adapter_id": None,
        "candidate_count": 0,
        "selected_count": 0,
        "max_items": max(1, int(adapter_max_items)),
        "stale_threshold_seconds": max(0, int(adapter_stale_seconds)),
        "tie_break_order": list(CONTEXT_LOAD_ADAPTER_TIE_BREAK_ORDER),
    }

    if adapter_mode == "off":
        return [], adapter_meta, warnings

    adapter_meta["status"] = "degraded"
    if adapter_mode != "beads_file":
        warnings.append(f"adapter_degraded:unsupported_mode:{adapter_mode}")
        return [], adapter_meta, warnings

    if not adapter_file:
        warnings.append("adapter_degraded:missing_adapter_file")
        return [], adapter_meta, warnings

    adapter_path = Path(adapter_file)
    if not adapter_path.is_absolute():
        adapter_path = project_dir / adapter_path
    if not adapter_path.exists():
        warnings.append(f"adapter_degraded:file_not_found:{adapter_path}")
        return [], adapter_meta, warnings

    try:
        payload = json.loads(adapter_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        warnings.append(f"adapter_degraded:invalid_json:{adapter_path}")
        return [], adapter_meta, warnings
    if not isinstance(payload, dict):
        warnings.append(f"adapter_degraded:invalid_payload_shape:{adapter_path}")
        return [], adapter_meta, warnings

    adapter_id = str(payload.get("adapter_id", "beads")).strip() or "beads"
    adapter_meta["adapter_id"] = adapter_id
    adapter_meta["adapter_file"] = str(adapter_path)
    adapter_meta["status"] = "loaded"

    adapter_fetched_at = str(payload.get("adapter_fetched_at", "")).strip()
    fetched_dt = _parse_rfc3339_utc(adapter_fetched_at)
    if adapter_fetched_at and fetched_dt is None:
        warnings.append(f"adapter_warning:invalid_adapter_fetched_at:{adapter_fetched_at}")
    if not adapter_fetched_at:
        warnings.append("adapter_warning:missing_adapter_fetched_at")

    items_raw = payload.get("items", [])
    if not isinstance(items_raw, list):
        warnings.append("adapter_degraded:items_not_list")
        adapter_meta["status"] = "degraded"
        return [], adapter_meta, warnings

    normalized_items: list[dict[str, Any]] = []
    stale_threshold = max(0, int(adapter_stale_seconds))
    for idx, raw_item in enumerate(items_raw, start=1):
        if not isinstance(raw_item, dict):
            continue
        item_id = str(raw_item.get("id", raw_item.get("item_id", f"item_{idx:03d}"))).strip() or f"item_{idx:03d}"
        state = str(raw_item.get("state", "unknown")).strip().lower() or "unknown"
        state = state if state in ADAPTER_STATE_PRIORITY else "unknown"
        source_updated_at = str(raw_item.get("source_updated_at", "")).strip()
        updated_dt = _parse_rfc3339_utc(source_updated_at)
        if source_updated_at and updated_dt is None:
            warnings.append(f"adapter_warning:invalid_source_updated_at:{item_id}:{source_updated_at}")
        staleness_seconds: int | None = None
        if fetched_dt and updated_dt:
            staleness_seconds = max(0, int((fetched_dt - updated_dt).total_seconds()))
            if stale_threshold > 0 and staleness_seconds > stale_threshold:
                warnings.append(f"adapter_warning:stale_item:{item_id}:{staleness_seconds}s")
        elif source_updated_at:
            warnings.append(f"adapter_warning:missing_or_invalid_fetched_at:{item_id}")

        normalized_items.append(
            {
                "adapter_id": adapter_id,
                "item_id": item_id,
                "state": state,
                "priority": raw_item.get("priority"),
                "title": str(raw_item.get("title", "")),
                "summary": str(raw_item.get("summary", "")),
                "tags": raw_item.get("tags", []),
                "source_updated_at": source_updated_at,
                "adapter_fetched_at": adapter_fetched_at,
                "staleness_seconds": staleness_seconds,
            }
        )

    adapter_meta["candidate_count"] = len(normalized_items)
    weight_map = CONTEXT_LOAD_WEIGHT_PRESETS[weighting_mode]
    scored = [
        _score_adapter_item(item, task_tokens, weight_map, stale_threshold)
        for item in normalized_items
    ]
    ranked = sorted(
        scored,
        key=lambda entry: (
            -float(entry.get("combined_score", 0.0)),
            int(entry.get("state_priority", ADAPTER_STATE_PRIORITY["unknown"])),
            int(entry.get("priority", 999999)),
            int(entry.get("source_updated_at_sort", 0)),
            str(entry.get("path", "")),
        ),
    )
    limited = ranked[: max(1, int(adapter_max_items))]
    for idx, entry in enumerate(limited, start=1):
        entry["rank"] = idx
    adapter_meta["selected_count"] = len(limited)
    return limited, adapter_meta, warnings


def _score_task_entry(
    project_dir: Path,
    entry: dict[str, Any],
    task_tokens: list[str],
    weight_map: dict[str, float],
) -> dict[str, Any]:
    rel_path = str(entry["path"])
    path_hits = _count_hits(rel_path, task_tokens)

    try:
        text = (project_dir / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    text = text[:6000]
    text_hits = _count_hits(text, task_tokens)

    lexical_score = _score_from_hits((path_hits * 3) + text_hits, norm=10.0)
    evidence_hits = _count_hits(rel_path, ["decision", "reflection", "report", "artifact", "policy", "spec", "contract"])
    evidence_score = _score_from_hits(evidence_hits, norm=3.0)
    outcome_hits = _count_hits(rel_path, ["closeout", "handoff", "readiness", "gate", "regression", "plan"])
    outcome_score = _score_from_hits(outcome_hits, norm=2.0)
    freshness_score = 0.0

    breakdown = {
        "lexical_score": lexical_score,
        "evidence_score": evidence_score,
        "outcome_score": outcome_score,
        "freshness_score": freshness_score,
    }
    combined_score = round(
        (weight_map["lexical_score"] * lexical_score)
        + (weight_map["evidence_score"] * evidence_score)
        + (weight_map["outcome_score"] * outcome_score)
        + (weight_map["freshness_score"] * freshness_score),
        6,
    )
    entry["score_breakdown"] = breakdown
    entry["combined_score"] = combined_score
    entry["confidence"] = _confidence_from_combined(combined_score)
    return entry


def select_task_files(
    project_dir: Path,
    task: str,
    task_key: str,
    weighting_mode: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    patterns = TASK_PATTERNS.get(task_key, TASK_PATTERNS["default"])
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pattern_index, pat in enumerate(patterns):
        for p in sorted(project_dir.glob(pat)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(project_dir))
            if rel in seen:
                continue
            seen.add(rel)
            out.append(
                {
                    "path": rel,
                    "selected_by": f"task:{task_key}:{pat}",
                    "pattern_priority": pattern_index,
                }
            )

    task_tokens = _query_tokens(task, task_key)
    weight_map = CONTEXT_LOAD_WEIGHT_PRESETS[weighting_mode]
    scored = [_score_task_entry(project_dir, entry, task_tokens, weight_map) for entry in out]
    ranked = sorted(
        scored,
        key=lambda item: (
            -float(item.get("combined_score", 0.0)),
            -float(item["score_breakdown"]["evidence_score"]),
            int(item.get("pattern_priority", 0)),
            item["path"],
        ),
    )
    for idx, entry in enumerate(ranked, start=1):
        entry["rank"] = idx

    ranking_meta = {
        "contract_version": CONTEXT_LOAD_RANKING_CONTRACT_VERSION,
        "retrieval_profile": None,  # populated by build_bundle
        "weighting_mode": weighting_mode,
        "weights": dict(weight_map),
        "confidence_bounds": dict(CONTEXT_LOAD_CONFIDENCE_BOUNDS),
        "tie_break_order": list(CONTEXT_LOAD_TIE_BREAK_ORDER),
        "query_tokens": task_tokens,
        "candidate_count": len(ranked),
    }
    return ranked, ranking_meta


def build_bundle(
    project_dir: Path,
    task: str,
    retrieval_profile: str,
    weighting_mode: str,
    adapter_mode: str,
    adapter_file: str | None,
    adapter_max_items: int,
    adapter_stale_seconds: int,
    max_files: int,
    max_chars_per_file: int,
    unrestricted: bool = False,
) -> dict[str, Any]:
    task_key = normalize_task(task)
    warnings: list[str] = []

    control_files, control_warnings = select_control_plane(project_dir)
    warnings.extend(control_warnings)

    task_files, ranking_meta = select_task_files(project_dir, task, task_key, weighting_mode)
    ranking_meta["retrieval_profile"] = retrieval_profile
    task_tokens = list(ranking_meta.get("query_tokens", []))
    adapter_files, adapter_meta, adapter_warnings = select_adapter_files(
        project_dir=project_dir,
        adapter_mode=adapter_mode,
        adapter_file=adapter_file,
        adapter_max_items=adapter_max_items,
        adapter_stale_seconds=adapter_stale_seconds,
        task_tokens=task_tokens,
        weighting_mode=weighting_mode,
    )
    warnings.extend(adapter_warnings)
    ranking_meta["adapter_candidate_count"] = adapter_meta.get("candidate_count", 0)
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

    # Optional adapter slice is appended after task selection and remains non-authoritative.
    for entry in adapter_files:
        if (not unrestricted) and len(selected_meta) >= max_files:
            break
        if any(e["path"] == entry["path"] for e in selected_meta):
            continue
        selected_meta.append(entry)

    excerpts: list[dict[str, Any]] = []
    truncated_count = 0
    for entry in selected_meta:
        adapter_excerpt = entry.get("adapter_excerpt")
        if isinstance(adapter_excerpt, str):
            if unrestricted or len(adapter_excerpt) <= max_chars_per_file:
                excerpt = adapter_excerpt
                truncated = False
            else:
                excerpt = adapter_excerpt[:max_chars_per_file]
                truncated = True
        else:
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
        selected_by = str(entry.get("selected_by", ""))
        rank = entry.get("rank")
        combined_score = entry.get("combined_score")
        confidence = entry.get("confidence")
        score_breakdown = entry.get("score_breakdown")
        if score_breakdown is None or combined_score is None or confidence is None:
            combined_score, confidence, score_breakdown = _default_control_plane_score(selected_by)
        confidence = _clamp_confidence(float(confidence))
        provenance = _entry_provenance(entry, task_key)
        excerpts.append(
            {
                "path": entry["path"],
                "selected_by": entry["selected_by"],
                "rank": rank,
                "combined_score": round(float(combined_score), 6),
                "confidence": confidence,
                "score_breakdown": score_breakdown,
                "provenance": provenance,
                "truncated": truncated,
                "excerpt": excerpt,
            }
        )
        adapter_item = entry.get("adapter_item")
        if isinstance(adapter_item, dict):
            excerpts[-1]["adapter"] = adapter_item

    report = {
        "version": "v0",
        "project_dir": str(project_dir),
        "assets_dir": None,
        "task": task,
        "task_key": task_key,
        "retrieval_profile": retrieval_profile,
        "weighting_mode": weighting_mode,
        "ranking": ranking_meta,
        "adapter": adapter_meta,
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
        retrieval_profile=args.retrieval_profile,
        weighting_mode=args.weighting_mode,
        adapter_mode=args.adapter_mode,
        adapter_file=args.adapter_file,
        adapter_max_items=max(1, int(args.adapter_max_items)),
        adapter_stale_seconds=max(0, int(args.adapter_stale_seconds)),
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
            retrieval_profile=args.retrieval_profile,
            weighting_mode=args.weighting_mode,
            adapter_mode=args.adapter_mode,
            adapter_file=args.adapter_file,
            adapter_max_items=max(1, int(args.adapter_max_items)),
            adapter_stale_seconds=max(0, int(args.adapter_stale_seconds)),
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
            retrieval_profile=args.retrieval_profile,
            weighting_mode=args.weighting_mode,
            adapter_mode=args.adapter_mode,
            adapter_file=args.adapter_file,
            adapter_max_items=max(1, int(args.adapter_max_items)),
            adapter_stale_seconds=max(0, int(args.adapter_stale_seconds)),
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
