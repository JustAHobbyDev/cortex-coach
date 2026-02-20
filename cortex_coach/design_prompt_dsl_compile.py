#!/usr/bin/env python3
"""
Compile a compact design prompt DSL into a design ontology JSON artifact.

DSL directives (one per line):
  - id <value>
  - version <value>
  - name <value>
  - token <path> | <vocabulary token text>
  - set <path> | <value>
  - add <path> | <value>
  - score <metric> | <1-10>

Notes:
  - Lines starting with # are comments.
  - Values can be JSON literals (strings, numbers, arrays, booleans) or raw text.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REQUIRED_PATHS = [
    "id",
    "version",
    "layout.grid",
    "layout.spacing",
    "layout.structure",
    "typography.hero",
    "typography.body",
    "surface.base",
    "surface.accent",
    "motion.scroll",
    "motion.hover",
    "influence.primary",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsl-file", required=True, help="Input DSL file path.")
    parser.add_argument(
        "--vocab-file",
        default="templates/modern_web_design_vocabulary_v0.json",
        help="Vocabulary JSON path.",
    )
    parser.add_argument(
        "--out-file",
        required=True,
        help="Output JSON file path.",
    )
    return parser.parse_args()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {path}: {exc}") from exc


def parse_value(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return ""

    # Try JSON literal first for arrays, quoted strings, numbers, booleans, objects.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def split_directive(line: str) -> tuple[str, str]:
    m = re.match(r"^([a-z]+)\s+(.+)$", line.strip())
    if not m:
        raise ValueError(f"Invalid directive format: {line}")
    return m.group(1), m.group(2)


def split_pipe(payload: str, line: str) -> tuple[str, str]:
    if "|" not in payload:
        raise ValueError(f"Missing '|' separator: {line}")
    left, right = payload.split("|", 1)
    return left.strip(), right.strip()


def set_path(obj: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur: dict[str, Any] = obj
    for key in parts[:-1]:
        nxt = cur.get(key)
        if nxt is None:
            cur[key] = {}
            nxt = cur[key]
        if not isinstance(nxt, dict):
            raise ValueError(f"Path collision at '{key}' in '{path}'")
        cur = nxt
    cur[parts[-1]] = value


def add_path(obj: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur: dict[str, Any] = obj
    for key in parts[:-1]:
        nxt = cur.get(key)
        if nxt is None:
            cur[key] = {}
            nxt = cur[key]
        if not isinstance(nxt, dict):
            raise ValueError(f"Path collision at '{key}' in '{path}'")
        cur = nxt
    leaf = parts[-1]
    existing = cur.get(leaf)
    if existing is None:
        cur[leaf] = [value]
        return
    if not isinstance(existing, list):
        raise ValueError(f"Path '{path}' is not a list; cannot add.")
    existing.append(value)


def get_path(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def validate_required_paths(spec: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for path in REQUIRED_PATHS:
        value = get_path(spec, path)
        if value is None:
            missing.append(path)
            continue
        if isinstance(value, str) and not value.strip():
            missing.append(path)
    return missing


def build_vocab_index(vocab_json: dict[str, Any]) -> dict[str, str]:
    tokens = vocab_json.get("tokens")
    if not isinstance(tokens, list):
        raise ValueError("Vocabulary JSON missing array: tokens")

    index: dict[str, str] = {}
    for item in tokens:
        if not isinstance(item, dict):
            continue
        token = item.get("token")
        maps_to = item.get("maps_to")
        if isinstance(token, str) and isinstance(maps_to, str):
            index[token] = maps_to
    return index


def compile_dsl(dsl_text: str, vocab_index: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for line_no, raw_line in enumerate(dsl_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        directive, payload = split_directive(line)
        try:
            if directive == "id":
                set_path(out, "id", payload.strip())
            elif directive == "version":
                set_path(out, "version", payload.strip())
            elif directive == "name":
                set_path(out, "name", payload.strip())
            elif directive == "token":
                path, token_text = split_pipe(payload, line)
                mapped = vocab_index.get(token_text)
                if mapped is None:
                    raise ValueError(f"Unknown vocabulary token: '{token_text}'")
                if mapped != path:
                    raise ValueError(
                        f"Token '{token_text}' maps to '{mapped}', not '{path}'"
                    )
                set_path(out, path, token_text)
            elif directive == "set":
                path, value_text = split_pipe(payload, line)
                set_path(out, path, parse_value(value_text))
            elif directive == "add":
                path, value_text = split_pipe(payload, line)
                add_path(out, path, parse_value(value_text))
            elif directive == "score":
                metric, value_text = split_pipe(payload, line)
                value = parse_value(value_text)
                if not isinstance(value, int) or not (1 <= value <= 10):
                    raise ValueError("score value must be an integer in [1,10]")
                set_path(out, f"quality_targets.{metric}", value)
            else:
                raise ValueError(f"Unsupported directive: {directive}")
        except ValueError as exc:
            raise ValueError(f"{exc} (line {line_no}: {raw_line})") from exc

    missing = validate_required_paths(out)
    if missing:
        raise ValueError(
            "Missing required paths: " + ", ".join(missing)
        )
    return out


def main() -> int:
    args = parse_args()
    dsl_file = Path(args.dsl_file)
    vocab_file = Path(args.vocab_file)
    out_file = Path(args.out_file)

    try:
        vocab_index = build_vocab_index(read_json(vocab_file))
        dsl_text = dsl_file.read_text(encoding="utf-8")
        compiled = compile_dsl(dsl_text, vocab_index)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(
            json.dumps(compiled, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except ValueError as exc:
        print(f"compile_error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"compile_error: File not found: {dsl_file}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
