#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[ci-validate] checking markdown links"
python3 - <<'PY'
import re
import sys
from pathlib import Path

root = Path(".").resolve()
targets = [Path("README.md"), Path("docs"), Path("playbooks"), Path("specs")]
md_files = []
for t in targets:
    if not t.exists():
        continue
    if t.is_file() and t.suffix == ".md":
        md_files.append(t)
    elif t.is_dir():
        md_files.extend(sorted(t.rglob("*.md")))

link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
errors: list[str] = []

for md in md_files:
    text = md.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in link_re.finditer(line):
            raw = match.group(1).strip()
            if not raw:
                continue
            if raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = raw.split("#", 1)[0].strip()
            if not target:
                continue
            resolved = (md.parent / target).resolve()
            if not resolved.exists():
                errors.append(f"{md}:{line_no}: missing link target '{raw}'")

if errors:
    print("markdown link validation failed:")
    for e in errors:
        print(f" - {e}")
    sys.exit(1)

print(f"ok: validated {len(md_files)} markdown files")
PY

echo "[ci-validate] checking json parseability"
python3 - <<'PY'
import json
import sys
from pathlib import Path

paths = []
for p in Path("templates").rglob("*.json"):
    if p.is_file():
        paths.append(p)
if Path(".cortex").exists():
    for p in Path(".cortex").rglob("*.json"):
        if p.is_file():
            paths.append(p)

errors = []
for p in sorted(paths):
    try:
        json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{p}: {exc}")

if errors:
    print("json validation failed:")
    for e in errors:
        print(f" - {e}")
    sys.exit(1)

print(f"ok: validated {len(paths)} json files")
PY

echo "[ci-validate] done"
