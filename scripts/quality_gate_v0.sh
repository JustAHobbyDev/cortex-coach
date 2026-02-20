#!/usr/bin/env bash
set -euo pipefail

export UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.uv-cache}"
mkdir -p "$UV_CACHE_DIR"

echo "[quality-gate] 1/5 audit-needed"
uv run python3 cortex_coach/coach.py audit-needed \
  --project-dir . \
  --format json \
  --fail-on-required

echo "[quality-gate] 2/5 coach smoke checks"
uv run python3 cortex_coach/coach.py --help >/dev/null
uv run python3 cortex_coach/coach.py audit-needed \
  --project-dir . \
  --format json >/dev/null

echo "[quality-gate] 3/5 reflection completeness"
uv run python3 cortex_coach/coach.py reflection-completeness-check \
  --project-dir . \
  --required-decision-status candidate \
  --format json >/dev/null

echo "[quality-gate] 4/5 docs and json integrity"
./scripts/ci_validate_docs_and_json_v0.sh

echo "[quality-gate] 5/5 focused coach tests"
uv run --locked --group dev pytest -q tests/test_coach_*.py

echo "[quality-gate] PASS"
