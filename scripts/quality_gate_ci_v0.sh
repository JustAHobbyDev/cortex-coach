#!/usr/bin/env bash
set -euo pipefail

export UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.uv-cache}"
mkdir -p "$UV_CACHE_DIR"

echo "[quality-gate-ci] 1/4 coach smoke checks"
uv run python3 cortex_coach/coach.py --help >/dev/null
uv run python3 cortex_coach/coach.py audit-needed \
  --project-dir . \
  --format json >/dev/null

echo "[quality-gate-ci] 2/4 reflection completeness"
uv run python3 cortex_coach/coach.py reflection-completeness-check \
  --project-dir . \
  --required-decision-status candidate \
  --format json >/dev/null

echo "[quality-gate-ci] 3/4 docs and json integrity"
./scripts/ci_validate_docs_and_json_v0.sh

echo "[quality-gate-ci] 4/4 focused coach tests"
uv run --locked --group dev pytest -q tests/test_coach_*.py

echo "[quality-gate-ci] PASS"
