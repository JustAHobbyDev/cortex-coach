#!/usr/bin/env bash
set -euo pipefail

export UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.uv-cache}"
mkdir -p "$UV_CACHE_DIR"

echo "[quality-gate] 1/4 audit-needed"
uv run python3 cortex_coach/coach.py audit-needed \
  --project-dir . \
  --format json \
  --fail-on-required

echo "[quality-gate] 2/4 coach smoke checks"
uv run python3 cortex_coach/coach.py --help >/dev/null
uv run python3 cortex_coach/coach.py audit-needed \
  --project-dir . \
  --format json >/dev/null

echo "[quality-gate] 3/4 docs and json integrity"
./scripts/ci_validate_docs_and_json_v0.sh

echo "[quality-gate] 4/4 focused coach tests"
uv run --locked --group dev pytest -q tests/test_coach_*.py

echo "[quality-gate] PASS"
