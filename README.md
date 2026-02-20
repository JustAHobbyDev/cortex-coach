# cortex-coach

Standalone runtime CLI for Cortex lifecycle coaching.

## Install (dev)

```bash
uv sync --group dev
```

## Run

```bash
uv run cortex-coach --help
```

Fallback script mode:

```bash
uv run python3 cortex_coach/coach.py --help
```

## Quality Gate

```bash
./scripts/quality_gate_ci_v0.sh
```
