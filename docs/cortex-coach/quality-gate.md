# Quality Gate

Use two deterministic commands:
- strict local maintainer gate
- CI correctness gate

Both gates run tests from the locked `dev` dependency group in `pyproject.toml` via `uv.lock`.
Gate scripts set `UV_CACHE_DIR` to a repo-local `.uv-cache/` by default to avoid host-level cache permission issues.

## Run

Preferred:

```bash
just quality-gate
```

Fallback without `just`:

```bash
./scripts/quality_gate_v0.sh
```

CI mode:

```bash
just quality-gate-ci
```

Fallback:

```bash
./scripts/quality_gate_ci_v0.sh
```

## What It Checks

`quality-gate` (strict local):

1. `audit-needed` with fail-on-required behavior
2. `cortex-coach` smoke commands
3. docs local-link + JSON integrity
4. focused `cortex-coach` pytest suite

`quality-gate-ci`:

1. `cortex-coach` smoke commands
2. docs local-link + JSON integrity
3. focused `cortex-coach` pytest suite

## When to Run

- `quality-gate` before merge/release in local maintainer flow
- `quality-gate-ci` in GitHub Actions (and optional local CI parity checks)
