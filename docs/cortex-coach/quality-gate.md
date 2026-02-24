# Quality Gate

Use two deterministic commands:
- strict local maintainer gate
- CI fast required gate
- CI full matrix gate

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

Full matrix (release/nightly):

```bash
./scripts/quality_gate_ci_full_v0.sh
```

## What It Checks

`quality-gate` (strict local):

1. `audit-needed` with fail-on-required behavior
2. `cortex-coach` smoke commands
3. `reflection-completeness-check`
4. docs local-link + JSON integrity
5. focused `cortex-coach` pytest suite

`quality-gate-ci` (fast required):

1. `cortex-coach` smoke commands
2. `reflection-completeness-check`
3. docs local-link + JSON integrity
4. required governance tests + memory command-family smoke

`quality-gate-ci-full` (full matrix):

1. `cortex-coach` smoke commands
2. `reflection-completeness-check`
3. docs local-link + JSON integrity
4. full `cortex-coach` pytest matrix (`tests/`)

## When to Run

- `quality-gate` before merge/release in local maintainer flow
- `quality-gate-ci` for push/PR required checks
- `quality-gate-ci-full` for release-grade full matrix verification
