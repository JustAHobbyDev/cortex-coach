# Maintainer Mode

Use maintainer mode when running `cortex-coach` against this repository (or any governance-heavy repo).

## Goal

Treat `.cortex/` as a lifecycle control plane for governance and drift prevention.

## Recommended Flow

1. Initialize once:

```bash
just coach-init . cortex_repo "Cortex Repository"
```

2. Run cycle + audit regularly:

```bash
just coach-cycle .
just coach-audit .
```

3. Optional fail-fast sequence:

```bash
just coach-maintainer-sequence . cortex_repo "Cortex Repository"
```

4. Optional scoped draft generation:

```bash
just coach-cycle-apply . direction,governance
```

5. Run the quality gate before merge/release:

```bash
just quality-gate
```

## Operating Rules

- Run dependent tasks sequentially (not in parallel).
- Treat failed audits as blockers.
- Version semantic changes (`vN -> vN+1`).
- Commit `.cortex` lifecycle artifacts with related governance/spec changes.
- Require `quality-gate` to pass before merge/release.
