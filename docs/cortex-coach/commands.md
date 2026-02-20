# Commands

Examples below use installed CLI form (`cortex-coach`).
Fallback: `uv run python3 scripts/cortex_project_coach_v0.py ...`

Common option:
- `--assets-dir /path/to/cortex-assets` to load contract/schema/vocabulary assets from an external Cortex asset root.

## `init`

Bootstrap `.cortex/` artifacts in a target project.

```bash
cortex-coach init \
  --project-dir /path/to/project \
  --project-id my_project \
  --project-name "My Project" \
  --cortex-root .cortex \
  --assets-dir /path/to/cortex-assets
```

Key options:

- `--force`: overwrite existing bootstrap artifacts
- `--lock-timeout-seconds <n>`
- `--lock-stale-seconds <n>`
- `--force-unlock`

## `audit`

Validate lifecycle artifacts and emit a health report.

```bash
cortex-coach audit \
  --project-dir /path/to/project \
  --cortex-root .cortex \
  --audit-scope cortex-only \
  --assets-dir /path/to/cortex-assets
```

`--audit-scope` options:
- `cortex-only` (default): conformance scans only inside the selected cortex root.
- `all`: conformance scans broader governance/spec dirs in the repository.

Output:

- `.cortex/reports/lifecycle_audit_v0.json`
- includes `spec_coverage` findings when `.cortex/spec_registry_v0.json` exists
- includes `artifact_conformance` findings (for example foreign project scope references)

Spec coverage registry is bootstrapped by `init` at:
- `.cortex/spec_registry_v0.json`

### `.cortexignore` exclusions

`audit` and conformance checks support project-local exclusions via `.cortexignore`
using gitignore-style glob patterns.

Example:

```text
# ignore imported reference docs
philosophy/legacy_imports/**

# keep one file included
!philosophy/legacy_imports/README.md
```

## `audit-needed`

Determine whether an audit should run now based on dirty-file risk tiers.

```bash
cortex-coach audit-needed \
  --project-dir /path/to/project
```

JSON mode + CI-friendly fail behavior:

```bash
cortex-coach audit-needed \
  --project-dir /path/to/project \
  --format json \
  --fail-on-required
```

Optional report output:

```bash
cortex-coach audit-needed \
  --project-dir /path/to/project \
  --out-file .cortex/reports/audit_needed_v0.json
```

## `contract-check`

Validate the target project against the coach asset contract.

```bash
cortex-coach contract-check \
  --project-dir /path/to/project \
  --assets-dir /path/to/cortex-assets
```

JSON output:

```bash
cortex-coach contract-check \
  --project-dir /path/to/project \
  --format json
```

Use a custom contract file:

```bash
cortex-coach contract-check \
  --project-dir /path/to/project \
  --contract-file /path/to/coach_asset_contract_v0.json
```

## `coach`

Run one lifecycle guidance cycle.

```bash
cortex-coach coach \
  --project-dir /path/to/project \
  --cortex-root .cortex \
  --audit-scope cortex-only
```

Outputs:

- `.cortex/reports/coach_cycle_<timestamp>_v0.json`
- `.cortex/reports/coach_cycle_<timestamp>_v0.md`
- `.cortex/prompts/coach_cycle_prompt_<timestamp>_v0.md`

### `coach --apply`

Generate draft `vN+1` artifact files for eligible actions.

```bash
cortex-coach coach \
  --project-dir /path/to/project \
  --apply
```

### `coach --apply-scope`

Limit draft generation to:

- `direction`
- `governance`
- `design`

Example:

```bash
cortex-coach coach \
  --project-dir /path/to/project \
  --apply \
  --apply-scope direction,design
```

## `context-load`

Generate a bounded context bundle for agent handoff.

```bash
cortex-coach context-load \
  --project-dir /path/to/project \
  --task "design drift" \
  --max-files 10 \
  --max-chars-per-file 2000 \
  --fallback-mode priority \
  --assets-dir /path/to/cortex-assets
```

Optional file output:

```bash
cortex-coach context-load \
  --project-dir /path/to/project \
  --task "governance updates" \
  --out-file .cortex/reports/agent_context_bundle_v0.json
```

`--fallback-mode priority` enables a fallback chain:
1. restricted budget
2. relaxed budget
3. unrestricted (no file/char limits) if prior levels fail

## `context-policy`

Analyze repository shape and recommend task focus + context budgets.

```bash
cortex-coach context-policy \
  --project-dir /path/to/project \
  --format json \
  --out-file .cortex/reports/context_policy_v0.json
```

## `policy-enable`

Enable an opt-in policy file inside the target project.

```bash
cortex-coach policy-enable \
  --project-dir /path/to/project \
  --policy usage-decision
```

Default output path:
- `.cortex/policies/cortex_coach_usage_decision_policy_v0.md`

Also supported:

```bash
cortex-coach policy-enable \
  --project-dir /path/to/project \
  --policy decision-reflection
```

Default output path:
- `.cortex/policies/cortex_coach_decision_reflection_policy_v0.md`

Optional overwrite:

```bash
cortex-coach policy-enable \
  --project-dir /path/to/project \
  --policy usage-decision \
  --force
```

## `decision-capture`

Capture a decision candidate during active work.

```bash
cortex-coach decision-capture \
  --project-dir /path/to/project \
  --title "Split local and CI quality gates" \
  --decision "Use strict local gate and CI correctness gate." \
  --rationale "Avoid dirty-tree false negatives in CI." \
  --impact-scope governance,ci,docs \
  --linked-artifacts .github/workflows/cortex-validation.yml,docs/cortex-coach/quality-gate.md
```

Writes/updates:
- `.cortex/reports/decision_candidates_v0.json`

## `decision-list`

List decision candidates or promoted decisions.

```bash
cortex-coach decision-list \
  --project-dir /path/to/project \
  --format json
```

Optional status filter:

```bash
cortex-coach decision-list \
  --project-dir /path/to/project \
  --status promoted
```

## `decision-promote`

Promote a captured decision into canonical decision artifact.

```bash
cortex-coach decision-promote \
  --project-dir /path/to/project \
  --decision-id dec_20260220T000000Z_example
```

Writes:
- `.cortex/artifacts/decisions/decision_<slug>_vN.md`
- updates `.cortex/reports/decision_candidates_v0.json`

Audit behavior:
- `audit` fails `unsynced_decisions` when promoted decisions have `impact_scope` but no `linked_artifacts`.

## `just quality-gate`

Run the unified maintainer quality gate for local/CI parity.

```bash
just quality-gate
```

Fallback:

```bash
./scripts/quality_gate_v0.sh
```

## `just quality-gate-ci`

Run CI-focused correctness checks without local dirty-tree enforcement.

```bash
just quality-gate-ci
```

Fallback:

```bash
./scripts/quality_gate_ci_v0.sh
```
