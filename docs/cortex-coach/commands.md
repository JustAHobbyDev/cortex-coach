# Commands

Examples below use installed CLI form (`cortex-coach`).
Fallback: `uv run python3 scripts/cortex_project_coach_v0.py ...`

Common option:
- `--assets-dir /path/to/cortex-assets` to load contract/schema/vocabulary assets from an external Cortex asset root.

## Tactical Memory Commands (Phase 1)

`memory-record`, `memory-search`, `memory-prime`, `memory-diff`, and `memory-prune` are implemented. The remaining tactical memory
commands are still pending.

### `memory-record`

Capture one tactical record, enforce sanitization policy controls, and persist to:
- `.cortex/state/tactical_memory/records_v0.jsonl`
- blocked sanitization incidents: `.cortex/state/tactical_memory/sanitization_incidents_v0.jsonl`

```bash
cortex-coach memory-record \
  --project-dir /path/to/project \
  --source-kind manual_capture \
  --source-ref session://local \
  --captured-by cortex-coach \
  --source-refs session://local \
  --text "Implemented lock timeout handling." \
  --content-class implementation_note \
  --tags phase1,lock \
  --format json
```

Key options:
- `--captured-at <RFC3339>` optional; defaults to current UTC
- `--ttl-expires-at <RFC3339>` optional; defaults by retention class
- `--retention-class short|standard|extended` (default `standard`)
- mutation lock controls:
  - `--lock-timeout-seconds`
  - `--lock-stale-seconds`
  - `--force-unlock`

Exit codes:
- `0` success
- `2` invalid arguments/payload shape
- `3` policy violation (blocked sanitization)
- `4` lock conflict/timeout
- `5` internal runtime failure

### `memory-search`

Search tactical records with deterministic ranking tie-break order:
1. `score_desc`
2. `captured_at_desc`
3. `record_id_asc`

```bash
cortex-coach memory-search \
  --project-dir /path/to/project \
  --query "phase1 lock timeout" \
  --content-classes-any implementation_note,risk_note \
  --tags-any phase1,lock \
  --limit 10 \
  --format json
```

Key options:
- `--tags-any <csv>`
- `--tags-all <csv>`
- `--captured-at-from <RFC3339>`
- `--captured-at-to <RFC3339>`
- `--limit <int>`

No-match semantics:
- query misses all records: `no_match.reason=no_match`
- query matches but filters remove all: `no_match.reason=filtered_out`

### `memory-prime`

Build a bounded priming bundle from tactical records with explicit budgets:
- `--max-records`
- `--max-chars`
- `--per-record-max-chars`

```bash
cortex-coach memory-prime \
  --project-dir /path/to/project \
  --task "phase1-handoff" \
  --query-ref "lock timeout" \
  --requested-limit 12 \
  --max-records 6 \
  --max-chars 3000 \
  --per-record-max-chars 400 \
  --format json
```

Output includes deterministic truncation metadata:
- `truncation.applied`
- `truncation.reason` (`none|record_limit|char_budget|per_record_char_limit`)
- `truncation.dropped_record_ids`
- `truncation.truncated_record_count`
- `truncation.truncated_char_count`

### `memory-diff`

Compare two tactical-record JSONL snapshots (or current vs current by default) and emit
deterministic change entries using key `record_id`.

```bash
cortex-coach memory-diff \
  --project-dir /path/to/project \
  --base-file .cortex/reports/diff_base_snapshot.jsonl \
  --target-file .cortex/state/tactical_memory/records_v0.jsonl \
  --format json
```

Ordering policy:
- `change_type_then_record_id_asc`
- change type order: `added`, `modified`, `removed`, `unchanged`

### `memory-prune`

Prune tactical records by policy-bounded criteria. Command defaults to dry-run mode.

```bash
cortex-coach memory-prune \
  --project-dir /path/to/project \
  --expired-before 2026-03-01T00:00:00Z \
  --policy-violation-classes-any secret,credential \
  --dry-run \
  --format json
```

Apply changes (non-dry-run):

```bash
cortex-coach memory-prune \
  --project-dir /path/to/project \
  --expired-before 2026-03-01T00:00:00Z \
  --no-dry-run \
  --format json
```

Ordering policy:
- `decision_then_record_id_asc` (`prune` before `skip`)

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
  --reflection-id ref_20260220T000000Z_split_local_ci_quality \
  --reflection-report .cortex/reports/reflection_scaffold_20260220T000000Z_split_local_ci_quality_v0.json \
  --linked-artifacts .github/workflows/cortex-validation.yml,docs/cortex-coach/quality-gate.md
```

Writes/updates:
- `.cortex/reports/decision_candidates_v0.json`

## `reflection-scaffold`

Scaffold reflection outcomes into decision-ready metadata and command sequence.

```bash
cortex-coach reflection-scaffold \
  --project-dir /path/to/project \
  --title "Require reflection for repeated governance misses" \
  --mistake "Forgot to promote governance decision before closeout." \
  --pattern "Reflection was ad hoc and not encoded." \
  --rule "Run reflection scaffold before closeout when governance files are touched." \
  --format json
```

Useful options:
- `--linked-artifacts a,b,c`: explicitly include artifact paths
- `--no-auto-link-governance-dirty`: disable automatic inclusion of governance-impacting dirty files
- `--strict-generated`: include generated audit deltas when auto-linking dirty files
- `--out-file <path>`: override scaffold report location

Outputs include:
- reflection report persisted by default to `.cortex/reports/reflection_scaffold_<timestamp>_<slug>_v0.json`
- `reflection_id` and `report_file` for linking into `decision-capture`
- suggested decision statement/rationale
- suggested decision artifact path
- suggested linked artifacts (explicit + auto-linked governance dirty files)
- validation checklist and recommended follow-up commands

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

## `decision-gap-check`

Detect governance-impacting dirty files that are not linked to decision entries.

```bash
cortex-coach decision-gap-check \
  --project-dir /path/to/project \
  --format json
```

Strict generated mode:

```bash
cortex-coach decision-gap-check \
  --project-dir /path/to/project \
  --strict-generated \
  --format json
```

Default behavior ignores audit-managed generated deltas (for example lifecycle-audit updates to
`updated_at` / `phases.lifecycle_audited` in manifest). Use `--strict-generated` to enforce on those.

## `reflection-completeness-check`

Fail when persisted reflection scaffold reports are not mapped to decision entries with linked artifacts.

```bash
cortex-coach reflection-completeness-check \
  --project-dir /path/to/project \
  --required-decision-status candidate \
  --format json
```

`--required-decision-status` options:
- `candidate` (default): reflection must map to candidate/promoted decision
- `promoted`: reflection must map to promoted decision

Checks enforced per scaffold report:
- at least one mapped decision entry
- mapped decision includes non-empty `linked_artifacts`
- mapped decision covers scaffold `suggested_linked_artifacts`

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
