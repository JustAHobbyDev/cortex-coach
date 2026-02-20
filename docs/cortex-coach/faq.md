# FAQ

## Is `cortex-coach` only for this repository?

No. It is designed to run against any target project directory via `--project-dir`.

## Do I need to run it from inside the target project?

No. You can run from anywhere and point at the project:

```bash
cortex-coach init --project-dir /path/to/project --project-id my_proj --project-name "My Project"
```

## What does it create in my project?

A `.cortex/` folder containing:

- `manifest_v0.json`
- lifecycle artifacts under `.cortex/artifacts/`
- cycle prompts under `.cortex/prompts/`
- reports under `.cortex/reports/`

## Should I commit `.cortex/`?

For governance-heavy workflows, yes. Track meaningful `.cortex/` artifacts and ignore transient temp files.

## Can policy rules be opt-in per project?

Yes. Use:

```bash
cortex-coach policy-enable --project-dir /path/to/project --policy usage-decision
```

This writes a policy file in that project rather than assuming global defaults.

## Can I exclude files from audit/conformance checks?

Yes. Add `.cortexignore` at the project root with gitignore-style patterns.

Use this for explicit, intentional exclusions (for example imported reference artifacts).

## How do I preserve important decisions for future agents?

Use decision lifecycle commands:

1. `decision-capture` during work
2. `decision-promote` when accepted
3. `audit` to verify promoted decisions are linked to impacted artifacts

## What is the recommended command cadence?

1. `init` once
2. `coach` at planning/review milestones
3. `audit` before key merge/release gates

## Why do I get lock timeout errors?

Another process is holding `.cortex/.lock`, or the lock is stale. Use timeout or force unlock options in controlled cases.

## Can I auto-generate drafts only for specific artifacts?

Yes:

```bash
cortex-coach coach --project-dir /path/to/project --apply --apply-scope direction,governance
```

## Can I still use script mode instead of installed CLI?

Yes. Use:

```bash
uv run python3 scripts/cortex_project_coach_v0.py <command> ...
```
