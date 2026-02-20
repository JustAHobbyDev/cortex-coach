# Cortex Coach User Docs

This documentation is for users running `cortex-coach` in their own projects.

## Start Here

1. [Install](install.md)
2. [Quickstart](quickstart.md)
3. [Commands](commands.md)
4. [Maintainer Mode](maintainer-mode.md)
5. [Agent Context Loader](agent-context-loader.md)
6. [Quality Gate](quality-gate.md)
7. [FAQ](faq.md)
8. [Troubleshooting](troubleshooting.md)
9. [Known Issue: decision-gap recursion](known_issue_decision_gap_recursive_v0.md)
10. [Bugfix Plan: decision-gap vs audit artifacts](bugfix_plan_decision_gap_audit_artifacts_v0.md)

## What Cortex Coach Does

`cortex-coach` creates and maintains a project-local `.cortex/` lifecycle layer:

- bootstrap project artifacts (`init`)
- audit artifact health (`audit`)
- run guidance cycles (`coach`)
- optionally draft next-version artifacts (`coach --apply`)

It is designed to keep lifecycle artifacts deterministic, versioned, and auditable.
