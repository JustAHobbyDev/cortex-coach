# State Storage Discussion Note v0

Status: Open
Owner: Maintainers

## Topic

Discuss whether some `cortex-coach` state should move from file-backed JSON/Markdown artifacts to a database-backed model.

## Why This Is On The Table

- Current state is spread across files (for example decision candidate registry and lifecycle reports).
- File-backed state is simple and transparent, but may become harder to coordinate under higher concurrency and larger scale.
- A DB-backed layer could improve transactional guarantees, querying, and multi-writer behavior.

## Scope To Evaluate

- Which state remains canonical in repo artifacts vs which state could be operationally cached/indexed in DB.
- Local-only DB vs optional service-backed DB.
- Migration, backup/export, and auditability requirements.
- Contract impact on existing `cortex` and `cortex-coach` workflows.

## Next Step

Schedule a design discussion and produce an ADR-style decision artifact before any storage model change.
