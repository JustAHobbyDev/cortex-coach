# Known Issue: `decision-gap-check` Recursive Failure Loop (v0)

## Summary

`decision-gap-check` can fail recursively when decision artifact files are part of governance-impact patterns.

Observed behavior:
- promoting a decision creates `.cortex/artifacts/decisions/decision_*.md`
- if that path class is included in decision-gap governance-impact matching,
  the newly created decision artifact itself can be flagged as uncovered
- this can force additional bookkeeping updates unrelated to user intent

## Impact

- noisy false-positive failures in quality gates
- friction during normal decision capture/promotion flow
- risk of meta-loop where decision artifacts require extra linkage edits

## Proposed Fix

1. Exclude decision artifact files from governance-impact matching in `decision-gap-check`.
2. Keep enforcing linkage for source governance-change files (scripts/policies/playbooks/manifests).
3. Add a regression test:
   - capture+promote decision
   - run `decision-gap-check`
   - assert no failure solely due to decision artifact path creation

## Suggested Implementation Direction

- Update pattern set in `cortex_coach/coach.py` to remove or ignore:
  - `.cortex/artifacts/decisions/**`
- Keep current linkage checks for explicit source files touched by the change.

## Status

Recorded for patch in next maintenance cycle.
